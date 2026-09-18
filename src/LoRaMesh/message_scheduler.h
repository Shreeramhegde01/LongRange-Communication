/*==============================================================================
  message_scheduler.h
  ------------------------------------------------------------------------------
  Transmission queue and scheduler:
  – Handles DATA, ACK, HELLO and ALT with a randomised send delay.
  – Tracks outstanding ACKs and retries.
  – Implements alternate-route re-enqueue and periodic HELLO.

  A message is encrypted once, when it is first queued at its source. Relays
  and retries re-queue the packet verbatim, so the ciphertext and its tag are
  never regenerated and the sequence number is never reused.
==============================================================================*/
#ifndef MESSAGE_SCHEDULER_H
#define MESSAGE_SCHEDULER_H

#include "config.h"
#include "packet_manager.h"
#include "communication_manager.h"
#include "routing_manager.h"
#include "security_manager.h"
#include "crypto_session.h"
#include <string.h>

/*----------------------------------------------------------------------------*/
/*  Declaración adelantada                                                    */
/*----------------------------------------------------------------------------*/
void windowCollisionPrevention(); //Esta en message_receiver.h
void requestSessionWith(uint16_t peer); // defined below, used by enqueueTextMessage
bool parkMessage(const DataPacket &packet); // defined below, in the outbox section

/*============================================================================*/
/*  1) Historial para limitar re-enqueue por rutas alternas                    */
/*============================================================================*/
static uint32_t routeHistory[ROUTE_HISTORY_SIZE] = {0};
static uint8_t  routeCount  [ROUTE_HISTORY_SIZE] = {0};
static int      routeIdx = 0;

inline bool canReenqueue(uint32_t messageID)
{
    for (int i = 0; i < ROUTE_HISTORY_SIZE; i++) {
        if (routeHistory[i] == messageID) {               
            if (routeCount[i] >= ROUTE_MAX_ALTERNATES)    
                return false;
            routeCount[i]++;                              
            return true;
        }
    }
    routeHistory[routeIdx] = messageID;
    routeCount [routeIdx]  = 1;
    routeIdx++;
    if (routeIdx >= ROUTE_HISTORY_SIZE) routeIdx = 0;
    return true;
}
/*============================================================================*/
/*  2) Ventana para evitar reenvío múltiple de ACK (ACK replay)               */
/*============================================================================*/
struct AckReplayEntry {
    uint32_t messageID;
    unsigned long ts; // “timestamp” (marca de tiempo)
};
static AckReplayEntry ackReplay[ACK_REPLAY_WINDOW] = {0};
static int ackReplayPos = 0;

inline void rememberAckSent(uint32_t messageID) {
    ackReplay[ackReplayPos].messageID = messageID;
    ackReplay[ackReplayPos].ts    = millis();
    ackReplayPos++;
    if (ackReplayPos >= ACK_REPLAY_WINDOW) ackReplayPos = 0;
}
inline bool recentlyAcked(uint32_t messageID) {
    unsigned long now = millis();
    for (int i = 0; i < ACK_REPLAY_WINDOW; i++) {
        if (ackReplay[i].messageID == messageID &&
            (now - ackReplay[i].ts) <= ACK_REPLAY_TTL_MS) {
            return true;
        }
    }
    return false;
}

/*============================================================================*/
/*  3) Estructura de la cola de transmisión                                   */
/*============================================================================*/
struct ScheduledItem {
    bool isAck;
    bool isHello;
    bool isAlt;
    bool isKey;
    bool isReceipt;
    DataPacket data;
    AckPacket ack;
    HelloPacket hello;
    AltPacket alt;
    KeyPacket key;
    ReceiptPacket receipt;
    unsigned long scheduleTime;
    bool inUse;
};

static ScheduledItem scheduledQueue[MAX_QUEUE_SIZE];

/*  Reported back to the app so it can match a queued message to the delivery
 *  receipt that eventually confirms it.                                     */
static uint32_t lastQueuedMessageID = 0;

/*----------------------------------------------------------------------------*/
/*  Variables globales de apoyo                                               */
/*----------------------------------------------------------------------------*/
PendingAck pendingAcks[MAX_PENDING_ACKS];

/*----------------------------------------------------------------------------*/
/*  HELLO periódico                                                           */
/*----------------------------------------------------------------------------*/
static unsigned long nextHelloTimeAuto = 0;

/*----------------------------------------------------------------------------*/
/*  Historial de ALT enviados (límite por messageID)                          */
/*----------------------------------------------------------------------------*/
static uint32_t altHistory[ALT_HISTORY_SIZE]   = {0};
static uint8_t  altCount  [ALT_HISTORY_SIZE]   = {0};
static int      altIdx = 0; //posicion actual


inline bool canSendAlt(uint32_t messageID) {
    for (int i = 0; i < ALT_HISTORY_SIZE; i++) {
        if (altHistory[i] == messageID) {            
            if (altCount[i] >= ALT_MAX_PER_MESSAGE) return false;
            altCount[i]++;                       
            return true;
        }
    }
    altHistory[altIdx] = messageID;
    altCount [altIdx]  = 1;
    altIdx++; 
    if (altIdx >= ALT_HISTORY_SIZE) {
        altIdx = 0;
    } 
    return true;
}


/*============================================================================*/
/*  4) Encolado de mensajes (DATA / ACK / HELLO / ALT)                        */
/*============================================================================*/
/*  Queues an already-built DATA packet unchanged. Used for relaying another
 *  node's traffic and for retrying our own - in both cases the ciphertext,
 *  tag and sequence number must survive untouched.                          */
/*  Clears the type flags so each enqueue only has to set its own. */
inline void resetQueueFlags(ScheduledItem &item) {
    item.isAck   = false;
    item.isHello = false;
    item.isAlt     = false;
    item.isKey     = false;
    item.isReceipt = false;
}

inline bool enqueueForwardMessage(const DataPacket &packet) {
    unsigned long randomWait = millis() + random(INITIAL_WAIT_LOWER, INITIAL_WAIT_UPPER);
    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        if (!scheduledQueue[i].inUse) {
            resetQueueFlags(scheduledQueue[i]);
            scheduledQueue[i].data = packet;
            scheduledQueue[i].scheduleTime = randomWait;
            scheduledQueue[i].inUse = true;
            return true;
        }
    }
    Serial.println("[QUEUE] full - DATA dropped");
    return false;
}

/*  Originates a new message from this node: assigns a fresh sequence number,
 *  encrypts the text under the key for this source/destination pair and
 *  queues the result.                                                       */
inline bool enqueueTextMessage(uint16_t destinationID, const char *text) {
    size_t textLen = strlen(text);
    if (textLen == 0) {
        Serial.println("[TX] empty message ignored");
        return false;
    }
    if (textLen > MAX_TEXT_LEN) {
        Serial.printf("[TX] message too long (%u > %u bytes)\n",
                      (unsigned)textLen, (unsigned)MAX_TEXT_LEN);
        return false;
    }

    uint16_t localID = getNodeID();
    if (destinationID == 0 || destinationID == localID) {
        Serial.println("[TX] invalid destination");
        return false;
    }

    /*  Without an agreed session key there is no way to encrypt for this
     *  peer, and falling back to a network-wide key would silently hand the
     *  message to every relay. Discovery is already running in the
     *  background, so this resolves on its own within a beacon or two.     */
    const uint8_t *sessionKey = getSessionKey(destinationID);
    if (sessionKey == nullptr) {
        /*  Ask for the peer's key now. The exchange takes a few seconds, so
         *  the caller reports a retryable failure rather than blocking.    */
        requestSessionWith(destinationID);
        Serial.printf("[TX] no secure session with %u yet - key requested\n", destinationID);
        return false;
    }

    /*  Sealed before a route is looked up: a message with nowhere to go yet
     *  is still a valid message, and holding the ciphertext means no
     *  plaintext waits around in memory.                                   */
    DataPacket packet;
    packet.messageType = MESSAGE_TYPE_DATA;
    packet.meshID = MESH_ID;
    packet.messageID = getMessageID(MESSAGE_TYPE_DATA);
    packet.prevHop = localID;
    packet.nextHop = INVALID_NEXT_HOP;
    packet.sourceNode = localID;
    packet.destinationNode = destinationID;
    packet.seqNum = nextSequenceNumber();
    packet.ttl = DEFAULT_TTL;
    packet.payloadLen = (uint8_t)textLen;
    /*  Drawn once, here, and then carried unchanged by every relay and retry:
     *  the salt is part of what was sealed.                                */
    esp_fill_random(packet.nonceSalt, NONCE_SALT_LEN);

    /* AAD covers the header as finalised above, so it must be built last. */
    uint8_t aad[DATA_AAD_SIZE];
    buildDataAad(packet, aad);

    if (!encryptPayload((const uint8_t *)text, textLen, sessionKey,
                        packet.nonceSalt, packet.seqNum,
                        aad, DATA_AAD_SIZE, packet.payload, packet.tag)) {
        Serial.println("[SEC] encryption failed - message not queued");
        return false;
    }

    metrics.messagesSent++;
    lastQueuedMessageID = packet.messageID;

    uint16_t nextHop = getNextHop(localID, destinationID, 0);
    if (nextHop == INVALID_NEXT_HOP) {
        Serial.printf("[TX] no route to %u yet - holding id=%u\n",
                      destinationID, packet.messageID);
        return parkMessage(packet);
    }
    packet.nextHop = nextHop;

    if (!enqueueForwardMessage(packet)) {
        return parkMessage(packet); // queue full: hold rather than lose it
    }

    Serial.printf("[TX] queued id=%u to %u via %u seq=%u (%u bytes encrypted)\n",
                  packet.messageID, destinationID, nextHop, packet.seqNum,
                  (unsigned)textLen);
    return true;
}

inline void enqueueAckMessage(uint32_t messageID, uint16_t destinationNode) {
    unsigned long randomWait = millis() + random(INITIAL_WAIT_LOWER, INITIAL_WAIT_UPPER);
    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        if (!scheduledQueue[i].inUse) {
            resetQueueFlags(scheduledQueue[i]);
            scheduledQueue[i].isAck = true;
            fillAckPacket(scheduledQueue[i].ack, messageID, destinationNode);
            scheduledQueue[i].scheduleTime = randomWait;
            scheduledQueue[i].inUse = true;
            return;
        }
    }
    Serial.println("COLA LLENA: no se pudo encolar ACK");
}

inline void enqueueHelloMessage() {
    unsigned long randomWait = millis() + random(INITIAL_WAIT_LOWER, INITIAL_WAIT_UPPER);

    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        if (!scheduledQueue[i].inUse) {
            resetQueueFlags(scheduledQueue[i]);
            scheduledQueue[i].isHello = true;
            fillHelloPacket(scheduledQueue[i].hello);
            attachRoutesToHello(scheduledQueue[i].hello);
            memcpy(scheduledQueue[i].hello.publicKey, getOwnPublicKey(), ECDH_PUBLIC_KEY_LEN);
            memset(scheduledQueue[i].hello.name, 0, NODE_NAME_FIELD);
            strncpy(scheduledQueue[i].hello.name, getLocalNodeName(), MAX_NODE_NAME_LEN);
            /*  Sampled here rather than continuously: the ADC read gates a
             *  divider on and costs current, and once a beacon is plenty.  */
            scheduledQueue[i].hello.batteryMv = readBatteryMillivolts();
            scheduledQueue[i].scheduleTime = randomWait;
            scheduledQueue[i].inUse = true;
            return;
        }
    }
    Serial.println("COLA LLENA => No se pudo encolar HELLO");
}
inline void enqueueAltMessage(uint32_t messageID, uint16_t destinationNode) {
    unsigned long randomWait = millis() + random(INITIAL_WAIT_LOWER, INITIAL_WAIT_UPPER);

    for(int i=0; i<MAX_QUEUE_SIZE; i++) {
        if(scheduledQueue[i].inUse == false) {
            resetQueueFlags(scheduledQueue[i]);
            scheduledQueue[i].isAlt = true;

            fillAltPacket(scheduledQueue[i].alt, messageID, destinationNode);

            scheduledQueue[i].scheduleTime = randomWait;
            scheduledQueue[i].inUse = true;

            Serial.println("ALT encolado en la cola.");
            return;
        }
    }
    Serial.println("COLA LLENA => no se pudo encolar ALT");
}

/*============================================================================*/
/*  Outbox - messages waiting for their recipient to come back               */
/*============================================================================*/
/*  Holding the encrypted packet rather than the plaintext means nothing
 *  readable sits in memory while a message waits, and the sequence number
 *  and nonce it was sealed with remain the ones the destination will check.
 *  Only the next hop changes when a route reappears.                        */
struct OutboxEntry {
    DataPacket packet;
    unsigned long parkedAt;
    unsigned long lastAttempt;
    uint8_t attempts;
    bool inUse;
};
static OutboxEntry outbox[MAX_OUTBOX];

inline uint8_t outboxCount() {
    uint8_t count = 0;
    for (int i = 0; i < MAX_OUTBOX; i++) {
        if (outbox[i].inUse) {
            count++;
        }
    }
    return count;
}

inline bool parkMessage(const DataPacket &packet) {
    /* Already waiting? Keep the original rather than storing it twice. */
    for (int i = 0; i < MAX_OUTBOX; i++) {
        if (outbox[i].inUse && outbox[i].packet.messageID == packet.messageID) {
            return true;
        }
    }
    for (int i = 0; i < MAX_OUTBOX; i++) {
        if (!outbox[i].inUse) {
            outbox[i].packet = packet;
            outbox[i].parkedAt = millis();
            outbox[i].lastAttempt = millis();
            outbox[i].attempts = 0;
            outbox[i].inUse = true;
            Serial.printf("[OUTBOX] holding id=%u for %u (%u waiting)\n",
                          packet.messageID, packet.destinationNode, outboxCount());
            onMessageHeld(packet.destinationNode, packet.messageID);
            return true;
        }
    }
    /*  Nowhere left to hold it, so this one really is lost. */
    Serial.println("[OUTBOX] full - message dropped");
    metrics.messagesFailed++;
    onMessageExpired(packet.destinationNode, packet.messageID);
    return false;
}

/*  A delivery receipt is the only proof the message actually arrived, so it
 *  is what releases the held copy.                                          */
inline void clearFromOutbox(uint32_t messageID) {
    for (int i = 0; i < MAX_OUTBOX; i++) {
        if (outbox[i].inUse && outbox[i].packet.messageID == messageID) {
            outbox[i].inUse = false;
            return;
        }
    }
}

/*  Retries held messages as soon as the destination is routable again. */
inline void maintainOutbox() {
    static unsigned long nextOutboxScan = 0;
    unsigned long now = millis();
    if (!timeReached(nextOutboxScan, now)) {
        return;
    }
    nextOutboxScan = now + OUTBOX_RETRY_INTERVAL_MS;

    for (int i = 0; i < MAX_OUTBOX; i++) {
        if (!outbox[i].inUse) {
            continue;
        }
        /*  Give up on time or on attempts, whichever comes first. Each
         *  attempt costs a transmission plus its retransmissions, so an
         *  unbounded retry of an unreachable peer is an airtime hazard.    */
        if (now - outbox[i].parkedAt > OUTBOX_TTL_MS ||
            outbox[i].attempts >= MAX_OUTBOX_ATTEMPTS) {
            Serial.printf("[OUTBOX] id=%u given up after %u attempts\n",
                          outbox[i].packet.messageID, outbox[i].attempts);
            metrics.messagesFailed++;
            onMessageExpired(outbox[i].packet.destinationNode,
                             outbox[i].packet.messageID);
            outbox[i].inUse = false;
            continue;
        }

        /*  Quick first try, then back off further after each failed attempt. */
        unsigned long wait = (outbox[i].attempts == 0)
                           ? OUTBOX_FIRST_RETRY_MS
                           : OUTBOX_RETRY_INTERVAL_MS * (unsigned long)outbox[i].attempts;
        if (now - outbox[i].lastAttempt < wait) {
            continue;
        }

        uint16_t destination = outbox[i].packet.destinationNode;
        uint16_t nextHop = getNextHop(getNodeID(), destination, 0);
        if (nextHop == INVALID_NEXT_HOP) {
            continue; // still unreachable, keep waiting
        }

        outbox[i].packet.prevHop = getNodeID();
        outbox[i].packet.nextHop = nextHop;
        outbox[i].packet.ttl = DEFAULT_TTL;
        if (enqueueForwardMessage(outbox[i].packet)) {
            Serial.printf("[OUTBOX] %u routable again - attempt %u for id=%u\n",
                          destination, outbox[i].attempts + 1, outbox[i].packet.messageID);
            metrics.messagesResumed++;
            outbox[i].attempts++;
            outbox[i].lastAttempt = now;
            /*  The entry stays until a delivery receipt confirms it. Freeing
             *  it here would let the message be parked afresh on the next
             *  failure with its attempt count back at zero, so the cap above
             *  would never be reached and an unreachable peer would be
             *  retried indefinitely.                                       */
        }
        return; // one at a time, so a backlog does not flood the channel
    }
}

/*============================================================================*/
/*  Broadcast                                                                 */
/*============================================================================*/
/*  Queues an already-built broadcast for re-flooding. Identical to forwarding
 *  a DATA packet, but kept separate so the intent is obvious at the call
 *  site.                                                                     */
inline void enqueueBroadcastForward(const DataPacket &packet) {
    enqueueForwardMessage(packet);
}

/*  Originates an alert to the whole mesh. Encrypted under the network
 *  broadcast key, so every member can read it and no outsider can.          */
inline bool enqueueBroadcastMessage(const char *text) {
    size_t textLen = strlen(text);
    if (textLen == 0 || textLen > MAX_TEXT_LEN) {
        Serial.println("[BCAST] empty or oversized message ignored");
        return false;
    }

    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        if (scheduledQueue[i].inUse) {
            continue;
        }
        DataPacket &packet = scheduledQueue[i].data;
        packet.messageType = MESSAGE_TYPE_BROADCAST;
        packet.meshID = MESH_ID;
        packet.messageID = getMessageID(MESSAGE_TYPE_BROADCAST);
        packet.prevHop = getNodeID();
        packet.nextHop = BROADCAST_ADDRESS;
        packet.sourceNode = getNodeID();
        packet.destinationNode = BROADCAST_ADDRESS;
        /*  Every node encrypts under the same broadcast key, so the nonce has
         *  to be unique across senders, not just within one. (source, seq)
         *  provides that: seq is monotonic per node and NVS-backed.        */
        packet.seqNum = nextSequenceNumber();
        packet.ttl = BROADCAST_TTL;
        packet.payloadLen = (uint8_t)textLen;
        /*  This is the salt that matters most: the broadcast key is compiled
         *  in and outlives every counter on the device.                    */
        esp_fill_random(packet.nonceSalt, NONCE_SALT_LEN);

        uint8_t aad[DATA_AAD_SIZE];
        buildDataAad(packet, aad);

        if (!encryptPayload((const uint8_t *)text, textLen, getBroadcastKey(),
                            packet.nonceSalt, packet.seqNum,
                            aad, DATA_AAD_SIZE, packet.payload, packet.tag)) {
            Serial.println("[SEC] broadcast encryption failed");
            return false;
        }

        resetQueueFlags(scheduledQueue[i]);
        scheduledQueue[i].scheduleTime = millis() + random(INITIAL_WAIT_LOWER, INITIAL_WAIT_UPPER);
        scheduledQueue[i].inUse = true;

        /*  Remembered now so our own alert echoing back off a neighbour is
         *  recognised as a duplicate rather than re-flooded.               */
        addMessageID(packet.messageID);
        metrics.broadcastsSent++;
        lastQueuedMessageID = packet.messageID;
        Serial.printf("[BCAST] queued id=%u ttl=%u (%u bytes)\n",
                      packet.messageID, packet.ttl, (unsigned)textLen);
        return true;
    }
    Serial.println("[QUEUE] full - broadcast not queued");
    return false;
}

/*============================================================================*/
/*  Key exchange                                                              */
/*============================================================================*/
inline void enqueueKeyPacket(const KeyPacket &packet) {
    unsigned long randomWait = millis() + random(INITIAL_WAIT_LOWER, INITIAL_WAIT_UPPER);
    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        if (!scheduledQueue[i].inUse) {
            resetQueueFlags(scheduledQueue[i]);
            scheduledQueue[i].isKey = true;
            scheduledQueue[i].key = packet;
            scheduledQueue[i].scheduleTime = randomWait;
            scheduledQueue[i].inUse = true;
            return;
        }
    }
    Serial.println("[QUEUE] full - key packet dropped");
}

inline bool sendKeyPacket(uint8_t messageType, uint16_t destinationNode) {
    if (!ownKeypairAvailable()) {
        return false;
    }
    uint16_t nextHop = getNextHop(getNodeID(), destinationNode, 0);
    if (nextHop == INVALID_NEXT_HOP) {
        return false;
    }
    KeyPacket packet;
    fillKeyPacket(packet, messageType, destinationNode, nextHop,
                  getOwnPublicKey(), getLocalNodeName());
    enqueueKeyPacket(packet);
    return true;
}

/*----------------------------------------------------------------------------*/
/*  Delivery receipts                                                         */
/*----------------------------------------------------------------------------*/
inline void enqueueReceiptPacket(const ReceiptPacket &packet) {
    unsigned long randomWait = millis() + random(INITIAL_WAIT_LOWER, INITIAL_WAIT_UPPER);
    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        if (!scheduledQueue[i].inUse) {
            resetQueueFlags(scheduledQueue[i]);
            scheduledQueue[i].isReceipt = true;
            scheduledQueue[i].receipt = packet;
            scheduledQueue[i].scheduleTime = randomWait;
            scheduledQueue[i].inUse = true;
            return;
        }
    }
    Serial.println("[QUEUE] full - receipt dropped");
}

inline void sendDeliveryReceipt(uint16_t originalSender, uint32_t messageID) {
    const uint8_t *sessionKey = getSessionKey(originalSender);
    if (sessionKey == nullptr) {
        return;
    }
    uint16_t nextHop = getNextHop(getNodeID(), originalSender, 0);
    if (nextHop == INVALID_NEXT_HOP) {
        return;
    }

    ReceiptPacket packet;
    packet.messageType = MESSAGE_TYPE_RECEIPT;
    packet.meshID = MESH_ID;
    packet.messageID = messageID;
    packet.prevHop = getNodeID();
    packet.nextHop = nextHop;
    packet.sourceNode = getNodeID();
    packet.destinationNode = originalSender;
    packet.ttl = DEFAULT_TTL;

    /*  Keyed to the session, so only this node can vouch for the delivery. */
    uint8_t input[8];
    buildReceiptInput(messageID, packet.sourceNode, packet.destinationNode, input);
    uint8_t proof[32];
    if (!hmacSha256(sessionKey, AES_KEY_LEN, input, sizeof(input), proof)) {
        return;
    }
    memcpy(packet.proof, proof, RECEIPT_PROOF_LEN);

    enqueueReceiptPacket(packet);
}

inline void sendKeyResponse(uint16_t destinationNode) {
    if (sendKeyPacket(MESSAGE_TYPE_KEY_RESP, destinationNode)) {
        Serial.printf("[KEY] responding to %u\n", destinationNode);
    }
}

/*----------------------------------------------------------------------------*/
/*  On-demand key discovery                                                   */
/*----------------------------------------------------------------------------*/
/*  Neighbours hand over their public key on every beacon, so those sessions
 *  cost nothing. Peers further away are fetched only when something actually
 *  wants to talk to them.
 *
 *  An earlier version chased a key for every destination in the routing table
 *  as soon as it appeared. That is O(N^2) exchanges across the mesh - at 20
 *  nodes, simulation showed it dominating channel traffic and pushing the
 *  duty cycle past the legal limit, to set up sessions that were mostly never
 *  used. Interest is now registered by an attempted send.                   */
struct KeyRequestState {
    uint16_t peer;
    unsigned long lastSent;
    uint8_t attempts;
    bool wanted;
    bool inUse;
};
static KeyRequestState keyRequests[MAX_SESSIONS];
static unsigned long nextKeyDiscoveryTime = 0;

inline KeyRequestState *findOrCreateKeyRequest(uint16_t peer) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (keyRequests[i].inUse && keyRequests[i].peer == peer) {
            return &keyRequests[i];
        }
    }
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!keyRequests[i].inUse) {
            keyRequests[i].inUse = true;
            keyRequests[i].peer = peer;
            keyRequests[i].attempts = 0;
            keyRequests[i].lastSent = 0;
            keyRequests[i].wanted = false;
            return &keyRequests[i];
        }
    }
    return nullptr;
}

/*  Registers that we need a session with this peer. Called when a send is
 *  attempted and no key is held yet.                                        */
inline void requestSessionWith(uint16_t peer) {
    if (peer == 0 || peer == getNodeID() || hasSession(peer)) {
        return;
    }
    KeyRequestState *state = findOrCreateKeyRequest(peer);
    if (state != nullptr && !state->wanted) {
        state->wanted = true;
        state->attempts = 0;
        state->lastSent = 0;
        nextKeyDiscoveryTime = 0; // service it on the next pass, not in 3 s
    }
}

inline void maintainKeyDiscovery() {
    unsigned long now = millis();
    if (!timeReached(nextKeyDiscoveryTime, now)) {
        return;
    }
    nextKeyDiscoveryTime = now + KEY_DISCOVERY_INTERVAL_MS;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        KeyRequestState *state = &keyRequests[i];
        if (!state->inUse || !state->wanted) {
            continue;
        }
        if (hasSession(state->peer)) {
            state->wanted = false;
            continue;
        }
        if (state->attempts >= MAX_KEY_REQUEST_RETRIES) {
            continue;
        }
        if (state->lastSent != 0 && (now - state->lastSent) < KEY_REQUEST_TIMEOUT_MS) {
            continue;
        }
        if (sendKeyPacket(MESSAGE_TYPE_KEY_REQ, state->peer)) {
            state->lastSent = now;
            state->attempts++;
            Serial.printf("[KEY] requesting public key from %u (attempt %u)\n",
                          state->peer, state->attempts);
        }
        return; // one request per pass keeps the queue and channel calm
    }
}

/*----------------------------------------------------------------------------*/
/*  Envoltorios de “schedule” (interfaz pública)                              */
/*----------------------------------------------------------------------------*/
inline void scheduleAltMessage(uint32_t messageID, uint16_t destinationNode) {
    if (!canSendAlt(messageID)) {
        Serial.printf("ALT SUPRIMIDO para messageID %u (límite %u alcanzado).\n", messageID, ALT_MAX_PER_MESSAGE);
        return;                    
    }
    enqueueAltMessage(messageID, destinationNode);
    Serial.println("ALT programado en cola.");
}

inline void scheduleHelloMessage() {
    enqueueHelloMessage();
}
inline void scheduleAckMessage(uint32_t messageID, uint16_t destinationNode) {
    enqueueAckMessage(messageID, destinationNode);
}

/*============================================================================*/
/*  5) Inicialización del planificador                                        */
/*============================================================================*/
inline void initMessageScheduler() {
    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        scheduledQueue[i].inUse = false;
    }
    for (int i = 0; i < MAX_PENDING_ACKS; i++) {
        pendingAcks[i].timestamp = 0;
        pendingAcks[i].retryCount = 0;
    }
    scheduleHelloMessage();
    nextHelloTimeAuto = millis() + currentHelloInterval();
}

/*============================================================================*/
/*  6) Gestion ACKs Pendientes                                                */
/*============================================================================*/
inline void addPendingAck(const DataPacket &packet) {
    for (int i = 0; i < MAX_PENDING_ACKS; i++) {
        if (pendingAcks[i].timestamp != 0 && pendingAcks[i].packet.messageID == packet.messageID)
        {
            Serial.printf("[addPendingAck] Ya existe pendiente para messageID=%u, se actualiza.\n",packet.messageID);
            pendingAcks[i].timestamp  = millis();
            return;
        }
    }
    for (int i = 0; i < MAX_PENDING_ACKS; i++) {
        if (pendingAcks[i].timestamp == 0) {
            pendingAcks[i].packet = packet;
            pendingAcks[i].timestamp = millis();
            pendingAcks[i].createdAt = millis();
            pendingAcks[i].retryCount = 0;
            return;
        }
    }
    Serial.println("No hay espacio en pendingAcks!");
}

/*============================================================================*/
/*  7) HELLO automático                                                       */
/*============================================================================*/
inline void checkAutoHello() {
    /*  A topology change beacons early rather than waiting out the interval;
     *  the queue's own 3-7 s randomised delay supplies the jitter that keeps
     *  a cascade of triggered updates from colliding.                       */
    if (consumeRoutingUpdateFlag() || timeReached(nextHelloTimeAuto, millis())) {
        scheduleHelloMessage();
        nextHelloTimeAuto = millis() + currentHelloInterval();
    }
}

/*============================================================================*/
/*  8) Función principal de mantenimiento                                     */
/*============================================================================*/
inline void updateMessageScheduler() {
    /*------ 8.1 Reintentos de ACK -----------------------------------------*/
    for (int i = 0; i < MAX_PENDING_ACKS; i++) {
        if (pendingAcks[i].timestamp != 0 && (millis() - pendingAcks[i].timestamp >= ACK_TIMEOUT)) {
            
            if (pendingAcks[i].retryCount < MAX_RETRIES) {
                Serial.printf("[ACK] timeout, retrying id=%u\n", pendingAcks[i].packet.messageID);
                metrics.retransmissions++;
                enqueueForwardMessage(pendingAcks[i].packet);
                pendingAcks[i].timestamp = millis();
                pendingAcks[i].retryCount++;
            } else {
                Serial.printf("[ACK] no reply after %u retries for id=%u - trying another route\n",
                              MAX_RETRIES, pendingAcks[i].packet.messageID);
                /*  Not a failure yet: the message is about to be re-routed or
                 *  held. Counting it here would tally the same message once
                 *  per retry cycle, and again when the outbox finally gives
                 *  up. Only that give-up is a real failure.                */
                DataPacket original = pendingAcks[i].packet;
                pendingAcks[i].timestamp = 0;
                pendingAcks[i].retryCount = 0;
                reEnqueueAlternateRoute(original, 0, true); 
            }
        }
    }

    /*------ 8.2 Nada que hacer si radio ocupado ---------------------------*/
    if (!loraIdle) {
        return;
    }
    /*------ 8.3 Selección de siguiente elemento listo ---------------------*/
    unsigned long now = millis();
    int indexToSend = -1;
    /* ACK prioritario */
    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        if (scheduledQueue[i].inUse && timeReached(scheduledQueue[i].scheduleTime, now)
            && scheduledQueue[i].isAck) {
            indexToSend = i;
            break;
        }
    }
    /* cualquier otro si no hubo ACK listo */
    if (indexToSend == -1) {
        for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
            if (scheduledQueue[i].inUse && timeReached(scheduledQueue[i].scheduleTime, now)) {
                indexToSend = i;
                break;
            }
        }
    }
    if (indexToSend == -1) {
        return;
    }
    /*------ 8.4 Listen-before-talk ----------------------------------------*/
    windowCollisionPrevention();
    /*------ 8.5 Envío ------------------------------------------------------*/
    if (scheduledQueue[indexToSend].isReceipt) {
        handleTransmission(scheduledQueue[indexToSend].receipt);
        Serial.printf("[RECEIPT] sent for id=%u to %u\n",
                      scheduledQueue[indexToSend].receipt.messageID,
                      scheduledQueue[indexToSend].receipt.destinationNode);
    }
    else if (scheduledQueue[indexToSend].isKey) {
        handleTransmission(scheduledQueue[indexToSend].key);
        Serial.printf("[KEY] sent %s to %u\n",
                      scheduledQueue[indexToSend].key.messageType == MESSAGE_TYPE_KEY_REQ
                          ? "request" : "response",
                      scheduledQueue[indexToSend].key.destinationNode);
    }
    else if(scheduledQueue[indexToSend].isAlt == true) {
        handleTransmission(scheduledQueue[indexToSend].alt);
        Serial.printf("ALT enviado => messageID=%u\n", scheduledQueue[indexToSend].alt.messageID);
    }
    else if (scheduledQueue[indexToSend].isAck) {
        handleTransmission(scheduledQueue[indexToSend].ack);
        Serial.printf("ACK enviado para messageID: %u\n", scheduledQueue[indexToSend].ack.messageID);
        rememberAckSent(scheduledQueue[indexToSend].ack.messageID);
    } 
    else if (scheduledQueue[indexToSend].isHello) {
        handleTransmission(scheduledQueue[indexToSend].hello);
    }
    else {
        DataPacket &outgoing = scheduledQueue[indexToSend].data;
        handleTransmission(outgoing);
        if (outgoing.messageType == MESSAGE_TYPE_BROADCAST) {
            /*  Nobody in particular is meant to answer a broadcast, so there
             *  is no ACK to wait for and nothing to retry.                 */
            Serial.printf("[BCAST] sent id=%u ttl=%u\n", outgoing.messageID, outgoing.ttl);
        } else {
            Serial.printf("[DATA] sent id=%u nextHop=%u\n",
                          outgoing.messageID, outgoing.nextHop);
            addPendingAck(outgoing);
        }
    }
    scheduledQueue[indexToSend].inUse = false;
}

/*============================================================================*/
/*  9) Re-enqueue por ruta alterna                                            */
/*============================================================================*/
inline void reEnqueueAlternateRoute(const DataPacket &originalPacket,uint16_t excludeNeighbor,bool removeNeighborFlag) {

    /*  Out of alternate routes. If it is ours, hold it rather than lose it -
     *  the destination may simply be temporarily out of reach. Traffic we are
     *  only relaying belongs to its source, which is holding its own copy.  */
    if (!canReenqueue(originalPacket.messageID)) {
        if (originalPacket.sourceNode == getNodeID()) {
            Serial.printf("[ROUTE] alternates exhausted for id=%u - holding\n",
                          originalPacket.messageID);
            parkMessage(originalPacket);
        } else {
            Serial.printf("[ROUTE] %u alternates exhausted for id=%u - discarded\n",
                          ROUTE_MAX_ALTERNATES, originalPacket.messageID);
        }
        return;
    }
    DataPacket copyPacket = originalPacket;

    if (removeNeighborFlag == true) {
        removeNeighbor(copyPacket.nextHop);
    }

    uint16_t newHop = getNextHop(getNodeID(), copyPacket.destinationNode, excludeNeighbor);

    if (newHop == INVALID_NEXT_HOP) {
        if (copyPacket.sourceNode == getNodeID()) {
            Serial.println("[ROUTE] no route left - holding for later");
            parkMessage(copyPacket);
        } else {
            Serial.println("[ROUTE] no alternate next hop - message discarded");
        }
    } else {
        copyPacket.nextHop = newHop;
        copyPacket.prevHop = getNodeID();
        enqueueForwardMessage(copyPacket);
        Serial.printf("[ROUTE] id=%u re-queued via %u\n", copyPacket.messageID, newHop);
    }
}

/*============================================================================*/
/*  10) Incremento de espera tras recepción                                    */
/*============================================================================*/
inline void increaseWaitTime() {
    for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
        if (scheduledQueue[i].inUse) {
            scheduledQueue[i].scheduleTime += random(BACKOFF_LOWER, BACKOFF_UPPER);
        }
    }
}


#endif
