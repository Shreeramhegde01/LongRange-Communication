/*==============================================================================
  communication_manager.h
  ------------------------------------------------------------------------------
  Link layer between the mesh logic and the radio driver.
  – Resolves RadioLib interrupts into transmit/receive completions.
  – Transmits each packet type and filters what arrives.
  – Decrypts and authenticates DATA, but only at the final destination.

  A relay forwards ciphertext byte-for-byte and never holds a traffic key it
  could use on someone else's message: only sourceNode and destinationNode
  derive the pair key, so an intermediate node cannot read what it carries.
==============================================================================*/
#ifndef COMMUNICATION_MANAGER_H
#define COMMUNICATION_MANAGER_H

#include "config.h"
#include "lora_manager.h"
#include "packet_manager.h"
#include "routing_manager.h"
#include "security_manager.h"
#include "crypto_session.h"
#include "Arduino.h"
#include <string.h>

/*----------------------------------------------------------------------------*/
/*  Forward declarations (break circular includes)                            */
/*----------------------------------------------------------------------------*/
void scheduleAckMessage(uint32_t messageID, uint16_t destinationNode); // message_scheduler.h
void scheduleAltMessage(uint32_t messageID, uint16_t destinationNode); // message_scheduler.h
bool enqueueForwardMessage(const DataPacket &packet);                  // message_scheduler.h
void enqueueKeyPacket(const KeyPacket &packet);                        // message_scheduler.h
void sendKeyResponse(uint16_t destinationNode);                        // message_scheduler.h
void enqueueReceiptPacket(const ReceiptPacket &packet);                // message_scheduler.h
void sendDeliveryReceipt(uint16_t originalSender, uint32_t messageID); // message_scheduler.h
void clearFromOutbox(uint32_t messageID);                              // message_scheduler.h
bool checkDuplicates(uint32_t messageID);                              // message_receiver.h
bool isPendingAck(uint32_t messageID);                                 // message_receiver.h
void addMessageID(uint32_t messageID);                                 // message_receiver.h
void addMessageIDAfterAck(uint32_t messageID);                         // message_receiver.h
void reEnqueueAlternateRoute(const DataPacket &originalPacket, uint16_t excludeNeighbor, bool removeNeighborFlag);
bool recentlyAcked(uint32_t messageID);                                // message_scheduler.h

/*  Implemented by the application layer (LoRaMesh.ino) */
void onSecureMessageDelivered(uint16_t sourceNode, const char *text, int16_t rssi);
void onBroadcastReceived(uint16_t sourceNode, const char *text);
void enqueueBroadcastForward(const DataPacket &packet);                // message_scheduler.h
void onSecurityEvent(const char *reason, uint16_t sourceNode);
void onMessageAcknowledged(uint32_t messageID);
void onMessageConfirmed(uint16_t destinationNode, uint32_t messageID);
void onMessageHeld(uint16_t destinationNode, uint32_t messageID);
void onMessageExpired(uint16_t destinationNode, uint32_t messageID);

/*----------------------------------------------------------------------------*/
/*  Shared globals                                                            */
/*----------------------------------------------------------------------------*/
extern volatile bool loraIdle;
extern volatile bool transmissionDone;
extern volatile bool receptionDone;
extern volatile bool transmissionError;

extern DataPacket receivedPacket;

extern uint8_t receivedBuffer[MAX_PACKET_SIZE];
extern uint16_t receivedSize;
extern int16_t receivedRssi;
extern int8_t receivedSnr;

extern LoraManager loraAntena;
extern PendingAck pendingAcks[MAX_PENDING_ACKS];

/*============================================================================*/
/*  Radio event dispatch                                                      */
/*============================================================================*/
/*  RadioLib raises one DIO1 interrupt for both events, so the outstanding
 *  operation decides which one just finished.                               */
inline void processRadioEvents() {
    /*  Test and clear under a critical section. Reading the flag and then
     *  clearing it leaves a window in which an interrupt raising it again is
     *  silently dropped; the receiver is re-armed every pass so the event
     *  would eventually be recovered, but the race is real and cheap to shut. */
    bool fired;
    portENTER_CRITICAL(&radioIrqMux);
    fired = radioIrqFired;
    radioIrqFired = false;
    portEXIT_CRITICAL(&radioIrqMux);
    if (!fired) {
        return;
    }

    if (loraAntena.state() == RADIO_STATE_TX) {
        loraAntena.finishTransmit();
        transmissionDone = true;
        loraIdle = true;
        loraAntena.startReceive();
        return;
    }

    if (loraAntena.state() == RADIO_STATE_RX) {
        uint16_t size = loraAntena.readPacket(receivedBuffer, MAX_PACKET_SIZE);
        receivedRssi = (int16_t)loraAntena.getRssi();
        receivedSnr  = (int8_t)loraAntena.getSnr();
        if (size > 0) {
            receivedSize = size;
            receptionDone = true;
        }
        loraAntena.restartReceive();
    }
}

/*============================================================================*/
/*  Frame authentication                                                      */
/*============================================================================*/
/*  Every outgoing frame is stamped with a MAC over its whole body. For DATA
 *  this happens on each transmission, so a relay that rewrites the hop fields
 *  re-authenticates them - the end-to-end GCM tag underneath is untouched.   */
inline void transmitFrame(uint8_t *buffer, uint16_t length) {
    uint8_t mac[CONTROL_MAC_LEN];
    if (!computeFrameMac(buffer, length, mac)) {
        Serial.println("[SEC] could not authenticate outgoing frame - not sent");
        transmissionError = true;
        return;
    }
    memcpy(&buffer[length], mac, CONTROL_MAC_LEN);

    uint16_t frameLength = length + CONTROL_MAC_LEN;
    if (loraAntena.send(buffer, frameLength)) {
        loraIdle = false;
        recordFrameSent(frameLength);
    } else {
        transmissionError = true;
    }
}

/*  Verifies and removes the trailing MAC, leaving `length` describing the
 *  frame body so the parsers below see exactly what the sender serialised.  */
inline bool stripAndVerifyFrameMac(uint8_t *buffer, uint16_t &length) {
    if (length <= CONTROL_MAC_LEN) {
        return false;
    }
    uint16_t bodyLength = (uint16_t)(length - CONTROL_MAC_LEN);
    if (!verifyFrameMac(buffer, bodyLength, &buffer[bodyLength])) {
        return false;
    }
    length = bodyLength;
    return true;
}

/*============================================================================*/
/*  Transmission                                                              */
/*============================================================================*/
inline void handleTransmission(const DataPacket &packet) {
    uint8_t txBuffer[MAX_PACKET_SIZE];
    transmitFrame(txBuffer, serializeDataPacket(packet, txBuffer));
}

inline void handleTransmission(const AckPacket &packet) {
    uint8_t txBuffer[MAX_PACKET_SIZE];
    serializePacket(&packet, txBuffer);
    transmitFrame(txBuffer, sizeof(AckPacket));
}

inline void handleTransmission(const HelloPacket &packet) {
    uint8_t txBuffer[MAX_PACKET_SIZE];
    transmitFrame(txBuffer, serializeHelloPacket(packet, txBuffer));
}

inline void handleTransmission(const AltPacket &packet) {
    uint8_t txBuffer[MAX_PACKET_SIZE];
    serializePacket(&packet, txBuffer);
    transmitFrame(txBuffer, sizeof(AltPacket));
}

inline void handleTransmission(const KeyPacket &packet) {
    uint8_t txBuffer[MAX_PACKET_SIZE];
    transmitFrame(txBuffer, serializeKeyPacket(packet, txBuffer));
}

inline void handleTransmission(const ReceiptPacket &packet) {
    uint8_t txBuffer[MAX_PACKET_SIZE];
    transmitFrame(txBuffer, serializeReceiptPacket(packet, txBuffer));
}

inline void handleReception() {
    loraAntena.startReceive();
}

/*----------------------------------------------------------------------------*/
/*  Debug output - header only, the payload is ciphertext here                */
/*----------------------------------------------------------------------------*/
inline void printReceivedPacket() {
    Serial.printf("[DATA] id=%u src=%u dst=%u prevHop=%u nextHop=%u seq=%u ttl=%u len=%u rssi=%d\n",
                  receivedPacket.messageID, receivedPacket.sourceNode,
                  receivedPacket.destinationNode, receivedPacket.prevHop,
                  receivedPacket.nextHop, receivedPacket.seqNum,
                  receivedPacket.ttl, receivedPacket.payloadLen, receivedRssi);
}

/*============================================================================*/
/*  Filters: should this node discard the packet?                             */
/*============================================================================*/
inline bool dropPacket(const DataPacket &packet, uint16_t localMeshID, uint16_t localNodeID) {
    if (packet.ttl == 0) {
        return true;
    }
    if (packet.meshID != localMeshID) {
        return true;
    }
    if (packet.sourceNode == localNodeID) {
        return true; // our own packet echoed back by a relay
    }
    /* Addressed to this node at the link layer, whoever it is ultimately for. */
    return packet.nextHop != localNodeID;
}

inline bool dropAckPacket(const AckPacket &packet, uint16_t localMeshID, uint16_t localNodeID) {
    if (packet.meshID != localMeshID) {
        return true;
    }
    return packet.destinationNode != localNodeID;
}

inline bool dropHelloPacket(const HelloPacket &packet, uint16_t localMeshID) {
    if (packet.meshID != localMeshID) {
        return true;
    }
    return !isAllowedNeighbor(packet.originNode);
}

inline bool dropAltPacket(const AltPacket &packet, uint16_t localMeshID, uint16_t localNodeID) {
    if (packet.meshID != localMeshID) {
        return true;
    }
    return packet.destinationNode != localNodeID;
}

/*============================================================================*/
/*  Final delivery - verify, decrypt, replay-check                            */
/*============================================================================*/
inline void deliverSecureMessage(const DataPacket &packet) {
    /*  Only the two endpoints can produce this key, so reaching here at all
     *  means we are the intended destination.                              */
    const uint8_t *sessionKey = getSessionKey(packet.sourceNode);
    if (sessionKey == nullptr) {
        Serial.printf("[SEC] no session with %u - cannot decrypt, discarded\n",
                      packet.sourceNode);
        onSecurityEvent("NO-SESSION", packet.sourceNode);
        return;
    }

    uint8_t aad[DATA_AAD_SIZE];
    buildDataAad(packet, aad);

    uint8_t plaintext[MAX_TEXT_LEN + 1];
    if (!decryptPayload(packet.payload, packet.payloadLen, packet.tag, sessionKey,
                        packet.nonceSalt, packet.seqNum,
                        aad, DATA_AAD_SIZE, plaintext)) {
        metrics.authFailures++;
        Serial.printf("[SEC] tag verification FAILED for id=%u from %u - discarded\n",
                      packet.messageID, packet.sourceNode);
        onSecurityEvent("AUTH-FAIL", packet.sourceNode);
        return;
    }

    /*  Replay is checked only after the tag verifies, otherwise forged
     *  sequence numbers could advance the window and lock out the real
     *  sender.                                                              */
    if (!checkAndUpdateReplay(packet.sourceNode, packet.seqNum)) {
        metrics.replaysBlocked++;
        Serial.printf("[SEC] replay/stale seq=%u from %u - discarded\n",
                      packet.seqNum, packet.sourceNode);
        onSecurityEvent("REPLAY", packet.sourceNode);
        return;
    }

    metrics.messagesReceived++;
    plaintext[packet.payloadLen] = '\0';
    onSecureMessageDelivered(packet.sourceNode, (const char *)plaintext, receivedRssi);

    /*  Tell the sender it genuinely arrived - the hop-by-hop ACK only ever
     *  proved the next radio along heard the frame.                        */
    sendDeliveryReceipt(packet.sourceNode, packet.messageID);
}

/*============================================================================*/
/*  Dispatch on message type                                                  */
/*============================================================================*/
static unsigned long lastMacAlert = 0;

inline void processPayload() {
    /*  Nothing is parsed until the frame proves it came from a mesh member,
     *  so forged beacons never reach the routing table.                     */
    if (!stripAndVerifyFrameMac(receivedBuffer, receivedSize)) {
        metrics.macFailures++;
        Serial.println("[SEC] frame authentication failed - discarded");
        /* Rate limited: an attacker could otherwise flood the phone link. */
        if (millis() - lastMacAlert > 5000) {
            lastMacAlert = millis();
            onSecurityEvent("UNAUTHENTICATED-FRAME", 0);
        }
        return;
    }

    uint8_t messageType = receivedBuffer[0];

    switch (messageType) {
    /*======================================================================
          DATA - duplicates, ACK, decrypt or relay
    ======================================================================*/
    case MESSAGE_TYPE_DATA: {
        if (!deserializeDataPacket(receivedPacket, receivedBuffer, receivedSize)) {
            Serial.println("[DATA] malformed frame - discarded");
            return;
        }
        if (dropPacket(receivedPacket, MESH_ID, getNodeID())) {
            return;
        }

        /*-- Duplicates -------------------------------------------------*/
        if (checkDuplicates(receivedPacket.messageID)) {
            metrics.duplicatesDropped++;
            if (recentlyAcked(receivedPacket.messageID)) {
                Serial.println("[DATA] duplicate, ACK already sent -> replaying ACK");
                scheduleAckMessage(receivedPacket.messageID, receivedPacket.prevHop);
                return;
            }
            if (isPendingAck(receivedPacket.messageID)) {
                Serial.println("[DATA] duplicate of our own in-flight packet - ignored");
                return;
            }
            /*  ALT asks the sender to find another route. Coming from the
             *  destination that would be wrong - the message did arrive, our
             *  ACK was simply lost or aged out of the replay window. Since
             *  ACK_REPLAY_TTL_MS and ACK_TIMEOUT are both 15 s, a
             *  retransmission lands right on that boundary and would
             *  otherwise trigger a reroute of a delivered message.         */
            if (receivedPacket.destinationNode == getNodeID()) {
                Serial.println("[DATA] duplicate already delivered here - re-ACKing");
                /*  The ACK must actually go out. Returning silently would
                 *  leave the sender retrying a message that did arrive,
                 *  until it exhausted its retries and parked it.           */
                scheduleAckMessage(receivedPacket.messageID, receivedPacket.prevHop);
                return;
            }
            Serial.printf("[DATA] duplicate id=%u -> sending ALT\n", receivedPacket.messageID);
            scheduleAltMessage(receivedPacket.messageID, receivedPacket.prevHop);
            return;
        }

        printReceivedPacket();

        /* Hop-by-hop ACK goes back to whoever actually transmitted it. */
        scheduleAckMessage(receivedPacket.messageID, receivedPacket.prevHop);

        if (receivedPacket.destinationNode == getNodeID()) {
            /*  Remember it so a retransmission (our ACK went missing) is
             *  caught as a duplicate and re-ACKed, rather than reaching the
             *  replay filter and being reported as an attack.               */
            addMessageID(receivedPacket.messageID);
            deliverSecureMessage(receivedPacket);
            return;
        }

        /*-- Relay: rewrite hop fields, leave ciphertext untouched -------*/
        receivedPacket.ttl--;
        if (receivedPacket.ttl == 0) {
            Serial.println("[DATA] TTL exhausted - not relayed");
            return;
        }

        uint16_t previousHop = receivedPacket.prevHop;
        receivedPacket.prevHop = getNodeID();
        receivedPacket.nextHop = getNextHop(getNodeID(), receivedPacket.destinationNode, previousHop);

        if (receivedPacket.nextHop == INVALID_NEXT_HOP) {
            Serial.println("[DATA] no viable next hop - not relayed");
            return;
        }
        Serial.printf("[DATA] relaying id=%u via %u ttl=%u\n",
                      receivedPacket.messageID, receivedPacket.nextHop, receivedPacket.ttl);
        metrics.packetsRelayed++;
        enqueueForwardMessage(receivedPacket);
        break;
    }

    /*======================================================================
          ACK
    ======================================================================*/
    case MESSAGE_TYPE_ACK: {
        AckPacket ackPacket;
        if (!deserializePacket(&ackPacket, receivedBuffer, receivedSize)) {
            Serial.println("[ACK] malformed frame - discarded");
            return;
        }
        if (dropAckPacket(ackPacket, MESH_ID, getNodeID())) {
            return;
        }
        Serial.printf("[ACK] id=%u from %u\n", ackPacket.messageID, ackPacket.originNode);

        for (int i = 0; i < MAX_PENDING_ACKS; i++) {
            if (pendingAcks[i].timestamp != 0 &&
                pendingAcks[i].packet.messageID == ackPacket.messageID) {
                /*  Only messages we originated count towards our own link
                 *  statistics; relayed traffic belongs to its source.      */
                if (pendingAcks[i].packet.sourceNode == getNodeID()) {
                    metrics.nextHopAcked++;
                    recordDeliveryLatency((uint32_t)(millis() - pendingAcks[i].createdAt));
                }
                pendingAcks[i].timestamp = 0;
                pendingAcks[i].retryCount = 0;
                onMessageAcknowledged(ackPacket.messageID);
                break;
            }
        }
        addMessageIDAfterAck(ackPacket.messageID);
        break;
    }

    /*======================================================================
          HELLO - neighbour table refresh
    ======================================================================*/
    case MESSAGE_TYPE_HELLO: {
        HelloPacket helloPacket;
        if (!deserializeHelloPacket(helloPacket, receivedBuffer, receivedSize)) {
            Serial.println("[HELLO] malformed frame - discarded");
            return;
        }
        if (dropHelloPacket(helloPacket, MESH_ID)) {
            return;
        }
        if (helloPacket.originNode == getNodeID()) {
            return; // our own beacon relayed back
        }
        Serial.printf("[HELLO] from %u rssi=%d seq=%u routes=%u\n",
                      helloPacket.originNode, receivedRssi,
                      helloPacket.originSeq, helloPacket.routeCount);
        processHelloRoutes(helloPacket, receivedRssi);
        /*  A neighbour's beacon carries its public key, so a session with any
         *  node we can hear directly costs no round trip at all.           */
        establishSession(helloPacket.originNode, helloPacket.publicKey);
        rememberNodeName(helloPacket.originNode, helloPacket.name);
        rememberNodeBattery(helloPacket.originNode, helloPacket.batteryMv);
        break;
    }

    /*======================================================================
          ALT - the next hop already saw this packet, try another route
    ======================================================================*/
    case MESSAGE_TYPE_ALT: {
        AltPacket altPacket;
        if (!deserializePacket(&altPacket, receivedBuffer, receivedSize)) {
            Serial.println("[ALT] malformed frame - discarded");
            return;
        }
        if (dropAltPacket(altPacket, MESH_ID, getNodeID())) {
            return;
        }
        Serial.printf("[ALT] id=%u from %u\n", altPacket.messageID, altPacket.originNode);

        for (int i = 0; i < MAX_PENDING_ACKS; i++) {
            if (pendingAcks[i].timestamp != 0 &&
                pendingAcks[i].packet.messageID == altPacket.messageID) {
                DataPacket original = pendingAcks[i].packet;
                pendingAcks[i].timestamp = 0;
                pendingAcks[i].retryCount = 0;
                reEnqueueAlternateRoute(original, altPacket.originNode, false);
                break;
            }
        }
        break;
    }

    /*======================================================================
          BROADCAST - network-wide alert, flooded rather than routed
    ======================================================================*/
    case MESSAGE_TYPE_BROADCAST: {
        DataPacket alert;
        if (!deserializeDataPacket(alert, receivedBuffer, receivedSize)) {
            Serial.println("[BCAST] malformed frame - discarded");
            return;
        }
        if (alert.meshID != MESH_ID ||
            alert.ttl == 0 ||
            alert.sourceNode == getNodeID()) {
            return; // wrong mesh, spent, or our own alert echoing back
        }

        /*  Flooding means the same alert arrives from several neighbours.
         *  The first copy is acted on; the rest are dropped silently, which
         *  is what keeps a flood from becoming a storm.                    */
        if (checkDuplicates(alert.messageID)) {
            metrics.duplicatesDropped++;
            return;
        }
        addMessageID(alert.messageID);

        uint8_t aad[DATA_AAD_SIZE];
        buildDataAad(alert, aad);
        uint8_t plaintext[MAX_TEXT_LEN + 1];

        if (!decryptPayload(alert.payload, alert.payloadLen, alert.tag,
                            getBroadcastKey(),
                            alert.nonceSalt, alert.seqNum,
                            aad, DATA_AAD_SIZE, plaintext)) {
            metrics.authFailures++;
            Serial.printf("[SEC] broadcast from %u failed verification\n", alert.sourceNode);
            onSecurityEvent("BAD-BROADCAST", alert.sourceNode);
            return;
        }
        if (!checkAndUpdateReplay(alert.sourceNode, alert.seqNum)) {
            metrics.replaysBlocked++;
            onSecurityEvent("REPLAY", alert.sourceNode);
            return;
        }

        metrics.broadcastsReceived++;
        plaintext[alert.payloadLen] = '\0';
        onBroadcastReceived(alert.sourceNode, (const char *)plaintext);

        /*-- Re-flood so the alert reaches beyond our own radio range ----*/
        alert.ttl--;
        if (alert.ttl > 0) {
            alert.prevHop = getNodeID();
            alert.nextHop = BROADCAST_ADDRESS;
            metrics.broadcastsRelayed++;
            Serial.printf("[BCAST] re-flooding id=%u ttl=%u\n", alert.messageID, alert.ttl);
            enqueueBroadcastForward(alert);
        }
        break;
    }

    /*======================================================================
          KEY_REQ / KEY_RESP - X25519 public key discovery beyond one hop
    ======================================================================*/
    case MESSAGE_TYPE_KEY_REQ:
    case MESSAGE_TYPE_KEY_RESP: {
        KeyPacket keyPacket;
        if (!deserializeKeyPacket(keyPacket, receivedBuffer, receivedSize)) {
            Serial.println("[KEY] malformed frame - discarded");
            return;
        }
        if (keyPacket.meshID != MESH_ID ||
            keyPacket.ttl == 0 ||
            keyPacket.nextHop != getNodeID() ||
            keyPacket.sourceNode == getNodeID()) {
            return;
        }

        if (keyPacket.destinationNode == getNodeID()) {
            bool isRequest = (keyPacket.messageType == MESSAGE_TYPE_KEY_REQ);
            Serial.printf("[KEY] %s from %u\n", isRequest ? "request" : "response",
                          keyPacket.sourceNode);
            /*  One exchange teaches both sides: the requester's key rides in
             *  the request, so the responder never has to ask separately.  */
            establishSession(keyPacket.sourceNode, keyPacket.publicKey);
            rememberNodeName(keyPacket.sourceNode, keyPacket.name);
            if (isRequest) {
                sendKeyResponse(keyPacket.sourceNode);
            }
            return;
        }

        /*-- Relay ------------------------------------------------------*/
        keyPacket.ttl--;
        if (keyPacket.ttl == 0) {
            return;
        }
        uint16_t previousHop = keyPacket.prevHop;
        keyPacket.prevHop = getNodeID();
        keyPacket.nextHop = getNextHop(getNodeID(), keyPacket.destinationNode, previousHop);
        if (keyPacket.nextHop == INVALID_NEXT_HOP) {
            return;
        }
        enqueueKeyPacket(keyPacket);
        break;
    }

    /*======================================================================
          RECEIPT - the destination confirming end-to-end delivery
    ======================================================================*/
    case MESSAGE_TYPE_RECEIPT: {
        ReceiptPacket receipt;
        if (!deserializeReceiptPacket(receipt, receivedBuffer, receivedSize)) {
            return;
        }
        if (receipt.meshID != MESH_ID ||
            receipt.ttl == 0 ||
            receipt.nextHop != getNodeID() ||
            receipt.sourceNode == getNodeID()) {
            return;
        }

        if (receipt.destinationNode == getNodeID()) {
            /*  The frame MAC only proves a mesh member sent this. The proof
             *  is keyed to the session, so only the actual destination could
             *  have produced it - otherwise any node could fake a delivery. */
            const uint8_t *sessionKey = getSessionKey(receipt.sourceNode);
            if (sessionKey == nullptr) {
                return;
            }
            uint8_t input[8];
            buildReceiptInput(receipt.messageID, receipt.sourceNode,
                              receipt.destinationNode, input);
            uint8_t expected[32];
            if (!hmacSha256(sessionKey, AES_KEY_LEN, input, sizeof(input), expected)) {
                return;
            }
            uint8_t difference = 0;
            for (int i = 0; i < RECEIPT_PROOF_LEN; i++) {
                difference |= (uint8_t)(expected[i] ^ receipt.proof[i]);
            }
            if (difference != 0) {
                Serial.printf("[SEC] forged delivery receipt for id=%u - discarded\n",
                              receipt.messageID);
                onSecurityEvent("FORGED-RECEIPT", receipt.sourceNode);
                return;
            }

            /*  A receipt arriving twice would inflate the delivery ratio the
             *  evaluation is measured on. Our own outgoing message IDs are
             *  never otherwise in this history, so it is free to reuse.    */
            if (checkDuplicates(receipt.messageID)) {
                return;
            }
            addMessageID(receipt.messageID);

            metrics.messagesConfirmed++;
            clearFromOutbox(receipt.messageID); // confirmed, stop holding it
            Serial.printf("[RECEIPT] %u confirmed delivery of id=%u\n",
                          receipt.sourceNode, receipt.messageID);
            onMessageConfirmed(receipt.sourceNode, receipt.messageID);
            return;
        }

        /*-- Relay ------------------------------------------------------*/
        receipt.ttl--;
        if (receipt.ttl == 0) {
            return;
        }
        uint16_t previousHop = receipt.prevHop;
        receipt.prevHop = getNodeID();
        receipt.nextHop = getNextHop(getNodeID(), receipt.destinationNode, previousHop);
        if (receipt.nextHop == INVALID_NEXT_HOP) {
            return;
        }
        enqueueReceiptPacket(receipt);
        break;
    }

    default:
        break;
    }
}
#endif
