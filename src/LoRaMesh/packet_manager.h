/*==============================================================================
  packet_manager.h
  ------------------------------------------------------------------------------
  Defines the DataPacket, AckPacket, HelloPacket and AltPacket structures.
  – Generates unique node and message identifiers.
  – Serialises DATA explicitly, big-endian, so the wire format does not depend
    on compiler struct padding and the header can be authenticated byte-exactly.

  DATA carries two distinct address pairs:
    sourceNode / destinationNode  end-to-end, never rewritten, authenticated
    prevHop / nextHop             hop-by-hop, rewritten by every relay
  Keeping them apart is what makes end-to-end encryption possible - the
  destination can still identify the true sender after several relays.
==============================================================================*/
#ifndef PACKET_MANAGER_H
#define PACKET_MANAGER_H

#include "config.h"
#include <stdint.h>
#include <string.h>
#include <esp_system.h>

/*----------------------------------------------------------------------------*/
/*  Wire layout                                                               */
/*----------------------------------------------------------------------------*/
/*  type(1) meshID(2) messageID(4) prevHop(2) nextHop(2)
 *  sourceNode(2) destinationNode(2) seqNum(4) ttl(1) payloadLen(1)
 *  nonceSalt(8)                                                             */
#define DATA_HEADER_SIZE 29

/*  Authenticated-but-not-encrypted header fields. Excludes prevHop, nextHop
 *  and ttl, which relays legitimately rewrite.                               */
#define DATA_AAD_SIZE 16

/*----------------------------------------------------------------------------*/
/*  Packet structures                                                         */
/*----------------------------------------------------------------------------*/
struct DataPacket {
    uint8_t  messageType;
    uint16_t meshID;
    uint32_t messageID;
    uint16_t prevHop;
    uint16_t nextHop;
    uint16_t sourceNode;
    uint16_t destinationNode;
    uint32_t seqNum;
    uint8_t  ttl;
    uint8_t  payloadLen;                 // ciphertext length in bytes
    uint8_t  nonceSalt[NONCE_SALT_LEN];  // random, drawn once when sealed
    uint8_t  payload[MAX_TEXT_LEN];      // AES-128-GCM ciphertext
    uint8_t  tag[GCM_TAG_LEN];           // GCM authentication tag
};
struct AckPacket {
    uint8_t messageType;
    uint16_t meshID;
    uint32_t messageID;
    uint16_t originNode;
    uint16_t destinationNode;
};
/*  One entry of an advertised distance vector. */
struct RouteAdvert {
    uint16_t destination;
    uint16_t seqNum;    // owned by the destination, not the advertiser
    uint8_t  hopCount;  // cost at the advertiser; ROUTE_INFINITY = unreachable
};

/*  HELLO carries three things at once: neighbour discovery, this node's
 *  distance vector, and its X25519 public key. Bundling them means routing
 *  and key distribution cost no transmissions of their own, and a direct
 *  neighbour can agree a session key without any round trip.               */
struct HelloPacket {
    uint8_t  messageType;
    uint16_t meshID;
    uint32_t messageID;
    uint16_t originNode;
    uint16_t originSeq;   // this node's own DSDV sequence number
    uint8_t  routeCount;
    uint8_t  publicKey[ECDH_PUBLIC_KEY_LEN];
    char     name[NODE_NAME_FIELD];
    uint16_t batteryMv;   // 0 when the node cannot measure it
    RouteAdvert routes[MAX_ROUTES_PER_HELLO];
};

/*  Key discovery for peers more than one hop away. Routed like DATA, but
 *  idempotent, so it needs no hop-by-hop ACK - a lost request is simply
 *  reissued by the discovery timer.                                        */
struct KeyPacket {
    uint8_t  messageType;   // MESSAGE_TYPE_KEY_REQ or MESSAGE_TYPE_KEY_RESP
    uint16_t meshID;
    uint32_t messageID;
    uint16_t prevHop;
    uint16_t nextHop;
    uint16_t sourceNode;
    uint16_t destinationNode;
    uint8_t  ttl;
    uint8_t  publicKey[ECDH_PUBLIC_KEY_LEN];
    char     name[NODE_NAME_FIELD];
};

/*  Returned by the destination once a message has been decrypted and shown,
 *  so the sender can distinguish "the next radio heard me" from "it actually
 *  arrived". Routed multi-hop like DATA but needs no ACK of its own.        */
struct ReceiptPacket {
    uint8_t  messageType;
    uint16_t meshID;
    uint32_t messageID;       // the DATA message being confirmed
    uint16_t prevHop;
    uint16_t nextHop;
    uint16_t sourceNode;      // the node confirming - the original destination
    uint16_t destinationNode; // the original sender
    uint8_t  ttl;
    uint8_t  proof[RECEIPT_PROOF_LEN];
};
struct AltPacket {
    uint8_t messageType;
    uint16_t meshID;
    uint32_t messageID;
    uint16_t originNode;
    uint16_t destinationNode;
};
/*----------------------------------------------------------------------------*/
/*  Awaiting ACK                                                              */
/*----------------------------------------------------------------------------*/
struct PendingAck {
    DataPacket packet;
    unsigned long timestamp;   // last transmission, drives the retry timer
    unsigned long createdAt;   // first transmission, drives the latency metric
    uint8_t retryCount;
};

/*============================================================================*/
/*  Node and message identity                                                 */
/*============================================================================*/
/*  0 means "unset", 0xFFFE is the broadcast address and 0xFFFF marks an
 *  unusable next hop, so an ID landing on one of those is nudged clear. The
 *  odds are about 3 in 65536, but a collision would be baffling to debug.   */
inline uint16_t getNodeID() {
    uint64_t chipId = ESP.getEfuseMac();
    uint16_t nodeId = (uint16_t)((chipId & 0xFFFF) ^ ((chipId >> 32) & 0xFFFF));
    if (nodeId == 0) {
        return 1;
    }
    if (nodeId >= BROADCAST_ADDRESS) {
        return (uint16_t)(nodeId - 3);
    }
    return nodeId;
}

/*  A rolling counter rather than a random byte: guarantees no repeat within
 *  256 consecutive messages, which the duplicate history depends on.         */
inline uint32_t getMessageID(uint8_t messageType) {
    static uint8_t counter = 0;
    uint16_t nodeId = getNodeID();
    return ((uint32_t)messageType << 24) | ((uint32_t)nodeId << 8) | (uint32_t)(counter++);
}

/*============================================================================*/
/*  Timing                                                                    */
/*============================================================================*/
/*  millis() wraps back to zero every ~49 days. Comparing a stored deadline
 *  directly against it - `now >= deadline` - misbehaves across that wrap:
 *  a deadline computed just before it becomes a small number, and every
 *  timer either fires at once or never. Comparing the signed difference is
 *  correct on both sides of the wrap, which matters for a node meant to sit
 *  in a field for months.
 *
 *  Elapsed-time checks of the form `now - stamp > interval` are already safe
 *  in unsigned arithmetic and are left as they are.                         */
inline bool timeReached(unsigned long deadline, unsigned long now) {
    return (long)(now - deadline) >= 0;
}

/*============================================================================*/
/*  Big-endian helpers                                                        */
/*============================================================================*/
inline void putU16(uint8_t *buffer, uint16_t value) {
    buffer[0] = (uint8_t)(value >> 8);
    buffer[1] = (uint8_t)(value & 0xFF);
}
inline void putU32(uint8_t *buffer, uint32_t value) {
    buffer[0] = (uint8_t)(value >> 24);
    buffer[1] = (uint8_t)(value >> 16);
    buffer[2] = (uint8_t)(value >> 8);
    buffer[3] = (uint8_t)(value & 0xFF);
}
inline uint16_t getU16(const uint8_t *buffer) {
    return ((uint16_t)buffer[0] << 8) | (uint16_t)buffer[1];
}
inline uint32_t getU32(const uint8_t *buffer) {
    return ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
           ((uint32_t)buffer[2] << 8)  | (uint32_t)buffer[3];
}

/*============================================================================*/
/*  Fill helpers                                                              */
/*============================================================================*/
inline void fillAckPacket(AckPacket &packet, uint32_t messageID, uint16_t destinationNode) {
    packet.messageType = MESSAGE_TYPE_ACK;
    packet.meshID = MESH_ID;
    packet.messageID = messageID;
    packet.originNode = getNodeID();
    packet.destinationNode = destinationNode;
}
/*  Fills the header only. The distance vector is attached separately by
 *  routing_manager.h, which owns the routing table.                         */
inline void fillHelloPacket(HelloPacket &pkt) {
    pkt.messageType = MESSAGE_TYPE_HELLO;
    pkt.meshID      = MESH_ID;
    pkt.messageID   = getMessageID(MESSAGE_TYPE_HELLO);
    pkt.originNode  = getNodeID();
    pkt.originSeq   = 0;
    pkt.routeCount  = 0;
    pkt.batteryMv   = 0;
}
inline void fillAltPacket(AltPacket &packet, uint32_t messageID, uint16_t destinationNode) {
    packet.messageType = MESSAGE_TYPE_ALT;
    packet.meshID = MESH_ID;
    packet.messageID = messageID;
    packet.originNode = getNodeID();
    packet.destinationNode = destinationNode;
}

/*============================================================================*/
/*  DATA serialisation                                                        */
/*============================================================================*/
/*  Builds the additional authenticated data covering every end-to-end header
 *  field. A relay that edits the source, destination, sequence number or
 *  length invalidates the GCM tag and the destination rejects the packet.    */
inline void buildDataAad(const DataPacket &packet, uint8_t aad[DATA_AAD_SIZE]) {
    aad[0] = packet.messageType;
    putU16(&aad[1], packet.meshID);
    putU32(&aad[3], packet.messageID);
    putU16(&aad[7], packet.sourceNode);
    putU16(&aad[9], packet.destinationNode);
    putU32(&aad[11], packet.seqNum);
    aad[15] = packet.payloadLen;
}

inline uint16_t serializeDataPacket(const DataPacket &packet, uint8_t *buffer) {
    buffer[0] = packet.messageType;
    putU16(&buffer[1], packet.meshID);
    putU32(&buffer[3], packet.messageID);
    putU16(&buffer[7], packet.prevHop);
    putU16(&buffer[9], packet.nextHop);
    putU16(&buffer[11], packet.sourceNode);
    putU16(&buffer[13], packet.destinationNode);
    putU32(&buffer[15], packet.seqNum);
    buffer[19] = packet.ttl;
    buffer[20] = packet.payloadLen;
    memcpy(&buffer[21], packet.nonceSalt, NONCE_SALT_LEN);

    memcpy(&buffer[DATA_HEADER_SIZE], packet.payload, packet.payloadLen);
    memcpy(&buffer[DATA_HEADER_SIZE + packet.payloadLen], packet.tag, GCM_TAG_LEN);

    return DATA_HEADER_SIZE + packet.payloadLen + GCM_TAG_LEN;
}

inline bool deserializeDataPacket(DataPacket &packet, const uint8_t *buffer, uint16_t size) {
    if (size < DATA_HEADER_SIZE + GCM_TAG_LEN) {
        return false;
    }
    packet.messageType = buffer[0];
    packet.meshID = getU16(&buffer[1]);
    packet.messageID = getU32(&buffer[3]);
    packet.prevHop = getU16(&buffer[7]);
    packet.nextHop = getU16(&buffer[9]);
    packet.sourceNode = getU16(&buffer[11]);
    packet.destinationNode = getU16(&buffer[13]);
    packet.seqNum = getU32(&buffer[15]);
    packet.ttl = buffer[19];
    packet.payloadLen = buffer[20];
    memcpy(packet.nonceSalt, &buffer[21], NONCE_SALT_LEN);

    if (packet.payloadLen > MAX_TEXT_LEN) {
        return false;
    }
    if (size != DATA_HEADER_SIZE + packet.payloadLen + GCM_TAG_LEN) {
        return false;
    }

    memcpy(packet.payload, &buffer[DATA_HEADER_SIZE], packet.payloadLen);
    memcpy(packet.tag, &buffer[DATA_HEADER_SIZE + packet.payloadLen], GCM_TAG_LEN);
    return true;
}

/*============================================================================*/
/*  HELLO serialisation                                                       */
/*============================================================================*/
inline uint16_t serializeHelloPacket(const HelloPacket &packet, uint8_t *buffer) {
    buffer[0] = packet.messageType;
    putU16(&buffer[1], packet.meshID);
    putU32(&buffer[3], packet.messageID);
    putU16(&buffer[7], packet.originNode);
    putU16(&buffer[9], packet.originSeq);
    buffer[11] = packet.routeCount;
    memcpy(&buffer[12], packet.publicKey, ECDH_PUBLIC_KEY_LEN);
    memcpy(&buffer[44], packet.name, NODE_NAME_FIELD);
    putU16(&buffer[60], packet.batteryMv);

    uint16_t offset = HELLO_HEADER_SIZE;
    for (uint8_t i = 0; i < packet.routeCount; i++) {
        putU16(&buffer[offset], packet.routes[i].destination);
        putU16(&buffer[offset + 2], packet.routes[i].seqNum);
        buffer[offset + 4] = packet.routes[i].hopCount;
        offset += ROUTE_ADVERT_SIZE;
    }
    return offset;
}

inline bool deserializeHelloPacket(HelloPacket &packet, const uint8_t *buffer, uint16_t size) {
    if (size < HELLO_HEADER_SIZE) {
        return false;
    }
    packet.messageType = buffer[0];
    packet.meshID = getU16(&buffer[1]);
    packet.messageID = getU32(&buffer[3]);
    packet.originNode = getU16(&buffer[7]);
    packet.originSeq = getU16(&buffer[9]);
    packet.routeCount = buffer[11];
    memcpy(packet.publicKey, &buffer[12], ECDH_PUBLIC_KEY_LEN);
    memcpy(packet.name, &buffer[44], NODE_NAME_FIELD);
    packet.name[MAX_NODE_NAME_LEN] = '\0'; // never trust a remote string
    packet.batteryMv = getU16(&buffer[60]);

    if (packet.routeCount > MAX_ROUTES_PER_HELLO) {
        return false;
    }
    if (size != HELLO_HEADER_SIZE + (uint16_t)packet.routeCount * ROUTE_ADVERT_SIZE) {
        return false;
    }

    uint16_t offset = HELLO_HEADER_SIZE;
    for (uint8_t i = 0; i < packet.routeCount; i++) {
        packet.routes[i].destination = getU16(&buffer[offset]);
        packet.routes[i].seqNum = getU16(&buffer[offset + 2]);
        packet.routes[i].hopCount = buffer[offset + 4];
        offset += ROUTE_ADVERT_SIZE;
    }
    return true;
}

/*============================================================================*/
/*  KEY_REQ / KEY_RESP serialisation                                          */
/*============================================================================*/
inline void fillKeyPacket(KeyPacket &packet, uint8_t messageType,
                          uint16_t destinationNode, uint16_t nextHop,
                          const uint8_t *publicKey, const char *name) {
    packet.messageType = messageType;
    packet.meshID = MESH_ID;
    packet.messageID = getMessageID(messageType);
    packet.prevHop = getNodeID();
    packet.nextHop = nextHop;
    packet.sourceNode = getNodeID();
    packet.destinationNode = destinationNode;
    packet.ttl = DEFAULT_TTL;
    memcpy(packet.publicKey, publicKey, ECDH_PUBLIC_KEY_LEN);
    memset(packet.name, 0, NODE_NAME_FIELD);
    strncpy(packet.name, name, MAX_NODE_NAME_LEN);
}

inline uint16_t serializeKeyPacket(const KeyPacket &packet, uint8_t *buffer) {
    buffer[0] = packet.messageType;
    putU16(&buffer[1], packet.meshID);
    putU32(&buffer[3], packet.messageID);
    putU16(&buffer[7], packet.prevHop);
    putU16(&buffer[9], packet.nextHop);
    putU16(&buffer[11], packet.sourceNode);
    putU16(&buffer[13], packet.destinationNode);
    buffer[15] = packet.ttl;
    memcpy(&buffer[KEY_HEADER_SIZE], packet.publicKey, ECDH_PUBLIC_KEY_LEN);
    memcpy(&buffer[KEY_HEADER_SIZE + ECDH_PUBLIC_KEY_LEN], packet.name, NODE_NAME_FIELD);
    return KEY_HEADER_SIZE + ECDH_PUBLIC_KEY_LEN + NODE_NAME_FIELD;
}

inline bool deserializeKeyPacket(KeyPacket &packet, const uint8_t *buffer, uint16_t size) {
    if (size != KEY_HEADER_SIZE + ECDH_PUBLIC_KEY_LEN + NODE_NAME_FIELD) {
        return false;
    }
    packet.messageType = buffer[0];
    packet.meshID = getU16(&buffer[1]);
    packet.messageID = getU32(&buffer[3]);
    packet.prevHop = getU16(&buffer[7]);
    packet.nextHop = getU16(&buffer[9]);
    packet.sourceNode = getU16(&buffer[11]);
    packet.destinationNode = getU16(&buffer[13]);
    packet.ttl = buffer[15];
    memcpy(packet.publicKey, &buffer[KEY_HEADER_SIZE], ECDH_PUBLIC_KEY_LEN);
    memcpy(packet.name, &buffer[KEY_HEADER_SIZE + ECDH_PUBLIC_KEY_LEN], NODE_NAME_FIELD);
    packet.name[MAX_NODE_NAME_LEN] = '\0';
    return true;
}

/*============================================================================*/
/*  Delivery receipt serialisation                                            */
/*============================================================================*/
inline uint16_t serializeReceiptPacket(const ReceiptPacket &packet, uint8_t *buffer) {
    buffer[0] = packet.messageType;
    putU16(&buffer[1], packet.meshID);
    putU32(&buffer[3], packet.messageID);
    putU16(&buffer[7], packet.prevHop);
    putU16(&buffer[9], packet.nextHop);
    putU16(&buffer[11], packet.sourceNode);
    putU16(&buffer[13], packet.destinationNode);
    buffer[15] = packet.ttl;
    memcpy(&buffer[RECEIPT_HEADER_SIZE], packet.proof, RECEIPT_PROOF_LEN);
    return RECEIPT_HEADER_SIZE + RECEIPT_PROOF_LEN;
}

inline bool deserializeReceiptPacket(ReceiptPacket &packet, const uint8_t *buffer, uint16_t size) {
    if (size != RECEIPT_HEADER_SIZE + RECEIPT_PROOF_LEN) {
        return false;
    }
    packet.messageType = buffer[0];
    packet.meshID = getU16(&buffer[1]);
    packet.messageID = getU32(&buffer[3]);
    packet.prevHop = getU16(&buffer[7]);
    packet.nextHop = getU16(&buffer[9]);
    packet.sourceNode = getU16(&buffer[11]);
    packet.destinationNode = getU16(&buffer[13]);
    packet.ttl = buffer[15];
    memcpy(packet.proof, &buffer[RECEIPT_HEADER_SIZE], RECEIPT_PROOF_LEN);
    return true;
}

/*  The proof binds the receipt to one message and one pair, under a key only
 *  the two endpoints hold.                                                   */
inline void buildReceiptInput(uint32_t messageID, uint16_t confirmer,
                              uint16_t originalSender, uint8_t input[8]) {
    putU32(&input[0], messageID);
    putU16(&input[4], confirmer);
    putU16(&input[6], originalSender);
}

/*============================================================================*/
/*  ACK / ALT serialisation                                                   */
/*============================================================================*/
/*  Fixed-size control frames exchanged between identical MCUs, so a struct
 *  copy is sufficient.                                                       */
inline void serializePacket(const void *packet, uint8_t *buffer) {
    if (packet == nullptr || buffer == nullptr) {
        return;
    }
    uint8_t messageType = *(reinterpret_cast<const uint8_t *>(packet));

    switch (messageType) {
        case MESSAGE_TYPE_ACK:
            memcpy(buffer, packet, sizeof(AckPacket));
            break;
        case MESSAGE_TYPE_ALT:
            memcpy(buffer, packet, sizeof(AltPacket));
            break;
        default:
            break;
    }
}

/*  Returns false if the frame is shorter than the struct it claims to be.
 *  Without this check a truncated frame would be copied out to its full
 *  struct length, filling the tail with whatever the previous packet left in
 *  the receive buffer.                                                       */
inline bool deserializePacket(void *packet, const uint8_t *buffer, uint16_t size) {
    if (packet == nullptr || buffer == nullptr || size == 0) {
        return false;
    }
    uint8_t messageType = buffer[0];
    switch (messageType) {
        case MESSAGE_TYPE_ACK:
            if (size < sizeof(AckPacket)) {
                return false;
            }
            memcpy(packet, buffer, sizeof(AckPacket));
            return true;
        case MESSAGE_TYPE_ALT:
            if (size < sizeof(AltPacket)) {
                return false;
            }
            memcpy(packet, buffer, sizeof(AltPacket));
            return true;
        default:
            return false;
    }
}

#endif
