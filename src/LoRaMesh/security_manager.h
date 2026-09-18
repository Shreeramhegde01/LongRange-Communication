/*==============================================================================
  security_manager.h
  ------------------------------------------------------------------------------
  Application-layer security for the mesh (FR6, FR7, FR8).
  – AES-128-GCM authenticated encryption of message payloads (mbedTLS,
    hardware-accelerated on ESP32/ESP32-S3).
  – Per-pair traffic keys derived from the network master key with HKDF-SHA256,
    so each source/destination pair encrypts under its own key.
  – Monotonic sequence numbers reserved from NVS in blocks, plus a sliding
    window replay filter that tolerates out-of-order multi-hop delivery.

  Relay nodes never call decrypt(): they forward ciphertext untouched, so a
  message is readable only at its destination.
==============================================================================*/
#ifndef SECURITY_MANAGER_H
#define SECURITY_MANAGER_H

#include "config.h"
#include "metrics.h"
#include <Arduino.h>
#include <Preferences.h>
#include <string.h>
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"

/*============================================================================*/
/*  Sequence numbers (outbound)                                               */
/*============================================================================*/
static Preferences securityPrefs;
static uint32_t seqNext = 0;      // next sequence number to hand out
static uint32_t seqBlockEnd = 0;  // first number beyond the reserved block

/*  Reserves SEQ_BLOCK_SIZE numbers in flash and hands them out from RAM.
 *  A reboot resumes past the whole reserved block, so a sequence number is
 *  never reissued even if power is lost mid-block. This keeps NVS writes at
 *  one per hundred messages instead of one per message.                      */
inline void reserveSequenceBlock() {
    securityPrefs.begin(NVS_NAMESPACE, false);
    uint32_t base = securityPrefs.getUInt(NVS_SEQ_KEY, 1);
    securityPrefs.putUInt(NVS_SEQ_KEY, base + SEQ_BLOCK_SIZE);
    securityPrefs.end();

    seqNext = base;
    seqBlockEnd = base + SEQ_BLOCK_SIZE;
}

inline uint32_t nextSequenceNumber() {
    if (seqNext >= seqBlockEnd) {
        reserveSequenceBlock();
    }
    return seqNext++;
}

/*============================================================================*/
/*  Key derivation - HKDF-SHA256 (RFC 5869)                                   */
/*============================================================================*/
/*  Implemented directly over HMAC rather than mbedtls_hkdf() because
 *  MBEDTLS_HKDF_C is not enabled in the stock ESP-IDF mbedTLS configuration. */
inline bool hmacSha256(const uint8_t *key, size_t keyLen,
                       const uint8_t *data, size_t dataLen,
                       uint8_t out[32]) {
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == nullptr) {
        return false;
    }
    return mbedtls_md_hmac(info, key, keyLen, data, dataLen, out) == 0;
}

/*  Single-block HKDF: extract then one expand round. 32 bytes of output is
 *  plenty for the 16-byte AES key we need.                                   */
inline bool hkdfSha256(const uint8_t *salt, size_t saltLen,
                       const uint8_t *ikm, size_t ikmLen,
                       const uint8_t *info, size_t infoLen,
                       uint8_t *out, size_t outLen) {
    uint8_t block[64];
    /*  info plus the one-byte T(1) counter has to fit the expand block. No
     *  caller comes close today, but an unchecked memcpy inside a key
     *  derivation is the wrong thing to leave for whoever adds the next
     *  label.                                                                */
    if (outLen > 32 || infoLen + 1 > sizeof(block)) {
        return false;
    }
    uint8_t prk[32];
    if (!hmacSha256(salt, saltLen, ikm, ikmLen, prk)) {
        return false;
    }

    size_t blockLen = 0;
    memcpy(block, info, infoLen);
    blockLen += infoLen;
    block[blockLen++] = 0x01; // T(1) counter

    uint8_t okm[32];
    if (!hmacSha256(prk, sizeof(prk), block, blockLen, okm)) {
        return false;
    }
    memcpy(out, okm, outLen);
    return true;
}

/*----------------------------------------------------------------------------*/
/*  Nonce construction                                                        */
/*----------------------------------------------------------------------------*/
/*  GCM security collapses if a nonce repeats under one key.
 *
 *  An earlier construction built the nonce purely from counters - source,
 *  sequence, destination, message id. That is only safe while every counter
 *  outlives the key, and the broadcast key is compiled in, so it survives an
 *  NVS erase that resets all of them. 64 bits of hardware randomness drawn
 *  per message removes that dependency; the sequence number is appended so
 *  two messages from one node still differ even in the vanishing case where
 *  the salt repeats.
 *
 *  Source and destination are no longer in the nonce, but they remain in the
 *  AAD, so the packet stays bound to its endpoints. The salt itself needs no
 *  separate authentication: altering it changes the nonce, and the tag then
 *  fails to verify.                                                          */
inline void buildNonce(const uint8_t salt[NONCE_SALT_LEN], uint32_t seq,
                       uint8_t nonce[GCM_NONCE_LEN]) {
    memcpy(nonce, salt, NONCE_SALT_LEN);
    nonce[8]  = (uint8_t)(seq >> 24);
    nonce[9]  = (uint8_t)(seq >> 16);
    nonce[10] = (uint8_t)(seq >> 8);
    nonce[11] = (uint8_t)(seq & 0xFF);
}

/*============================================================================*/
/*  Authenticated encryption / decryption                                     */
/*============================================================================*/
inline bool encryptPayload(const uint8_t *plaintext, size_t length,
                           const uint8_t key[AES_KEY_LEN],
                           const uint8_t salt[NONCE_SALT_LEN], uint32_t seq,
                           const uint8_t *aad, size_t aadLen,
                           uint8_t *ciphertext, uint8_t tag[GCM_TAG_LEN]) {
    if (key == nullptr) {
        return false;
    }
    uint8_t nonce[GCM_NONCE_LEN];
    buildNonce(salt, seq, nonce);

    unsigned long started = micros();
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    bool ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_LEN * 8) == 0
           && mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, length,
                                        nonce, GCM_NONCE_LEN, aad, aadLen,
                                        plaintext, ciphertext,
                                        GCM_TAG_LEN, tag) == 0;
    mbedtls_gcm_free(&gcm);
    if (ok) {
        recordEncrypt((uint32_t)(micros() - started));
    }
    return ok;
}

/*  Verifies the tag before releasing any plaintext - mbedtls_gcm_auth_decrypt
 *  returns non-zero and leaves the output unusable on a tag mismatch.        */
inline bool decryptPayload(const uint8_t *ciphertext, size_t length,
                           const uint8_t tag[GCM_TAG_LEN],
                           const uint8_t key[AES_KEY_LEN],
                           const uint8_t salt[NONCE_SALT_LEN], uint32_t seq,
                           const uint8_t *aad, size_t aadLen,
                           uint8_t *plaintext) {
    if (key == nullptr) {
        return false;
    }
    uint8_t nonce[GCM_NONCE_LEN];
    buildNonce(salt, seq, nonce);

    unsigned long started = micros();
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    bool ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_LEN * 8) == 0
           && mbedtls_gcm_auth_decrypt(&gcm, length,
                                       nonce, GCM_NONCE_LEN, aad, aadLen,
                                       tag, GCM_TAG_LEN,
                                       ciphertext, plaintext) == 0;
    mbedtls_gcm_free(&gcm);
    if (ok) {
        recordDecrypt((uint32_t)(micros() - started));
    }
    return ok;
}

/*============================================================================*/
/*  Link-layer frame authentication                                           */
/*============================================================================*/
/*  One network-wide control key, derived from the master key under its own
 *  label. This proves a frame came from a mesh member, not from which member -
 *  every node holds the same key, so an insider could still impersonate a
 *  peer. Distinguishing nodes would need per-node keypairs; what this buys is
 *  that an outsider in radio range can no longer inject routing beacons,
 *  forge acknowledgements, or trigger route churn.                          */
static bool controlKeyReady = false;
static uint8_t controlKey[32];

inline const uint8_t *getControlKey() {
    if (!controlKeyReady) {
        static const uint8_t masterKey[AES_KEY_LEN] = MESH_MASTER_KEY;
        const uint8_t salt[2] = { (uint8_t)(MESH_ID >> 8), (uint8_t)(MESH_ID & 0xFF) };
        const char *label = KDF_CTRL_LABEL;
        /*  Only cache a key that actually derived. Marking it ready
         *  regardless would pin an all-zero key for the life of the node. */
        if (hkdfSha256(salt, sizeof(salt), masterKey, sizeof(masterKey),
                       (const uint8_t *)label, strlen(label),
                       controlKey, sizeof(controlKey))) {
            controlKeyReady = true;
        } else {
            Serial.println("[SEC] control key derivation failed");
        }
    }
    return controlKey;
}

/*----------------------------------------------------------------------------*/
/*  Broadcast key                                                             */
/*----------------------------------------------------------------------------*/
/*  Shared by the whole mesh, under its own HKDF label so it is unrelated to
 *  the control key or any pair's session key. Every member can read a
 *  broadcast; nobody outside can. Note this means a broadcast's *sender* is
 *  only as trustworthy as mesh membership - unlike a one-to-one message,
 *  which only its two endpoints can produce.                                */
static bool broadcastKeyReady = false;
static uint8_t broadcastKey[AES_KEY_LEN];

inline const uint8_t *getBroadcastKey() {
    if (!broadcastKeyReady) {
        static const uint8_t masterKey[AES_KEY_LEN] = MESH_MASTER_KEY;
        const uint8_t salt[2] = { (uint8_t)(MESH_ID >> 8), (uint8_t)(MESH_ID & 0xFF) };
        const char *label = KDF_BROADCAST_LABEL;
        if (hkdfSha256(salt, sizeof(salt), masterKey, sizeof(masterKey),
                       (const uint8_t *)label, strlen(label),
                       broadcastKey, sizeof(broadcastKey))) {
            broadcastKeyReady = true;
        } else {
            Serial.println("[SEC] broadcast key derivation failed");
        }
    }
    return broadcastKey;
}

inline bool computeFrameMac(const uint8_t *frame, size_t length,
                            uint8_t mac[CONTROL_MAC_LEN]) {
    uint8_t full[32];
    if (!hmacSha256(getControlKey(), sizeof(controlKey), frame, length, full)) {
        return false;
    }
    memcpy(mac, full, CONTROL_MAC_LEN);
    return true;
}

/*  Compared in constant time: bailing out on the first mismatched byte would
 *  leak how much of a guessed tag was correct.                              */
inline bool verifyFrameMac(const uint8_t *frame, size_t length, const uint8_t *mac) {
    uint8_t expected[CONTROL_MAC_LEN];
    if (!computeFrameMac(frame, length, expected)) {
        return false;
    }
    uint8_t difference = 0;
    for (size_t i = 0; i < CONTROL_MAC_LEN; i++) {
        difference |= (uint8_t)(expected[i] ^ mac[i]);
    }
    return difference == 0;
}

/*============================================================================*/
/*  Replay protection                                                         */
/*============================================================================*/
struct ReplayEntry {
    uint16_t source;
    uint32_t highest;   // highest sequence number accepted from this source
    uint32_t bitmap;    // bit i set => (highest - i) already seen
    unsigned long lastSeen;
    bool inUse;
};
static ReplayEntry replayTable[MAX_REPLAY_SOURCES];

inline void initReplayTable() {
    for (int i = 0; i < MAX_REPLAY_SOURCES; i++) {
        replayTable[i].inUse = false;
    }
}

inline ReplayEntry *findOrCreateReplayEntry(uint16_t source) {
    for (int i = 0; i < MAX_REPLAY_SOURCES; i++) {
        if (replayTable[i].inUse && replayTable[i].source == source) {
            return &replayTable[i];
        }
    }
    for (int i = 0; i < MAX_REPLAY_SOURCES; i++) {
        if (!replayTable[i].inUse) {
            return &replayTable[i];
        }
    }
    /* Table full: recycle the slot untouched for the longest. */
    int oldest = 0;
    for (int i = 1; i < MAX_REPLAY_SOURCES; i++) {
        if (replayTable[i].lastSeen < replayTable[oldest].lastSeen) {
            oldest = i;
        }
    }
    return &replayTable[oldest];
}

/*  Drops what we remember about a peer's sequence numbers.
 *
 *  Called when a new session key is agreed with that peer. Replay protection
 *  only has meaning inside a key epoch: once the key changes, a replayed
 *  message from the old epoch cannot decrypt under the new one, so the window
 *  is protecting nothing and holding it costs availability.
 *
 *  Without this, a node whose NVS was erased - restarting its sequence at 1 -
 *  is rejected by every peer that still remembers a higher number, with no
 *  recovery short of rebooting the whole mesh.                              */
inline void resetReplayFor(uint16_t source) {
    for (int i = 0; i < MAX_REPLAY_SOURCES; i++) {
        if (replayTable[i].inUse && replayTable[i].source == source) {
            replayTable[i].inUse = false;
            Serial.printf("[SEC] replay window for %u reset on rekey\n", source);
            return;
        }
    }
}

/*  Call only after the GCM tag has verified. Checking an unauthenticated
 *  sequence number would let an attacker poison the window with forged
 *  numbers and lock out the genuine sender.
 *
 *  Returns true if the message is fresh; false if it is a replay or has
 *  fallen outside the window.                                               */
inline bool checkAndUpdateReplay(uint16_t source, uint32_t seq) {
    ReplayEntry *entry = findOrCreateReplayEntry(source);

    if (!entry->inUse || entry->source != source) {
        entry->inUse = true;
        entry->source = source;
        entry->highest = seq;
        entry->bitmap = 1u; // bit 0 marks `highest` itself as seen
        entry->lastSeen = millis();
        return true;
    }

    entry->lastSeen = millis();

    if (seq > entry->highest) {
        uint32_t shift = seq - entry->highest;
        entry->bitmap = (shift >= REPLAY_WINDOW_BITS) ? 0u : (entry->bitmap << shift);
        entry->bitmap |= 1u;
        entry->highest = seq;
        return true;
    }

    uint32_t behind = entry->highest - seq;
    if (behind >= REPLAY_WINDOW_BITS) {
        return false; // too old to prove it is not a replay
    }
    uint32_t mask = 1u << behind;
    if (entry->bitmap & mask) {
        return false; // already seen
    }
    entry->bitmap |= mask;
    return true;
}

/*============================================================================*/
/*  Initialisation                                                            */
/*============================================================================*/
inline void initSecurityManager() {
    reserveSequenceBlock();
    initReplayTable();
    Serial.printf("[SEC] AES-128-GCM ready. Sequence block %u..%u\n",
                  seqNext, seqBlockEnd - 1);
}

#endif
