/*==============================================================================
  crypto_session.h
  ------------------------------------------------------------------------------
  X25519 key agreement and per-peer session keys.

  Every node holds a long-term Curve25519 keypair, generated on first boot and
  kept in NVS. Two endpoints derive a shared secret from their own private key
  and the peer's public key; a relay holds neither private key, so it cannot
  compute that secret and cannot read the traffic it forwards - even though it
  holds the same pre-shared network key as everyone else.

  The message key mixes the ECDH secret *with* the master key:

      sessionKey = HKDF(salt = meshID,
                        ikm  = X25519(ourPrivate, theirPublic) || masterKey,
                        info = "loramesh-session-v1" || lowNode || highNode)

  so an attacker must break both mechanisms, not either one. Public keys are
  distributed inside MAC-authenticated frames, which is what stops an outsider
  substituting their own key and standing in the middle.
==============================================================================*/
#ifndef CRYPTO_SESSION_H
#define CRYPTO_SESSION_H

#include "config.h"
#include "packet_manager.h"
#include "security_manager.h"
#include <Arduino.h>
#include <Preferences.h>
#include <esp_random.h>
#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"

/*----------------------------------------------------------------------------*/
/*  Long-term identity                                                        */
/*----------------------------------------------------------------------------*/
static uint8_t ownPublicKey[ECDH_PUBLIC_KEY_LEN];
static uint8_t ownPrivateKey[ECDH_PRIVATE_KEY_LEN];
static bool ownKeypairReady = false;
static Preferences sessionPrefs;

/*  mbedTLS wants an RNG callback; the ESP32's hardware generator is properly
 *  seeded here because the radio subsystem is running.                      */
static int espRandomForMbedtls(void *context, unsigned char *output, size_t length) {
    (void)context;
    esp_fill_random(output, length);
    return 0;
}

/*----------------------------------------------------------------------------*/
/*  Curve25519 primitives                                                     */
/*----------------------------------------------------------------------------*/
/*  Public keys are the 32-byte X coordinate in little-endian order, the
 *  standard X25519 wire encoding.                                           */
inline bool x25519DerivePublic(const uint8_t privateKey[ECDH_PRIVATE_KEY_LEN],
                               uint8_t publicKey[ECDH_PUBLIC_KEY_LEN]) {
    mbedtls_ecp_group group;
    mbedtls_mpi scalar;
    mbedtls_ecp_point point;
    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&scalar);
    mbedtls_ecp_point_init(&point);

    bool ok = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519) == 0
           && mbedtls_mpi_read_binary_le(&scalar, privateKey, ECDH_PRIVATE_KEY_LEN) == 0
           && mbedtls_ecp_mul(&group, &point, &scalar, &group.G,
                              espRandomForMbedtls, nullptr) == 0
           && mbedtls_mpi_write_binary_le(&point.X, publicKey, ECDH_PUBLIC_KEY_LEN) == 0;

    mbedtls_ecp_point_free(&point);
    mbedtls_mpi_free(&scalar);
    mbedtls_ecp_group_free(&group);
    return ok;
}

inline bool x25519GenerateKeypair(uint8_t privateKey[ECDH_PRIVATE_KEY_LEN],
                                  uint8_t publicKey[ECDH_PUBLIC_KEY_LEN]) {
    mbedtls_ecp_group group;
    mbedtls_mpi scalar;
    mbedtls_ecp_point point;
    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&scalar);
    mbedtls_ecp_point_init(&point);

    /*  gen_keypair applies the Montgomery clamping X25519 requires, so the
     *  stored bytes are already a valid scalar when reloaded.               */
    bool ok = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519) == 0
           && mbedtls_ecp_gen_keypair(&group, &scalar, &point,
                                      espRandomForMbedtls, nullptr) == 0
           && mbedtls_mpi_write_binary_le(&scalar, privateKey, ECDH_PRIVATE_KEY_LEN) == 0
           && mbedtls_mpi_write_binary_le(&point.X, publicKey, ECDH_PUBLIC_KEY_LEN) == 0;

    mbedtls_ecp_point_free(&point);
    mbedtls_mpi_free(&scalar);
    mbedtls_ecp_group_free(&group);
    return ok;
}

inline bool x25519SharedSecret(const uint8_t privateKey[ECDH_PRIVATE_KEY_LEN],
                               const uint8_t peerPublicKey[ECDH_PUBLIC_KEY_LEN],
                               uint8_t shared[ECDH_SHARED_LEN]) {
    /*  RFC 7748 requires the most significant bit of the u-coordinate to be
     *  masked off before use; a peer that leaves it set would otherwise be
     *  interpreted as a different, larger value.                            */
    uint8_t peerU[ECDH_PUBLIC_KEY_LEN];
    memcpy(peerU, peerPublicKey, ECDH_PUBLIC_KEY_LEN);
    peerU[ECDH_PUBLIC_KEY_LEN - 1] &= 0x7F;

    mbedtls_ecp_group group;
    mbedtls_mpi scalar;
    mbedtls_ecp_point peerPoint;
    mbedtls_ecp_point result;
    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&scalar);
    mbedtls_ecp_point_init(&peerPoint);
    mbedtls_ecp_point_init(&result);

    bool ok = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519) == 0
           && mbedtls_mpi_read_binary_le(&scalar, privateKey, ECDH_PRIVATE_KEY_LEN) == 0
           && mbedtls_mpi_read_binary_le(&peerPoint.X, peerU, ECDH_PUBLIC_KEY_LEN) == 0
           && mbedtls_mpi_lset(&peerPoint.Z, 1) == 0
           && mbedtls_ecp_mul(&group, &result, &scalar, &peerPoint,
                              espRandomForMbedtls, nullptr) == 0
           && mbedtls_mpi_write_binary_le(&result.X, shared, ECDH_SHARED_LEN) == 0;

    /*  An all-zero result means the peer sent a low-order point. The secret
     *  is then a fixed value the sender knows without holding any private
     *  key, which would let a mesh member impersonate any node by offering
     *  such a key. RFC 7748 section 6.1 calls for exactly this check.
     *  Accumulated over every byte so the test does not short-circuit.     */
    if (ok) {
        uint8_t bits = 0;
        for (size_t i = 0; i < ECDH_SHARED_LEN; i++) {
            bits |= shared[i];
        }
        if (bits == 0) {
            memset(shared, 0, ECDH_SHARED_LEN);
            ok = false;
        }
    }

    mbedtls_ecp_point_free(&result);
    mbedtls_ecp_point_free(&peerPoint);
    mbedtls_mpi_free(&scalar);
    mbedtls_ecp_group_free(&group);
    return ok;
}

/*----------------------------------------------------------------------------*/
/*  Identity setup                                                            */
/*----------------------------------------------------------------------------*/
/*  The keypair must outlive reboots: peers cache our public key, and losing
 *  the private half would silently break every established session.         */
inline void initCryptoSessions() {
    sessionPrefs.begin(NVS_NAMESPACE, false);
    size_t stored = sessionPrefs.getBytesLength(NVS_ECDH_PRIVATE_KEY);

    if (stored == ECDH_PRIVATE_KEY_LEN) {
        sessionPrefs.getBytes(NVS_ECDH_PRIVATE_KEY, ownPrivateKey, ECDH_PRIVATE_KEY_LEN);
        ownKeypairReady = x25519DerivePublic(ownPrivateKey, ownPublicKey);
        if (ownKeypairReady) {
            Serial.println("[ECDH] identity key loaded from NVS");
        }
    }

    if (!ownKeypairReady) {
        unsigned long started = millis();
        ownKeypairReady = x25519GenerateKeypair(ownPrivateKey, ownPublicKey);
        if (ownKeypairReady) {
            sessionPrefs.putBytes(NVS_ECDH_PRIVATE_KEY, ownPrivateKey, ECDH_PRIVATE_KEY_LEN);
            Serial.printf("[ECDH] new identity key generated in %lu ms\n", millis() - started);
        } else {
            Serial.println("[ECDH] FAILED to create identity key - messaging disabled");
        }
    }
    sessionPrefs.end();

    if (ownKeypairReady) {
        Serial.print("[ECDH] public key ");
        for (int i = 0; i < 8; i++) {
            Serial.printf("%02x", ownPublicKey[i]);
        }
        Serial.println("...");
    }
}

inline const uint8_t *getOwnPublicKey() {
    return ownPublicKey;
}

inline bool ownKeypairAvailable() {
    return ownKeypairReady;
}

/*============================================================================*/
/*  Session table                                                             */
/*============================================================================*/
struct SessionEntry {
    uint16_t peer;
    uint8_t  sessionKey[AES_KEY_LEN];
    uint8_t  peerPublicKey[ECDH_PUBLIC_KEY_LEN];
    unsigned long establishedAt;
    bool inUse;
};
static SessionEntry sessionTable[MAX_SESSIONS];

inline void initSessionTable() {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        sessionTable[i].inUse = false;
    }
}

inline SessionEntry *findSession(uint16_t peer) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessionTable[i].inUse && sessionTable[i].peer == peer) {
            return &sessionTable[i];
        }
    }
    return nullptr;
}

inline SessionEntry *allocateSession() {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessionTable[i].inUse) {
            return &sessionTable[i];
        }
    }
    int oldest = 0;
    for (int i = 1; i < MAX_SESSIONS; i++) {
        if (sessionTable[i].establishedAt < sessionTable[oldest].establishedAt) {
            oldest = i;
        }
    }
    return &sessionTable[oldest];
}

/*  Runs the key agreement and caches the result. Repeat calls with the same
 *  public key are cheap no-ops, so a beacon arriving every 30 seconds does
 *  not repeat the scalar multiplication.                                    */
inline bool establishSession(uint16_t peer, const uint8_t *peerPublicKey) {
    if (!ownKeypairReady || peer == 0 || peer == getNodeID()) {
        return false;
    }

    SessionEntry *entry = findSession(peer);
    if (entry != nullptr &&
        memcmp(entry->peerPublicKey, peerPublicKey, ECDH_PUBLIC_KEY_LEN) == 0) {
        return true; // already agreed with this exact key
    }

    uint8_t shared[ECDH_SHARED_LEN];
    unsigned long started = micros();
    if (!x25519SharedSecret(ownPrivateKey, peerPublicKey, shared)) {
        Serial.printf("[ECDH] key agreement with %u failed\n", peer);
        return false;
    }
    unsigned long elapsed = micros() - started;
    recordEcdh((uint32_t)elapsed);

    /*  Mixing the master key in means compromising one mechanism is not
     *  enough on its own.                                                   */
    static const uint8_t masterKey[AES_KEY_LEN] = MESH_MASTER_KEY;
    uint8_t ikm[ECDH_SHARED_LEN + AES_KEY_LEN];
    memcpy(ikm, shared, ECDH_SHARED_LEN);
    memcpy(ikm + ECDH_SHARED_LEN, masterKey, AES_KEY_LEN);

    uint16_t low  = (peer < getNodeID()) ? peer : getNodeID();
    uint16_t high = (peer < getNodeID()) ? getNodeID() : peer;

    const char *label = KDF_SESSION_LABEL;
    size_t labelLen = strlen(label);
    uint8_t info[32];
    memcpy(info, label, labelLen);
    info[labelLen + 0] = (uint8_t)(low >> 8);
    info[labelLen + 1] = (uint8_t)(low & 0xFF);
    info[labelLen + 2] = (uint8_t)(high >> 8);
    info[labelLen + 3] = (uint8_t)(high & 0xFF);

    const uint8_t salt[2] = { (uint8_t)(MESH_ID >> 8), (uint8_t)(MESH_ID & 0xFF) };

    if (entry == nullptr) {
        entry = allocateSession();
    }
    if (!hkdfSha256(salt, sizeof(salt), ikm, sizeof(ikm),
                    info, labelLen + 4, entry->sessionKey, AES_KEY_LEN)) {
        return false;
    }

    memset(shared, 0, sizeof(shared));
    memset(ikm, 0, sizeof(ikm));

    entry->peer = peer;
    memcpy(entry->peerPublicKey, peerPublicKey, ECDH_PUBLIC_KEY_LEN);
    entry->establishedAt = millis();
    entry->inUse = true;

    /*  A new key epoch starts here, so what we remembered about this peer's
     *  sequence numbers no longer applies - and holding it would lock out a
     *  peer whose NVS was erased and whose counter restarted at 1.         */
    resetReplayFor(peer);

    Serial.printf("[ECDH] session with %u established (%lu us)\n", peer, elapsed);
    return true;
}

inline const uint8_t *getSessionKey(uint16_t peer) {
    SessionEntry *entry = findSession(peer);
    return (entry != nullptr) ? entry->sessionKey : nullptr;
}

inline bool hasSession(uint16_t peer) {
    return findSession(peer) != nullptr;
}

inline uint8_t sessionCount() {
    uint8_t count = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessionTable[i].inUse) {
            count++;
        }
    }
    return count;
}

inline String sessionTableToString() {
    String out = "Secure sessions:";
    bool any = false;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessionTable[i].inUse) {
            continue;
        }
        any = true;
        out += "\n  " + String(sessionTable[i].peer) + "  key ";
        for (int b = 0; b < 4; b++) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", sessionTable[i].peerPublicKey[b]);
            out += hex;
        }
        out += "..  up " + String((millis() - sessionTable[i].establishedAt) / 1000) + "s";
    }
    if (!any) {
        out += " none yet";
    }
    return out;
}

#endif
