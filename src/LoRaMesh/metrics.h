/*==============================================================================
  metrics.h
  ------------------------------------------------------------------------------
  Runtime instrumentation for the performance evaluation.

  Collects exactly the quantities the requirements are written against, so the
  evaluation can quote measurements rather than estimates:

    NFR2  end-to-end latency          < 5 s over three hops
    NFR3  packet delivery ratio       >= 90%
    NFR5  cryptographic overhead      < 10 ms per message
    NFR6  energy                      - airtime and duty cycle stand in for it

  Latency here is source-to-ACK measured on one node's own clock, which needs
  no time synchronisation between nodes - the alternative would mean shipping
  timestamps across a mesh with no common time base.
==============================================================================*/
#ifndef METRICS_H
#define METRICS_H

#include "config.h"
#include <Arduino.h>
#include <math.h>

struct MeshMetrics {
    /* Messages this node originated */
    uint32_t messagesSent;
    uint32_t nextHopAcked;      // first hop confirmed receipt - NOT end-to-end
    uint32_t messagesConfirmed; // destination returned a delivery receipt
    uint32_t messagesFailed;
    uint32_t messagesResumed;   // held for an absent recipient, later delivered
    uint32_t retransmissions;

    /* Traffic this node received or carried */
    uint32_t messagesReceived;
    uint32_t packetsRelayed;
    uint32_t duplicatesDropped;

    /* Broadcast alerts */
    uint32_t broadcastsSent;
    uint32_t broadcastsReceived;
    uint32_t broadcastsRelayed;

    /* Security events */
    uint32_t authFailures;
    uint32_t replaysBlocked;
    uint32_t macFailures;
    uint32_t sessionsEstablished;

    /* Cryptographic cost, microseconds */
    uint32_t encryptCount;
    uint64_t encryptTotalUs;
    uint32_t encryptMaxUs;
    uint32_t decryptCount;
    uint64_t decryptTotalUs;
    uint32_t decryptMaxUs;
    uint32_t ecdhCount;
    uint64_t ecdhTotalUs;
    uint32_t ecdhMaxUs;

    /* Delivery latency, milliseconds */
    uint32_t latencySamples;
    uint64_t latencyTotalMs;
    uint32_t latencyMaxMs;

    /* Channel occupancy */
    uint32_t framesSent;
    uint64_t airtimeTxMs;
};

static MeshMetrics metrics;

inline void initMetrics() {
    memset(&metrics, 0, sizeof(metrics));
}

/*----------------------------------------------------------------------------*/
/*  LoRa airtime, per Semtech AN1200.13                                       */
/*----------------------------------------------------------------------------*/
/*  Computed rather than measured so duty cycle can be reported without extra
 *  hardware, and checked against the 1% ceiling for the 865-867 MHz band.   */
inline float loraAirtimeMs(uint16_t payloadBytes) {
    const float symbolTime = (float)(1UL << LORA_SPREADING_FACTOR) / (LORA_BANDWIDTH_KHZ * 1000.0f);
    const int lowDataRateOptimise =
        (LORA_SPREADING_FACTOR >= 11 && LORA_BANDWIDTH_KHZ <= 125.0) ? 1 : 0;

    float numerator = 8.0f * payloadBytes - 4.0f * LORA_SPREADING_FACTOR + 28.0f + 16.0f;
    float denominator = 4.0f * (LORA_SPREADING_FACTOR - 2 * lowDataRateOptimise);
    float payloadSymbols = 8.0f + fmaxf(ceilf(numerator / denominator) * (LORA_CODINGRATE), 0.0f);

    float preambleTime = (LORA_PREAMBLE_LENGTH + 4.25f) * symbolTime;
    return (preambleTime + payloadSymbols * symbolTime) * 1000.0f;
}

/*----------------------------------------------------------------------------*/
/*  Battery                                                                   */
/*----------------------------------------------------------------------------*/
/*  Returns millivolts, or 0 when the reading is not believable - a board
 *  without the divider, or the wrong pin for this revision. Reporting
 *  "unknown" is far more useful than a confident wrong voltage.            */
inline uint16_t readBatteryMillivolts() {
#if defined(BATTERY_ADC_PIN)
  #if defined(BATTERY_ADC_CTRL)
    pinMode(BATTERY_ADC_CTRL, OUTPUT);
    digitalWrite(BATTERY_ADC_CTRL, LOW);  // gate the divider on
    delay(2);
  #endif
    uint32_t total = 0;
    for (int i = 0; i < 8; i++) {
        total += analogReadMilliVolts(BATTERY_ADC_PIN);
    }
  #if defined(BATTERY_ADC_CTRL)
    digitalWrite(BATTERY_ADC_CTRL, HIGH); // and off again, it costs current
  #endif

    uint32_t millivolts = (uint32_t)((total / 8.0f) * BATTERY_DIVIDER);
    if (millivolts < BATTERY_MIN_PLAUSIBLE_MV || millivolts > BATTERY_MAX_PLAUSIBLE_MV) {
        return 0;
    }
    return (uint16_t)millivolts;
#else
    return 0;
#endif
}

inline uint8_t batteryPercent(uint16_t millivolts) {
    if (millivolts == 0) {
        return 0;
    }
    if (millivolts >= BATTERY_FULL_MV) {
        return 100;
    }
    if (millivolts <= BATTERY_EMPTY_MV) {
        return 1;
    }
    return (uint8_t)(1 + 99UL * (millivolts - BATTERY_EMPTY_MV)
                            / (BATTERY_FULL_MV - BATTERY_EMPTY_MV));
}

inline void recordFrameSent(uint16_t frameBytes) {
    metrics.framesSent++;
    metrics.airtimeTxMs += (uint64_t)loraAirtimeMs(frameBytes);
}

/*----------------------------------------------------------------------------*/
/*  Timing helpers                                                            */
/*----------------------------------------------------------------------------*/
inline void recordEncrypt(uint32_t microseconds) {
    metrics.encryptCount++;
    metrics.encryptTotalUs += microseconds;
    if (microseconds > metrics.encryptMaxUs) {
        metrics.encryptMaxUs = microseconds;
    }
}

inline void recordDecrypt(uint32_t microseconds) {
    metrics.decryptCount++;
    metrics.decryptTotalUs += microseconds;
    if (microseconds > metrics.decryptMaxUs) {
        metrics.decryptMaxUs = microseconds;
    }
}

inline void recordEcdh(uint32_t microseconds) {
    metrics.ecdhCount++;
    metrics.ecdhTotalUs += microseconds;
    if (microseconds > metrics.ecdhMaxUs) {
        metrics.ecdhMaxUs = microseconds;
    }
    metrics.sessionsEstablished++;
}

inline void recordDeliveryLatency(uint32_t milliseconds) {
    metrics.latencySamples++;
    metrics.latencyTotalMs += milliseconds;
    if (milliseconds > metrics.latencyMaxMs) {
        metrics.latencyMaxMs = milliseconds;
    }
}

/*----------------------------------------------------------------------------*/
/*  Report                                                                    */
/*----------------------------------------------------------------------------*/
inline String formatMicros(uint64_t total, uint32_t count) {
    if (count == 0) {
        return "n/a";
    }
    float meanMs = (float)(total / count) / 1000.0f;
    return String(meanMs, 3) + " ms";
}

inline String metricsToString() {
    unsigned long uptimeMs = millis();
    float uptimeMin = uptimeMs / 60000.0f;

    String out = "=== Performance ===";
    out += "\nUptime      " + String(uptimeMin, 1) + " min";

    out += "\n-- Delivery (NFR3 >=90%) --";
    out += "\n  sent        " + String(metrics.messagesSent);
    out += "\n  acked hop1  " + String(metrics.nextHopAcked);
    out += "\n  confirmed   " + String(metrics.messagesConfirmed);
    out += "\n  failed      " + String(metrics.messagesFailed);
    out += "\n  retries     " + String(metrics.retransmissions);
    out += "\n  held/resent " + String(metrics.messagesResumed);
    if (metrics.messagesSent > 0) {
        /*  PDR uses end-to-end receipts. The first-hop ACK ratio is shown
         *  alongside it because the gap between the two is exactly the loss
         *  happening beyond the first radio link.                          */
        float pdr = 100.0f * metrics.messagesConfirmed / metrics.messagesSent;
        float linkRatio = 100.0f * metrics.nextHopAcked / metrics.messagesSent;
        out += "\n  PDR e2e     " + String(pdr, 1) + "%";
        out += "\n  hop1 ratio  " + String(linkRatio, 1) + "%";
    } else {
        out += "\n  PDR e2e     n/a";
    }

    out += "\n-- Latency to first hop (NFR2 <5000 ms) --";
    if (metrics.latencySamples > 0) {
        uint32_t mean = (uint32_t)(metrics.latencyTotalMs / metrics.latencySamples);
        out += "\n  mean        " + String(mean) + " ms";
        out += "\n  worst       " + String(metrics.latencyMaxMs) + " ms";
        out += "\n  samples     " + String(metrics.latencySamples);
    } else {
        out += "\n  no samples yet";
    }

    out += "\n-- Crypto (NFR5 <10 ms) --";
    out += "\n  encrypt     " + formatMicros(metrics.encryptTotalUs, metrics.encryptCount)
         + "  max " + String(metrics.encryptMaxUs / 1000.0f, 3) + " ms";
    out += "\n  decrypt     " + formatMicros(metrics.decryptTotalUs, metrics.decryptCount)
         + "  max " + String(metrics.decryptMaxUs / 1000.0f, 3) + " ms";
    out += "\n  ECDH        " + formatMicros(metrics.ecdhTotalUs, metrics.ecdhCount)
         + "  max " + String(metrics.ecdhMaxUs / 1000.0f, 3) + " ms";

    out += "\n-- Mesh --";
    out += "\n  received    " + String(metrics.messagesReceived);
    out += "\n  relayed     " + String(metrics.packetsRelayed);
    out += "\n  duplicates  " + String(metrics.duplicatesDropped);

    out += "\n-- Broadcast --";
    out += "\n  sent        " + String(metrics.broadcastsSent);
    out += "\n  received    " + String(metrics.broadcastsReceived);
    out += "\n  reflooded   " + String(metrics.broadcastsRelayed);

    out += "\n-- Security --";
    out += "\n  sessions    " + String(metrics.sessionsEstablished);
    out += "\n  bad MAC     " + String(metrics.macFailures);
    out += "\n  bad tag     " + String(metrics.authFailures);
    out += "\n  replays     " + String(metrics.replaysBlocked);

    out += "\n-- Channel (limit 1%) --";
    out += "\n  frames      " + String(metrics.framesSent);
    out += "\n  airtime     " + String((uint32_t)(metrics.airtimeTxMs / 1000)) + " s";
    if (uptimeMs > 0) {
        float duty = 100.0f * (float)metrics.airtimeTxMs / (float)uptimeMs;
        out += "\n  duty cycle  " + String(duty, 2) + "%";
    }

    out += "\n-- Resources --";
    out += "\n  free heap   " + String(ESP.getFreeHeap() / 1024) + " KB";
    uint16_t battery = readBatteryMillivolts();
    if (battery > 0) {
        out += "\n  battery     " + String(battery / 1000.0f, 2) + " V ("
             + String(batteryPercent(battery)) + "%)";
    } else {
        out += "\n  battery     unknown (USB power, or check the ADC pins)";
    }
    return out;
}

#endif
