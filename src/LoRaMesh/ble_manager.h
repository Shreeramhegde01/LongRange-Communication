/*==============================================================================
  ble_manager.h
  ------------------------------------------------------------------------------
  Bluetooth Low Energy bridge between a phone and this mesh node.
  – Exposes the Nordic UART Service, the de-facto "BLE serial port" profile, so
    nRF Connect, Serial Bluetooth Terminal (BLE mode) or a custom app can talk
    to the node with no pairing ceremony.
  – Each write from the phone is queued as one line and drained by the main
    loop; nothing touches the radio or the mesh from the BLE task.

  ESP32-S3 has no Bluetooth Classic radio, so SPP is not an option here - BLE
  is the only path to the phone.
==============================================================================*/
#ifndef BLE_MANAGER_H
#define BLE_MANAGER_H

#include "config.h"
#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>

/*----------------------------------------------------------------------------*/
/*  Inbound line queue (BLE task -> main loop)                                */
/*----------------------------------------------------------------------------*/
#define BLE_QUEUE_SLOTS 4

static char bleQueue[BLE_QUEUE_SLOTS][BLE_RX_LINE_MAX];
static volatile uint8_t bleQueueHead = 0;
static volatile uint8_t bleQueueTail = 0;
static portMUX_TYPE bleQueueMux = portMUX_INITIALIZER_UNLOCKED;

static BLECharacteristic *bleTxCharacteristic = nullptr;
static volatile bool blePhoneConnected = false;

/*  Caller already holds bleQueueMux. Kept separate so the write callback can
 *  take the lock once and commit several lines, rather than re-entering it
 *  per line and relying on the spinlock being recursive.                    */
inline void blePushLineLocked(const char *line) {
    uint8_t next = (uint8_t)((bleQueueHead + 1) % BLE_QUEUE_SLOTS);
    if (next != bleQueueTail) {
        strncpy(bleQueue[bleQueueHead], line, BLE_RX_LINE_MAX - 1);
        bleQueue[bleQueueHead][BLE_RX_LINE_MAX - 1] = '\0';
        bleQueueHead = next;
    }
}

inline void blePushLine(const char *line) {
    portENTER_CRITICAL(&bleQueueMux);
    blePushLineLocked(line);
    portEXIT_CRITICAL(&bleQueueMux);
}

inline bool bleReadLine(char *out, size_t outSize) {
    bool got = false;
    portENTER_CRITICAL(&bleQueueMux);
    if (bleQueueTail != bleQueueHead) {
        strncpy(out, bleQueue[bleQueueTail], outSize - 1);
        out[outSize - 1] = '\0';
        bleQueueTail = (uint8_t)((bleQueueTail + 1) % BLE_QUEUE_SLOTS);
        got = true;
    }
    portEXIT_CRITICAL(&bleQueueMux);
    return got;
}

/*----------------------------------------------------------------------------*/
/*  Callbacks                                                                 */
/*----------------------------------------------------------------------------*/
class MeshBleServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer *server) override {
        blePhoneConnected = true;
        Serial.println("[BLE] phone connected");
    }
    void onDisconnect(BLEServer *server) override {
        blePhoneConnected = false;
        Serial.println("[BLE] phone disconnected");
        server->startAdvertising(); // stay discoverable for the next connection
    }
};

/*----------------------------------------------------------------------------*/
/*  Line framing                                                              */
/*----------------------------------------------------------------------------*/
/*  A long message can exceed the negotiated MTU, so a phone may deliver one
 *  line across several writes. Bytes are accumulated and cut on a newline.
 *  Generic terminals like nRF Connect send no terminator at all, so a short
 *  idle gap also ends a line - which is why the main loop has to poke this.  */
static char blePendingLine[BLE_RX_LINE_MAX];
static size_t blePendingLength = 0;
static volatile unsigned long blePendingSince = 0;

/*  Caller must hold bleQueueMux. */
inline void bleCommitPendingLine() {
    if (blePendingLength == 0) {
        /*  Clear the idle timer even with nothing to commit. Leaving it set
         *  would make bleFlushIdleLine() take a critical section - disabling
         *  interrupts - on every main-loop pass from then on.              */
        blePendingSince = 0;
        return;
    }
    blePendingLine[blePendingLength] = '\0';
    blePushLineLocked(blePendingLine);
    blePendingLength = 0;
    blePendingSince = 0;
}

class MeshBleRxCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *characteristic) override {
        uint8_t *data = characteristic->getData();
        size_t length = characteristic->getLength();
        if (data == nullptr || length == 0) {
            return;
        }

        portENTER_CRITICAL(&bleQueueMux);
        for (size_t i = 0; i < length; i++) {
            char c = (char)data[i];
            if (c == '\n' || c == '\r') {
                bleCommitPendingLine();
            } else if (blePendingLength < BLE_RX_LINE_MAX - 1) {
                blePendingLine[blePendingLength++] = c;
            }
        }
        /*  Only arm the idle timer when a partial line is actually waiting.
         *  A write that ended on a newline has nothing left to flush.      */
        blePendingSince = (blePendingLength > 0) ? millis() : 0;
        portEXIT_CRITICAL(&bleQueueMux);
    }
};

/*  Called from the main loop: closes a line that arrived without a
 *  terminator once the sender has clearly stopped writing.                  */
inline void bleFlushIdleLine() {
    if (blePendingSince == 0) {
        return;
    }
    if (millis() - blePendingSince < BLE_LINE_IDLE_MS) {
        return;
    }
    portENTER_CRITICAL(&bleQueueMux);
    bleCommitPendingLine();
    portEXIT_CRITICAL(&bleQueueMux);
}

/*----------------------------------------------------------------------------*/
/*  Setup and output                                                          */
/*----------------------------------------------------------------------------*/
inline void initBleManager(uint16_t nodeID) {
    String deviceName = String(BLE_NAME_PREFIX) + String(nodeID);

    BLEDevice::init(deviceName.c_str());
    BLEDevice::setMTU(247); // room for a full message in one notification

    BLEServer *server = BLEDevice::createServer();
    server->setCallbacks(new MeshBleServerCallbacks());

    BLEService *service = server->createService(BLE_SERVICE_UUID);

    bleTxCharacteristic = service->createCharacteristic(
        BLE_CHAR_TX_UUID, BLECharacteristic::PROPERTY_NOTIFY);
    bleTxCharacteristic->addDescriptor(new BLE2902());

    BLECharacteristic *rxCharacteristic = service->createCharacteristic(
        BLE_CHAR_RX_UUID,
        BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR);
    rxCharacteristic->setCallbacks(new MeshBleRxCallbacks());

    service->start();

    BLEAdvertising *advertising = BLEDevice::getAdvertising();
    advertising->addServiceUUID(BLE_SERVICE_UUID);
    advertising->setScanResponse(true);
    BLEDevice::startAdvertising();

    Serial.printf("[BLE] advertising as \"%s\"\n", deviceName.c_str());
}

/*  Notifications are capped by the negotiated MTU, so long lines are split
 *  rather than silently truncated.                                          */
inline void bleSend(const String &text) {
    if (!blePhoneConnected || bleTxCharacteristic == nullptr) {
        return;
    }
    const size_t chunkSize = 180;
    String line = text + "\n";

    for (size_t offset = 0; offset < line.length(); offset += chunkSize) {
        String chunk = line.substring(offset, offset + chunkSize);
        bleTxCharacteristic->setValue((uint8_t *)chunk.c_str(), chunk.length());
        bleTxCharacteristic->notify();
        delay(8); // let the stack drain between notifications
    }
}

inline bool blePhoneIsConnected() {
    return blePhoneConnected;
}

#endif
