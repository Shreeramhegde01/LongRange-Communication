/*==============================================================================
  oled_manager.h
  ------------------------------------------------------------------------------
  Utilities for the onboard SSD1306 display (128x64 on Heltec WiFi LoRa 32 V3).
  – Power-up via Vext, reset pulse, init, wrapped multi-line text, timeout.
  – Compiles to no-ops on boards without a display, so the same firmware runs
    on a bare ESP32 DevKit + SX1276.
==============================================================================*/
#ifndef OLED_MANAGER_H
#define OLED_MANAGER_H

#include "config.h"
#include <Arduino.h>

#if HAS_OLED
#include <Wire.h>
#include "SSD1306Wire.h"

#define OLED_ADDRESS 0x3c

class OLEDManager {
public:
    OLEDManager() : display(OLED_ADDRESS, OLED_SDA, OLED_SCL, GEOMETRY_128_64) {}

    /* Vext gates the display rail on Heltec boards; active low. */
    void oledOn() {
        pinMode(OLED_VEXT, OUTPUT);
        digitalWrite(OLED_VEXT, LOW);
    }
    void oledOff() {
        pinMode(OLED_VEXT, OUTPUT);
        digitalWrite(OLED_VEXT, HIGH);
    }

    void oledInit() {
        oledOn();
        delay(50);
        pinMode(OLED_RST, OUTPUT);
        digitalWrite(OLED_RST, LOW);
        delay(20);
        digitalWrite(OLED_RST, HIGH);
        delay(50);

        display.init();
        display.setFont(ArialMT_Plain_10);
        display.setTextAlignment(TEXT_ALIGN_LEFT);
        display.clear();
        display.display();
    }

    void oledClear() {
        display.clear();
        display.display();
    }

    void oledShow(const String &message) {
        display.clear();
        display.drawStringMaxWidth(0, 0, 128, message);
        display.display();
    }

    /* Header line plus wrapped body - used for incoming messages. */
    void oledShowMessage(const String &header, const String &body) {
        display.clear();
        display.drawString(0, 0, header);
        display.drawStringMaxWidth(0, 14, 128, body);
        display.display();
    }

    void checkOledTimeout(unsigned long &oledDisplayTime) {
        if (oledDisplayTime != 0 && millis() - oledDisplayTime >= OLED_DISPLAY_DURATION) {
            oledClear();
            oledDisplayTime = 0;
        }
    }

private:
    SSD1306Wire display;
};

#else  /* board without a display */

class OLEDManager {
public:
    void oledOn() {}
    void oledOff() {}
    void oledInit() {}
    void oledClear() {}
    void oledShow(const String &message) { (void)message; }
    void oledShowMessage(const String &header, const String &body) { (void)header; (void)body; }
    void checkOledTimeout(unsigned long &oledDisplayTime) { oledDisplayTime = 0; }
};

#endif

#endif
