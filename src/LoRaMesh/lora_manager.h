/*==============================================================================
  lora_manager.h
  ------------------------------------------------------------------------------
  Radio abstraction built on RadioLib.
  – Drives an SX1262 (Heltec V3) or an SX1276 (ESP32 DevKit + RA-02) behind one
    interface, selected by the board macros in config.h.
  – A single DIO1 interrupt sets a flag; the main loop resolves it against the
    tracked radio state to decide whether a transmit or a receive completed.

  The interrupt handler only raises a flag - all radio work happens in the main
  loop, so nothing calls into SPI from interrupt context.
==============================================================================*/
#ifndef LORA_MANAGER_H
#define LORA_MANAGER_H

#include "config.h"
#include <RadioLib.h>
#include <SPI.h>
#include <Arduino.h>

/*----------------------------------------------------------------------------*/
/*  Radio instance                                                            */
/*----------------------------------------------------------------------------*/
#if defined(BOARD_ESP32_SX1276)
#define RADIO_NAME "SX1276"
static SPIClass loraSpi(VSPI);
static SX1276 radioChip = new Module(LORA_NSS, LORA_DIO0, LORA_RST, LORA_DIO1, loraSpi);
#else
#define RADIO_NAME "SX1262"
static SPIClass loraSpi(FSPI);
static SX1262 radioChip = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY, loraSpi);
#endif

/*----------------------------------------------------------------------------*/
/*  Interrupt flag and radio state                                            */
/*----------------------------------------------------------------------------*/
enum RadioState : uint8_t {
    RADIO_STATE_IDLE,
    RADIO_STATE_TX,
    RADIO_STATE_RX
};

static volatile bool radioIrqFired = false;
/*  Guards the test-and-clear of radioIrqFired against the ISR raising it in
 *  the gap between the two.                                                 */
static portMUX_TYPE radioIrqMux = portMUX_INITIALIZER_UNLOCKED;
/*  Sits beside an ISR-written flag and is read on the same path, so it is
 *  declared volatile even though only the main loop writes it.          */
static volatile RadioState radioState = RADIO_STATE_IDLE;

static void IRAM_ATTR onRadioIrq() {
    radioIrqFired = true;
}

/*==============================================================================
  LoraManager
==============================================================================*/
class LoraManager {
public:
    /*  Brings up SPI and the transceiver with the modulation settings from
     *  config.h. Returns false if the radio does not answer, which almost
     *  always means miswired SPI or the wrong board target.                  */
    bool begin() {
        loraSpi.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);

#if defined(BOARD_ESP32_SX1276)
        int state = radioChip.begin(RF_FREQUENCY_MHZ, LORA_BANDWIDTH_KHZ,
                                    LORA_SPREADING_FACTOR, LORA_CODINGRATE,
                                    LORA_SYNC_WORD, TX_OUTPUT_POWER,
                                    LORA_PREAMBLE_LENGTH);
#else
        /*  Heltec V3 clocks the SX1262 from a 1.8 V TCXO and switches the RF
         *  front end with DIO2; both must be declared or the radio stays mute. */
        int state = radioChip.begin(RF_FREQUENCY_MHZ, LORA_BANDWIDTH_KHZ,
                                    LORA_SPREADING_FACTOR, LORA_CODINGRATE,
                                    LORA_SYNC_WORD, TX_OUTPUT_POWER,
                                    LORA_PREAMBLE_LENGTH, 1.8, false);
        if (state == RADIOLIB_ERR_NONE) {
            radioChip.setDio2AsRfSwitch(true);
        }
#endif
        if (state != RADIOLIB_ERR_NONE) {
            Serial.printf("[LORA] init failed, code %d\n", state);
            return false;
        }

        /*  SX127x reports both TxDone and RxDone on DIO0 and wants a trigger
         *  edge; SX126x multiplexes both onto DIO1.                        */
#if defined(BOARD_ESP32_SX1276)
        radioChip.setDio0Action(onRadioIrq, RISING);
#else
        radioChip.setDio1Action(onRadioIrq);
#endif
        Serial.printf("[LORA] %s up at %.1f MHz SF%d BW%.0f kHz\n",
                      RADIO_NAME, (double)RF_FREQUENCY_MHZ,
                      LORA_SPREADING_FACTOR, (double)LORA_BANDWIDTH_KHZ);
        return true;
    }

    /*----------------------------------------------------------------------*/
    /*  Continuous receive                                                  */
    /*----------------------------------------------------------------------*/
    /*  Guarded so the main loop can call this every iteration without
     *  restarting the receiver mid-packet.                                  */
    void startReceive() {
        if (radioState == RADIO_STATE_RX) {
            return;
        }
        int state = radioChip.startReceive();
        if (state == RADIOLIB_ERR_NONE) {
            radioState = RADIO_STATE_RX;
        }
    }

    /*  Forces the receiver back on after a frame has been read out. */
    void restartReceive() {
        radioState = RADIO_STATE_IDLE;
        startReceive();
    }

    /*----------------------------------------------------------------------*/
    /*  Channel activity detection                                          */
    /*----------------------------------------------------------------------*/
    /*  The transceiver's own CAD: it looks for a LoRa preamble and answers in
     *  a couple of symbol times, around 5 ms at SF7. Listening for a fixed
     *  window instead would cost that window on every single frame, which at
     *  three hops is most of the latency budget.
     *
     *  CAD leaves the radio in standby, so the caller either transmits at once
     *  or restarts the receiver.                                           */
    bool channelBusy() {
        int state = radioChip.scanChannel();
        radioState = RADIO_STATE_IDLE;
        return state == RADIOLIB_LORA_DETECTED;
    }

    /*----------------------------------------------------------------------*/
    /*  Non-blocking transmit                                               */
    /*----------------------------------------------------------------------*/
    bool send(uint8_t *buffer, uint16_t size) {
        int state = radioChip.startTransmit(buffer, size);
        if (state != RADIOLIB_ERR_NONE) {
            Serial.printf("[LORA] transmit failed, code %d\n", state);
            radioState = RADIO_STATE_IDLE;
            return false;
        }
        radioState = RADIO_STATE_TX;
        return true;
    }

    /*  Releases the transmit buffer once DIO1 reports the packet is gone.   */
    void finishTransmit() {
        radioChip.finishTransmit();
        radioState = RADIO_STATE_IDLE;
    }

    /*----------------------------------------------------------------------*/
    /*  Read a received frame                                               */
    /*----------------------------------------------------------------------*/
    uint16_t readPacket(uint8_t *buffer, uint16_t maxSize) {
        uint16_t length = (uint16_t)radioChip.getPacketLength();
        if (length == 0 || length > maxSize) {
            return 0; // restartReceive() flushes whatever is left in the FIFO
        }
        int state = radioChip.readData(buffer, length);
        if (state != RADIOLIB_ERR_NONE) {
            return 0;
        }
        return length;
    }

    float getRssi() { return radioChip.getRSSI(); }
    float getSnr()  { return radioChip.getSNR(); }

    RadioState state() const { return radioState; }
    void sleep() { radioChip.sleep(); radioState = RADIO_STATE_IDLE; }
};

#endif
