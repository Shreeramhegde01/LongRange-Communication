# Hardware: bill of materials

Everything needed to build the five-node mesh, with exact parts, the chips on each board,
the pin map the firmware uses, and the software versions the firmware is built against.

**Status (29 September 2026):** specified for purchase, not yet received. Nothing in this
project has run on radio hardware yet. When the boards arrive, record the PCB revision
printed on them in [section 9](#9-buying-checklist-and-on-arrival).

---

## 1. Per-node components (5 nodes)

| # | Component | Exact part / specification | Per node | Total |
|---|---|---|:-:|:-:|
| 1 | Node board | **Heltec WiFi LoRa 32 V3**, SKU TIFCC0193, **863–928 MHz** variant | 1 | 5 |
| 2 | LoRa antenna | 868 MHz, omnidirectional, 2–3 dBi, **SMA male** (plug) | 1 | 5 |
| 3 | RF pigtail | **U.FL (IPEX-1)** to **SMA female** bulkhead, short (≈10–15 cm) | 1 | 5 |
| 4 | Battery | Li-Po, single cell (1S), 3.7 V nominal / 4.2 V full, 2000 mAh, **SH1.25-2** connector; a cell with a protection circuit is recommended | 1 | 5 |
| 5 | Enclosure | Protective housing for field trials (plastic project box or similar) | 1 | 5 |

## 2. Shared items

| # | Component | Specification | Qty |
|---|---|---|:-:|
| 6 | USB-C cable | **Data-capable**, for flashing and the serial console. Charge-only cables will not work | 2 |
| 7 | Consumables | Connectors, headers, hook-up wire, heat-shrink, mounting hardware | as needed |

## 3. What is on the Heltec WiFi LoRa 32 V3

These come soldered on the board; nothing here is bought separately.

| Function | Part | Detail |
|---|---|---|
| Microcontroller | Espressif **ESP32-S3FN8** | Xtensa LX7 dual-core, up to 240 MHz; 512 KB SRAM; 8 MB flash in the package; no PSRAM |
| LoRa transceiver | Semtech **SX1262** | 150–960 MHz capable, up to +22 dBm (we use 14 dBm). Clocked from a **1.8 V TCXO**; **DIO2** drives the RF switch |
| Display | 0.96" 128×64 OLED, **SSD1306** controller | I²C at address **0x3C**; its power rail is switched by the **Vext** pin (active low) |
| USB-to-serial | Silicon Labs **CP2102** | Windows may need the driver in `docs/CP210x_Windows_Drivers.zip` |
| USB | Type-C | With voltage regulator, ESD and short-circuit protection |
| Battery management | On-board | Charge and discharge management, overcharge protection, battery-voltage sensing, automatic USB/battery switchover. Connector **SH1.25-2** |
| LoRa antenna port | **U.FL (IPEX)** | External antenna via the pigtail (items 2 and 3) |
| Wi-Fi / Bluetooth antenna | On-board 2.4 GHz metal spring antenna | Serves Wi-Fi and Bluetooth only. **Not** usable for LoRa |
| Wireless | ESP32-S3 radio | Wi-Fi 802.11 b/g/n (2.4 GHz), Bluetooth 5 LE. No Bluetooth Classic. Wi-Fi is not used by the firmware |

## 4. Pin map used by the firmware

From `src/LoRaMesh/config.h`, branch `BOARD_HELTEC_V3_OLED` (the default build).

| Signal | GPIO | | Signal | GPIO |
|---|:-:|---|---|:-:|
| SX1262 NSS (chip select) | 8 | | OLED SDA | 17 |
| SX1262 SCK | 9 | | OLED SCL | 18 |
| SX1262 MOSI | 10 | | OLED reset | 21 |
| SX1262 MISO | 11 | | Vext (OLED power, active low) | 36 |
| SX1262 reset | 12 | | Status LED | 35 |
| SX1262 BUSY | 13 | | Battery ADC | 1 |
| SX1262 DIO1 (interrupt) | 14 | | Battery ADC control | 37 |

## 5. Radio operating parameters

| Parameter | Value |
|---|---|
| Frequency | 866.0 MHz, centre of India's 865–867 MHz licence-exempt band (WPC G.S.R. 564(E)) |
| Transmit power | 14 dBm |
| Spreading factor | SF7 |
| Bandwidth | 125 kHz |
| Coding rate | 4/5 |
| Preamble | 8 symbols |
| Sync word | 0x34 (private network; LoRaWAN uses 0x12) |
| TCXO voltage | 1.8 V |

## 6. Firmware stack versions

Versions installed in this project as of 29 September 2026, which are the ones the firmware
is built against. The builds of all three targets succeed with zero warnings.

| Component | Version | Constraint in `platformio.ini` |
|---|---|---|
| PlatformIO platform `espressif32` | 6.13.0 | `^6.9.0` |
| Arduino-ESP32 core | 2.0.17 (package `3.20017.241212`) | set by the platform |
| ESP-IDF (bundled with the core) | v4.4.7 | set by the core |
| mbedTLS (AES-GCM, SHA-256, X25519) | 2.28.7 | bundled with ESP-IDF |
| Bluetooth LE | ESP32 BLE library bundled with the core, on the Bluedroid stack | bundled with the core |
| Compiler | GCC 8.4.0 (`toolchain-xtensa-esp32s3 8.4.0+2021r2-patch5`) | set by the platform |
| Flashing tool | esptool.py 4.11.0 | set by the platform |
| RadioLib | 7.7.1 | `^7.1.2` |
| ThingPulse SSD1306 OLED driver | 4.6.2 | `^4.6.1` |

The `^` constraints allow newer minor versions. A teammate installing fresh may get later
versions than these. To make every machine build identically, pin exact versions in
`platformio.ini`.

## 7. User and development equipment

Not part of the node, but needed to use and build it.

| Item | Requirement |
|---|---|
| Phone (user interface) | Android with Bluetooth LE, running Chrome. Opens the web app in `app/`. iPhone needs the **Bluefy** browser, because no normal iOS browser supports Web Bluetooth |
| Development computer | Windows, macOS or Linux with VS Code and the PlatformIO extension. On Windows, the CP2102 driver may be needed before the board's COM port appears |

## 8. Indicative cost (India, September 2026)

| Item | Qty | Rate (Rs.) | Amount (Rs.) |
|---|:-:|--:|--:|
| Heltec WiFi LoRa 32 V3 (863–928 MHz) | 5 | 2,600 | 13,000 |
| 868 MHz SMA antenna | 5 | 400 | 2,000 |
| U.FL to SMA pigtail | 5 | 100 | 500 |
| Li-Po 3.7 V 2000 mAh, SH1.25-2 | 5 | 700 | 3,500 |
| USB-C data cable | 2 | 150 | 300 |
| Enclosures and consumables | — | — | 1,000 |
| **Total** | | | **20,300** |

## 9. Buying checklist and on arrival

Before ordering:

- **Frequency variant.** Buy the 863–928 MHz board. The 470–510 MHz variant looks
  identical and is useless in India's 865–867 MHz band.
- **SMA, not RP-SMA.** They look alike but don't mate properly. The antenna and the
  pigtail must both be standard SMA.
- **Battery connector.** SH1.25-2 (1.25 mm pitch), not JST-PH 2.0 (2 mm). A JST-PH cell
  will not plug in.
- **USB-C cable carries data.** A charge-only cable powers the board but can't flash it.

On arrival:

- **Check battery polarity** against the + and − marked on the board before plugging a
  cell in. Connector polarity is not standardised between battery sellers, and a reversed
  cell can destroy the charging circuit.
- **Never transmit without the LoRa antenna attached** to the U.FL port. Transmitting into
  an open connector can damage the radio's power amplifier.
- **Record the PCB revision** printed on each board, for example V3.1 or V3.2. The
  battery-sense circuit is the part `config.h` flags as varying between revisions. A
  wrong setting reports battery as "unknown" rather than a wrong voltage, so check the
  first reading.

## 10. Supported by the firmware but not being purchased

| Build target | Hardware |
|---|---|
| `heltec_v3_nodisplay` | The same board with the display left off, for measuring the OLED's current cost. Also fits the Heltec Wireless Stick V3 and Wireless Stick Lite V3, which share the pin map. The Lite was the original choice but is not sold in India in the 863–870 MHz band |
| `esp32dev_sx1276` | Generic ESP32 DevKit with an Ai-Thinker RA-01H module (SX1276, 868 MHz). Compiles, but has never been wired or tested. The RA-02 is a 433 MHz part and won't work here |
