/*==============================================================================
  LoRaMesh.ino
  ------------------------------------------------------------------------------
  Long-Range Secure Messaging System using ESP32 and LoRa.

  Entry point for a mesh node built on the Heltec Wireless Stick Lite V3
  (ESP32-S3 + SX1262). The node has no display: a phone paired over BLE is the
  user interface, and the serial console mirrors it for lab work.

    phone --BLE--> node --LoRa mesh--> ... --> node --BLE--> phone

  Message text is encrypted with AES-128-GCM at the source and decrypted only
  at the destination, so relays forward ciphertext they cannot read.
==============================================================================*/
#include "config.h"
#include <Arduino.h>
#include "metrics.h"
#include "lora_manager.h"
#include "packet_manager.h"
#include "routing_manager.h"
#include "security_manager.h"
#include "crypto_session.h"
#include "communication_manager.h"
#include "message_scheduler.h"
#include "message_receiver.h"
#include "ble_manager.h"
#include "oled_manager.h"

/*----------------------------------------------------------------------------*/
/*  Global radio state                                                        */
/*----------------------------------------------------------------------------*/
volatile bool loraIdle = true;
volatile bool transmissionDone = false;
volatile bool receptionDone = false;
volatile bool transmissionError = false;

uint8_t receivedBuffer[MAX_PACKET_SIZE];
uint16_t receivedSize = 0;
int16_t receivedRssi = 0;
int8_t receivedSnr = 0;

LoraManager loraAntena;
OLEDManager oledDisplay;
DataPacket receivedPacket;

unsigned long oledDisplayTime = 0;
static unsigned long ledOffTime = 0;

/*============================================================================*/
/*  Local output helpers                                                      */
/*============================================================================*/
/*  Everything the user should see goes to both the console and the phone.   */
inline void report(const String &line) {
    Serial.println(line);
    bleSend(line);
}

/*  Message text arrives from another node and is placed inside a
 *  newline-delimited protocol the app parses. A message containing a newline
 *  could otherwise forge a whole protocol line - a fake delivery
 *  confirmation, or a message attributed to somebody else - so control
 *  characters are flattened before the text leaves this node.
 *
 *  Encryption proves who sent a message; it does not make its contents safe
 *  to splice into a protocol.                                              */
inline String sanitizeForLine(const char *text) {
    String out;
    for (const char *p = text; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        out += (c < 0x20 || c == 0x7F) ? ' ' : (char)c;
    }
    return out;
}

inline void pulseStatusLed() {
    digitalWrite(STATUS_LED, HIGH);
    ledOffTime = millis() + 60;
}

/*============================================================================*/
/*  Application callbacks invoked by the mesh layers                          */
/*============================================================================*/
/*  MSG carries the numeric id so the app can key conversations reliably, and
 *  the name separately so it can show something human.                       */
void onSecureMessageDelivered(uint16_t sourceNode, const char *text, int16_t rssi) {
    pulseStatusLed();
    const char *name = lookupNodeName(sourceNode);
    String safe = sanitizeForLine(text);
    report("MSG " + String(sourceNode) + " " + String(name ? name : "?") + ": " + safe);
    Serial.printf("[SEC] verified and decrypted from %s (rssi %d)\n",
                  describeNode(sourceNode).c_str(), rssi);
    oledDisplay.oledShowMessage("From " + describeNode(sourceNode), safe);
    oledDisplayTime = millis();
}

void onMessageConfirmed(uint16_t destinationNode, uint32_t messageID) {
    report("DELIVERED " + String(messageID) + " " + String(destinationNode));
}

/*  The recipient is unreachable for now, so the message is being held rather
 *  than lost. The app shows it as pending instead of failed.                */
void onMessageHeld(uint16_t destinationNode, uint32_t messageID) {
    report("HELD " + String(messageID) + " " + String(destinationNode));
}

void onMessageExpired(uint16_t destinationNode, uint32_t messageID) {
    report("EXPIRED " + String(messageID) + " " + String(destinationNode));
}

void onBroadcastReceived(uint16_t sourceNode, const char *text) {
    pulseStatusLed();
    const char *name = lookupNodeName(sourceNode);
    String safe = sanitizeForLine(text);
    report("BCAST " + String(sourceNode) + " " + String(name ? name : "?") + ": " + safe);
    oledDisplay.oledShowMessage("ALERT " + describeNode(sourceNode), safe);
    oledDisplayTime = millis();
}

/*  sourceNode is 0 when the offending frame failed authentication, since its
 *  claimed origin cannot be trusted and was never parsed.                    */
void onSecurityEvent(const char *reason, uint16_t sourceNode) {
    String line = "SEC " + String(reason);
    if (sourceNode != 0) {
        line += " from " + String(sourceNode);
    }
    report(line);
}

void onMessageAcknowledged(uint32_t messageID) {
    report("ACK " + String(messageID));
}

/*============================================================================*/
/*  Command handling - shared by the BLE link and the serial console          */
/*============================================================================*/
/*  Accepted input:
 *    <nodeID>:<text>   send an encrypted message to that node
 *    /id               this node's ID
 *    /nodes            neighbour table
 *    /hello            broadcast a HELLO now
 *    /help             usage                                                */
void handleCommand(const String &rawInput) {
    String input = rawInput;
    input.trim();
    if (input.length() == 0) {
        return;
    }

    if (input.equalsIgnoreCase("/id")) {
        report("ID " + String(getNodeID()) + " " + String(getLocalNodeName()));
        return;
    }
    /*  Matched with the trailing space so "/nameless" is not read as "/name". */
    if (input == "/name" || input.startsWith("/name ")) {
        String newName = input.substring(5);
        newName.trim();
        if (newName.length() == 0) {
            report("Name is \"" + String(getLocalNodeName()) + "\"");
        } else {
            setLocalNodeName(newName.c_str());
            scheduleHelloMessage(); // announce it without waiting for the timer
            report("Name set to \"" + String(getLocalNodeName()) + "\"");
        }
        return;
    }
    /*  Machine-readable peer list for the phone app: one PEER line per known
     *  node, so the app never has to parse the human-facing tables.        */
    if (input.equalsIgnoreCase("/peers")) {
        String out = "";
        for (int i = 0; i < MAX_ROUTES; i++) {
            if (!routingTable[i].inUse || routingTable[i].hopCount >= ROUTE_INFINITY) {
                continue;
            }
            uint16_t node = routingTable[i].destination;
            const char *name = lookupNodeName(node);
            int16_t rssi = 0;
            for (int n = 0; n < MAX_NEIGHBORS; n++) {
                if (neighborTable[n].neighborId == node) {
                    rssi = neighborTable[n].rssi;
                    break;
                }
            }
            out += "PEER " + String(node)
                 + " " + String(name ? name : "?")
                 + " " + String(routingTable[i].hopCount)
                 + " " + String(rssi)
                 + " " + String(hasSession(node) ? 1 : 0)
                 + " " + String(batteryPercent(lookupNodeBattery(node))) + "\n";
        }
        report(out.length() ? out : "PEERS none");
        return;
    }
    if (input.equalsIgnoreCase("/nodes")) {
        report(neighborTableToString());
        return;
    }
    if (input.equalsIgnoreCase("/routes")) {
        report(routingTableToString());
        return;
    }
    if (input.equalsIgnoreCase("/keys")) {
        report(sessionTableToString());
        return;
    }
    if (input.equalsIgnoreCase("/stats")) {
        report(metricsToString());
        return;
    }
    if (input == "/all" || input.startsWith("/all ")) {
        String alert = input.substring(4);
        alert.trim();
        if (alert.length() == 0) {
            report("ERR usage: /all <message to every node>");
        } else if (enqueueBroadcastMessage(alert.c_str())) {
            pulseStatusLed();
            report("BCASTQUEUED " + String(lastQueuedMessageID));
        } else {
            report("ERR broadcast not queued - queue full or over "
                   + String(MAX_TEXT_LEN) + " chars");
        }
        return;
    }
    if (input.equalsIgnoreCase("/hello")) {
        scheduleHelloMessage();
        report("HELLO queued");
        return;
    }
    if (input.equalsIgnoreCase("/help")) {
        report("Send: <nodeID|name>:<message>   Alert everyone: /all <message>\n"
               "Commands: /id /name /peers /nodes /routes /keys /stats /hello /help");
        return;
    }

    int separator = input.indexOf(':');
    if (separator <= 0) {
        report("ERR expected <nodeID>:<message> - try /help");
        return;
    }

    String destinationText = input.substring(0, separator);
    String messageText = input.substring(separator + 1);
    destinationText.trim();
    messageText.trim();

    /*  A recipient may be given as a node ID or as an advertised name. */
    uint16_t destination = 0;
    bool numeric = destinationText.length() > 0;
    for (unsigned int i = 0; i < destinationText.length(); i++) {
        if (!isdigit(destinationText[i])) {
            numeric = false;
            break;
        }
    }
    if (numeric) {
        uint32_t parsed = destinationText.toInt();
        if (parsed > 0 && parsed <= 0xFFFF) {
            destination = (uint16_t)parsed;
        }
    } else {
        destination = lookupNodeByName(destinationText.c_str());
    }

    if (destination == 0) {
        /*  Echoing input back into a line-delimited protocol without
         *  sanitising it is the same mistake as trusting a remote name; keep
         *  the invariant that nothing reaches report() unsanitised.        */
        report("ERR unknown recipient \"" + sanitizeForLine(destinationText.c_str())
               + "\" - try /peers");
        return;
    }

    if (enqueueTextMessage(destination, messageText.c_str())) {
        pulseStatusLed();
        report("QUEUED " + String(lastQueuedMessageID) + " " + String(destination));
    } else {
        report("ERR could not send to " + describeNode(destination)
               + " - no route, no session yet, queue full, or over "
               + String(MAX_TEXT_LEN) + " chars");
    }
}

/*============================================================================*/
/*  setup()                                                                   */
/*============================================================================*/
void setup() {
    Serial.begin(115200);
    delay(200);

    pinMode(STATUS_LED, OUTPUT);
    digitalWrite(STATUS_LED, LOW);

    uint16_t nodeID = getNodeID();
    Serial.println("\n=== Secure LoRa Mesh node ===");
    Serial.printf("Node ID: %u\n", nodeID);

    initMetrics();
    initSecurityManager();
    initRoutingManager();
    initSessionTable();
    initCryptoSessions();

    if (!loraAntena.begin()) {
        Serial.println("[FATAL] radio did not initialise - check wiring and board target");
        while (true) {
            digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
            delay(150);
        }
    }
    loraAntena.startReceive();

    oledDisplay.oledInit();
    initBleManager(nodeID);
    initMessageScheduler();
    initMessageReceiver();

    Serial.printf("I am \"%s\" (%u)\n", getLocalNodeName(), nodeID);
    Serial.println("Send: <nodeID|name>:<message>   /help for commands");
}

/*============================================================================*/
/*  loop()                                                                    */
/*============================================================================*/
void loop() {
    /*-- Radio interrupts ---------------------------------------------------*/
    processRadioEvents();

    /*-- Input from the phone ----------------------------------------------*/
    bleFlushIdleLine();
    char bleLine[BLE_RX_LINE_MAX];
    while (bleReadLine(bleLine, sizeof(bleLine))) {
        handleCommand(String(bleLine));
    }

    /*-- Input from the serial console -------------------------------------*/
    /*  Accumulated a byte at a time: readStringUntil() would stall the loop
     *  for its full timeout whenever a line arrives without a terminator.   */
    static char serialLine[BLE_RX_LINE_MAX];
    static size_t serialLength = 0;
    while (Serial.available() > 0) {
        char c = (char)Serial.read();
        if (c == '\n' || c == '\r') {
            if (serialLength > 0) {
                serialLine[serialLength] = '\0';
                handleCommand(String(serialLine));
                serialLength = 0;
            }
        } else if (serialLength < sizeof(serialLine) - 1) {
            serialLine[serialLength++] = c;
        }
    }

    /*-- Keep listening when the radio is free -----------------------------*/
    if (loraIdle) {
        handleReception();
    }

    if (processReceivedMessage(oledDisplayTime) != 0) {
        pulseStatusLed();
    }

    /*-- Queue, retries, periodic HELLO and key discovery -------------------*/
    updateMessageScheduler();
    checkAutoHello();
    maintainKeyDiscovery();
    maintainOutbox();

    /*-- Transmit outcome --------------------------------------------------*/
    transmissionDone = false;
    if (transmissionError) {
        report("ERR transmission failed");
        transmissionError = false;
    }

    /*-- Housekeeping ------------------------------------------------------*/
    if (ledOffTime != 0 && timeReached(ledOffTime, millis())) {
        digitalWrite(STATUS_LED, LOW);
        ledOffTime = 0;
    }
    oledDisplay.checkOledTimeout(oledDisplayTime);
    cleanupNeighbors();
}
