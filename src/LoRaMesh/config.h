/*==============================================================================
  config.h
  ------------------------------------------------------------------------------
  Compile-time parameters and constants for the secure LoRa mesh network.
  – Radio band / modulation, board pin maps, buffer sizes, ACK timing.
  – Security layer: AES-128-GCM sizes, pre-shared key, anti-replay window.
  – BLE bridge: Nordic UART Service UUIDs and device naming.
==============================================================================*/
#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

/*----------------------------------------------------------------------------*/
/*  Radio – band and modulation                                               */
/*----------------------------------------------------------------------------*/
/*  866.0 MHz sits in the middle of India's 865-867 MHz licence-exempt band
 *  (WPC GSR 564(E)). Alternatives: 868.0 (EU), 915.0 (US/AU).                */
#define RF_FREQUENCY_MHZ 866.0

#define TX_OUTPUT_POWER 14      // dBm - 14 dBm is the India/EU legal ceiling
#define LORA_BANDWIDTH_KHZ 125.0
#define LORA_SPREADING_FACTOR 7
#define LORA_CODINGRATE 5       // 4/5
#define LORA_PREAMBLE_LENGTH 8
#define LORA_SYNC_WORD 0x34     // private network (0x34); 0x12 is LoRaWAN

/*----------------------------------------------------------------------------*/
/*  Board pin maps                                                            */
/*----------------------------------------------------------------------------*/
#if defined(BOARD_ESP32_SX1276)
  /* Generic ESP32 DevKit wired to an SX1276 (RA-01H) module over VSPI.
   * Note RA-02 is a 433 MHz part - use RA-01H for the 865 MHz band.         */
  #define LORA_NSS   5
  #define LORA_DIO0  2
  #define LORA_DIO1  4
  #define LORA_RST   14
  #define LORA_SCK   18
  #define LORA_MISO  19
  #define LORA_MOSI  23
  #define HAS_OLED   0
  #define STATUS_LED 2

#elif defined(BOARD_HELTEC_V3_OLED)
  /* Heltec WiFi LoRa 32 V3 - ESP32-S3 + SX1262 with a 128x64 OLED */
  #define LORA_NSS   8
  #define LORA_DIO1  14
  #define LORA_RST   12
  #define LORA_BUSY  13
  #define LORA_SCK   9
  #define LORA_MISO  11
  #define LORA_MOSI  10
  #define HAS_OLED   1
  #define OLED_SDA   17
  #define OLED_SCL   18
  #define OLED_RST   21
  #define OLED_VEXT  36
  #define STATUS_LED 35

#else
  /* Heltec Wireless Stick Lite V3 - ESP32-S3 + SX1262, no display.
   * The phone is the user interface; the LED is the only local indicator.   */
  #define LORA_NSS   8
  #define LORA_DIO1  14
  #define LORA_RST   12
  #define LORA_BUSY  13
  #define LORA_SCK   9
  #define LORA_MISO  11
  #define LORA_MOSI  10
  #define HAS_OLED   0
  #define STATUS_LED 35
  #define BATTERY_ADC_PIN 1
  #define BATTERY_ADC_CTRL 37
#endif

/*----------------------------------------------------------------------------*/
/*  Battery sensing                                                           */
/*----------------------------------------------------------------------------*/
/*  A relay left in a field is invisible until it goes silent. Nodes report
 *  battery voltage on their beacon so the app can show which one is fading
 *  while there is still time to swap it.
 *
 *  VERIFY THESE PINS against your board revision. Heltec wire the battery
 *  through a divider gated by a control pin, and the assignment has moved
 *  between revisions. A wrong pin reads an implausible voltage, which is
 *  reported as "unknown" rather than as a confident wrong number.           */
#define BATTERY_DIVIDER 4.9f       // 390k / 100k ladder
#define BATTERY_MIN_PLAUSIBLE_MV 2500
#define BATTERY_MAX_PLAUSIBLE_MV 4600
/*  A single-cell LiPo is effectively flat at 3.3 V and full at 4.2 V. */
#define BATTERY_EMPTY_MV 3300
#define BATTERY_FULL_MV 4200

/*----------------------------------------------------------------------------*/
/*  Buffers                                                                   */
/*----------------------------------------------------------------------------*/
#define MAX_PACKET_SIZE 256

/*  Longest plaintext message a user may send. Ciphertext is the same length
 *  (GCM is a stream mode), so the wire frame is
 *  DATA_HEADER_SIZE + MAX_TEXT_LEN + GCM_TAG_LEN + CONTROL_MAC_LEN
 *  = 21 + 200 + 16 + 8 = 245 bytes, inside LoRa's 255-byte ceiling. Sizing it
 *  to fill one frame avoids needing fragmentation and reassembly at all.
 *  Costs ~390 ms of airtime at SF7/BW125 for a full-length message.          */
#define MAX_TEXT_LEN 200

/*----------------------------------------------------------------------------*/
/*  Mesh identification                                                       */
/*----------------------------------------------------------------------------*/
#define MESH_ID 0x1234

/*----------------------------------------------------------------------------*/
/*  OLED                                                                      */
/*----------------------------------------------------------------------------*/
#define OLED_DISPLAY_DURATION 8000 // ms

/*----------------------------------------------------------------------------*/
/*  Send timers and back-off                                                  */
/*----------------------------------------------------------------------------*/
/*  Each queued frame waits a random spell before transmitting, which spreads
 *  nodes that would otherwise answer the same event together.
 *
 *  The base project used 3-7 s. That alone makes NFR2 unreachable: three hops
 *  would spend 15 s in queues before a single byte went out. Channel activity
 *  detection now does the collision avoidance, so this only has to break the
 *  synchronisation between nodes.                                           */
#define INITIAL_WAIT_LOWER 200
#define INITIAL_WAIT_UPPER 1200
#define BACKOFF_LOWER 50
#define BACKOFF_UPPER 250

/*----------------------------------------------------------------------------*/
/*  Packet types                                                              */
/*----------------------------------------------------------------------------*/
#define MESSAGE_TYPE_DATA 1
#define MESSAGE_TYPE_ACK 2
#define MESSAGE_TYPE_HELLO  3
#define MESSAGE_TYPE_ALT 4
#define MESSAGE_TYPE_KEY_REQ 5
#define MESSAGE_TYPE_KEY_RESP 6
#define MESSAGE_TYPE_RECEIPT 7
#define MESSAGE_TYPE_BROADCAST 8

/*----------------------------------------------------------------------------*/
/*  Broadcast / emergency alert                                               */
/*----------------------------------------------------------------------------*/
/*  One-to-many alerts for the disaster-response and field-safety cases, where
 *  the message has to reach everyone rather than one peer.
 *
 *  Confidentiality is network-wide rather than pairwise: encrypted under a key
 *  derived from the network master key, so every mesh member can read it and
 *  nobody outside the mesh can. That is the correct property for an alert
 *  everyone is meant to act on - pairwise encryption would defeat the point.
 *
 *  Delivery is by controlled flooding: no route lookup, no ACK, bounded by TTL
 *  and by the duplicate history that stops a node forwarding the same alert
 *  twice.                                                                    */
#define BROADCAST_ADDRESS 0xFFFE
#define BROADCAST_TTL 4

/*----------------------------------------------------------------------------*/
/*  Human-readable node names                                                 */
/*----------------------------------------------------------------------------*/
/*  Node IDs are derived from the chip MAC and mean nothing to a user, so each
 *  node also carries a name it advertises in its beacon and key exchanges.
 *  Peers build a directory from those, and messages can be addressed to
 *  "Rakshith" instead of 21087.                                             */
#define MAX_NODE_NAME_LEN 15
#define NODE_NAME_FIELD (MAX_NODE_NAME_LEN + 1)
#define NVS_NODE_NAME_KEY "nodename"

/*----------------------------------------------------------------------------*/
/*  End-to-end delivery receipts                                              */
/*----------------------------------------------------------------------------*/
/*  An ACK is hop-by-hop and only proves the next radio got the frame. The
 *  destination returns a receipt so the sender - and the phone app - can show
 *  genuine delivery, and so end-to-end PDR is measurable at the sender.
 *
 *  The proof is an HMAC under the pair's session key, which only the real
 *  destination can produce; a frame MAC alone would let any mesh member forge
 *  a delivery confirmation.                                                  */
#define RECEIPT_HEADER_SIZE 16
#define RECEIPT_PROOF_LEN 8

/*----------------------------------------------------------------------------*/
/*  ACK and retries                                                           */
/*----------------------------------------------------------------------------*/
#define MAX_PENDING_ACKS 10
#define ACK_TIMEOUT 15000  // 15 s
#define ACK_REPLAY_WINDOW   10
#define ACK_REPLAY_TTL_MS   15000
#define MAX_RETRIES 3

/*----------------------------------------------------------------------------*/
/*  Store and forward                                                         */
/*----------------------------------------------------------------------------*/
/*  A recipient that is switched off, out of range, or behind a hill is the
 *  normal case in the field, not an error. Rather than discarding a message
 *  once its retries are spent, the sender holds it and delivers it when the
 *  destination reappears.
 *
 *  What is held is the already-encrypted packet, so no plaintext is retained
 *  and the sequence number and nonce stay valid; only the next hop is
 *  rewritten when a route comes back.                                        */
#define MAX_OUTBOX 8
#define OUTBOX_TTL_MS 3600000          // give up after an hour
/*  Between attempts this must exceed a full ACK cycle - ACK_TIMEOUT x
 *  (MAX_RETRIES + 1) = 60 s - or the outbox would re-send a message while the
 *  link layer is still retrying the previous copy.                          */
#define OUTBOX_RETRY_INTERVAL_MS 75000
/*  The first attempt is different: a message is only parked once it has
 *  either never been sent or already finished its ACK cycle, so there is no
 *  copy in flight to collide with. Waiting a full interval here would just
 *  delay recovery for a recipient that is already back.                     */
#define OUTBOX_FIRST_RETRY_MS 20000
/*  Attempts are capped as well as timed. Each re-send costs a transmission
 *  plus up to MAX_RETRIES retransmissions, so a message to a node that never
 *  returns would otherwise spend an hour burning airtime - far more duty
 *  cycle than the whole mesh is budgeted. The gap between attempts also grows,
 *  so a long-absent recipient is retried patiently rather than constantly.  */
#define MAX_OUTBOX_ATTEMPTS 5

/*----------------------------------------------------------------------------*/
/*  Queue and listen-before-talk                                              */
/*----------------------------------------------------------------------------*/
#define MAX_QUEUE_SIZE 12
/*  How many times to re-check the channel before transmitting regardless. */
#define MAX_WINDOW_RETRIES 5

/*----------------------------------------------------------------------------*/
/*  Neighbours and routing                                                    */
/*----------------------------------------------------------------------------*/
/*  Tables are sized for 24 nodes, giving headroom over the 20-node target in
 *  NFR4. In a 20-node mesh every node needs 19 routes, 19 sessions and 19
 *  replay windows, so anything sized at 16 would thrash its own cache.
 *
 *  Neighbours need the same headroom: in a dense deployment, where most of
 *  the mesh is within one radio hop, a node can hear nearly everyone.
 *  Simulation at 20 nodes overflowed a 16-entry table.                      */
#define MAX_NEIGHBORS 24
/*  The beacon interval scales with the size of the mesh.
 *
 *  A fixed interval does not survive growth: N nodes each beaconing every T
 *  put N x airtime / T of constant load on one shared channel. At 20 nodes a
 *  30 s interval saturates it - simulation showed 41% occupancy, collisions,
 *  and routing that never converged. Scaling T with N holds aggregate beacon
 *  load near 5% of the channel whatever the mesh size:
 *
 *      interval = knownNodes x beaconAirtime x HELLO_AIRTIME_MULTIPLIER
 *
 *  which gives ~60 s for a handful of nodes and ~120 s at twenty.
 *
 *  The per-node budget this is tuned against is 1% duty cycle. That figure
 *  comes from EU practice (ETSI EN 300 220) and is used here as a
 *  conservative design target; India's 865-867 MHz delicensing is written
 *  mainly around power limits. Confirm the current WPC requirement before
 *  any deployment rather than relying on this number.                       */
/*  The floor matters as much as the scaling. A full 190-byte beacon is ~300 ms
 *  of airtime; at a 30 s floor that alone is ~1% duty, leaving no room for
 *  data. 60 s halves it and still converges a small mesh in about two
 *  minutes.                                                                 */
#define HELLO_INTERVAL_MIN_MS 60000
#define HELLO_INTERVAL_MAX_MS 300000
#define HELLO_AIRTIME_MULTIPLIER 20

/*  Expiry has to track the interval, or at large mesh sizes a single missed
 *  beacon would drop a perfectly good neighbour.                            */
#define NEIGHBOR_EXPIRY_BEACONS 4
#define ROUTING_MAX_CANDIDATES 3
#define INVALID_NEXT_HOP 0xFFFF
#define DEFAULT_TTL 6

/*----------------------------------------------------------------------------*/
/*  Distance-vector routing (FR4)                                             */
/*----------------------------------------------------------------------------*/
/*  DSDV-style: every node advertises its whole distance vector on the HELLO
 *  beacon, so routing costs no extra transmissions. 24 destinations is
 *  headroom over the 20-node scalability target.                           */
#define MAX_ROUTES 24
/*  The whole distance vector fits in one beacon: 62 + 24*5 + 8 = 190 bytes,
 *  inside LoRa's 255-byte frame.
 *
 *  Advertising a partial vector and rotating through it looks cheaper, but it
 *  halves how fast routes propagate - each hop of the mesh then needs two
 *  beacon rounds instead of one. Since the interval already scales with the
 *  beacon's airtime, a larger beacon costs nothing in duty cycle; it simply
 *  spaces beacons further apart while carrying strictly more information.
 *  The rotation below is retained and becomes a no-op whenever the table
 *  fits, which with MAX_ROUTES entries it always does.                      */
#define MAX_ROUTES_PER_HELLO 24
#define ROUTE_ADVERT_SIZE 5
/*  12 base + 32 public key + 16 name + 2 battery millivolts */
#define HELLO_HEADER_SIZE 62

/*  Metric meaning "unreachable". Advertising it is how a broken link is
 *  propagated, so these entries are kept and gossiped, not deleted.         */
#define ROUTE_INFINITY 255

/*  How long an unreachable route is retained before the slot is reclaimed.  */
#define ROUTE_HOLD_DOWN_MS 300000  // 5 minutes

/*  Reserved from NVS in blocks so a reboot resumes with a higher sequence
 *  number than neighbours already hold - otherwise our updates would be
 *  rejected as stale until the counter caught up.                          */
#define ROUTE_SEQ_BLOCK 200
#define NVS_ROUTE_SEQ_KEY "rtseq"

/* Neighbour whitelist used to force a physical topology during lab tests.
 * {0} disables the filter and lets the mesh self-organise.                   */
#define ALLOWED_NEIGHBORS { 0 }

/*----------------------------------------------------------------------------*/
/*  Re-enqueue and ALT control                                                */
/*----------------------------------------------------------------------------*/
#define ROUTE_MAX_ALTERNATES   5
#define ROUTE_HISTORY_SIZE     10
#define MAX_DUPLICATE_HISTORY 64
#define ALT_MAX_PER_MESSAGE   1
#define ALT_HISTORY_SIZE     30

/*============================================================================*/
/*  Security layer                                                            */
/*============================================================================*/
#define AES_KEY_LEN 16   // AES-128
#define GCM_TAG_LEN 16   // full-length GCM authentication tag
#define GCM_NONCE_LEN 12 // NIST SP 800-38D recommended IV length

/*  Random salt carried in every DATA frame and used to build the GCM nonce.
 *
 *  A nonce built only from counters is unsafe under a key that outlives them.
 *  The broadcast key is compiled in, so it survives an NVS erase - while the
 *  sequence number restarts at 1 and the message counter restarts at 0. The
 *  first broadcast after an erase would then reuse the exact nonce of the
 *  first broadcast before it, under the same key, which in GCM leaks the XOR
 *  of both plaintexts and exposes the authentication subkey.
 *
 *  Eight bytes from the hardware RNG, drawn once when a message is sealed,
 *  remove the dependency on any counter surviving. Applied to unicast too:
 *  a wire format that is conditional on message type is its own bug source,
 *  and the cost is 8 bytes.                                                 */
#define NONCE_SALT_LEN 8

/*  Pre-shared network master key. Every node in the mesh must carry the same
 *  16 bytes. Per-pair traffic keys are derived from it with HKDF-SHA256, so
 *  this value itself never encrypts a packet.
 *
 *  CHANGE THIS before any deployment - a published key protects nothing.
 *  Generate one with:  openssl rand -hex 16                                  */
#define MESH_MASTER_KEY { \
    0x4c, 0x6f, 0x52, 0x61, 0x4d, 0x65, 0x73, 0x68, \
    0x42, 0x4d, 0x53, 0x43, 0x45, 0x32, 0x30, 0x32 }

/*  Context strings binding derived keys to this protocol and version. Distinct
 *  labels keep each key cryptographically separate, so none can stand in for
 *  another's role.                                                           */
#define KDF_CTRL_LABEL "loramesh-ctrl-v1"
#define KDF_SESSION_LABEL "loramesh-session-v1"
#define KDF_BROADCAST_LABEL "loramesh-broadcast-v1"

/*============================================================================*/
/*  ECDH key agreement (X25519)                                               */
/*============================================================================*/
/*  Each node holds a long-term Curve25519 keypair. Message keys come from
 *  ECDH between the two endpoints, so a relay - which holds the pre-shared
 *  key like everyone else, but neither endpoint's private key - cannot derive
 *  them and cannot read what it forwards.
 *
 *  The shared secret is mixed *with* the master key when deriving the message
 *  key, so security is the stronger of the two mechanisms rather than the
 *  weaker: breaking either one alone does not expose traffic.                */
#define ECDH_PUBLIC_KEY_LEN 32
#define ECDH_PRIVATE_KEY_LEN 32
#define ECDH_SHARED_LEN 32

#define NVS_ECDH_PRIVATE_KEY "ecdhpriv"

/*  Cached sessions, one per peer. */
#define MAX_SESSIONS 24

/*  Key discovery: nodes learn a neighbour's public key straight from its
 *  beacon, and ask multi-hop peers for theirs on demand. Discovery runs in
 *  the background off the routing table, so a key is normally in hand before
 *  the user ever sends anything.                                            */
#define KEY_DISCOVERY_INTERVAL_MS 3000
#define KEY_REQUEST_TIMEOUT_MS 20000
#define MAX_KEY_REQUEST_RETRIES 4
#define KEY_HEADER_SIZE 16

/*----------------------------------------------------------------------------*/
/*  Link-layer frame authentication                                           */
/*----------------------------------------------------------------------------*/
/*  Every frame carries a truncated HMAC-SHA256 tag so an outsider cannot
 *  forge routing beacons, acknowledgements or route-failure notices. Eight
 *  bytes is ~15 ms of extra airtime; against a link carrying a handful of
 *  packets per minute, a 2^-64 forgery chance is far more margin than the
 *  attacker's realistic attempt rate needs.
 *
 *  On DATA this sits underneath the end-to-end GCM tag and is recomputed at
 *  each hop, because relays legitimately rewrite the hop fields.             */
#define CONTROL_MAC_LEN 8

/*----------------------------------------------------------------------------*/
/*  Anti-replay (FR8)                                                         */
/*----------------------------------------------------------------------------*/
/*  Sequence numbers are reserved from NVS in blocks so a reboot can never
 *  reissue a number, without writing to flash on every single message.       */
#define SEQ_BLOCK_SIZE 100
#define NVS_NAMESPACE "loramesh"
#define NVS_SEQ_KEY "txseq"

/*  Sliding replay window, one entry per remote source node. A 32-bit bitmap
 *  tolerates the out-of-order delivery that multi-hop routing produces.      */
#define MAX_REPLAY_SOURCES 24
#define REPLAY_WINDOW_BITS 32

/*============================================================================*/
/*  BLE bridge (phone <-> node)                                               */
/*============================================================================*/
/*  Nordic UART Service - the de-facto "BLE serial port" profile, supported by
 *  nRF Connect, Serial Bluetooth Terminal (BLE mode) and any custom app.     */
#define BLE_NAME_PREFIX "LoRaMesh-"
#define BLE_SERVICE_UUID        "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define BLE_CHAR_RX_UUID        "6E400002-B5A3-F393-E0A9-E50E24DCCA9E" // phone -> node (write)
#define BLE_CHAR_TX_UUID        "6E400003-B5A3-F393-E0A9-E50E24DCCA9E" // node -> phone (notify)
#define BLE_RX_LINE_MAX 256
/*  A write that arrives without a newline is treated as a complete line once
 *  the sender has been quiet this long.                                     */
#define BLE_LINE_IDLE_MS 120

#endif
