# Long-Range Secure Messaging System using ESP32 and LoRa

A decentralised, gateway-free messaging network built on ESP32-S3 microcontrollers with
LoRa radios in a multi-hop mesh topology. Every node is simultaneously a sender, a receiver
and a relay. There is no gateway, no cloud, and no internet dependency.

Message text is encrypted end-to-end with **AES-128-GCM** under a key agreed by **X25519
ECDH** between the two endpoints. A relay genuinely cannot read what it forwards — it holds
the same pre-shared network key as everyone else, but neither endpoint's private key. A
phone connects to any node over **BLE** and acts as the user interface.

```
phone --BLE--> node A --LoRa--> node C --LoRa--> node B --BLE--> phone
                                (relay, sees only ciphertext)
```

This extends the gateway-free ESP32 LoRa mesh of Arregui (PUCE, 2025), which provided the
relay, ACK and self-healing layers but carried no security layer and no routing table.

## Repository structure

```
LoRaMeshProject/
├── platformio.ini             # Build configuration (three board targets)
├── app/                       # Installable Web Bluetooth phone client (PWA)
├── sim/mesh_sim.py            # 20-node protocol simulator
├── src/LoRaMesh/
│   ├── LoRaMesh.ino           # Entry point, command handling, app callbacks
│   ├── config.h               # Band, pin maps, crypto and BLE parameters
│   ├── lora_manager.h         # RadioLib driver for SX1262 / SX1276
│   ├── packet_manager.h       # Packet structures and wire serialisation
│   ├── security_manager.h     # AES-128-GCM, HKDF, frame MAC, anti-replay
│   ├── crypto_session.h       # X25519 key agreement and per-peer session keys
│   ├── metrics.h              # Performance counters for the evaluation
│   ├── ble_manager.h          # Nordic UART Service bridge to the phone
│   ├── communication_manager.h# Link layer, filters, encrypt/relay/decrypt
│   ├── message_scheduler.h    # Priority queue, retries, alternate routes
│   ├── message_receiver.h     # Duplicate detection, listen-before-talk
│   ├── routing_manager.h      # Neighbour table, DSDV routing table, next hop
│   └── oled_manager.h         # Optional display (no-op on display-less boards)
└── docs/                      # Diagrams, STL enclosures, USB driver
```

## Hardware

| Item | Choice | Per node |
|---|---|---|
| Board | **Heltec Wireless Stick Lite V3** (ESP32-S3 + SX1262), 863–870 MHz variant | 1 |
| Antenna | 868 MHz SMA, ~3 dBi | 1 |
| Battery | 3.7 V LiPo (the board has charging built in) | 1 |

The Lite V3 has no display — the phone is the user interface, which saves cost and the
~10–20 mA an OLED draws on a relay node nobody is looking at. An onboard LED pulses on
message activity for local feedback.

Two alternate targets are supported without code changes: the **Heltec WiFi LoRa 32 V3**
(same chipset plus a 128×64 OLED) and a generic **ESP32 DevKit + SX1276 (RA-01H)**.

> Buy the **863–870 MHz** board variant. India's licence-exempt band is 865–867 MHz
> (WPC GSR 564(E)); the firmware defaults to 866.0 MHz. Note that RA-02 modules are
> 433 MHz parts — use RA-01H for this band.

## Building

Requires the PlatformIO extension for VS Code, or the `pio` CLI.

```bash
pio run                          # build the default Lite V3 target
pio run -t upload                # flash over USB-C
pio device monitor               # serial console at 115200
```

Other targets:

```bash
pio run -e heltec_wifi_lora_32_V3 -t upload   # board with an OLED
pio run -e esp32dev_sx1276 -t upload          # ESP32 DevKit + SX1276
```

Before deploying, change `MESH_MASTER_KEY` in `src/LoRaMesh/config.h`. Generate one with
`openssl rand -hex 16`. Every node in the mesh must carry the same key.

## The phone app

`app/` is a Web Bluetooth client, installable as a PWA — chat threads, a node list with
signal and encryption status, delivery ticks, broadcast alerts, and a diagnostics pane
exposing every command the firmware supports.

### It works with no internet, but it has to be installed once

Talking to a node uses the Bluetooth radio only — no internet, no SIM, no cellular. But
*loading* a web page needs a server, and browsers only permit Web Bluetooth over HTTPS
(a `file://` page will not work).

So: host it once, install it once, then use it offline forever.

```bash
git init
git add .
git commit -m "Secure LoRa mesh"
git remote add origin https://github.com/<user>/<repo>.git
git push -u origin main
```

Then on GitHub: **Settings → Pages → Source: Deploy from a branch → main → / (root)**.
After a minute the app is at `https://<user>.github.io/<repo>/app/`.

Open that in **Chrome on Android**, then use the browser menu's **Install app** /
**Add to Home Screen**. A service worker caches everything on that first load, so from then
on it launches from the home screen like a native app with no network of any kind. That is
what makes it usable in the field.

Conversations are stored on the phone and survive closing the app — a messenger that forgets
everything when you close it is not one you would carry anywhere. Only names are restored
for known nodes; hop count, signal and session state are live facts and would be misleading
if shown from a previous session, so those nodes appear as *not heard from yet*.

**iOS Safari does not support Web Bluetooth at all.** iPhone users need the Bluefy browser,
or you would have to write a native app. Worth settling before the demo.

If you later need iOS or a Play Store build, the alternative is a native app talking to the
same Nordic UART service — the firmware side would not change at all.

## Messages survive an absent recipient

A recipient who is switched off, out of power, or behind a hill is the normal case in the
field, not an error. Rather than discarding a message once its retries and alternate routes
are spent, the sender **holds it and delivers it when the destination reappears**.

What is held is the already-encrypted packet, so no plaintext waits in memory and the
sequence number and nonce it was sealed with stay valid — only the next hop is rewritten
when a route comes back. Messages are held for up to an hour, then reported as undelivered
rather than silently forgotten. The app shows them as *waiting for recipient*, not failed.

Measured in simulation with nodes dropping offline at random:

| | Without holding | With holding |
|---|---|---|
| End-to-end PDR under churn | 79.1% | **88.1%** |
| Messages permanently lost | 9 | 0 |

Every held message was eventually delivered. Note this is *source-side* holding: a relay
still discards traffic it cannot pass on, because the original sender is holding its own
copy. Full custodial store-and-forward at every hop is a larger design.

## Knowing when a node is dying

Every beacon carries the sender's battery voltage, so the app's node list shows the state of
charge of every node in the mesh. A relay left on a pole is otherwise invisible until it
goes silent, which is exactly too late.

> The battery ADC pins differ between Heltec board revisions. `config.h` flags which ones to
> verify. A wrong pin reads an implausible voltage and is reported as **unknown** rather than
> as a confident wrong number.

## Sharing location

Tap 📍 to send your position to a node, or to everyone as an emergency alert. Incoming
positions render as a card with coordinates, accuracy, how far away the sender is, and a
link that opens the phone's map app.

**The position comes from the phone, not the node.** The Heltec board has no GPS chip, and
adding one per node would mean an extra module, extra current draw and a sky view for every
relay. The phone in your hand already has a better GPS receiver, and it is already the user
interface — so the node stays a radio and the phone stays the sensor.

This needs no firmware support at all. A position travels as an ordinary message with a
known prefix:

```
!loc:12.94150,77.56550,12          lat, lon, accuracy in metres
```

so it inherits the same end-to-end encryption, routing, retries and delivery receipts as
any other message, and a broadcast location works as an SOS. The map link uses a `geo:` URI,
which hands off to the phone's map app and works from cached maps with no connectivity.

If you ever do want position without a phone attached — an unattended sensor node reporting
its own location — that is where a NEO-6M or NEO-M8N on the spare UART would earn its place.
Nothing in the protocol would change; only the source of the coordinates.

## Knowing who is who

A node ID is derived from the chip MAC, so it is a number like `21087` that means nothing to
a user. Every node therefore also carries a **name**, set with `/name Rakshith` and stored in
NVS. Names are advertised on the beacon and in key exchanges, so peers build a directory
automatically and you can address messages either way:

```
Rakshith:meet at the north gate
21087:meet at the north gate
```

`/peers` lists every reachable node with its name, hop count, signal and whether an
encrypted session is established — that is what the app's node list is built from.

## Using it

Each node advertises over BLE as `LoRaMesh-<nodeID>`. Besides the app, nRF Connect or
Serial Bluetooth Terminal in BLE mode work, and the same commands work on the serial
console.

| Input | Effect |
|---|---|
| `<nodeID\|name>:<message>` | Send an encrypted message, up to 200 characters |
| `/all <message>` | Broadcast an alert to every node in the mesh |
| `<target>:!loc:<lat>,<lon>,<acc>` | Share a position (the app's 📍 button sends this) |
| `/id` | This node's ID and name |
| `/name <text>` | Set this node's name (max 15 chars, saved to NVS) |
| `/peers` | Machine-readable list of reachable nodes — the app's node list |
| `/nodes` | Show the neighbour table with RSSI |
| `/routes` | Show the routing table: destination, next hop, hop count |
| `/keys` | Show established ECDH sessions |
| `/stats` | Performance counters — delivery, latency, crypto cost, duty cycle |
| `/hello` | Broadcast a HELLO immediately |
| `/help` | Usage |

The node answers with structured lines the app parses, all of which are also readable on the
serial console:

| Line | Meaning |
|---|---|
| `MSG <id> <name>: <text>` | An incoming message |
| `BCAST <id> <name>: <text>` | An incoming broadcast alert |
| `QUEUED <msgID> <destID>` | Accepted for sending |
| `DELIVERED <msgID> <destID>` | The destination confirmed receipt end-to-end |
| `HELD <msgID> <destID>` | Recipient unreachable; the node is holding it |
| `EXPIRED <msgID> <destID>` | Held for an hour and given up on |
| `SEC <reason>` | A frame failed authentication, or a replay was blocked |
| `PEER <id> <name> <hops> <rssi> <secure> <battery%>` | One line per reachable node |

Messages are up to 200 characters — sized to fill a single LoRa frame, so no fragmentation
and reassembly is needed. A node will refuse to send until it has agreed a session key with
the destination; discovery runs in the background, so this resolves within a beacon or two
of the mesh forming. Check with `/keys`.

## Protocol

Four packet types operate from the physical up to the application layer:

- `DATA` — encrypted payload with TTL and routing control
- `ACK` — hop-by-hop delivery confirmation
- `HELLO` — neighbour discovery, distance-vector advertisement, public key and name
- `ALT` — notification of a failed or congested route
- `KEY_REQ` / `KEY_RESP` — X25519 public key discovery beyond one hop
- `RECEIPT` — end-to-end delivery confirmation from the destination
- `BROADCAST` — a network-wide alert, flooded rather than routed

An `ACK` only proves the next radio along heard the frame. `RECEIPT` is what proves a
message actually arrived: the destination returns one carrying an HMAC under the pair's
session key, so only the real destination can produce it — the frame MAC alone would let
any mesh member forge a delivery confirmation. This is what drives the app's delivery ticks
and makes end-to-end PDR measurable at the sender.

### DATA frame

```
offset  size  field                     encrypted?  end-to-end auth?
0       1     messageType               no          yes
1       2     meshID                    no          yes
3       4     messageID                 no          yes
7       2     prevHop                   no          no   (rewritten per hop)
9       2     nextHop                   no          no   (rewritten per hop)
11      2     sourceNode                no          yes
13      2     destinationNode           no          yes
15      4     seqNum                    no          yes
19      1     ttl                       no          no   (decremented per hop)
20      1     payloadLen                no          yes
21      N     ciphertext                yes         yes
21+N    16    GCM authentication tag    -           -
37+N    8     link-layer MAC            -           -    (recomputed per hop)
```

Keeping `sourceNode`/`destinationNode` separate from `prevHop`/`nextHop` is what makes
end-to-end encryption possible: relays rewrite only the hop fields, so the destination can
still identify the true sender and derive the right key. The mutable fields sit outside the
end-to-end authenticated data; everything a relay must not touch sits inside it. The
mutable fields are instead covered by the link-layer MAC, which every hop recomputes.

### Security layer

Two layers, deliberately separate. End-to-end protection travels with the message and only
the destination can undo it. Link-layer protection is recomputed at every hop and covers
the fields relays legitimately rewrite.

- **Confidentiality and integrity** — AES-128-GCM (hardware-accelerated on the ESP32-S3)
  encrypts the payload and produces a 16-byte tag verified before any plaintext is released.
- **Key agreement** — each node holds a long-term X25519 keypair, generated on first boot
  and kept in NVS. One-to-one message keys come from ECDH between the two endpoints, so a
  relay — which holds the same pre-shared key as everyone else, but neither endpoint's
  private key — cannot derive them and cannot read what it forwards.
- **Broadcast key** — a separate network-wide key under its own HKDF label, so it can never
  stand in for a pair's session key or the control key.
- **Hybrid key derivation** — the message key mixes the ECDH secret *with* the master key:

  ```
  sessionKey = HKDF(salt = meshID,
                    ikm  = X25519(ourPrivate, theirPublic) || masterKey,
                    info = "loramesh-session-v1" || lowNode || highNode)
  ```

  Security is therefore the stronger of the two mechanisms rather than the weaker: an
  attacker must break both, not either one.
- **Key distribution** — a node's public key rides on its `HELLO` beacon, so a session with
  any direct neighbour costs no round trip. Peers further away are found by `KEY_REQ` /
  `KEY_RESP`, driven in the background off the routing table so a key is normally in hand
  before the user sends anything. One exchange teaches both sides.
- **Frame authentication** — every frame, including `HELLO`, `ACK` and `ALT`, carries a
  truncated HMAC-SHA256 tag under a control key derived from the master key with its own
  label, so it cannot stand in for a traffic key. Nothing is parsed until the tag verifies,
  so a forged routing beacon never reaches the routing table, and a public key cannot be
  substituted in transit. Tags are compared in constant time. Costs 8 bytes and ~10 ms of
  airtime per frame.
- **Replay prevention** — every message carries a monotonic sequence number reserved from
  NVS in blocks, so a reboot can never reissue one. Receivers keep a 32-entry sliding window
  per source, which rejects replays while tolerating the out-of-order delivery multi-hop
  routing produces. The window is only consulted *after* the tag verifies, so forged
  sequence numbers cannot lock out a genuine sender.

### Two kinds of message, two confidentiality models

The distinction is deliberate, and it maps onto what each kind of message is *for*.

| | One-to-one | Broadcast alert |
|---|---|---|
| Key | X25519 ECDH between the endpoints | Network key from the master key |
| Who can read it | Only the two endpoints | Any mesh member |
| Who cannot | Everyone else, **relays included** | Anyone outside the mesh |
| Delivery | Routed hop-by-hop, ACKed, retried, receipted | Flooded, TTL-bounded, no ACK |
| Sender proof | Only the two endpoints can produce it | Any mesh member could forge one |

An alert exists to reach everyone at once, so encrypting it pairwise would defeat its
purpose — it is network-confidential by design, not by compromise. The cost is that a
broadcast's claimed sender is only as trustworthy as mesh membership, whereas a one-to-one
message genuinely could not have come from anyone but its sender.

Flooding is bounded by TTL and by the duplicate history: a node acts on the first copy of
an alert and silently drops the rest, so each node transmits it at most once. On the
five-node test topology an alert from any node reaches all four others in five
transmissions.

### Routing (DSDV)

Each node keeps a routing table mapping destination → next hop → hop count, built with a
destination-sequenced distance-vector protocol.

```
offset  size  field
0       1     messageType
1       2     meshID
3       4     messageID
7       2     originNode
9       2     originSeq          this node's own sequence number
11      1     routeCount
12      N*5   routes: destination(2) seqNum(2) hopCount(1)
```

- **No dedicated routing traffic.** The distance vector rides on the HELLO beacon that
  neighbour discovery already sends, which is what makes distance-vector routing affordable
  inside LoRa's bandwidth.
- **Authenticated.** Beacons carry a link-layer MAC and are discarded before parsing if it
  fails, so an outsider cannot poison the routing table with forged advertisements.
- **Loop freedom.** Every destination owns a sequence number that only it increments, in
  even steps. A route wins if it is fresher, or equally fresh but shorter. A node that
  detects a broken link advertises the sequence number *plus one* — odd, meaning
  "unreachable" — which outranks the stale reachable routes its neighbours still hold and
  cannot be undone until the destination itself issues a fresh even number. This is what
  prevents the count-to-infinity behaviour a naive distance-vector protocol suffers from.
- **Triggered updates.** A broken link beacons immediately rather than waiting out the
  interval, so the invalidation races outwards and nodes stop black-holing traffic at once.
  Only bad news triggers a beacon, which keeps a powering-up mesh from storming.
- **Sequence numbers survive reboots.** They are reserved from NVS in blocks, so a
  restarted node does not spend a beacon interval having its updates rejected as stale.
- **Graceful fallback.** Before routes converge, or when a destination is genuinely unknown,
  the node falls back to the base project's opportunistic choice — the best neighbour by
  RSSI and recency. The mesh works from the first beacon rather than only after convergence.

Route recovery is bounded by the destination's next beacon, so the table heals in roughly
one to two beacon intervals. Message delivery heals faster than that: the `ALT` and
retry machinery reroutes an individual packet at the data plane as soon as an ACK fails,
without waiting for the routing table.

### Mesh mechanisms

Inherited from the base implementation: hop-by-hop acknowledgment with retries, duplicate
detection, listen-before-talk channel access, alternate-route re-enqueue via `ALT` packets,
and a priority queue that sends ACKs ahead of other traffic.

## Security review findings

A pass over the whole codebase looking for bugs and vulnerabilities turned up four issues,
all since fixed:

- **Line-protocol injection (the serious one).** Node names and message text arrive from
  remote nodes and were placed straight into the newline-delimited protocol the app parses.
  A message containing a newline could forge whole protocol lines — a fake delivery
  confirmation, or a message attributed to a different node. Encryption proves *who* sent
  a message; it does not make the contents safe to splice into a protocol. Both are now
  sanitised at the boundary: names to printable non-space ASCII, message text with control
  characters flattened.
- **`millis()` rollover.** Absolute deadline comparisons (`now >= deadline`) misbehave when
  the millisecond counter wraps at ~49 days, which matters for a node meant to sit in a
  field for months. All such comparisons now use a signed difference.
- **Nested spinlock in the BLE path.** The write callback took the queue lock and then
  called a helper that took it again. ESP-IDF spinlocks happen to be recursive, so it
  worked, but relying on that is fragile — the locking is now flat.
- **Duplicate delivery receipts would inflate PDR**, the number the evaluation is measured
  on. Receipts are now deduplicated.

## Known limitations

- **No forward secrecy.** Identity keys are long-term, so an attacker who both recorded
  traffic and later extracted a node's private key could decrypt that node's past messages.
  Ephemeral keys per session would fix this, at the cost of a handshake that cannot be
  cached across reboots.
- **A broadcast's sender is not cryptographically proven.** Every member holds the broadcast
  key, so any of them could forge an alert attributed to another node. This is inherent to
  a key everyone can read with; proving the sender would need per-node signatures (Ed25519
  or ECDSA), which mbedTLS on this platform does not make cheap. One-to-one messages are
  unaffected — those genuinely could only have come from their sender.
- **Key distribution is authenticated by the shared key, so an insider could man-in-the-
  middle a *new* exchange.** An outsider cannot: public keys travel in MAC-authenticated
  frames. Note the weaker property is confined to key setup — an insider who merely relays
  traffic, without intercepting the exchange, still cannot read it. That is the ECDH gain.
- **No sleep scheduling yet** (FR10). Nodes receive continuously; see below.

Replay of control frames is bounded rather than eliminated: `HELLO` replays are rejected by
the DSDV sequence number, and `ACK`/`ALT` replays only matter inside the 15-second window
where a matching message ID is still pending.

### Why FR10 is not implemented

Naive sleeping would break the mesh: a sleeping node misses the packets it is supposed to
relay. Doing it correctly needs the preamble-sampling approach the project's own survey
cites, where nodes wake periodically to sample the channel. That is also in tension with
the BLE requirement — a node acting as a phone's interface has to stay connectable. The
realistic design is asymmetric: relay-only nodes duty-cycle, endpoint nodes stay awake.
Implementing it blind, without hardware to measure against, would risk a mesh that silently
drops traffic, so it is left as documented future work rather than a half-built feature.

## Simulating the mesh before building it

`sim/mesh_sim.py` runs the whole protocol — 20 nodes by default — over a modelled radio
channel with airtime, range and collisions. No dependencies beyond Python 3.

```bash
python sim/mesh_sim.py                                    # 20 nodes, 10 minutes
python sim/mesh_sim.py --nodes 24 --minutes 25
python sim/mesh_sim.py --nodes 10 --area 1200 --range 700 --interval 30000
```

It reports against the requirements and prints PASS or FAIL per criterion, so results can
go straight into an evaluation chapter.

**What it proves and what it does not.** It reimplements the *protocol* — DSDV routing,
beacon-carried vectors, key discovery, ACK and retry, flooded broadcast, duplicate
suppression, the replay window — so it validates protocol behaviour, timing, channel load
and whether the table sizes in `config.h` are adequate. It does not execute the C++
firmware, so it cannot find bugs in that code, and cryptography is modelled only as "a
session exists" (the primitives are verified separately against RFC test vectors). Its
assumptions are deliberately pessimistic: no LoRa capture effect, hard radio range.

### What it found

Running it at 20 nodes exposed five problems that a five-node bench test never would:

| Finding | Fix |
|---|---|
| Session and replay tables sized 16, but a 20-node mesh needs 19 each | Tables sized for 24 |
| A fixed 30 s beacon put 20 nodes at 41% channel occupancy — routing never converged | Beacon interval scales with mesh size |
| Proactive key discovery is O(N²); it dominated all traffic to build sessions never used | Discovery is on demand |
| A 3–7 s send delay per hop made NFR2's 5 s target arithmetically impossible | 200–1200 ms, with CAD doing collision avoidance |
| Advertising a partial routing vector halved propagation speed | Whole vector in one beacon |

### Measured results

25 simulated minutes, 1200 m field, 700 m range, one message every 15 s:

| Nodes | Converged | PDR | Mean latency | Peak duty cycle | Verdict |
|---|---|---|---|---|---|
| 5 | 56 s | 100% | 1.7 s | 0.67% | PASS |
| 10 | 137 s | 100% | 3.3 s | 1.19% | duty cycle over target |
| 20 | 119 s | 96.6% | 2.6 s | 0.58% | PASS |
| 24 | 142 s | 98.3% | 2.9 s | 0.49% | PASS |

The 10-node exception is not a protocol fault: it is one hub node relaying for the whole
mesh at that message rate. Duty cycle, not bandwidth, is what limits throughput here — at
one message per 45 s the same topology stays under target with 100% delivery. Budget the
message rate accordingly, and expect the busiest relay to hit the ceiling first.

Beyond ~24 nodes the tables overflow and routing stops converging. That is the honest
ceiling of this configuration.

## Measuring performance

`/stats` reports the quantities the requirements are written against, so the evaluation can
quote measurements instead of estimates:

| Requirement | Target | Where to read it |
|---|---|---|
| NFR2 latency | < 5 s | `latency mean` |
| NFR3 delivery | ≥ 90% | `PDR e2e` |
| NFR5 crypto overhead | < 10 ms | `encrypt` / `decrypt` mean and max |
| NFR6 energy | — | `airtime` and `duty cycle` |

`PDR e2e` counts delivery receipts against messages sent, so it is genuine end-to-end
delivery. `hop1 ratio` is shown next to it because the gap between the two is exactly the
loss happening beyond the first radio link — useful for arguing about where a multi-hop
path is failing. Latency is measured on one node's own clock, which avoids needing time
synchronisation across the mesh; note it is measured to the first-hop ACK, so it understates
full end-to-end time on a multi-hop path.

## Credits

Capstone project, Department of Information Science and Engineering,
B.M.S. College of Engineering, 2025–2026.
Rakshith H R (1BM23IS191), Shreeram Prakash Hegde (1BM23IS232),
Shreevatsa G Uppalli (1BM23IS234), Suchit K S (1BM23IS255).
Under the guidance of Dr. P Jayarekha.

Mesh routing, ACK and self-healing layers derive from the gateway-free LoRa mesh by
Danilo Arregui (PUCE, 2025), released under the licence in `LICENSE`.
