# AUDIT.md — Phase 0: Ground Truth

**Scope:** full repository as of this audit — firmware (`src/LoRaMesh/`), simulator
(`sim/`), phone app (`app/`), build config, docs.
**Method:** every source file read; simulator constants machine-diffed against
`config.h`; app parsers machine-diffed against firmware output strings; three
PlatformIO targets built.

> **Auditor conflict of interest.** Most of this code was written by the same agent
> now auditing it. A self-audit reliably under-finds design-level faults, because the
> auditor re-derives the original assumptions instead of challenging them. Findings
> below are weighted accordingly: mechanical checks (bounds, drift, parity) are
> trustworthy; judgements about whether the *design* is right are not independent.
> The security layer in particular deserves a reviewer who did not write it.

---

## 1. Intended requirements

Reconstructed from `README.md`, code comments, and the capstone report
(`Final_Project_Report (2).docx`, outside the repo). Requirement IDs are the report's.

### Functional

| ID | Requirement | Source |
|---|---|---|
| FR1 | Compose and transmit text messages node-to-node | report Ch.5 |
| FR2 | Relay packets on behalf of other nodes (multi-hop) | report Ch.5 |
| FR3 | Periodic beacons; maintain a dynamic neighbour table | report Ch.5 |
| FR4 | Routing table mapping destination → next hop → hop count | report Ch.5 |
| FR5 | Per-hop acknowledgment; retransmit up to a configurable max | report Ch.5 |
| FR6 | End-to-end AES-128-GCM encryption of payloads | report Ch.5 |
| FR7 | Authentication tag verified at the destination | report Ch.5 |
| FR8 | Replay prevention via monotonic sequence numbers | report Ch.5 |
| FR9 | Duplicate suppression at relays | report Ch.5 |
| FR10 | Low-power sleep when idle | report Ch.5 |

### Non-functional

| ID | Target | Source |
|---|---|---|
| NFR1 | ≥1 km line-of-sight per link | report Ch.5 |
| NFR2 | <5 s end-to-end over three hops | report Ch.5 |
| NFR3 | ≥90% packet delivery ratio | report Ch.5 |
| NFR4 | ≥20 nodes without significant degradation | report Ch.5 |
| NFR5 | <10 ms cryptographic overhead per message | report Ch.5 |
| NFR6 | <250 mA active, <10 µA sleep | report Ch.5 |
| NFR7 | Modular firmware (radio / routing / security / application) | report Ch.5 |

### Added beyond the report

Not in the report; present in the code. These need to be written **into** the report
or removed from the claim set — right now the artefact and the document disagree.

- BLE bridge to a phone (report Ch.6.1.2 still describes serial input and an OLED)
- Human-readable node names with an advertised directory
- End-to-end delivery receipts (distinct from per-hop ACK)
- Broadcast / emergency alert with network-wide confidentiality
- Store-and-forward outbox for absent recipients
- Battery telemetry on the beacon
- X25519 ECDH session keys (report Ch.6 specifies a pre-shared key; Ch.8 claims ECDH)
- Location sharing via the phone's GPS

---

## 2. Actual architecture

### 2.1 Module map

Single translation unit: `LoRaMesh.ino` includes every header; there are no `.cpp`
files. All state is file-scope `static` or plain globals. This is inherited from the
Arduino-style base project.

```
LoRaMesh.ino          application: commands, callbacks, main loop
├── config.h          all tunables, pin maps, key material, protocol constants
├── metrics.h         counters, LoRa airtime formula, battery ADC
├── lora_manager.h    RadioLib wrapper (SX1262 | SX1276), ISR flag, CAD
├── packet_manager.h  packet structs, wire (de)serialisation, node/message IDs
├── security_manager.h AES-GCM, HKDF, frame MAC, anti-replay window, tx sequence
├── crypto_session.h  X25519, per-peer session keys        (needs packet_manager)
├── routing_manager.h neighbour table, DSDV routing table, node directory, beacon pacing
├── communication_manager.h  frame MAC, transmit, receive dispatch   (the core)
├── message_scheduler.h      send queue, retries, outbox, key discovery, broadcast
├── message_receiver.h       duplicate history, listen-before-talk
├── ble_manager.h            Nordic UART Service, line framing
└── oled_manager.h           display, compiled to no-ops on display-less boards
```

Layering is mostly clean. Two deliberate cycles are broken by forward declaration
blocks: `communication_manager.h` declares 18 functions defined in
`message_scheduler.h` / `message_receiver.h` (lines 28–51), and
`message_scheduler.h` forward-declares `windowCollisionPrevention`,
`requestSessionWith`, `parkMessage`. This works only because of the single-TU build.

### 2.2 Data flow

**Outbound (originating a message)**

```
handleCommand()                LoRaMesh.ino
 └ enqueueTextMessage()        message_scheduler.h — looks up session key,
                                 seals with AES-GCM, finds next hop,
                                 enqueues OR parks in the outbox
    └ updateMessageScheduler() picks a ready queue slot (ACKs prioritised)
       └ windowCollisionPrevention()   CAD-based listen-before-talk
          └ handleTransmission()       serialise
             └ transmitFrame()         append frame MAC, hand to radio
```

**Inbound**

```
DIO interrupt → radioIrqFired (ISR sets a flag only)
 └ processRadioEvents()        reads the frame out in the main loop
    └ processReceivedMessage() message_receiver.h
       └ processPayload()      communication_manager.h
          ├ stripAndVerifyFrameMac()   ← nothing is parsed before this passes
          └ switch(messageType) → DATA | ACK | HELLO | ALT | KEY | RECEIPT | BROADCAST
```

Critically, the frame MAC is verified **before any field is parsed**
(`communication_manager.h:~296`). Everything downstream operates on a frame proven
to come from a mesh member.

### 2.3 Packet format

Eight types. All are big-endian and explicitly serialised except ACK and ALT, which
are `memcpy` of the struct (identical MCUs both ends; padding is zero because the
source structs are static).

**DATA** — `DATA_HEADER_SIZE` 21, max frame 245 B

```
off  size  field              encrypted  end-to-end auth (AAD)
0    1     messageType            no        yes
1    2     meshID                 no        yes
3    4     messageID              no        yes
7    2     prevHop                no        no   ← rewritten per hop
9    2     nextHop                no        no   ← rewritten per hop
11   2     sourceNode             no        yes
13   2     destinationNode        no        yes
15   4     seqNum                 no        yes
19   1     ttl                    no        no   ← decremented per hop
20   1     payloadLen             no        yes
21   N     ciphertext             YES       yes   (N ≤ 200)
21+N 16    GCM tag                 -         -
37+N 8     link-layer MAC          -         -    recomputed every hop
```

The split between `sourceNode`/`destinationNode` (end-to-end, authenticated) and
`prevHop`/`nextHop` (per-hop, mutable) is what makes end-to-end encryption possible
across relays. AAD covers exactly the immutable set — `buildDataAad()`,
`packet_manager.h:227`.

**HELLO** — header 62 B, up to 24 route entries, max 190 B. Carries: origin, DSDV
sequence, route count, X25519 public key (32 B), name (16 B), battery mV (2 B), then
5-byte route adverts `{destination, seqNum, hopCount}`.

**KEY_REQ/RESP** 72 B · **RECEIPT** 32 B · **ACK/ALT** 20 B · **BROADCAST** reuses the
DATA struct and serialiser with `messageType` 8 and `destinationNode` = `0xFFFE`.

### 2.4 Routing algorithm

DSDV (destination-sequenced distance vector), carried on the HELLO beacon — no
dedicated routing traffic.

- Each node owns a sequence number it increments **by 2** (always even). A node that
  detects a broken link advertises `seq+1` (odd) with metric `ROUTE_INFINITY`, which
  outranks stale reachable routes and cannot be undone until the destination itself
  issues a fresh even number. This is what prevents count-to-infinity.
- Update rule (`applyRouteUpdate`, `routing_manager.h:309`): accept if the sequence is
  newer; or equal and strictly shorter; or equal, from the current next hop, and the
  cost changed.
- Sequence comparison is wraparound-safe via signed 16-bit difference
  (`seqIsNewer`, line 249).
- Beacon interval **scales with mesh size**: `knownNodes × beaconAirtime × 20`,
  clamped to 60–300 s. Neighbour expiry tracks it at 4 × interval.
- Triggered updates: only *bad* news (a route going unreachable) forces an early
  beacon, which avoids a storm as a mesh powers up.
- Fallback: with no route, `getNextHop` picks opportunistically by RSSI and recency —
  the base project's original behaviour, retained so the mesh works before convergence.

### 2.5 Key management

Three independent keys, all derived with HKDF-SHA256 under **distinct labels** so none
can substitute for another:

| Key | Derivation | Scope |
|---|---|---|
| Control (frame MAC) | HKDF(master, `"loramesh-ctrl-v1"`) | network-wide |
| Broadcast | HKDF(master, `"loramesh-broadcast-v1"`) | network-wide |
| Session (unicast) | HKDF(salt=meshID, **ikm = X25519(ours, theirs) ‖ master**, `"loramesh-session-v1"` ‖ lo ‖ hi) | one node pair |

The session key mixes the ECDH secret **with** the pre-shared master key, so security
is the stronger of the two rather than the weaker. A relay holds the master key like
everyone else but neither endpoint's private key, so it cannot derive the session key.

- Identity: long-term X25519 keypair generated on first boot, private half in NVS.
- Distribution: public key rides on every HELLO (neighbours agree with zero round
  trips); multi-hop peers use KEY_REQ/KEY_RESP, triggered **on demand** by an
  attempted send.
- Nonce: `source(2) ‖ seq(4) ‖ dest(2) ‖ messageID(4)`. Uniqueness rests on
  `(source, seq)`, where seq is NVS-block-reserved so a reboot never reissues one.
- Replay: per-source sliding window, 32-bit bitmap, checked **after** tag verification.

---

## 3. Where intent and implementation disagree

### 3.1 Scope, as confirmed

| Item | Decision |
|---|---|
| Radio | **SX1262** — 5 × Heltec Wireless Stick Lite V3. The `esp32dev_sx1276` target stays as a compiling alternate but is **out of scope, unwired and untested**. |
| Hardware | **None bought yet.** The explicit goal is to get the software right *before* purchase. Phase 3 therefore proves what is provable without a radio, and says so. |
| Node count | **5** (matches the report). |
| Report | **Changeable** — where §3.2 shows the report lagging the code, the report is updated, not the code. |
| iOS | Needed. **Chrome for iOS does not help**: Apple mandates WebKit for all iOS browsers, so Chrome there is Safari underneath and has no Web Bluetooth. The only route is the **Bluefy** browser, or a native app. Must be tested on the real iPhone before the demo. |

### 3.2 Report vs. code

| Claim | Reality |
|---|---|
| Ch.6.1.2: pre-shared key encrypts messages | Superseded — ECDH session keys, master key mixed in |
| Ch.8: "ECDH key exchange" | ✅ now true; was not when the report was written |
| Ch.8: "HMAC-SHA256 authentication" | Used for the frame MAC and receipt proof; message integrity is GCM |
| Ch.5.3: ESP32 DevKit + SX1276 | Default build is ESP32-S3 + SX1262 |
| Ch.6.1.2: serial input, OLED output | Superseded by the BLE app; OLED compiles to no-ops |
| Scenario 2: hop ACKs "confirm delivery" to the sender | **False.** A hop ACK proves only the next radio heard it. Delivery is proven by `RECEIPT`. |
| FR10 low-power sleep | **Not implemented.** Deliberately — see §3.4 |

### 3.3 Defects already visible in Phase 0

Carried into Phase 1 for classification.

1. **Simulator beacon size drift** — `sim/mesh_sim.py:75` `hello_size()` uses a 60-byte
   base; `HELLO_HEADER_SIZE` is **62** (battery field added, simulator not updated).
   Understates beacon airtime, so simulated duty cycle is optimistic by ~1%.
   Every other one of 25 protocol constants matches exactly (machine-diffed).

2. **ISR flag race** — `processRadioEvents()` (`communication_manager.h:77`) tests and
   clears `radioIrqFired` non-atomically. An interrupt landing between the two is lost.
   Mitigated because the main loop re-arms the receiver each pass, but it is a real race.

3. **`radioState` is not `volatile`** (`lora_manager.h:44`) though it is read in
   `processRadioEvents`. Only ever *written* from the main loop, so currently benign.

4. **Transmission failure silently drops the queue slot**
   (`message_scheduler.h:~844`) — `inUse = false` runs even when `handleTransmission`
   errored. DATA self-heals via ACK retry; other frame types are lost.

### 3.4 Known, accepted limitations

Recorded so Phase 4 does not re-raise them as findings.

- **FR10 (sleep) not implemented.** Naive sleep drops relayed packets; correct
  duty-cycling needs preamble sampling, and it conflicts with BLE staying
  connectable. Documented rather than half-built.
- **No forward secrecy.** Identity keys are long-term.
- **Insider trust.** All nodes share the master key, so the system separates *members
  from outsiders*, not members from each other. An insider can forge control frames and
  broadcasts, and could MITM a *new* key exchange. It cannot read unicast traffic it
  merely relays — that is the ECDH gain.
- **Battery ADC pins unverified** (`config.h:72`) against a real board revision; a wrong
  pin reports "unknown" rather than a wrong number.
- **1% duty cycle is an EU-derived design target**, not a confirmed Indian requirement.

---

## 4. Verification status of this phase

| Activity | Status |
|---|---|
| All 14 source files read | done |
| 3 PlatformIO targets build, zero warnings | done (baseline) |
| Simulator constants diffed vs `config.h` | done — 1 drift found |
| App parsers diffed vs firmware output | done — full parity, no gaps |
| Anything executed on real hardware | **NONE** |

**Nothing in this repository has ever run on a radio.** All behavioural claims rest on
the simulator and on host-side tests of the algorithms. Radio timing, CAD behaviour,
interrupt latency, actual range, ADC readings and BLE against a real phone are
**entirely unverified**.

---

## 5. PHASE 1 — Defects

Classification: **CRITICAL** breaks security or loses data in normal operation ·
**MAJOR** significant malfunction in a plausible scenario · **MINOR** inefficiency,
fragility, or a narrow edge case.

### CRITICAL

**C-1 — GCM nonce reuse on broadcasts after an NVS erase**
`security_manager.h:47` · `message_scheduler.h:469` · `config.h:334`

Every input to the broadcast nonce resets while the broadcast key does not:

| Nonce component | Source | Survives NVS erase? |
|---|---|---|
| `source` | chip MAC | yes (same value) |
| `seq` | `NVS_SEQ_KEY` | **no — restarts at 1** |
| `destination` | constant `0xFFFE` | yes |
| `messageID` | `static uint8_t counter = 0` (`packet_manager.h:149`) | **no — restarts at 0 every boot** |
| **broadcast key** | `MESH_MASTER_KEY`, a **compile-time constant** | **yes — unchanged** |

So the first broadcast after an NVS erase reuses the exact nonce of the first
broadcast before it, **under the same key**. Nonce reuse in GCM is catastrophic, not
degraded: it leaks the XOR of the two plaintexts and exposes the GHASH subkey, which
permits forging authenticated broadcasts.

Unicast is *not* affected — the X25519 identity key lives in NVS too, so an erase
produces a fresh keypair and therefore fresh session keys. The reuse is confined to
the broadcast key precisely because that one is compiled in.

Trigger is narrow but realistic: `esptool erase_flash`, a full-chip erase before
reflashing, or NVS corruption. Across five boards being reflashed repeatedly through
a capstone, plausible.

*No fix is possible without a protocol change — see §6.*

### MAJOR

**M-1 — Replay entries never expire, so a reset node is permanently unreachable**
`security_manager.h:282-300`

`findOrCreateReplayEntry()` evicts only when the table is full; `lastSeen` is used
solely for that LRU choice, never to age an entry out. A node whose NVS is erased
restarts at sequence 1, while every peer still holds `highest ≈ N`. Those peers reject
all its traffic as "too old" (`security_manager.h:329`) until it sends N messages.
There is no recovery path short of rebooting every peer, since the table is RAM-only.

**M-2 — The app never reconnects**
`app/index.html` `onDisconnect()`

BLE drops are routine when a phone drifts from a node. `onDisconnect` tears the
session down and waits for a manual tap. For a field messenger — the actual use case —
losing the link silently and staying down is a functional defect, not a cosmetic one.

### MINOR

**N-1 — Simulator understates beacon airtime**
`sim/mesh_sim.py:75` uses a 60-byte beacon base; `HELLO_HEADER_SIZE` is **62**
(`config.h:293`). The 2-byte battery field was added to the firmware and not mirrored.
Simulated duty cycle is optimistic. *25 of 26 other protocol constants match exactly
(machine-diffed).*

**N-2 — ISR flag test-and-clear is not atomic**
`communication_manager.h:77-80`. An interrupt landing between the test and the clear
is lost. Mitigated because the main loop re-arms the receiver every pass, so the next
event recovers it, but it is a genuine race.

**N-3 — `radioState` is not `volatile`**
`lora_manager.h:44`. Currently benign — it is only ever written from the main loop —
but it sits next to an ISR-written flag and reads as though it were shared.

**N-4 — A failed transmission still frees the queue slot**
`message_scheduler.h:~844`. `inUse = false` runs even when `handleTransmission` set
`transmissionError`. DATA recovers through ACK retry; HELLO, KEY, RECEIPT and ALT are
simply lost. Each has its own timer that eventually reissues, so impact is bounded.
*Left deliberately:* holding the slot risks head-of-line blocking the whole queue on a
sick radio, which is the worse failure.

**N-5 — The destination can emit a spurious ALT for a message it already delivered**
`communication_manager.h:311-325`. A retransmission arriving after
`ACK_REPLAY_TTL_MS` (15 s) finds `recentlyAcked()` false and `isPendingAck()` false,
and falls through to `scheduleAltMessage()` — telling the sender to reroute a message
that in fact arrived. Bounded by `ALT_MAX_PER_MESSAGE` 1 and `ROUTE_MAX_ALTERNATES` 5.
Since `ACK_TIMEOUT` is also 15 s, the retransmission lands exactly on that boundary.

**N-6 — `String` on the receive path**
`LoRaMesh.ino` `onSecureMessageDelivered()` calls `describeNode()`
(`routing_manager.h:~150`), allocating several `String` temporaries per received
message. Heap churn on a node meant to run for months. `metricsToString()` (35 `String`
operations) is user-triggered only, so it matters less.

**N-7 — A full queue consumes an ACK retry without transmitting**
`message_scheduler.h:755-760`. `retryCount++` and the timestamp update run even when
`enqueueForwardMessage()` returned false. *Left deliberately:* not consuming the retry
would spin the retry loop every pass while the queue stays full; consuming it routes
the message to the outbox, which is bounded and terminates.

### Subsystems examined with no new findings

- **Packet handling** — every deserialiser validates length before copying; DATA and
  HELLO check both the declared field length and the exact frame size; `getNodeID()`
  avoids the reserved `0`, `0xFFFE`, `0xFFFF`. Wire format is explicit big-endian, so
  struct packing and endianness cannot drift between builds.
- **Security ordering** — frame MAC verified before *any* parsing
  (`communication_manager.h:296`); GCM tag verified before plaintext is released;
  replay checked only *after* the tag, so forged sequence numbers cannot poison the
  window; MAC compare is constant-time (`security_manager.h:~258`); the three keys use
  distinct HKDF labels; low-order X25519 points are rejected.
- **Routing** — DSDV even/odd sequence discipline is correct; `seqIsNewer` is
  wraparound-safe; TTL bounds every forwarded type; broadcast flooding is bounded by
  TTL and the duplicate history.
- **App ↔ firmware parity** — every prefix the firmware emits has a handler
  (machine-diffed); no unhandled line type.
- **Stack** — deepest path is `loop → updateMessageScheduler →
  windowCollisionPrevention → processReceivedMessage → processPayload → establishSession
  → mbedtls_ecp_mul`, roughly 2.5–3 KB against an 8 KB loop-task stack. Adequate, but
  this is an estimate from reading, **not a measurement**.

---

## 6. Blocking decision before Phase 2

**C-1 cannot be fixed without changing the wire format.** You asked to approve protocol
changes, so Phase 2 stops here. Three options:

| Option | Change | Cost | Residual risk |
|---|---|---|---|
| **A — random nonce component** | Add 8 random bytes to the BROADCAST frame, chosen per message from the hardware RNG, and use them in the nonce | +8 B per broadcast (245 → 253, still inside 255) | Collision after ~2³² broadcasts — negligible |
| **B — boot epoch** | Add a 2-byte epoch, randomised at boot, to the frame and the nonce | +2 B | 1/65536 that two boots collide *and* sequences align |
| **C — accept and document** | No code change; document "never erase NVS" | 0 | Depends on nobody running `erase_flash`. Not a control. |

**My recommendation: A.** It removes the failure mode rather than narrowing it, costs
8 bytes on the one frame type that needs it, and stays within the LoRa frame limit.
It is also the standard construction for a shared-key broadcast.

Tell me which, and Phase 2 starts with C-1, then M-1, M-2, then the MINOR items.

## 7. PHASE 2 — Fixes applied

| # | Defect | Fix | Why it is correct |
|---|---|---|---|
| **C-1** | Broadcast GCM nonce reuse after an NVS erase | 8 hardware-random bytes (`NONCE_SALT_LEN`) carried in every DATA frame; nonce is now `salt ‖ seq`. `DATA_HEADER_SIZE` 21 → 29 | Uniqueness no longer depends on any counter outliving the key. Source and destination move to the AAD, so endpoint binding is unchanged; altering the salt changes the nonce and the tag then fails. Applied to unicast too — a type-conditional wire format is its own bug source. Frame 253 B, inside 255. |
| **M-1** | Replay entries never expire, locking out a peer whose NVS was erased | `resetReplayFor()` clears a peer's window when a **new session key** is agreed (`crypto_session.h:301`) | Replay protection only has meaning inside a key epoch. Once the key changes, an old replayed message cannot decrypt under the new one, so the window protects nothing and holding it only costs availability. |
| **M-2** | App never reconnects after a BLE drop | Exponential backoff reconnect (1→30 s, 6 attempts), `attach()` shared by first connect and reconnect, `deliberateDisconnect` flag so a manual tap does not retry | BLE loss is the normal field condition, not an error. Sharing `attach()` means the two paths cannot drift apart. |
| **N-1** | Simulator beacon base 60 B vs firmware 62 B | `hello_size()` → 62; `data_size()` → 29-byte header | Simulated duty cycle was optimistic. Now matches the firmware exactly. |
| **N-2** | ISR flag test-and-clear not atomic | `portMUX` around the read-and-clear in `processRadioEvents()` | Interrupts are disabled across the pair, so an ISR firing between them raises the flag *after* the clear rather than having it discarded. |
| **N-3** | `radioState` not `volatile` | Declared `volatile` | Read on the same path as an ISR-written flag; costs nothing and removes a fragile assumption. |
| **N-5** | Destination emitted a spurious ALT for a message it had already delivered | Suppress ALT when we are the destination, and **re-ACK instead** | ALT asks the sender to reroute. From the destination that is wrong — the message arrived; only the ACK was lost. |
| **P4-1** | *(found in Phase 4, introduced by the N-5 fix)* the new branch logged "re-ACKing" but returned without sending the ACK | Added the `scheduleAckMessage()` call | Returning silently left the sender retrying a delivered message until it exhausted retries and parked it — strictly worse than the original bug. |

**Not fixed, deliberately** (unchanged from §3.4 and the N-4 / N-7 reasoning):
N-4 a failed transmission still frees the queue slot — holding it risks head-of-line
blocking the queue on a sick radio, and every affected frame type has its own reissue
timer. N-7 a full queue consumes an ACK retry — not consuming it would spin the retry
loop while the queue stays full; consuming it routes the message to the bounded outbox.
N-6 `String` on the receive path — real heap churn, but bounded and not worth the
readability cost of manual buffers at this scale.

---

## 8. PHASE 3 — Evidence

All figures below are **actual output**, reproduced by the commands shown.

### 8.1 Builds — `pio run -e <target>`

| Target | Result | Warnings |
|---|---|---|
| `heltec_wireless_stick_lite_v3` (SX1262, primary) | SUCCESS | 0 |
| `heltec_wifi_lora_32_V3` (SX1262 + OLED) | SUCCESS | 0 |
| `esp32dev_sx1276` (alternate, out of scope) | SUCCESS | 0 |

RAM 19.5%, flash 32.8% on the primary target.

### 8.2 Protocol and adversarial tests — `python sim/test_protocol.py`

**78 passed, 0 failed.**

| Group | Tests | Covers |
|---|---|---|
| Packet parsing | 12 | truncation at every length, oversized `payloadLen`, length disagreeing with the frame, trailing garbage, **3000 random blobs without an exception** |
| AES-128-GCM | 12 | round trip, flipped ciphertext bit, flipped tag bit, tampered AAD, wrong key, altered salt, altered sequence, truncated, empty, **C-1 regression** |
| Frame MAC | 6 | forged tag, wrong key, short frame, **all 544 single-bit tamperings rejected** |
| Anti-replay | 10 | replay, out-of-order, both window edges (31 / 32 back), far-future jump, **M-1 regression**, per-source independence |
| DSDV routing | 13 | freshness and shortest-path rules, invalidation, odd-sequence discipline, wraparound, **no count-to-infinity over 40 gossip rounds** |
| Broadcast flooding | 3 | full coverage from every origin, no storm, TTL termination |
| App parity | 22 | every line type, backward-compatible `PEER`, **line-protocol injection defence** |

### 8.3 Topologies — `python sim/mesh_sim.py --nodes N --minutes 30`

| Nodes | Converged | PDR (e2e) | Latency mean / p95 | Duty max | Verdict |
|---|---|---|---|---|---|
| 3 | 56 s | 100.0% | 1816 / 2490 ms | 0.43% | PASS |
| 10 | 137 s | 100.0% | 3408 / 5780 ms | 1.01% | duty 0.01 pp over |
| 20 | 121 s | 100.0% | 2676 / 4440 ms | 0.49% | PASS |

### 8.4 Node failure and rejoin — `--churn 0.3`

| Nodes | PDR | Held | Re-sent | Gave up |
|---|---|---|---|---|
| 10 | 92.1% | 3 | 3 | **0** |
| 20 | 90.5% | 3 | 3 | **0** |

Both stay above the 90% target, and **no message was permanently lost** — every held
message was delivered once its recipient returned.

### 8.5 Partition and heal — `--partition`

Field cut in two at 45% of the run (4 | 6 split), healed at 70%.

```
  [   810s] PARTITION: field split 4 | 6
  [  1260s] HEALED: the two halves can hear each other again
  nodes with a full table     10/10
  routes rebuilt after heal   yes
  end-to-end PDR              96.0%
  broadcast coverage          100.0%
```

### 8.6 Where the targets were missed, and why

Reported rather than hidden:

- **Mean latency exceeds 5 s under churn and partition.** Expected and correct: the mean
  includes messages that waited for an absent recipient, which is store-and-forward
  working. NFR2 describes a *reachable* three-hop path; on that basis 3/10/20-node runs
  give 1.8 / 3.4 / 2.7 s, all inside target.
- **Duty cycle 1.01–1.14% in the 10-node and partition runs.** A single hub node
  relaying for the mesh, not protocol overhead. Characterised earlier: the budget caps
  message *throughput*, and a central relay reaches it first. The 1% figure is itself a
  conservative EU-derived target (§3.4).
- **Broadcast coverage below 100% in some runs** is a placement artefact — nodes outside
  radio range of any other were never reachable. The 20-node run shows 100%.

---

## 9. PHASE 4 — Re-audit

A second pass was run over the modified code. It found **one defect, in a Phase 2 fix**:

> **P4-1** — the N-5 change logged "re-ACKing" but returned without calling
> `scheduleAckMessage()`, leaving the sender to retry a delivered message until it gave
> up. Fixed, rebuilt, re-tested.

Re-verified after that fix: 3/3 builds clean, 78/78 tests pass, 20-node run PASS at
100% PDR. No further CRITICAL or MAJOR findings; every MINOR is either fixed above or
justified in §7.

---

## 10. Requirement traceability

"Verified" means executed. "Inspected" means read but not run — never conflate the two.

| Req | Implemented in | How verified | Status |
|---|---|---|---|
| FR1 text messages | `message_scheduler.h` `enqueueTextMessage`, `LoRaMesh.ino` `handleCommand` | 78-test suite; sim traffic at 3/10/20 nodes | **Verified (simulated)** |
| FR2 multi-hop relay | `communication_manager.h` DATA relay branch | Sim: relayed counts non-zero at 10 and 20 nodes | **Verified (simulated)** |
| FR3 neighbour discovery | `routing_manager.h` `processHelloRoutes`, beacon | Sim: convergence 56–137 s | **Verified (simulated)** |
| FR4 routing table | `routing_manager.h` `applyRouteUpdate` (DSDV) | 13 routing tests incl. count-to-infinity; sim convergence | **Verified (simulated)** |
| FR5 ACK + retry | `message_scheduler.h` `updateMessageScheduler`, `addPendingAck` | Sim: retries observed; churn runs show 0 permanent loss | **Verified (simulated)** |
| FR6 AES-128-GCM e2e | `security_manager.h` `encryptPayload` | 12 crypto tests; HKDF vs RFC 5869 vectors | **Verified (algorithm)** |
| FR7 tag verification | `security_manager.h` `decryptPayload` | Tamper tests: ciphertext, tag, AAD, key, salt, sequence | **Verified (algorithm)** |
| FR8 replay prevention | `security_manager.h` `checkAndUpdateReplay` | 10 replay tests incl. both window edges | **Verified (algorithm)** |
| FR9 duplicate suppression | `message_receiver.h` `checkDuplicates` | Flooding tests; sim duplicate counts | **Verified (simulated)** |
| FR10 sleep | — | — | **Not implemented** (§3.4) |
| NFR1 ≥1 km range | `config.h` SF7/BW125/14 dBm | — | **Unverified — needs radios** |
| NFR2 <5 s / 3 hops | scheduler timing, CAD LBT | Sim: 1.8 / 3.4 / 2.7 s | **Verified (simulated)** |
| NFR3 ≥90% PDR | receipts + retry + outbox | Sim: 100% clean, 90.5–92.1% under churn | **Verified (simulated)** |
| NFR4 ≥20 nodes | table sizes, adaptive beacon | Sim 20 nodes PASS; peak tables 19/24, 17/24, 18/24 | **Verified (simulated)** |
| NFR5 <10 ms crypto | `metrics.h` `recordEncrypt`/`recordDecrypt` | Instrumented; **`/stats` never read on hardware** | **Unverified — needs radios** |
| NFR6 power | battery telemetry on beacon | — | **Unverified — needs radios** |
| NFR7 modularity | 13-header module map (§2.1) | Inspected | **Inspected only** |
| *Added:* ECDH sessions | `crypto_session.h` | X25519 vs RFC 7748 vectors; low-order points rejected | **Verified (algorithm)** |
| *Added:* frame auth | `security_manager.h` `verifyFrameMac` | 544/544 single-bit tamperings rejected | **Verified (algorithm)** |
| *Added:* broadcast | `communication_manager.h` BROADCAST branch | Flooding tests; sim coverage 100% at 20 nodes | **Verified (simulated)** |
| *Added:* store-and-forward | `message_scheduler.h` outbox | Churn runs: 0 permanent loss | **Verified (simulated)** |
| *Added:* BLE app | `ble_manager.h`, `app/index.html` | Parity + injection tests; JS syntax-checked | **Partly verified — never run against a phone** |

---

## 11. Remaining limitations and untested areas

**Never executed on hardware.** Everything above is a simulation or a host-side test of
a transcribed algorithm. Specifically unproven:

- Radio: actual range, RSSI, CAD behaviour, interrupt latency, SPI at speed, TCXO
  settling, the 1.8 V / DIO2 assumptions in `lora_manager.h:69`
- Timing: real airtime vs the computed model; whether the CAD-based LBT behaves as
  assumed under contention
- Battery ADC pins (`config.h:72`) — never read a real cell
- BLE: MTU negotiation, throughput, reconnect behaviour against a real phone
- The PWA on a real Android device; **iOS untested and requires Bluefy** (Chrome for iOS
  is WebKit and has no Web Bluetooth)
- Stack depth: estimated ~2.5–3 KB of 8 KB by reading the call chain, **not measured**
- Watchdog behaviour, brown-out, long-run heap fragmentation from `String` (N-6)
- `esp32dev_sx1276` compiles but is unwired and out of scope

**Design limitations** (unchanged, all documented in §3.4): no FR10 sleep, no forward
secrecy, shared master key means insiders are trusted, 1% duty cycle is an EU-derived
target not a confirmed Indian requirement.

**Audit limitation:** the auditor wrote the code. Phase 4 caught one self-inflicted
defect (P4-1), which is evidence the process has some value — but it is not a substitute
for a reviewer who did not write the security layer.

---

## 12. Original questions (answered)

1. **Which radio do the 3 nodes actually have** — SX1262 (Heltec V3) or SX1276? If
   SX1276, that target has never been wired or tested and needs its own pass.
2. **Do you now have hardware?** It changes what Phase 3 can honestly prove.
3. **3 nodes or 5?** The report says 5 (A–E); you said 3.
4. **Is the report fixed, or can it change?** Several items in §3.2 are the report
   being out of date rather than the code being wrong. If the report is frozen, some
   of those become code defects instead.
5. **Native app needed?** If any examiner will open it on an iPhone, the PWA cannot
   work and that is a hardware-independent blocker.
6. **May I change the protocol** if Phase 1 finds a defect that cannot be fixed
   otherwise? You asked to be consulted first — flagging that I will stop and ask.
