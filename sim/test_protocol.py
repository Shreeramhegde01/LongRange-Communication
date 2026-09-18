#!/usr/bin/env python3
"""
Protocol conformance and adversarial test suite.

Each test transcribes the algorithm from the firmware header named beside it and
exercises it with valid, malformed and hostile input. This proves the *protocol
and its algorithms* are correct; it does not execute the C++ (see AUDIT.md §4).

    python test_protocol.py
"""

import hashlib
import hmac
import os
import struct
import sys

PASS, FAIL = [], []


def check(group, name, ok, detail=""):
    (PASS if ok else FAIL).append(f"{group}: {name}")
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail and not ok else ""))


# =====================================================================
# 1. Packet parsing — packet_manager.h
# =====================================================================
DATA_HEADER_SIZE = 29
GCM_TAG_LEN = 16
MAX_TEXT_LEN = 200
NONCE_SALT_LEN = 8
MAX_PACKET = 255


def deserialize_data(buf):
    """Transcription of deserializeDataPacket()."""
    if len(buf) < DATA_HEADER_SIZE + GCM_TAG_LEN:
        return None
    payload_len = buf[20]
    if payload_len > MAX_TEXT_LEN:
        return None
    if len(buf) != DATA_HEADER_SIZE + payload_len + GCM_TAG_LEN:
        return None
    return {
        "type": buf[0],
        "mesh": int.from_bytes(buf[1:3], "big"),
        "id": int.from_bytes(buf[3:7], "big"),
        "src": int.from_bytes(buf[11:13], "big"),
        "dst": int.from_bytes(buf[13:15], "big"),
        "seq": int.from_bytes(buf[15:19], "big"),
        "ttl": buf[19],
        "len": payload_len,
        "salt": buf[21:29],
    }


def build_data(payload_len=40, declared=None, total=None):
    declared = payload_len if declared is None else declared
    buf = bytearray(DATA_HEADER_SIZE + payload_len + GCM_TAG_LEN)
    buf[0] = 1
    buf[1:3] = (0x1234).to_bytes(2, "big")
    buf[20] = declared
    buf[21:29] = os.urandom(8)
    if total is not None:
        buf = buf[:total] if total < len(buf) else buf + bytes(total - len(buf))
    return bytes(buf)


def test_packet_parsing():
    print("\n1. Packet parsing (packet_manager.h) — malformed and hostile frames")
    check("parse", "well-formed frame accepted", deserialize_data(build_data(40)) is not None)
    check("parse", "empty payload accepted", deserialize_data(build_data(0)) is not None)
    check("parse", "maximum payload accepted", deserialize_data(build_data(MAX_TEXT_LEN)) is not None)

    check("parse", "zero-length frame rejected", deserialize_data(b"") is None)
    check("parse", "single byte rejected", deserialize_data(b"\x01") is None)
    for n in range(1, DATA_HEADER_SIZE + GCM_TAG_LEN):
        if deserialize_data(build_data(40, total=n)) is not None:
            check("parse", f"truncated to {n} bytes rejected", False)
            break
    else:
        check("parse", "every truncation below the minimum rejected", True)

    check("parse", "oversized payloadLen (201) rejected",
          deserialize_data(build_data(40, declared=201)) is None)
    check("parse", "payloadLen 255 rejected",
          deserialize_data(build_data(40, declared=255)) is None)
    check("parse", "payloadLen disagreeing with frame size rejected",
          deserialize_data(build_data(40, declared=39)) is None)
    check("parse", "trailing garbage rejected",
          deserialize_data(build_data(40) + b"\x00" * 4) is None)

    longest = DATA_HEADER_SIZE + MAX_TEXT_LEN + GCM_TAG_LEN + 8   # + frame MAC
    check("parse", f"longest frame is {longest} B, inside LoRa's {MAX_PACKET}",
          longest <= MAX_PACKET, f"{longest} > {MAX_PACKET}")

    # The parser must never read past what it was handed.
    survived = True
    for _ in range(3000):
        blob = os.urandom(int.from_bytes(os.urandom(1), "big") % 120)
        try:
            deserialize_data(blob)
        except Exception:
            survived = False
            break
    check("parse", "3000 random blobs parsed without exception", survived)


# =====================================================================
# 2. Crypto round-trip and tampering — security_manager.h
# =====================================================================
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_AESGCM = True
except ImportError:
    HAVE_AESGCM = False


def build_nonce(salt, seq):
    """Transcription of buildNonce() after the C-1 fix."""
    return salt + seq.to_bytes(4, "big")


def test_crypto():
    print("\n2. AES-128-GCM round trip and tampering (security_manager.h)")
    if not HAVE_AESGCM:
        print("  [SKIP] python 'cryptography' not installed — AEAD tests skipped")
        print("         install with: pip install cryptography")
        return

    key = os.urandom(16)
    salt = os.urandom(NONCE_SALT_LEN)
    seq = 42
    nonce = build_nonce(salt, seq)
    aad = bytes([1]) + (0x1234).to_bytes(2, "big") + os.urandom(13)
    text = b"north gate, bring the spare battery"

    aes = AESGCM(key)
    sealed = aes.encrypt(nonce, text, aad)
    ct, tag = sealed[:-16], sealed[-16:]

    check("crypto", "round trip recovers the plaintext",
          aes.decrypt(nonce, sealed, aad) == text)
    check("crypto", "ciphertext is the same length as plaintext (stream mode)",
          len(ct) == len(text))

    def rejects(n=nonce, blob=sealed, a=aad, k=aes):
        try:
            k.decrypt(n, blob, a)
            return False
        except Exception:
            return True

    bad = bytearray(sealed); bad[0] ^= 1
    check("crypto", "flipped ciphertext bit rejected", rejects(blob=bytes(bad)))
    bad = bytearray(sealed); bad[-1] ^= 1
    check("crypto", "flipped tag bit rejected", rejects(blob=bytes(bad)))
    bad = bytearray(aad); bad[0] ^= 1
    check("crypto", "tampered AAD rejected (header binding holds)", rejects(a=bytes(bad)))
    check("crypto", "wrong key rejected", rejects(k=AESGCM(os.urandom(16))))
    check("crypto", "altered nonce salt rejected",
          rejects(n=build_nonce(bytes(x ^ 1 for x in salt), seq)))
    check("crypto", "altered sequence number rejected", rejects(n=build_nonce(salt, seq + 1)))
    check("crypto", "truncated ciphertext rejected", rejects(blob=sealed[:-1]))
    check("crypto", "empty blob rejected", rejects(blob=b""))

    # C-1 regression: a reset counter must no longer reproduce a nonce.
    def boot(n):
        return {build_nonce(os.urandom(NONCE_SALT_LEN), 1 + i) for i in range(n)}
    check("crypto", "C-1: nonce survives an NVS erase (counters restart)",
          not (boot(50) & boot(50)))

    seen, dupes = set(), 0
    for _ in range(200):
        for i in range(50):
            n = build_nonce(os.urandom(NONCE_SALT_LEN), 1 + i)
            dupes += n in seen
            seen.add(n)
    check("crypto", "10 000 nonces across 200 simulated erases are unique", dupes == 0)


# =====================================================================
# 3. Frame MAC — security_manager.h
# =====================================================================
MAC_LEN = 8


def test_frame_mac():
    print("\n3. Link-layer frame authentication (security_manager.h)")
    key = os.urandom(32)
    mac = lambda body: hmac.new(key, body, hashlib.sha256).digest()[:MAC_LEN]

    body = os.urandom(60)
    frame = body + mac(body)

    def accepts(f):
        return len(f) > MAC_LEN and hmac.compare_digest(mac(f[:-MAC_LEN]), f[-MAC_LEN:])

    check("mac", "genuine frame accepted", accepts(frame))
    check("mac", "frame shorter than the tag rejected", not accepts(b"\x01" * MAC_LEN))
    check("mac", "empty frame rejected", not accepts(b""))
    check("mac", "forged tag rejected", not accepts(body + b"\x00" * MAC_LEN))
    check("mac", "wrong key rejected",
          not hmac.compare_digest(
              hmac.new(os.urandom(32), body, hashlib.sha256).digest()[:MAC_LEN],
              frame[-MAC_LEN:]))

    rejected = sum(
        not accepts(bytes(f))
        for i in range(len(frame))
        for bit in range(8)
        for f in [bytearray(frame)]
        if (f.__setitem__(i, f[i] ^ (1 << bit)) or True)
    )
    total = len(frame) * 8
    check("mac", f"all {total} single-bit tamperings rejected", rejected == total,
          f"only {rejected}/{total}")


# =====================================================================
# 4. Anti-replay window — security_manager.h
# =====================================================================
WINDOW = 32


class Replay:
    """Transcription of checkAndUpdateReplay() and resetReplayFor()."""

    def __init__(self):
        self.entries = {}

    def reset(self, src):
        self.entries.pop(src, None)

    def check(self, src, seq):
        e = self.entries.get(src)
        if e is None:
            self.entries[src] = {"hi": seq, "bits": 1}
            return True
        if seq > e["hi"]:
            shift = seq - e["hi"]
            e["bits"] = 0 if shift >= WINDOW else (e["bits"] << shift) & 0xFFFFFFFF
            e["bits"] |= 1
            e["hi"] = seq
            return True
        behind = e["hi"] - seq
        if behind >= WINDOW or (e["bits"] & (1 << behind)):
            return False
        e["bits"] |= 1 << behind
        return True


def test_replay():
    print("\n4. Anti-replay window (security_manager.h)")
    S = 21087

    r = Replay()
    check("replay", "ascending sequence accepted",
          all(r.check(S, i) for i in range(1, 40)))

    r = Replay(); r.check(S, 10)
    check("replay", "immediate replay rejected", not r.check(S, 10))

    r = Replay()
    for s in (5, 3, 4):
        r.check(S, s)
    check("replay", "out-of-order delivery accepted once", not r.check(S, 3))

    r = Replay(); r.check(S, 40)
    check("replay", "edge of window (31 back) accepted", r.check(S, 9))
    r = Replay(); r.check(S, 40)
    check("replay", "just outside window (32 back) rejected", not r.check(S, 8))

    r = Replay(); r.check(S, 100)
    check("replay", "far-future jump accepted (NVS block reservation)", r.check(S, 5000))
    check("replay", "stale message after a jump rejected", not r.check(S, 100))

    # M-1 regression: a peer that restarts at 1 must recover on rekey.
    r = Replay()
    for i in range(1, 500):
        r.check(S, i)
    check("replay", "M-1: peer restarting at seq 1 is blocked before rekey",
          not r.check(S, 1))
    r.reset(S)
    check("replay", "M-1: rekey clears the window and the peer is heard again",
          r.check(S, 1))

    r = Replay()
    for i in range(30):
        r.check(1000 + i, 1)
    check("replay", "windows are independent per source",
          all(not r.check(1000 + i, 1) for i in range(30)))


# =====================================================================
# 5. Routing decisions — routing_manager.h
# =====================================================================
INF = 255


def seq_newer(a, b):
    return ((a - b + 32768) % 65536) - 32768 > 0


class Router:
    """Transcription of applyRouteUpdate() and invalidateRoutesVia()."""

    def __init__(self, node_id):
        self.id = node_id
        self.routes = {}

    def apply(self, dest, via, adv_hops, seq):
        if dest in (0, self.id):
            return
        hops = INF if adv_hops >= INF - 1 else adv_hops + 1
        e = self.routes.get(dest)
        if e is None:
            if hops < INF:
                self.routes[dest] = {"next": via, "seq": seq, "hops": hops}
            return
        if (seq_newer(seq, e["seq"])
                or (seq == e["seq"] and hops < e["hops"])
                or (seq == e["seq"] and e["next"] == via and hops != e["hops"])):
            e.update(next=via, seq=seq, hops=hops)

    def invalidate_via(self, gone):
        for r in self.routes.values():
            if r["next"] == gone and r["hops"] < INF:
                r["hops"] = INF
                r["seq"] = (r["seq"] + 1) & 0xFFFF


def test_routing():
    print("\n5. DSDV routing decisions (routing_manager.h)")
    r = Router(1)

    r.apply(5, 2, 0, 10)
    check("route", "new destination learned", r.routes[5]["hops"] == 1)

    r.apply(5, 3, 3, 10)
    check("route", "same sequence, longer path rejected", r.routes[5]["next"] == 2)

    r.apply(5, 3, 0, 12)
    check("route", "newer sequence wins even via a different hop",
          r.routes[5]["next"] == 3 and r.routes[5]["seq"] == 12)

    r.apply(5, 4, 0, 8)
    check("route", "older sequence rejected", r.routes[5]["seq"] == 12)

    r.apply(5, 3, 4, 12)
    check("route", "current next hop may revise its own cost upward",
          r.routes[5]["hops"] == 5)

    r.apply(1, 2, 0, 99)
    check("route", "route to self ignored", 1 not in r.routes)
    r.apply(0, 2, 0, 99)
    check("route", "route to node 0 ignored", 0 not in r.routes)

    r2 = Router(1); r2.apply(5, 2, 0, 10)
    r2.invalidate_via(2)
    check("route", "link break marks the route unreachable", r2.routes[5]["hops"] == INF)
    check("route", "link break makes the sequence odd (DSDV invalidation)",
          r2.routes[5]["seq"] % 2 == 1)

    r2.apply(5, 3, 0, 10)
    check("route", "stale reachable route cannot undo an invalidation",
          r2.routes[5]["hops"] == INF)
    r2.apply(5, 3, 0, 12)
    check("route", "destination's own fresh sequence restores it",
          r2.routes[5]["hops"] == 1)

    check("route", "sequence comparison is wraparound-safe",
          seq_newer(2, 65535) and not seq_newer(65535, 2))

    # Count-to-infinity: two nodes gossiping about a destination that vanished.
    a, b = Router(1), Router(2)
    a.apply(9, 2, 0, 20); b.apply(9, 1, 0, 20)
    a.invalidate_via(2)
    for _ in range(40):
        for d, e in list(b.routes.items()):
            a.apply(d, 2, e["hops"], e["seq"])
        for d, e in list(a.routes.items()):
            b.apply(d, 1, e["hops"], e["seq"])
    metric = a.routes[9]["hops"]
    check("route", "no count-to-infinity after 40 gossip rounds", metric >= INF,
          f"metric crept to {metric}")


# =====================================================================
# 6. Broadcast flooding — communication_manager.h
# =====================================================================
def test_flooding():
    print("\n6. Broadcast flooding (communication_manager.h)")

    def flood(links, origin, ttl=4, nodes=None):
        nodes = nodes or sorted({n for l in links for n in l})
        seen, tx, delivered = {origin}, 1, set()
        frontier = [(origin, ttl)]
        while frontier:
            nxt = []
            for sender, rem in frontier:
                for a, b in links:
                    peer = b if a == sender else (a if b == sender else None)
                    if peer is None or peer in seen:
                        continue
                    seen.add(peer); delivered.add(peer)
                    if rem - 1 > 0:
                        tx += 1
                        nxt.append((peer, rem - 1))
            frontier = nxt
        return delivered, tx, nodes

    mesh = [("A", "C"), ("C", "B"), ("A", "D"), ("D", "B"), ("B", "E")]
    allok, txok = True, True
    for origin in "ABCDE":
        d, tx, nodes = flood(mesh, origin)
        allok &= d == set(nodes) - {origin}
        txok &= tx <= len(nodes)
    check("flood", "every node reached from every origin", allok)
    check("flood", "transmissions never exceed the node count (no storm)", txok)

    chain = [("A", "B"), ("B", "C"), ("C", "D"), ("D", "E")]
    d, _, _ = flood(chain, "A", ttl=2)
    check("flood", "TTL bounds the spread and terminates", d == {"B", "C"})


# =====================================================================
# 7. App protocol parity — app/index.html
# =====================================================================
import re

APP_PATTERNS = {
    "MSG": re.compile(r"^MSG (\d+) (\S*): ([\s\S]*)$"),
    "BCAST": re.compile(r"^BCAST (\d+) (\S*): ([\s\S]*)$"),
    "QUEUED": re.compile(r"^QUEUED (\d+) (\d+)$"),
    "DELIVERED": re.compile(r"^DELIVERED (\d+) (\d+)$"),
    "HELD": re.compile(r"^HELD (\d+) (\d+)$"),
    "EXPIRED": re.compile(r"^EXPIRED (\d+) (\d+)$"),
    "PEER": re.compile(r"^PEER (\d+) (\S+) (\d+) (-?\d+) ([01])(?: (\d+))?$"),
    "ID": re.compile(r"^ID (\d+) (.*)$"),
}


def sanitize_name(n):
    return "".join("_" if (ord(c) <= 0x20 or ord(c) >= 0x7F) else c for c in n[:15])


def sanitize_line(t):
    return "".join(" " if (ord(c) < 0x20 or ord(c) == 0x7F) else c for c in t)


def test_app_parity():
    print("\n7. App protocol parity and injection defence (LoRaMesh.ino / index.html)")
    samples = {
        "MSG": "MSG 21087 Rakshith: north gate",
        "BCAST": "BCAST 10412 BaseCamp: evacuate sector 4",
        "QUEUED": "QUEUED 16852993 21087",
        "DELIVERED": "DELIVERED 16852993 21087",
        "HELD": "HELD 16852993 21087",
        "EXPIRED": "EXPIRED 16852993 21087",
        "PEER": "PEER 21087 Rakshith 2 -71 1 87",
        "ID": "ID 61039 Relay-1",
    }
    for k, line in samples.items():
        check("app", f"{k} line parses", APP_PATTERNS[k].match(line) is not None)

    check("app", "PEER without the battery field still parses (backward compatible)",
          APP_PATTERNS["PEER"].match("PEER 21087 Rakshith 2 -71 1") is not None)
    check("app", "message text containing a colon survives",
          APP_PATTERNS["MSG"].match("MSG 1 A: meet at 5: bring radio").group(3)
          == "meet at 5: bring radio")
    check("app", "200-character message parses",
          len(APP_PATTERNS["MSG"].match("MSG 1 A: " + "x" * 200).group(3)) == 200)

    for diag in ["=== Performance ===", "  PDR e2e     94.0%", "PEERS none",
                 "SEC REPLAY from 21087", "Routes (dest via hops):"]:
        check("app", f"diagnostic line not mistaken for structured output: {diag[:26]!r}",
              not any(p.match(diag) for p in APP_PATTERNS.values()))

    emit = lambda src, name, text: f"MSG {src} {sanitize_name(name)}: {sanitize_line(text)}"
    lines = lambda blob: [l for l in blob.split("\n") if l]

    check("app", "newline in message cannot forge DELIVERED",
          len(lines(emit(1, "Bob", "hi\nDELIVERED 9 9"))) == 1)
    check("app", "newline in message cannot forge a second MSG",
          len(lines(emit(1, "Bob", "x\nMSG 999 Admin: pay now"))) == 1)
    check("app", "newline in node name cannot forge a line",
          len(lines(emit(1, "A\nDELIVERED 1 2", "hello"))) == 1)
    check("app", "space in a name cannot break PEER field splitting",
          APP_PATTERNS["PEER"].match(f"PEER 1 {sanitize_name('Base Camp')} 2 -70 1") is not None)
    check("app", "ordinary message passes through unchanged",
          APP_PATTERNS["MSG"].match(emit(1, "Rakshith", "north gate")).group(3) == "north gate")
    check("app", "location payload passes through unchanged",
          sanitize_line("!loc:12.94150,77.56550,12") == "!loc:12.94150,77.56550,12")


# =====================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("  Secure LoRa mesh — protocol conformance and adversarial tests")
    print("=" * 70)
    test_packet_parsing()
    test_crypto()
    test_frame_mac()
    test_replay()
    test_routing()
    test_flooding()
    test_app_parity()

    print("\n" + "=" * 70)
    print(f"  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("\n  FAILURES:")
        for f in FAIL:
            print(f"    - {f}")
    print("=" * 70)
    sys.exit(1 if FAIL else 0)
