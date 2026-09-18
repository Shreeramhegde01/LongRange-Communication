#!/usr/bin/env python3
"""
Protocol-level simulator for the secure LoRa mesh.

Runs a whole mesh - 20 nodes by default - with a shared radio channel that
models airtime, range and collisions, so the protocol and its buffer sizes can
be checked at scale before any hardware is bought.

WHAT THIS DOES AND DOES NOT PROVE
---------------------------------
It reimplements the *protocol* from the firmware headers: DSDV routing,
beacon-carried distance vectors, key discovery, hop-by-hop ACK and retry,
flooded broadcast, duplicate suppression and the anti-replay window. It
therefore validates protocol behaviour, timing, channel load and whether the
table sizes in config.h are adequate.

It does NOT execute the C++ firmware, so it cannot find bugs in that code.
Cryptography is modelled only as "a session exists"; the primitives are
verified separately against RFC test vectors.

Simplifying assumptions, all pessimistic:
  * any overlap at a receiver destroys both frames - no LoRa capture effect
  * range is a hard radius, no fading or terrain
  * the listen-before-talk check is instantaneous at the transmitter

Usage:
    python mesh_sim.py                    # 20 nodes, 10 simulated minutes
    python mesh_sim.py --nodes 30 --minutes 20
    python mesh_sim.py --nodes 20 --area 3000 --range 800
"""

import argparse
import math
import random
from collections import deque

# ----------------------------------------------------------------- config.h
# Mirrors src/LoRaMesh/config.h. Keep these in step with the firmware.
SF                      = 7
BANDWIDTH_HZ            = 125_000
CODING_RATE             = 1          # 4/5
PREAMBLE                = 8

HELLO_INTERVAL_MIN_MS   = 60_000
HELLO_INTERVAL_MAX_MS   = 300_000
HELLO_AIRTIME_MULTIPLIER = 20
NEIGHBOR_EXPIRY_BEACONS = 4
ACK_TIMEOUT_MS          = 15_000
MAX_RETRIES             = 3
INITIAL_WAIT            = (200, 1_200)
DEFAULT_TTL             = 6
BROADCAST_TTL           = 4
ROUTE_INFINITY          = 255

MAX_NEIGHBORS           = 24
MAX_ROUTES              = 24
MAX_ROUTES_PER_HELLO    = 24
MAX_SESSIONS            = 24
MAX_REPLAY_SOURCES      = 24
MAX_DUPLICATE_HISTORY   = 64
MAX_QUEUE_SIZE          = 12
MAX_OUTBOX              = 8
OUTBOX_TTL_MS           = 3_600_000
MAX_OUTBOX_ATTEMPTS     = 5
OUTBOX_RETRY_INTERVAL_MS = 75_000
OUTBOX_FIRST_RETRY_MS   = 20_000

KEY_DISCOVERY_INTERVAL_MS = 3_000
KEY_REQUEST_TIMEOUT_MS    = 20_000
MAX_KEY_REQUEST_RETRIES   = 4

# Wire sizes including the 8-byte frame MAC
def hello_size(route_count):
    """Beacons carry only the routes actually held, so a small mesh sends a
    much smaller frame than the table capacity implies."""
    return 62 + min(route_count, MAX_ROUTES_PER_HELLO) * 5 + 8

SIZE_HELLO    = hello_size(MAX_ROUTES_PER_HELLO)
SIZE_ACK      = 12 + 8
SIZE_ALT      = 12 + 8
SIZE_KEY      = 16 + 32 + 16 + 8
SIZE_RECEIPT  = 16 + 8 + 8

def data_size(text_len):
    # 29-byte header (includes the 8-byte nonce salt) + ciphertext + tag + MAC
    return 29 + text_len + 16 + 8

STEP_MS = 10


def airtime_ms(payload_bytes):
    """Semtech AN1200.13 LoRa time-on-air."""
    symbol = (2 ** SF) / BANDWIDTH_HZ
    de = 1 if (SF >= 11 and BANDWIDTH_HZ == 125_000) else 0
    numerator = 8 * payload_bytes - 4 * SF + 28 + 16
    denominator = 4 * (SF - 2 * de)
    n = 8 + max(math.ceil(numerator / denominator) * (CODING_RATE + 4), 0)
    return ((PREAMBLE + 4.25) * symbol + n * symbol) * 1000


def seq_newer(candidate, stored):
    return ((candidate - stored + 32768) % 65536) - 32768 > 0


# ------------------------------------------------------------------ channel
class Channel:
    """Shared medium. Tracks in-flight frames and resolves collisions."""

    def __init__(self, nodes, radio_range):
        self.nodes = nodes
        self.range = radio_range
        # When set, the field is cut in two at this x and no radio crosses it.
        # Models terrain or distance splitting the mesh into islands.
        self.split_x = None
        self.inflight = []          # dicts: sender, start, end, packet, size
        self.delivered = 0
        self.collided = 0

    def in_range(self, a, b):
        na, nb = self.nodes[a], self.nodes[b]
        if self.split_x is not None and (na.pos[0] < self.split_x) != (nb.pos[0] < self.split_x):
            return False
        return math.dist(na.pos, nb.pos) <= self.range

    def busy_at(self, node_id, now):
        """Listen-before-talk: can this node hear anything right now?"""
        return any(t['start'] <= now < t['end'] and self.in_range(node_id, t['sender'])
                   for t in self.inflight)

    def transmit(self, sender, packet, size, now):
        duration = airtime_ms(size)
        self.inflight.append({'sender': sender, 'start': now, 'end': now + duration,
                              'packet': packet, 'size': size})
        self.nodes[sender].airtime_ms += duration
        self.nodes[sender].frames_sent += 1
        return duration

    def step(self, now):
        """Deliver frames whose airtime has elapsed, dropping collisions."""
        finished = [t for t in self.inflight if t['end'] <= now]
        if not finished:
            return
        for t in finished:
            for node in self.nodes.values():
                if node.id == t['sender'] or not self.in_range(node.id, t['sender']):
                    continue
                # Collision: another frame this node could hear overlapped.
                clash = any(
                    other is not t
                    and self.in_range(node.id, other['sender'])
                    and other['start'] < t['end'] and t['start'] < other['end']
                    for other in self.inflight
                )
                if clash:
                    self.collided += 1
                    node.frames_lost += 1
                else:
                    self.delivered += 1
                    node.receive(dict(t['packet']), now)
            self.inflight.remove(t)


# --------------------------------------------------------------------- node
class Node:
    def __init__(self, node_id, pos, rng):
        self.id = node_id
        self.pos = pos
        self.rng = rng

        self.neighbours = {}        # id -> last_heard
        self.routes = {}            # dest -> dict(next_hop, seq, hops, updated)
        self.sessions = set()
        self.names = {}
        self.key_requests = {}      # peer -> dict(last_sent, attempts)

        self.own_seq = 0
        self.msg_counter = 0
        self.tx_seq = 0

        self.queue = deque()        # (ready_at, packet, size)
        self.pending_acks = {}      # msg_id -> dict(packet, sent_at, retries, created)
        # Kept apart from pending_acks: the hop-by-hop ACK clears that entry
        # long before the end-to-end receipt arrives.
        self.originated_at = {}     # msg_id -> time the message was first queued
        self.dup_history = deque(maxlen=MAX_DUPLICATE_HISTORY)
        self.replay = {}            # src -> dict(highest, bitmap)

        self.next_hello = rng.randint(0, HELLO_INTERVAL_MIN_MS)
        self.next_key_scan = rng.randint(0, KEY_DISCOVERY_INTERVAL_MS)
        self.busy_until = 0

        # metrics
        self.airtime_ms = 0.0
        self.frames_sent = 0
        self.frames_lost = 0
        self.queue_drops = 0
        self.sent = 0
        self.confirmed = 0
        self.failed = 0
        self.retries = 0
        self.received = 0
        self.relayed = 0
        self.bcast_received = 0
        self.bcast_relayed = 0
        self.latencies = []
        self.peak_routes = 0
        self.peak_neighbours = 0
        self.peak_sessions = 0
        self.peak_queue = 0
        self.blocked_on_key = 0
        self.outbox = []            # (packet, parked_at) held for absent peers
        self.held = 0
        self.resumed = 0
        self.offline_until = 0
        self._sim_now = 0

    # ------------------------------------------------------------ helpers
    def hello_interval(self):
        """Mirrors currentHelloInterval() in routing_manager.h: beacon pacing
        scales with mesh size so aggregate beacon load stays bounded."""
        known = 1 + len(self.routes)
        interval = (known * airtime_ms(hello_size(len(self.routes)))
                    * HELLO_AIRTIME_MULTIPLIER)
        return min(max(interval, HELLO_INTERVAL_MIN_MS), HELLO_INTERVAL_MAX_MS)

    def new_msg_id(self, kind):
        self.msg_counter = (self.msg_counter + 1) & 0xFF
        return (kind << 24) | (self.id << 8) | self.msg_counter

    def enqueue(self, packet, size, now):
        if len(self.queue) >= MAX_QUEUE_SIZE:
            self.queue_drops += 1
            return False
        self.queue.append((now + self.rng.randint(*INITIAL_WAIT), packet, size))
        self.peak_queue = max(self.peak_queue, len(self.queue))
        return True

    def is_duplicate(self, msg_id):
        return msg_id in self.dup_history

    def remember(self, msg_id):
        self.dup_history.append(msg_id)

    def check_replay(self, src, seq):
        entry = self.replay.get(src)
        if entry is None:
            if len(self.replay) >= MAX_REPLAY_SOURCES:
                self.replay.pop(next(iter(self.replay)))
            self.replay[src] = {'highest': seq, 'bitmap': 1}
            return True
        if seq > entry['highest']:
            shift = seq - entry['highest']
            entry['bitmap'] = 0 if shift >= 32 else (entry['bitmap'] << shift) & 0xFFFFFFFF
            entry['bitmap'] |= 1
            entry['highest'] = seq
            return True
        behind = entry['highest'] - seq
        if behind >= 32 or (entry['bitmap'] & (1 << behind)):
            return False
        entry['bitmap'] |= 1 << behind
        return True

    def next_hop(self, dest, exclude=None):
        if dest in self.neighbours and dest != exclude:
            return dest
        route = self.routes.get(dest)
        if (route and route['hops'] < ROUTE_INFINITY
                and route['next_hop'] != exclude
                and route['next_hop'] in self.neighbours):
            return route['next_hop']
        candidates = [n for n in self.neighbours if n != exclude]
        return self.rng.choice(candidates) if candidates else None

    # ------------------------------------------------------------- routing
    def apply_route(self, dest, via, advertised_hops, seq):
        if dest == self.id:
            return
        hops = ROUTE_INFINITY if advertised_hops >= ROUTE_INFINITY - 1 else advertised_hops + 1
        entry = self.routes.get(dest)

        if entry is None:
            if hops >= ROUTE_INFINITY or len(self.routes) >= MAX_ROUTES:
                return
            self.routes[dest] = {'next_hop': via, 'seq': seq, 'hops': hops}
            self.peak_routes = max(self.peak_routes, len(self.routes))
            return

        accept = (seq_newer(seq, entry['seq'])
                  or (seq == entry['seq'] and hops < entry['hops'])
                  or (seq == entry['seq'] and entry['next_hop'] == via and hops != entry['hops']))
        if accept:
            entry.update(next_hop=via, seq=seq, hops=hops)

    def invalidate_via(self, gone):
        for dest, route in self.routes.items():
            if route['next_hop'] == gone and route['hops'] < ROUTE_INFINITY:
                route['hops'] = ROUTE_INFINITY
                route['seq'] = (route['seq'] + 1) & 0xFFFF

    # ------------------------------------------------------------ receive
    def receive(self, packet, now):
        if self._sim_now < self.offline_until:
            return
        kind = packet['type']

        if kind == 'HELLO':
            src = packet['src']
            new_neighbour = src not in self.neighbours
            if new_neighbour and len(self.neighbours) >= MAX_NEIGHBORS:
                return                      # table full: neighbour ignored
            self.neighbours[src] = now
            self.peak_neighbours = max(self.peak_neighbours, len(self.neighbours))
            self.names[src] = packet['name']
            self.apply_route(src, src, 0, packet['seq'])
            for dest, seq, hops in packet['routes']:
                self.apply_route(dest, src, hops, seq)
            if src not in self.sessions and len(self.sessions) < MAX_SESSIONS:
                self.sessions.add(src)      # neighbour key rides on the beacon
                self.peak_sessions = max(self.peak_sessions, len(self.sessions))
            return

        if kind == 'BROADCAST':
            if packet['src'] == self.id or packet['ttl'] == 0:
                return
            if self.is_duplicate(packet['id']):
                return
            self.remember(packet['id'])
            if not self.check_replay(packet['src'], packet['seq']):
                return
            self.bcast_received += 1
            packet['ttl'] -= 1
            if packet['ttl'] > 0:
                packet['prev'] = self.id
                if self.enqueue(packet, packet['size'], now):
                    self.bcast_relayed += 1
            return

        # Everything below is addressed hop-by-hop.
        if packet.get('next') != self.id:
            return

        if kind == 'DATA':
            if packet['ttl'] == 0 or packet['src'] == self.id:
                return
            if self.is_duplicate(packet['id']):
                self.enqueue({'type': 'ACK', 'id': packet['id'], 'next': packet['prev'],
                              'src': self.id}, SIZE_ACK, now)
                return
            self.enqueue({'type': 'ACK', 'id': packet['id'], 'next': packet['prev'],
                          'src': self.id}, SIZE_ACK, now)

            if packet['dst'] == self.id:
                self.remember(packet['id'])
                if not self.check_replay(packet['src'], packet['seq']):
                    return
                if packet['src'] not in self.sessions:
                    return              # cannot decrypt without a session
                self.received += 1
                self.enqueue({'type': 'RECEIPT', 'id': packet['id'], 'src': self.id,
                              'dst': packet['src'], 'ttl': DEFAULT_TTL,
                              'next': self.next_hop(packet['src']), 'prev': self.id},
                             SIZE_RECEIPT, now)
                return

            packet['ttl'] -= 1
            if packet['ttl'] == 0:
                return
            nxt = self.next_hop(packet['dst'], exclude=packet['prev'])
            if nxt is None:
                return
            packet['prev'] = self.id
            packet['next'] = nxt
            if self.enqueue(packet, packet['size'], now):
                self.relayed += 1
            return

        if kind == 'ACK':
            entry = self.pending_acks.pop(packet['id'], None)
            if entry and entry['origin']:
                pass                     # first hop confirmed; receipt proves delivery
            return

        if kind == 'RECEIPT':
            if packet['dst'] == self.id:
                self.pending_acks.pop(packet['id'], None)
                self.clear_from_outbox(packet['id'])
                started = self.originated_at.pop(packet['id'], None)
                if started is None:
                    return          # not ours, or already confirmed
                self.confirmed += 1
                self.latencies.append(now - started)
                return
            packet['ttl'] -= 1
            if packet['ttl'] == 0:
                return
            nxt = self.next_hop(packet['dst'], exclude=packet['prev'])
            if nxt is None:
                return
            packet['prev'] = self.id
            packet['next'] = nxt
            self.enqueue(packet, SIZE_RECEIPT, now)
            return

        if kind in ('KEY_REQ', 'KEY_RESP'):
            if packet['dst'] == self.id:
                if len(self.sessions) < MAX_SESSIONS:
                    self.sessions.add(packet['src'])
                    self.peak_sessions = max(self.peak_sessions, len(self.sessions))
                self.names[packet['src']] = packet['name']
                if kind == 'KEY_REQ':
                    nxt = self.next_hop(packet['src'])
                    if nxt:
                        self.enqueue({'type': 'KEY_RESP', 'src': self.id, 'dst': packet['src'],
                                      'ttl': DEFAULT_TTL, 'next': nxt, 'prev': self.id,
                                      'name': f'N{self.id}'}, SIZE_KEY, now)
                return
            packet['ttl'] -= 1
            if packet['ttl'] == 0:
                return
            nxt = self.next_hop(packet['dst'], exclude=packet['prev'])
            if nxt is None:
                return
            packet['prev'] = self.id
            packet['next'] = nxt
            self.enqueue(packet, SIZE_KEY, now)

    # --------------------------------------------------------- application
    def request_session(self, peer):
        """Mirrors requestSessionWith(): interest is registered by an
        attempted send, not by a route appearing."""
        if peer in self.sessions:
            return
        state = self.key_requests.setdefault(
            peer, {'last': -10 ** 9, 'attempts': 0, 'wanted': False})
        if not state['wanted']:
            state['wanted'] = True
            state['attempts'] = 0
            self.next_key_scan = 0

    def park(self, packet, now):
        """Mirrors parkMessage(): hold an encrypted message whose recipient is
        currently unreachable, rather than discarding it."""
        for item in self.outbox:
            if item['packet']['id'] == packet['id']:
                return True         # already waiting
        if len(self.outbox) >= MAX_OUTBOX:
            self.failed += 1
            return False
        self.outbox.append({'packet': packet, 'parked': now,
                            'attempts': 0, 'last': now})
        self.held += 1
        return True

    def maintain_outbox(self, now):
        for item in list(self.outbox):
            packet = item['packet']
            # Bounded by time and by attempts: each attempt costs a transmit
            # plus its retransmissions.
            if (now - item['parked'] > OUTBOX_TTL_MS
                    or item['attempts'] >= MAX_OUTBOX_ATTEMPTS):
                self.outbox.remove(item)
                self.failed += 1
                continue
            wait = (OUTBOX_FIRST_RETRY_MS if item['attempts'] == 0
                    else OUTBOX_RETRY_INTERVAL_MS * item['attempts'])
            if now - item['last'] < wait:
                continue
            nxt = self.next_hop(packet['dst'])
            if nxt is None:
                continue
            packet['prev'] = self.id
            packet['next'] = nxt
            packet['ttl'] = DEFAULT_TTL
            if self.enqueue(packet, packet['size'], now):
                self.resumed += 1
                item['attempts'] += 1
                item['last'] = now
                # Held until a receipt confirms it; freeing here would reset
                # the attempt count on the next failure.
                self.pending_acks[packet['id']] = {
                    'packet': packet, 'sent_at': now, 'retries': 0,
                    'created': now, 'origin': True}
            return

    def clear_from_outbox(self, message_id):
        for item in list(self.outbox):
            if item['packet']['id'] == message_id:
                self.outbox.remove(item)
                return

    def send_message(self, dest, text_len, now):
        if dest not in self.sessions:
            self.request_session(dest)
            self.blocked_on_key += 1
            return False
        nxt = self.next_hop(dest)
        self.tx_seq += 1
        msg_id = self.new_msg_id(1)
        size = data_size(text_len)
        packet = {'type': 'DATA', 'id': msg_id, 'src': self.id, 'dst': dest,
                  'prev': self.id, 'next': nxt, 'ttl': DEFAULT_TTL,
                  'seq': self.tx_seq, 'size': size}
        self.sent += 1
        self.originated_at[msg_id] = now
        if nxt is None or not self.enqueue(packet, size, now):
            return self.park(packet, now)
        self.pending_acks[msg_id] = {'packet': packet, 'sent_at': now, 'retries': 0,
                                     'created': now, 'origin': True}
        return True

    def send_broadcast(self, text_len, now):
        self.tx_seq += 1
        msg_id = self.new_msg_id(8)
        size = data_size(text_len)
        packet = {'type': 'BROADCAST', 'id': msg_id, 'src': self.id, 'prev': self.id,
                  'ttl': BROADCAST_TTL, 'seq': self.tx_seq, 'size': size}
        self.remember(msg_id)
        return self.enqueue(packet, size, now)

    # ---------------------------------------------------------------- tick
    def tick(self, channel, now):
        # A node that is switched off neither hears nor sends.
        if now < self.offline_until:
            return
        self.maintain_outbox(now)

        # Expire neighbours and invalidate what routed through them.
        expiry = self.hello_interval() * NEIGHBOR_EXPIRY_BEACONS
        for peer, last in list(self.neighbours.items()):
            if now - last > expiry:
                del self.neighbours[peer]
                self.invalidate_via(peer)

        # Periodic beacon carrying the distance vector, key and name.
        if now >= self.next_hello:
            self.next_hello = now + self.hello_interval()
            self.own_seq += 2
            advert = [(d, r['seq'], r['hops']) for d, r in
                      list(self.routes.items())[:MAX_ROUTES_PER_HELLO]]
            self.enqueue({'type': 'HELLO', 'src': self.id, 'seq': self.own_seq,
                          'routes': advert, 'name': f'N{self.id}'},
                         hello_size(len(advert)), now)

        # Key discovery, on demand only: chasing a key for every destination
        # in the routing table is O(N^2) and swamps the channel at scale.
        if now >= self.next_key_scan:
            self.next_key_scan = now + KEY_DISCOVERY_INTERVAL_MS
            for dest, state in self.key_requests.items():
                if not state['wanted'] or dest in self.sessions:
                    state['wanted'] = False
                    continue
                if state['attempts'] >= MAX_KEY_REQUEST_RETRIES:
                    continue
                if now - state['last'] < KEY_REQUEST_TIMEOUT_MS:
                    continue
                nxt = self.next_hop(dest)
                if nxt:
                    state['last'] = now
                    state['attempts'] += 1
                    self.enqueue({'type': 'KEY_REQ', 'src': self.id, 'dst': dest,
                                  'ttl': DEFAULT_TTL, 'next': nxt, 'prev': self.id,
                                  'name': f'N{self.id}'}, SIZE_KEY, now)
                break

        # ACK timeouts and retries.
        for msg_id, entry in list(self.pending_acks.items()):
            if now - entry['sent_at'] < ACK_TIMEOUT_MS:
                continue
            if entry['retries'] < MAX_RETRIES:
                entry['retries'] += 1
                entry['sent_at'] = now
                self.retries += 1
                self.enqueue(entry['packet'], entry['packet']['size'], now)
            else:
                del self.pending_acks[msg_id]
                if entry['origin']:
                    if not self.park(entry['packet'], now):
                        self.failed += 1

        # Transmit the head of the queue if the channel is clear.
        if now < self.busy_until or not self.queue:
            return
        ready_at, packet, size = self.queue[0]
        if now < ready_at:
            return
        if channel.busy_at(self.id, now):
            self.queue[0] = (now + self.rng.randint(50, 250), packet, size)
            return
        self.queue.popleft()
        self.busy_until = now + channel.transmit(self.id, packet, size, now)


# ---------------------------------------------------------------------- run
def run(args):
    rng = random.Random(args.seed)
    nodes = {}
    for i in range(args.nodes):
        node_id = 1000 + i
        pos = (rng.uniform(0, args.area), rng.uniform(0, args.area))
        nodes[node_id] = Node(node_id, pos, random.Random(rng.random()))

    channel = Channel(nodes, args.range)
    ids = list(nodes)

    # Connectivity check: an unreachable node is a placement problem, not a
    # protocol one, so say so rather than blaming the results on the mesh.
    reachable = {ids[0]}
    frontier = [ids[0]]
    while frontier:
        current = frontier.pop()
        for other in ids:
            if other not in reachable and channel.in_range(current, other):
                reachable.add(other)
                frontier.append(other)
    partitioned = len(reachable) < len(ids)

    total_ms = args.minutes * 60_000
    converge_ms = None
    traffic_start = total_ms * 0.4          # let routing settle first
    next_message = traffic_start
    next_broadcast = total_ms * 0.7
    retries = []
    partition_at = int(total_ms * 0.45 // STEP_MS) * STEP_MS
    partition_heal = int(total_ms * 0.70 // STEP_MS) * STEP_MS
    broadcasts_sent = 0

    now = 0
    while now < total_ms:
        for node in nodes.values():
            node._sim_now = now
            node.tick(channel, now)
        channel.step(now)

        # Convergence: every node holds a route to every other reachable node.
        if converge_ms is None and now > 5_000:
            if all(len([d for d, r in n.routes.items() if r['hops'] < ROUTE_INFINITY])
                   >= len(reachable) - 1
                   for n in nodes.values() if n.id in reachable):
                converge_ms = now

        # Offered traffic: random pairs exchange messages.
        if now >= next_message and now > traffic_start:
            next_message = now + args.interval
            src = nodes[rng.choice(ids)]
            dst = rng.choice([i for i in ids if i != src.id])
            if not src.send_message(dst, args.msglen, now):
                # The app retries once the key exchange has had time to run.
                retries.append((now + 8_000, src, dst))

        for item in [r for r in retries if r[0] <= now]:
            retries.remove(item)
            item[1].send_message(item[2].id if hasattr(item[2], 'id') else item[2],
                                 args.msglen, now)

        if args.partition and now == partition_at:
            channel.split_x = args.area / 2
            left = sum(1 for n in nodes.values() if n.pos[0] < channel.split_x)
            print(f"  [{now/1000:6.0f}s] PARTITION: field split {left} | {len(nodes)-left}")
        if args.partition and now == partition_heal:
            channel.split_x = None
            print(f"  [{now/1000:6.0f}s] HEALED: the two halves can hear each other again")

        if args.churn > 0 and now % 30_000 == 0 and now > traffic_start:
            for node in nodes.values():
                if node.offline_until <= now and rng.random() < args.churn / 4:
                    node.offline_until = now + rng.randint(60_000, 180_000)

        if now >= next_broadcast and broadcasts_sent < args.broadcasts:
            next_broadcast = now + 60_000
            broadcasts_sent += 1
            nodes[rng.choice(ids)].send_broadcast(args.msglen, now)

        now += STEP_MS

    report(args, nodes, channel, converge_ms, total_ms, reachable, partitioned,
           broadcasts_sent)


def report(args, nodes, channel, converge_ms, total_ms, reachable, partitioned,
           broadcasts_sent):
    def total(attr):
        return sum(getattr(n, attr) for n in nodes.values())

    print("=" * 66)
    print(f"  {args.nodes}-node mesh, {args.area:.0f} m area, {args.range:.0f} m range,"
          f" {args.minutes} min")
    print("=" * 66)

    if partitioned:
        print(f"\n  NOTE: only {len(reachable)}/{args.nodes} nodes are radio-connected."
              f"\n  Increase --range or reduce --area; the rest cannot be reached at all.")

    print("\nROUTING")
    if converge_ms is not None:
        print(f"  converged in                {converge_ms / 1000:.0f} s")
    else:
        print(f"  did NOT fully converge in {args.minutes} min")
    routes = [len([d for d, r in n.routes.items() if r['hops'] < ROUTE_INFINITY])
              for n in nodes.values()]
    print(f"  routes known per node       min {min(routes)}, max {max(routes)},"
          f" need {len(reachable) - 1}")
    print(f"  peak routing table          {max(n.peak_routes for n in nodes.values())}"
          f" / {MAX_ROUTES}")
    print(f"  peak neighbour table        {max(n.peak_neighbours for n in nodes.values())}"
          f" / {MAX_NEIGHBORS}")

    print("\nSECURITY")
    sessions = [len(n.sessions) for n in nodes.values()]
    print(f"  sessions per node           min {min(sessions)}, max {max(sessions)}")
    print(f"  peak session table          {max(n.peak_sessions for n in nodes.values())}"
          f" / {MAX_SESSIONS}")

    print("\nDELIVERY (NFR3 target >= 90%)")
    sent, confirmed, failed = total('sent'), total('confirmed'), total('failed')
    print(f"  messages sent               {sent}")
    print(f"  confirmed by receipt        {confirmed}")
    print(f"  gave up after retries       {failed}")
    if sent:
        print(f"  end-to-end PDR              {100 * confirmed / sent:.1f}%")
    print(f"  relayed by intermediates    {total('relayed')}")
    print(f"  held for absent recipients  {total('held')}")
    print(f"  re-send attempts from hold  {total('resumed')}")
    print(f"  retransmissions             {total('retries')}")

    print("\nLATENCY (NFR2 target < 5000 ms)")
    all_latencies = [x for n in nodes.values() for x in n.latencies]
    if all_latencies:
        all_latencies.sort()
        mean = sum(all_latencies) / len(all_latencies)
        p95 = all_latencies[int(len(all_latencies) * 0.95) - 1]
        print(f"  mean                        {mean:.0f} ms")
        print(f"  95th percentile             {p95:.0f} ms")
        print(f"  worst                       {max(all_latencies):.0f} ms")
    else:
        print("  no confirmed deliveries to measure")

    print("\nBROADCAST")
    print(f"  alerts originated           {broadcasts_sent}")
    print(f"  node-receptions             {total('bcast_received')}")
    print(f"  re-floods                   {total('bcast_relayed')}")
    if broadcasts_sent:
        expected = broadcasts_sent * (len(reachable) - 1)
        coverage = min(1.0, total('bcast_received') / expected) if expected else 0
        print(f"  coverage of reachable nodes {100 * coverage:.1f}%")

    print("\nCHANNEL (regulatory limit 1% per node)")
    duties = [100 * n.airtime_ms / total_ms for n in nodes.values()]
    print(f"  duty cycle per node         mean {sum(duties)/len(duties):.2f}%,"
          f" max {max(duties):.2f}%")
    occupancy = 100 * sum(n.airtime_ms for n in nodes.values()) / total_ms
    print(f"  total channel occupancy     {occupancy:.1f}%")
    print(f"  frames sent / lost to collision  {total('frames_sent')} / {total('frames_lost')}")
    if total('frames_sent'):
        print(f"  collision loss rate         "
              f"{100 * total('frames_lost') / (channel.delivered + channel.collided):.1f}%")
    print(f"  queue overflows             {total('queue_drops')}")

    if args.partition:
        print("")
        print("PARTITION / HEAL")
        need = len(reachable) - 1
        full = [n for n in nodes.values() if n.id in reachable
                and len([d for d, r in n.routes.items() if r["hops"] < ROUTE_INFINITY]) >= need]
        print(f"  nodes with a full table     {len(full)}/{len(reachable)}")
        print(f"  routes rebuilt after heal   {'yes' if len(full) == len(reachable) else 'NO'}")

    print("\nVERDICT")
    problems = []
    if converge_ms is None:
        problems.append("routing did not converge")
    if max(n.peak_routes for n in nodes.values()) >= MAX_ROUTES:
        problems.append(f"routing table hit its {MAX_ROUTES}-entry limit")
    if max(n.peak_neighbours for n in nodes.values()) >= MAX_NEIGHBORS:
        problems.append(f"neighbour table hit its {MAX_NEIGHBORS}-entry limit")
    if max(n.peak_sessions for n in nodes.values()) >= MAX_SESSIONS:
        problems.append(f"session table hit its {MAX_SESSIONS}-entry limit")
    if sent and 100 * confirmed / sent < 90:
        problems.append(f"PDR {100 * confirmed / sent:.1f}% is below the 90% target")
    if all_latencies and sum(all_latencies) / len(all_latencies) > 5000:
        problems.append("mean latency exceeds 5 s")
    if max(duties) > 1.0:
        problems.append(f"duty cycle {max(duties):.2f}% exceeds the 1% target")
    if total('queue_drops'):
        problems.append(f"{total('queue_drops')} frames dropped by full queues")

    if problems:
        for p in problems:
            print(f"  FAIL  {p}")
    else:
        print("  PASS  all checked requirements met")
    print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--nodes', type=int, default=20)
    parser.add_argument('--minutes', type=int, default=10)
    parser.add_argument('--area', type=float, default=2000, help='square field side, metres')
    parser.add_argument('--range', type=float, default=700, help='radio range, metres')
    parser.add_argument('--interval', type=int, default=5000, help='ms between messages')
    parser.add_argument('--msglen', type=int, default=40, help='message length, characters')
    parser.add_argument('--broadcasts', type=int, default=3)
    parser.add_argument('--partition', action='store_true',
                        help='split the field in two at 45%% of the run, heal at 70%%')
    parser.add_argument('--churn', type=float, default=0.0,
                        help='how often nodes drop offline (0 = never)')
    parser.add_argument('--seed', type=int, default=42)
    run(parser.parse_args())
