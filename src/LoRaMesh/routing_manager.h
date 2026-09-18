/*==============================================================================
  routing_manager.h
  ------------------------------------------------------------------------------
  Neighbour table and distance-vector routing (FR4).

  Routing follows DSDV: every destination owns a sequence number that only it
  increments, and a route is preferred if it is fresher, or equally fresh but
  shorter. Those sequence numbers are what stop the count-to-infinity loops a
  plain distance-vector protocol suffers from.

  Distance vectors ride on the existing HELLO beacon rather than a protocol of
  their own, so routing costs no extra airtime - the approach Pueyo Centelles
  et al. (2024) show is necessary to fit within LoRa's bandwidth.

  Two metrics coexist: hop count decides the route, while RSSI and recency
  decide which neighbour to gamble on when no route is known yet.
==============================================================================*/
#ifndef ROUTING_MANAGER_H
#define ROUTING_MANAGER_H

#include "config.h"
#include "packet_manager.h"
#include "metrics.h"
#include <Arduino.h>
#include <Preferences.h>

/*----------------------------------------------------------------------------*/
/*  Neighbour table - who we can hear directly                                */
/*----------------------------------------------------------------------------*/
struct NeighborInfo {
  uint16_t neighborId;
  int16_t  rssi;
  unsigned long lastHeard;
};
static NeighborInfo neighborTable[MAX_NEIGHBORS];

/*----------------------------------------------------------------------------*/
/*  Optional whitelist (ALLOWED_NEIGHBORS) to force a lab topology            */
/*----------------------------------------------------------------------------*/
inline bool isAllowedNeighbor(uint16_t nodeID) {
    static uint16_t allowed[] = ALLOWED_NEIGHBORS;
    if (allowed[0] == 0) {
        return true;
    }
    for (int i = 0; allowed[i] != 0; i++) {
        if (allowed[i] == nodeID) {
            return true;
        }
    }
    return false;
}

inline bool isNeighbor(uint16_t nodeID) {
    if (nodeID == 0 || nodeID == INVALID_NEXT_HOP) {
        return false;
    }
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (neighborTable[i].neighborId == nodeID) {
            return true;
        }
    }
    return false;
}

/*============================================================================*/
/*  Node directory - names for node IDs                                       */
/*============================================================================*/
/*  Node IDs come from the chip MAC and mean nothing to a user. Every node
 *  advertises a name on its beacon and in key exchanges; peers collect them
 *  here so messages can be addressed to "Rakshith" rather than 21087.       */
struct NodeName {
    uint16_t node;
    char name[NODE_NAME_FIELD];
    uint16_t batteryMv;   // last value this node reported; 0 means unknown
    bool inUse;
};
static NodeName nodeDirectory[MAX_ROUTES];

static char localNodeName[NODE_NAME_FIELD];
static Preferences namePrefs;

/*  Names travel over the air and end up inside the newline-delimited protocol
 *  the phone app parses, where fields are whitespace-separated. A name
 *  carrying a newline could forge whole protocol lines - a fake delivery
 *  confirmation, or a message attributed to another node - so anything
 *  outside printable non-space ASCII is replaced rather than trusted.
 *
 *  Applied to names we receive as well as ones we set: a remote node's name
 *  is no more trustworthy than any other remote input.                      */
inline void sanitizeNodeName(char *name) {
    for (int i = 0; i < MAX_NODE_NAME_LEN; i++) {
        if (name[i] == '\0') {
            break;
        }
        unsigned char c = (unsigned char)name[i];
        if (c <= 0x20 || c >= 0x7F) {
            name[i] = '_';
        }
    }
    name[MAX_NODE_NAME_LEN] = '\0';
}

inline const char *getLocalNodeName() {
    return localNodeName;
}

inline void setLocalNodeName(const char *name) {
    memset(localNodeName, 0, NODE_NAME_FIELD);
    strncpy(localNodeName, name, MAX_NODE_NAME_LEN);
    sanitizeNodeName(localNodeName);

    namePrefs.begin(NVS_NAMESPACE, false);
    namePrefs.putString(NVS_NODE_NAME_KEY, localNodeName);
    namePrefs.end();
}

inline void loadLocalNodeName() {
    namePrefs.begin(NVS_NAMESPACE, true);
    String stored = namePrefs.getString(NVS_NODE_NAME_KEY, "");
    namePrefs.end();

    memset(localNodeName, 0, NODE_NAME_FIELD);
    if (stored.length() > 0) {
        strncpy(localNodeName, stored.c_str(), MAX_NODE_NAME_LEN);
    } else {
        snprintf(localNodeName, NODE_NAME_FIELD, "Node-%u", getNodeID());
    }
}

inline void rememberNodeName(uint16_t node, const char *name) {
    if (node == 0 || name == nullptr || name[0] == '\0') {
        return;
    }
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (nodeDirectory[i].inUse && nodeDirectory[i].node == node) {
            strncpy(nodeDirectory[i].name, name, MAX_NODE_NAME_LEN);
            nodeDirectory[i].name[MAX_NODE_NAME_LEN] = '\0';
            sanitizeNodeName(nodeDirectory[i].name);
            return;
        }
    }
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (!nodeDirectory[i].inUse) {
            nodeDirectory[i].inUse = true;
            nodeDirectory[i].node = node;
            memset(nodeDirectory[i].name, 0, NODE_NAME_FIELD);
            strncpy(nodeDirectory[i].name, name, MAX_NODE_NAME_LEN);
            sanitizeNodeName(nodeDirectory[i].name);
            Serial.printf("[MESH] %u is \"%s\"\n", node, nodeDirectory[i].name);
            return;
        }
    }
}

/*  Battery is reported on every beacon, so a fading relay shows up in the
 *  app's node list long before it goes silent.                             */
inline void rememberNodeBattery(uint16_t node, uint16_t batteryMv) {
    if (node == 0 || batteryMv == 0) {
        return;
    }
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (nodeDirectory[i].inUse && nodeDirectory[i].node == node) {
            nodeDirectory[i].batteryMv = batteryMv;
            return;
        }
    }
}

inline uint16_t lookupNodeBattery(uint16_t node) {
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (nodeDirectory[i].inUse && nodeDirectory[i].node == node) {
            return nodeDirectory[i].batteryMv;
        }
    }
    return 0;
}

inline const char *lookupNodeName(uint16_t node) {
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (nodeDirectory[i].inUse && nodeDirectory[i].node == node) {
            return nodeDirectory[i].name;
        }
    }
    return nullptr;
}

/*  Case-insensitive so a user does not have to match capitals exactly. */
inline uint16_t lookupNodeByName(const char *name) {
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (nodeDirectory[i].inUse && strcasecmp(nodeDirectory[i].name, name) == 0) {
            return nodeDirectory[i].node;
        }
    }
    return 0;
}

inline String describeNode(uint16_t node) {
    const char *name = lookupNodeName(node);
    if (name != nullptr) {
        return String(name) + " (" + String(node) + ")";
    }
    return String(node);
}

/*============================================================================*/
/*  Routing table - how to reach nodes we cannot hear directly                */
/*============================================================================*/
struct RouteEntry {
    uint16_t destination;
    uint16_t nextHop;
    uint16_t seqNum;     // owned by the destination
    uint8_t  hopCount;   // ROUTE_INFINITY means known-unreachable
    unsigned long lastUpdated;
    bool inUse;
};
static RouteEntry routingTable[MAX_ROUTES];

/*----------------------------------------------------------------------------*/
/*  This node's own sequence number                                           */
/*----------------------------------------------------------------------------*/
/*  Always even. A node that detects a broken link advertises seq+1, so odd
 *  numbers mark invalidations and can only be overridden by a fresh even
 *  number from the destination itself - the standard DSDV convention.       */
static Preferences routingPrefs;
static uint16_t localRouteSeq = 0;
static uint16_t localRouteSeqEnd = 0;

inline void reserveRouteSeqBlock() {
    routingPrefs.begin(NVS_NAMESPACE, false);
    uint32_t base = routingPrefs.getUInt(NVS_ROUTE_SEQ_KEY, 0);
    routingPrefs.putUInt(NVS_ROUTE_SEQ_KEY, base + ROUTE_SEQ_BLOCK);
    routingPrefs.end();

    localRouteSeq = (uint16_t)base;
    localRouteSeqEnd = (uint16_t)(base + ROUTE_SEQ_BLOCK);
}

inline uint16_t nextLocalRouteSeq() {
    localRouteSeq += 2;
    if (localRouteSeq >= localRouteSeqEnd) {
        reserveRouteSeqBlock();
    }
    return localRouteSeq;
}

/*----------------------------------------------------------------------------*/
/*  Sequence comparison, wraparound-safe (RFC 1982 style)                     */
/*----------------------------------------------------------------------------*/
inline bool seqIsNewer(uint16_t candidate, uint16_t stored) {
    return (int16_t)(candidate - stored) > 0;
}

/*----------------------------------------------------------------------------*/
/*  Triggered updates                                                         */
/*----------------------------------------------------------------------------*/
/*  DSDV beacons on a timer, but waiting a full interval to announce a broken
 *  link makes recovery take two intervals. Raising this flag makes the
 *  scheduler beacon early, so an invalidation races outwards ahead of the
 *  timer. Only bad news triggers one - good news can wait for the next
 *  scheduled beacon, which avoids a broadcast storm as a mesh powers up.    */
static bool routingUpdatePending = false;

inline bool consumeRoutingUpdateFlag() {
    bool pending = routingUpdatePending;
    routingUpdatePending = false;
    return pending;
}

inline RouteEntry *findRoute(uint16_t destination) {
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (routingTable[i].inUse && routingTable[i].destination == destination) {
            return &routingTable[i];
        }
    }
    return nullptr;
}

inline RouteEntry *allocateRoute() {
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (!routingTable[i].inUse) {
            return &routingTable[i];
        }
    }
    /* Table full: reclaim the least recently updated unreachable entry, or
     * failing that the stalest entry of any kind. */
    int victim = -1;
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (routingTable[i].hopCount >= ROUTE_INFINITY &&
            (victim < 0 || routingTable[i].lastUpdated < routingTable[victim].lastUpdated)) {
            victim = i;
        }
    }
    if (victim < 0) {
        victim = 0;
        for (int i = 1; i < MAX_ROUTES; i++) {
            if (routingTable[i].lastUpdated < routingTable[victim].lastUpdated) {
                victim = i;
            }
        }
    }
    return &routingTable[victim];
}

/*----------------------------------------------------------------------------*/
/*  DSDV update rule                                                          */
/*----------------------------------------------------------------------------*/
/*  advertisedHops is the sender's own cost to the destination, so ours is one
 *  more than that.                                                          */
inline void applyRouteUpdate(uint16_t destination, uint16_t viaNeighbor,
                             uint8_t advertisedHops, uint16_t seq) {
    /*  A route to ourselves is meaningless. destination == viaNeighbor is
     *  legitimate - that is the direct one-hop entry for the sender.       */
    if (destination == 0 || destination == getNodeID()) {
        return;
    }

    uint8_t newHops = (advertisedHops >= ROUTE_INFINITY - 1)
                    ? ROUTE_INFINITY
                    : (uint8_t)(advertisedHops + 1);

    RouteEntry *entry = findRoute(destination);

    if (entry == nullptr) {
        if (newHops >= ROUTE_INFINITY) {
            return; // no point creating an entry purely to record unreachability
        }
        entry = allocateRoute();
        entry->destination = destination;
        entry->nextHop = viaNeighbor;
        entry->seqNum = seq;
        entry->hopCount = newHops;
        entry->lastUpdated = millis();
        entry->inUse = true;
        Serial.printf("[ROUTE] learned %u via %u (%u hops)\n", destination, viaNeighbor, newHops);
        return;
    }

    bool accept = false;
    if (seqIsNewer(seq, entry->seqNum)) {
        accept = true;                                  // fresher wins outright
    } else if (seq == entry->seqNum) {
        if (newHops < entry->hopCount) {
            accept = true;                              // equally fresh but shorter
        } else if (entry->nextHop == viaNeighbor && newHops != entry->hopCount) {
            accept = true;                              // our own next hop revised its cost
        }
    }
    if (!accept) {
        return;
    }

    bool wasReachable = entry->hopCount < ROUTE_INFINITY;
    bool nowReachable = newHops < ROUTE_INFINITY;
    if (wasReachable != nowReachable) {
        Serial.printf("[ROUTE] %u is now %s\n", destination,
                      nowReachable ? "reachable" : "unreachable");
        if (!nowReachable) {
            routingUpdatePending = true; // pass the invalidation on immediately
        }
    }

    entry->nextHop = viaNeighbor;
    entry->seqNum = seq;
    entry->hopCount = newHops;
    entry->lastUpdated = millis();
}

/*----------------------------------------------------------------------------*/
/*  Link failure                                                              */
/*----------------------------------------------------------------------------*/
/*  Marks everything reached through a dead neighbour as unreachable and bumps
 *  the sequence number to an odd value, so the invalidation propagates and
 *  outranks the stale reachable routes our neighbours still hold.           */
inline void invalidateRoutesVia(uint16_t neighborId) {
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (routingTable[i].inUse &&
            routingTable[i].nextHop == neighborId &&
            routingTable[i].hopCount < ROUTE_INFINITY) {
            routingTable[i].hopCount = ROUTE_INFINITY;
            routingTable[i].seqNum++;
            routingTable[i].lastUpdated = millis();
            routingUpdatePending = true;
            Serial.printf("[ROUTE] %u unreachable, %u went away\n",
                          routingTable[i].destination, neighborId);
        }
    }
}

inline void cleanupRoutes() {
    unsigned long now = millis();
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (routingTable[i].inUse &&
            routingTable[i].hopCount >= ROUTE_INFINITY &&
            (now - routingTable[i].lastUpdated) > ROUTE_HOLD_DOWN_MS) {
            routingTable[i].inUse = false;
        }
    }
}

/*============================================================================*/
/*  Neighbour table maintenance                                               */
/*============================================================================*/
/*  Returns false when the table is full and this neighbour could not be
 *  recorded. That matters: routes learned via a node we do not hold as a
 *  neighbour are unusable, because getNextHop() will not select a next hop
 *  it cannot hear - so installing them would advertise reachability we
 *  cannot honour and black-hole the traffic it attracts.                    */
inline bool addOrUpdateNeighbor(uint16_t neighborId, int16_t rssi) {
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (neighborTable[i].neighborId == neighborId) {
            neighborTable[i].rssi = rssi;
            neighborTable[i].lastHeard = millis();
            return true;
        }
    }
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (neighborTable[i].neighborId == 0) {
            neighborTable[i].neighborId = neighborId;
            neighborTable[i].rssi       = rssi;
            neighborTable[i].lastHeard  = millis();
            Serial.printf("[MESH] neighbour %u appeared (rssi %d)\n", neighborId, rssi);
            return true;
        }
    }
    Serial.printf("[MESH] neighbour table full - ignoring %u\n", neighborId);
    return false;
}

/*============================================================================*/
/*  Beacon pacing                                                             */
/*============================================================================*/
/*  Every node this one knows about, itself included, is a node that beacons
 *  onto the same channel.                                                    */
inline uint8_t knownNodeCount() {
    uint8_t count = 1; // ourselves
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (routingTable[i].inUse) {
            count++;
        }
    }
    return count;
}

/*  Holds aggregate beacon load near a fixed fraction of the channel however
 *  large the mesh grows. See the note in config.h.                          */
inline unsigned long currentHelloInterval() {
    /*  Sized from the routes actually held, not the table capacity: a
     *  five-node mesh sends a 90-byte beacon, not a 188-byte one, and should
     *  not be paced as though it were.                                     */
    uint8_t known = knownNodeCount();
    uint8_t advertised = (known > 1) ? (uint8_t)(known - 1) : 0;
    if (advertised > MAX_ROUTES_PER_HELLO) {
        advertised = MAX_ROUTES_PER_HELLO;
    }
    const uint16_t beaconBytes = HELLO_HEADER_SIZE
                               + advertised * ROUTE_ADVERT_SIZE
                               + CONTROL_MAC_LEN;
    unsigned long airtime = (unsigned long)loraAirtimeMs(beaconBytes);
    unsigned long interval = (unsigned long)known * airtime * HELLO_AIRTIME_MULTIPLIER;

    if (interval < HELLO_INTERVAL_MIN_MS) {
        return HELLO_INTERVAL_MIN_MS;
    }
    if (interval > HELLO_INTERVAL_MAX_MS) {
        return HELLO_INTERVAL_MAX_MS;
    }
    return interval;
}

inline unsigned long currentNeighborExpiration() {
    return currentHelloInterval() * NEIGHBOR_EXPIRY_BEACONS;
}

inline void cleanupNeighbors() {
    unsigned long now = millis();
    unsigned long expiry = currentNeighborExpiration();
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (neighborTable[i].neighborId != 0 &&
            (now - neighborTable[i].lastHeard) > expiry) {
            uint16_t lost = neighborTable[i].neighborId;
            Serial.printf("[MESH] neighbour %u timed out\n", lost);
            neighborTable[i].neighborId = 0;
            neighborTable[i].rssi = 0;
            neighborTable[i].lastHeard = 0;
            invalidateRoutesVia(lost);
        }
    }
    cleanupRoutes();
}

inline void removeNeighbor(uint16_t neighborId) {
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (neighborTable[i].neighborId == neighborId) {
            Serial.printf("[MESH] dropping neighbour %u (no ACK)\n", neighborId);
            neighborTable[i].neighborId = 0;
            neighborTable[i].rssi = 0;
            neighborTable[i].lastHeard = 0;
            invalidateRoutesVia(neighborId);
            return;
        }
    }
}

/*============================================================================*/
/*  Beacon integration                                                        */
/*============================================================================*/
/*  Attaches our whole distance vector to an outgoing HELLO and stamps it with
 *  a fresh sequence number for ourselves.                                   */
/*  The beacon has room for MAX_ROUTES_PER_HELLO entries alongside the public
 *  key. With more destinations than that, the window advances each beacon so
 *  every route is still announced within a few rounds rather than the tail of
 *  the table never being advertised at all.                                 */
static int helloRouteCursor = 0;

inline void attachRoutesToHello(HelloPacket &hello) {
    hello.originSeq = nextLocalRouteSeq();

    uint8_t count = 0;
    int examined = 0;
    while (examined < MAX_ROUTES && count < MAX_ROUTES_PER_HELLO) {
        int index = (helloRouteCursor + examined) % MAX_ROUTES;
        examined++;
        if (!routingTable[index].inUse) {
            continue;
        }
        hello.routes[count].destination = routingTable[index].destination;
        hello.routes[count].seqNum      = routingTable[index].seqNum;
        hello.routes[count].hopCount    = routingTable[index].hopCount;
        count++;
    }
    hello.routeCount = count;

    if (count == MAX_ROUTES_PER_HELLO) {
        helloRouteCursor = (helloRouteCursor + count) % MAX_ROUTES;
    } else {
        helloRouteCursor = 0; // whole table fitted, no need to rotate
    }
}

/*  Folds a received beacon into the neighbour and routing tables. */
inline void processHelloRoutes(const HelloPacket &hello, int16_t rssi) {
    if (!addOrUpdateNeighbor(hello.originNode, rssi)) {
        /*  We cannot route through a node we have no room to track, so
         *  taking its distance vector would only add routes we would refuse
         *  to use and then drop traffic for.                               */
        return;
    }

    /* The sender is one hop away; its cost to itself is zero. */
    applyRouteUpdate(hello.originNode, hello.originNode, 0, hello.originSeq);

    for (uint8_t i = 0; i < hello.routeCount; i++) {
        applyRouteUpdate(hello.routes[i].destination, hello.originNode,
                         hello.routes[i].hopCount, hello.routes[i].seqNum);
    }
}

/*============================================================================*/
/*  Reporting                                                                 */
/*============================================================================*/
inline String neighborTableToString() {
    String out = "Neighbours:";
    bool any = false;
    unsigned long now = millis();
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (neighborTable[i].neighborId != 0) {
            any = true;
            out += "\n  " + describeNode(neighborTable[i].neighborId) +
                   "  rssi " + String(neighborTable[i].rssi) +
                   "  seen " + String((now - neighborTable[i].lastHeard) / 1000) + "s ago";
        }
    }
    if (!any) {
        out += " none yet";
    }
    return out;
}

inline String routingTableToString() {
    String out = "Routes (dest via hops):";
    bool any = false;
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (!routingTable[i].inUse) {
            continue;
        }
        any = true;
        out += "\n  " + describeNode(routingTable[i].destination) +
               " via " + describeNode(routingTable[i].nextHop);
        if (routingTable[i].hopCount >= ROUTE_INFINITY) {
            out += "  UNREACHABLE";
        } else {
            out += "  " + String(routingTable[i].hopCount) + " hop";
            if (routingTable[i].hopCount != 1) {
                out += "s";
            }
        }
        out += "  seq " + String(routingTable[i].seqNum);
    }
    if (!any) {
        out += " none yet";
    }
    return out;
}

inline void printNeighborTable() {
    Serial.println(neighborTableToString());
    Serial.println(routingTableToString());
}

/*============================================================================*/
/*  Next-hop selection                                                        */
/*============================================================================*/
inline float getNeighborScore(int16_t rssi, unsigned long lastHeard) {
    unsigned long now = millis();
    float secsAgo = (float)(now - lastHeard) / 1000.0;
    return (float)rssi - secsAgo;
}

/*  Preference order: a direct link, then the distance-vector table, then a
 *  gamble on the best-sounding neighbour. The last case covers the window
 *  before routes have converged, and is what the base project did always.   */
inline uint16_t getNextHop(uint16_t localID, uint16_t destID, uint16_t excludeID) {
    /*-------------------------- 1. Direct neighbour -----------------------*/
    if (destID != excludeID && isNeighbor(destID)) {
        return destID;
    }

    /*-------------------------- 2. Routing table --------------------------*/
    RouteEntry *route = findRoute(destID);
    if (route != nullptr &&
        route->hopCount < ROUTE_INFINITY &&
        route->nextHop != excludeID &&
        isNeighbor(route->nextHop)) {
        return route->nextHop;
    }

    /*-------------------------- 3. Opportunistic --------------------------*/
    struct Candidate {
        uint16_t id;
        float score;
    };
    Candidate allCandidates[MAX_NEIGHBORS];
    int countAll = 0;

    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        uint16_t neighborIdCandidate = neighborTable[i].neighborId;
        if (neighborIdCandidate == 0 ||
            neighborIdCandidate == localID ||
            neighborIdCandidate == excludeID ||
            !isAllowedNeighbor(neighborIdCandidate)) {
            continue;
        }
        allCandidates[countAll].id = neighborIdCandidate;
        allCandidates[countAll].score =
            getNeighborScore(neighborTable[i].rssi, neighborTable[i].lastHeard);
        countAll++;
    }
    if (countAll == 0) {
        return INVALID_NEXT_HOP;
    }

    for (int outer = 0; outer < (countAll - 1); outer++) {
        for (int inner = 0; inner < (countAll - 1 - outer); inner++) {
            if (allCandidates[inner].score < allCandidates[inner + 1].score) {
                Candidate temp = allCandidates[inner];
                allCandidates[inner] = allCandidates[inner + 1];
                allCandidates[inner + 1] = temp;
            }
        }
    }

    int topCount = (countAll > ROUTING_MAX_CANDIDATES) ? ROUTING_MAX_CANDIDATES : countAll;
    uint16_t chosen = allCandidates[random(0, topCount)].id;
    Serial.printf("[ROUTE] no route to %u, trying %u on link quality\n", destID, chosen);
    return chosen;
}

/*============================================================================*/
/*  Initialisation                                                            */
/*============================================================================*/
inline void initRoutingManager() {
    for (int i = 0; i < MAX_ROUTES; i++) {
        routingTable[i].inUse = false;
        nodeDirectory[i].inUse = false;
    }
    loadLocalNodeName();
    reserveRouteSeqBlock();
    Serial.printf("[ROUTE] distance-vector routing ready, own seq %u\n", localRouteSeq);
    Serial.printf("[MESH] this node is \"%s\" (%u)\n", localNodeName, getNodeID());
}

#endif
