#include "ZeroTierOne.h"
#include "NetworkController.hpp"
#include "World.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace ZeroTier;

void require(bool condition, const char *message) {
    if (!condition) {
        std::fprintf(stderr, "%s\n", message);
        std::exit(1);
    }
}

constexpr int64_t epoch = 1'800'000'000'000;
using Key = std::array<uint64_t, 3>;
using Bytes = std::vector<uint8_t>;

Key key(ZT_StateObjectType type, const uint64_t *id) {
    if (type == ZT_STATE_OBJECT_IDENTITY_PUBLIC || type == ZT_STATE_OBJECT_IDENTITY_SECRET ||
        type == ZT_STATE_OBJECT_PLANET) return {static_cast<uint64_t>(type), 0, 0};
    return {static_cast<uint64_t>(type), id[0], id[1]};
}

struct Datagram {
    InetAddress source;
    InetAddress destination;
    Bytes payload;
};

struct Device {
    std::deque<Datagram> &wire;
    InetAddress endpoint;
    std::map<Key, Bytes> persisted;
    ZT_Node *node = nullptr;
    int64_t deadline = 0;
    std::vector<Bytes> frames;

    Device(std::deque<Datagram> &wire, const char *endpoint) : wire(wire), endpoint(endpoint) {}
    ~Device() { if (node) ZT_Node_delete(node); }

    void boot(const Bytes &planet, int64_t now) {
        if (node) ZT_Node_delete(node);
        node = nullptr;
        persisted[key(ZT_STATE_OBJECT_PLANET, nullptr)] = planet;
        ZT_Node_Callbacks cb{};
        cb.stateGetFunction = [](ZT_Node *, void *owner, void *, ZT_StateObjectType type,
                                 const uint64_t *id, void *output, unsigned size) {
            const auto &state = static_cast<Device *>(owner)->persisted;
            const auto it = state.find(key(type, id));
            if (it == state.end() || it->second.size() > size) return -1;
            std::copy(it->second.begin(), it->second.end(), static_cast<uint8_t *>(output));
            return static_cast<int>(it->second.size());
        };
        cb.statePutFunction = [](ZT_Node *, void *owner, void *, ZT_StateObjectType type,
                                 const uint64_t *id, const void *input, int size) {
            auto &state = static_cast<Device *>(owner)->persisted;
            if (size < 0) state.erase(key(type, id));
            else if (size == 0) state[key(type, id)].clear();
            else {
                const auto *p = static_cast<const uint8_t *>(input);
                state[key(type, id)] = Bytes(p, p + size);
            }
        };
        cb.wirePacketSendFunction = [](ZT_Node *, void *owner, void *, int64_t, const sockaddr_storage *to,
                                       const void *payload, unsigned size, unsigned) {
            auto &self = *static_cast<Device *>(owner);
            if (self.wire.size() >= 4096) return -1;
            const auto *p = static_cast<const uint8_t *>(payload);
            self.wire.push_back({self.endpoint, InetAddress(*to), Bytes(p, p + size)});
            return 0;
        };
        cb.virtualNetworkFrameFunction = [](ZT_Node *, void *owner, void *, uint64_t, void **, uint64_t,
                                           uint64_t, unsigned ether_type, unsigned, const void *data, unsigned size) {
            if (ether_type == 0x0800) {
                const auto *p = static_cast<const uint8_t *>(data);
                static_cast<Device *>(owner)->frames.emplace_back(p, p + size);
            }
        };
        cb.virtualNetworkConfigFunction = [](ZT_Node *, void *, void *, uint64_t, void **,
                                             ZT_VirtualNetworkConfigOperation,
                                             const ZT_VirtualNetworkConfig *) { return 0; };
        cb.eventCallback = [](ZT_Node *, void *, void *, ZT_Event, const void *) {};
        const ZT_Node_Config options{};
        require(ZT_Node_new(&node, &options, this, nullptr, &cb, now) == ZT_RESULT_OK, "boot SDK node");
        deadline = 0;
    }

    void tick(int64_t now) {
        if (now >= deadline)
            require(ZT_Node_processBackgroundTasks(node, nullptr, now, &deadline) == ZT_RESULT_OK, "process SDK tasks");
    }
    void receive(const Datagram &packet, int64_t now) {
        require(ZT_Node_processWirePacket(node, nullptr, now, 0, &packet.source,
                   packet.payload.data(), packet.payload.size(), &deadline) == ZT_RESULT_OK, "receive SDK datagram");
    }
    uint64_t address() const { return ZT_Node_address(node); }
    ZT_VirtualNetworkConfig config(uint64_t network) const {
        auto *value = ZT_Node_networkConfig(node, network);
        require(value != nullptr, "network is present");
        const auto result = *value;
        ZT_Node_freeQueryResult(node, value);
        return result;
    }
};

struct Controller final : NetworkController {
    Identity signer;
    Sender *sender = nullptr;
    uint64_t network = 0;
    uint64_t member = 0;
    unsigned denied = 0;
    unsigned allowed = 0;
    int64_t now = epoch;
    bool authorize = false;

    void init(const Identity &id, Sender *s) override {
        signer = id;
        sender = s;
        network = (id.address().toInt() << 24) | 0x000001;
    }
    void request(uint64_t net, const InetAddress &, uint64_t packet, const Identity &id,
                 const Dictionary<ZT_NETWORKCONFIG_METADATA_DICT_CAPACITY> &) override {
        require(net == network, "controller received expected network request");
        const bool self = id.address() == signer.address();
        require(self || id.address().toInt() == member, "request uses actual member identity");
        if (!self && !authorize) {
            ++denied;
            sender->ncSendError(net, packet, id.address(), NC_ERROR_ACCESS_DENIED, nullptr, 0);
            return;
        }
        if (!self) ++allowed;
        NetworkConfig config{};
        config.networkId = net;
        config.timestamp = now;
        config.revision = 1;
        config.issuedTo = id.address();
        config.type = ZT_NETWORK_TYPE_PRIVATE;
        config.mtu = 1400;
        config.credentialTimeMaxDelta = 600000;
        config.ruleCount = 1;
        config.rules[0].t = ZT_NETWORK_RULE_ACTION_ACCEPT;
        config.staticIpCount = 1;
        config.staticIps[0] = InetAddress(self ? "10.203.0.1/24" : "10.203.0.2/24");
        config.com = CertificateOfMembership(now, 600000, net, id);
        require(config.com.sign(signer), "sign member certificate");
        sender->ncSendConfig(net, packet, id.address(), config, false);
    }
};

Bytes encode(const World &world) {
    Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH> buffer;
    world.serialize(buffer);
    const auto *p = reinterpret_cast<const uint8_t *>(buffer.data());
    return Bytes(p, p + buffer.size());
}
} // namespace

int main() {
    // The fabric feeds actual encrypted ZeroTier datagrams to the SDK, but
    // never opens a socket or contacts an external controller or root.
    std::deque<Datagram> wire;
    Controller controller;
    Device root(wire, "192.168.250.1/9993"), client(wire, "192.168.250.2/9993");
    Device moon(wire, "192.168.250.3/9993");
    const auto make_root = [](Device &device) {
        Identity identity;
        identity.generate();
        char secret[ZT_IDENTITY_STRING_BUFFER_LENGTH]{}, public_id[ZT_IDENTITY_STRING_BUFFER_LENGTH]{};
        identity.toString(true, secret);
        device.persisted[key(ZT_STATE_OBJECT_IDENTITY_SECRET, nullptr)] =
            Bytes(secret, secret + std::char_traits<char>::length(secret));
        World::Root root_identity;
        root_identity.identity = Identity(identity.toString(false, public_id));
        root_identity.stableEndpoints.push_back(device.endpoint);
        return root_identity;
    };
    const auto root_identity = make_root(root);
    const auto moon_identity = make_root(moon);
    const auto authority = ECC::generate();
    const auto planet = encode(World::make(World::TYPE_PLANET, 0x10203040, epoch, authority.pub, {root_identity}, authority));
    root.boot(planet, epoch);
    client.boot(planet, epoch);
    moon.boot(planet, epoch);
    const auto moon_id = moon.address();
    const auto moon_authority = ECC::generate();
    const auto moon_world = encode(World::make(World::TYPE_MOON, moon_id, epoch, moon_authority.pub,
                                                  {moon_identity}, moon_authority));
    const Key moon_key{ZT_STATE_OBJECT_MOON, moon_id, 0};
    moon.persisted[moon_key] = moon_world;
    client.persisted[moon_key] = moon_world;
    require(ZT_Node_orbit(moon.node, nullptr, moon_id, 0) == ZT_RESULT_OK, "start isolated Moon");
    require(ZT_Node_orbit(client.node, nullptr, moon_id, 0) == ZT_RESULT_OK, "orbit isolated Moon");
    ZT_Node_setNetconfMaster(root.node, &controller);
    controller.member = client.address();
    const auto network = controller.network;
    require(ZT_Node_join(root.node, network, nullptr, nullptr) == ZT_RESULT_OK, "controller joins");
    require(ZT_Node_join(client.node, network, nullptr, nullptr) == ZT_RESULT_OK, "client requests membership");
    require(client.config(network).status == ZT_NETWORK_STATUS_REQUESTING_CONFIGURATION,
            "pending join does not imply membership");

    int64_t clock = epoch;
    const auto step = [&] {
        clock += 100;
        controller.now = clock;
        root.tick(clock);
        client.tick(clock);
        moon.tick(clock);
        for (unsigned budget = 4096; !wire.empty() && budget; --budget) {
            auto packet = std::move(wire.front());
            wire.pop_front();
            if (packet.destination == root.endpoint) root.receive(packet, clock);
            else if (packet.destination == client.endpoint) client.receive(packet, clock);
            else if (packet.destination == moon.endpoint) moon.receive(packet, clock);
            else require(false, "test fabric must not select any external peer");
        }
        require(wire.empty(), "drain fabric within test budget");
    };
    const auto wait_for = [&](const auto &ready, const char *failure) {
        for (unsigned attempts = 0; !ready() && attempts < 1500; ++attempts) step();
        require(ready(), failure);
    };
    wait_for([&] { return client.config(network).status == ZT_NETWORK_STATUS_ACCESS_DENIED; },
             "unauthorized join receives explicit rejection");
    require(controller.denied > 0 && root.frames.empty(), "rejected membership forwards nothing");

    controller.authorize = true;
    require(ZT_Node_leave(client.node, network, nullptr, nullptr) == ZT_RESULT_OK, "retry leaves old status");
    require(ZT_Node_join(client.node, network, nullptr, nullptr) == ZT_RESULT_OK, "retry authorized join");
    wait_for([&] { return client.config(network).status == ZT_NETWORK_STATUS_OK; },
             "client completes authenticated membership");
    const auto root_view = root.config(network), client_view = client.config(network);
    require(controller.allowed > 0 && root_view.status == ZT_NETWORK_STATUS_OK,
            "both members have private network configuration");
    require(client_view.assignedAddressCount == 1 &&
            InetAddress(client_view.assignedAddresses[0]) == InetAddress("10.203.0.2/24"),
            "member receives its assigned address from the controller");
    const Bytes outbound{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 203, 0, 2, 10, 203, 0, 1};
    const Bytes reply{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 203, 0, 1, 10, 203, 0, 2};
    const auto send = [&](Device &source, uint64_t src, uint64_t dst, const Bytes &payload) {
        require(ZT_Node_processVirtualNetworkFrame(source.node, nullptr, clock, network, src, dst,
                    0x0800, 0, payload.data(), payload.size(), &source.deadline) == ZT_RESULT_OK,
                "submit device frame to SDK");
    };
    for (unsigned i = 0; root.frames.empty() && i < 20; ++i) {
        send(client, client_view.mac, root_view.mac, outbound);
        for (unsigned j = 0; root.frames.empty() && j < 20; ++j) step();
    }
    require(!root.frames.empty() && root.frames.front() == outbound, "controller member sees exact client frame");
    for (unsigned i = 0; client.frames.empty() && i < 20; ++i) {
        send(root, root_view.mac, client_view.mac, reply);
        for (unsigned j = 0; client.frames.empty() && j < 20; ++j) step();
    }
    require(!client.frames.empty() && client.frames.front() == reply, "client sees exact peer reply");
    require(ZT_Node_leave(client.node, network, nullptr, nullptr) == ZT_RESULT_OK, "leave authorized network");
    require(!ZT_Node_networkConfig(client.node, network), "removed authorized membership");
    client.frames.clear();
    send(root, root_view.mac, client_view.mac, reply);
    for (unsigned i = 0; i < 20; ++i) step();
    require(client.frames.empty(), "left member no longer receives frames");

    const auto recent_moon = [&] {
        auto *peers = ZT_Node_peers(client.node);
        if (!peers) return false;
        bool recently_seen = false;
        for (unsigned i = 0; i < peers->peerCount; ++i) {
            const auto &peer = peers->peers[i];
            if (peer.address != moon_id || peer.role != ZT_PEER_ROLE_MOON) continue;
            for (unsigned j = 0; j < peer.pathCount; ++j)
                recently_seen |= peer.paths[j].lastReceive >= static_cast<uint64_t>(epoch) &&
                                 InetAddress(peer.paths[j].address) == moon.endpoint;
        }
        ZT_Node_freeQueryResult(client.node, peers);
        return recently_seen;
    };
    wait_for(recent_moon, "orbit performs authenticated IO to the configured Moon root");
    require(ZT_Node_deorbit(client.node, nullptr, moon_id) == ZT_RESULT_OK, "remove contacted Moon");
    require(!recent_moon(), "removed root must no longer retain Moon role");
    require(client.persisted.count(moon_key) == 0, "deorbit retires the cached world");
    client.boot(planet, clock);
    for (unsigned i = 0; i < 100; ++i) step();
    require(!recent_moon(), "restart does not restore removed Moon role");
}

