#include "client.h"
#include "ZeroTierOne.h"
#include "World.hpp"
#include "Node.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

struct mzt_client {
    explicit mzt_client(const char *directory, mzt_frame callback, void *opaque)
        : home(directory), frame(callback), context(opaque) {}

    ~mzt_client() {
        if (node) ZT_Node_delete(node);
        if (ipv4 != -1) close(ipv4);
        if (ipv6 != -1) close(ipv6);
    }

    ZT_Node *node = nullptr;
    std::string home;
    mzt_frame frame;
    void *context;
    int ipv4 = -1;
    int ipv6 = -1;
    int64_t next_deadline = 0;
    bool storage_error = false;
};

namespace {
constexpr unsigned ether_ipv4 = 0x0800;
constexpr unsigned ether_arp = 0x0806;
constexpr uint64_t broadcast = 0xffffffffffff;

int protected_socket(int family, mzt_protect protect, void *context) {
    const int fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (!protect(context, fd)) {
        close(fd);
        return -1;
    }
    if (family == AF_INET) {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        if (bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) == 0) return fd;
    } else {
        sockaddr_in6 local{};
        local.sin6_family = AF_INET6;
        const int only_ipv6 = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only_ipv6, sizeof(only_ipv6)) == 0 &&
            bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) == 0) return fd;
    }
    close(fd);
    return -1;
}

std::string state_path(const mzt_client &client, ZT_StateObjectType type, const uint64_t *id) {
    if (type == ZT_STATE_OBJECT_IDENTITY_PUBLIC) return client.home + "/identity.public";
    if (type == ZT_STATE_OBJECT_IDENTITY_SECRET) return client.home + "/identity.secret";
    if (type == ZT_STATE_OBJECT_PLANET) return client.home + "/planet";
    if (!id) return {};
    char filename[32];
    if (type == ZT_STATE_OBJECT_NETWORK_CONFIG) {
        std::snprintf(filename, sizeof(filename), "/network-%016llx", static_cast<unsigned long long>(id[0]));
    } else if (type == ZT_STATE_OBJECT_MOON) {
        std::snprintf(filename, sizeof(filename), "/moon-%016llx", static_cast<unsigned long long>(id[0]));
    } else {
        return {}; // Peer caches are optional and do not have to touch flash.
    }
    return client.home + filename;
}

int state_get(ZT_Node *, void *owner, void *, ZT_StateObjectType type,
              const uint64_t *id, void *data, unsigned capacity) {
    auto &client = *static_cast<mzt_client *>(owner);
    const auto path = state_path(client, type, id);
    if (path.empty()) return -1;
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno != ENOENT) client.storage_error = true;
        return -1;
    }
    struct stat info {};
    int result = -1;
    if (fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_size >= 0 &&
        static_cast<uint64_t>(info.st_size) <= capacity) {
        const auto size = static_cast<size_t>(info.st_size);
        size_t total = 0;
        while (total < size) {
            const auto n = read(fd, static_cast<uint8_t *>(data) + total, size - total);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            total += static_cast<size_t>(n);
        }
        if (total == size) result = static_cast<int>(size);
    }
    close(fd);
    if (result < 0) client.storage_error = true;
    return result;
}

void state_put(ZT_Node *, void *owner, void *, ZT_StateObjectType type,
               const uint64_t *id, const void *data, int size) {
    auto &client = *static_cast<mzt_client *>(owner);
    const auto path = state_path(client, type, id);
    if (path.empty()) return;
    if (size < 0) {
        if (unlink(path.c_str()) < 0 && errno != ENOENT) client.storage_error = true;
        return;
    }
    auto temp = path + ".XXXXXX";
    const int fd = mkstemp(temp.data()); // 0600; an interrupted write cannot replace the identity.
    if (fd < 0) {
        client.storage_error = true;
        return;
    }
    const auto expected = static_cast<size_t>(size);
    size_t total = 0;
    while (total < expected) {
        const auto n = write(fd, static_cast<const uint8_t *>(data) + total, expected - total);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        total += static_cast<size_t>(n);
    }
    const bool saved = total == expected && fsync(fd) == 0;
    const int closed = close(fd);
    if (!saved || closed != 0 || rename(temp.c_str(), path.c_str()) != 0) {
        unlink(temp.c_str());
        client.storage_error = true;
    }
}

int wire_send(ZT_Node *, void *owner, void *, int64_t, const sockaddr_storage *remote,
              const void *data, unsigned size, unsigned ttl) {
    auto &client = *static_cast<mzt_client *>(owner);
    if (!remote) return -1;
    const int family = remote->ss_family;
    const int fd = family == AF_INET ? client.ipv4 : family == AF_INET6 ? client.ipv6 : -1;
    if (fd < 0) return -1;
    const auto len = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    // ZeroTier requests non-default hop limits when attempting UDP hole punching.
    const int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    const int option = family == AF_INET ? IP_TTL : IPV6_UNICAST_HOPS;
    int previous = 0;
    socklen_t previous_size = sizeof(previous);
    const int requested = static_cast<int>(std::min(ttl, 255u));
    const bool adjusted = requested &&
        getsockopt(fd, level, option, &previous, &previous_size) == 0 &&
        setsockopt(fd, level, option, &requested, sizeof(requested)) == 0;
    const auto sent = sendto(fd, data, size, 0, reinterpret_cast<const sockaddr *>(remote), len);
    if (adjusted) setsockopt(fd, level, option, &previous, sizeof(previous));
    return sent == static_cast<ssize_t>(size) ? 0 : -1;
}

ZT_Node_Callbacks callbacks() {
    ZT_Node_Callbacks cb{};
    cb.stateGetFunction = state_get;
    cb.statePutFunction = state_put;
    cb.wirePacketSendFunction = wire_send;
    cb.virtualNetworkFrameFunction = [](ZT_Node *, void *owner, void *, uint64_t network, void **,
        uint64_t from, uint64_t to, unsigned type, unsigned vlan, const void *data, unsigned size) {
        auto &client = *static_cast<mzt_client *>(owner);
        if (client.frame && vlan == 0 && (type == ether_arp || type == ether_ipv4)) {
            client.frame(client.context, network, from, to, type, static_cast<const uint8_t *>(data), size);
        }
    };
    cb.virtualNetworkConfigFunction = [](ZT_Node *, void *, void *, uint64_t, void **,
        ZT_VirtualNetworkConfigOperation, const ZT_VirtualNetworkConfig *) { return 0; };
    cb.eventCallback = [](ZT_Node *, void *, void *, ZT_Event, const void *) {};
    return cb;
}
} // namespace

mzt_client *mzt_open(const char *directory, mzt_protect protect, mzt_frame frame, void *context, int64_t now) {
    if (!directory || !*directory || !protect) return nullptr;
    try {
        auto client = std::make_unique<mzt_client>(directory, frame, context);
        client->ipv4 = protected_socket(AF_INET, protect, context);
        if (client->ipv4 < 0) return nullptr;
        client->ipv6 = protected_socket(AF_INET6, protect, context); // Optional physical IPv6.
        const auto config_callbacks = callbacks();
        const ZT_Node_Config config{};
        if (ZT_Node_new(&client->node, &config, client.get(), nullptr, &config_callbacks, now) != ZT_RESULT_OK ||
            client->storage_error) return nullptr;
        return client.release();
    } catch (...) {
        return nullptr;
    }
}

void mzt_close(mzt_client *client) { delete client; }
uint64_t mzt_address(const mzt_client *client) { return ZT_Node_address(client->node); }
int mzt_online(const mzt_client *client) {
    ZT_NodeStatus status{};
    ZT_Node_status(client->node, &status);
    return status.online != 0;
}

int mzt_join(mzt_client *c, uint64_t network) {
    return ZT_Node_join(c->node, network, nullptr, nullptr);
}
int mzt_leave(mzt_client *c, uint64_t network) {
    return ZT_Node_leave(c->node, network, nullptr, nullptr);
}
size_t mzt_peers(const mzt_client *c, mzt_peer_view *out, size_t capacity) {
    if (!c || !out || !capacity) return 0;
    auto *peers = ZT_Node_peers(c->node);
    if (!peers) return 0;
    size_t count = 0;
    for (size_t i = 0; i < peers->peerCount && count < capacity; ++i) {
        const auto &p = peers->peers[i];
        const uint32_t role = p.role == ZT_PEER_ROLE_PLANET ? 2 : (p.role == ZT_PEER_ROLE_MOON ? 1 : 0);
        uint64_t rx = 0;
        for (unsigned j = 0; j < p.pathCount && j < ZT_MAX_PEER_NETWORK_PATHS; ++j) {
            rx = std::max(rx, p.paths[j].lastReceive);
        }
        out[count++] = {p.address, rx, role, p.latency};
    }
    ZT_Node_freeQueryResult(c->node, peers);
    return count;
}

size_t mzt_moon_roots(mzt_client *c, uint64_t world, mzt_moon_root *out, size_t capacity) {
    if (!c || !out || !capacity || !world) return 0;
    try {
        // The pinned SDK documents its opaque C node as this C++ instance.
        const auto worlds = reinterpret_cast<ZeroTier::Node *>(c->node)->moons();
        const auto found = std::find_if(worlds.begin(), worlds.end(),
            [world](const auto &w) { return w.id() == world; });
        if (found == worlds.end()) return 0;
        const auto count = std::min(capacity, found->roots().size());
        for (size_t i = 0; i < count; ++i) {
            out[i] = {found->roots()[i].identity.address().toInt(), 0};
        }
        auto *peers = ZT_Node_peers(c->node);
        if (!peers) return count;
        for (unsigned long i = 0; i < peers->peerCount; ++i) {
            const auto &peer = peers->peers[i];
            if (peer.role != ZT_PEER_ROLE_MOON) continue;
            const auto root = std::find_if(out, out + count,
                [&peer](const auto &candidate) { return candidate.address == peer.address; });
            if (root == out + count) continue;
            for (unsigned j = 0; j < peer.pathCount && j < ZT_MAX_PEER_NETWORK_PATHS; ++j) {
                root->last_receive_ms = std::max(root->last_receive_ms, peer.paths[j].lastReceive);
            }
        }
        ZT_Node_freeQueryResult(c->node, peers);
        return count;
    } catch (...) {
        return 0;
    }
}

uint64_t mzt_moon_id(const uint8_t *bytes, size_t size) {
    if (!bytes || !size || size > ZT_WORLD_MAX_SERIALIZED_LENGTH) return 0;
    try {
        ZeroTier::World world;
        const ZeroTier::Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH> encoded(bytes, static_cast<unsigned>(size));
        if (world.deserialize(encoded) != size || world.type() != ZeroTier::World::TYPE_MOON ||
            !world.id() || world.roots().empty()) return 0;
        for (const auto &root : world.roots()) {
            if (root.identity.hasPrivate() || !root.identity.locallyValidate()) return 0;
        }
        return world.id();
    } catch (...) {
        return 0;
    }
}

int mzt_install_moon(mzt_client *c, uint64_t world, const uint8_t *bytes, size_t size) {
    if (!world || mzt_moon_id(bytes, size) != world) return -1;
    const uint64_t id[2] = {world, 0};
    std::array<uint8_t, ZT_WORLD_MAX_SERIALIZED_LENGTH> cached{};
    const auto count = state_get(c->node, c, nullptr, ZT_STATE_OBJECT_MOON, id, cached.data(), cached.size());
    if (count > 0 && mzt_moon_id(cached.data(), static_cast<size_t>(count)) == world) {
        // Keep any authenticated upstream update over the original import.
        return 0;
    }
    state_put(c->node, c, nullptr, ZT_STATE_OBJECT_MOON, id, bytes, static_cast<int>(size));
    return c->storage_error ? -1 : 0;
}

int mzt_orbit(mzt_client *c, uint64_t world, uint64_t seed) {
    return ZT_Node_orbit(c->node, nullptr, world, seed);
}
int mzt_deorbit(mzt_client *c, uint64_t world) {
    if (!world) return -1;
    const auto result = ZT_Node_deorbit(c->node, nullptr, world);
    if (result != ZT_RESULT_OK) return result;
    // The engine only deletes a loaded World. Offline retirement must remove
    // a cached definition as well, even just after a reboot.
    const uint64_t id[2] = {world, 0};
    state_put(c->node, c, nullptr, ZT_STATE_OBJECT_MOON, id, nullptr, -1);
    return c->storage_error ? -1 : 0;
}
int mzt_network(const mzt_client *c, uint64_t network, mzt_network_view *result) {
    if (!result) return 0;
    const auto *view = ZT_Node_networkConfig(c->node, network);
    if (!view) return 0;
    *result = {};
    result->mac = view->mac;
    result->status = static_cast<int>(view->status);
    result->mtu = view->mtu;
    result->flags = (view->type == ZT_NETWORK_TYPE_PUBLIC ? 1u : 0u)
        | (view->broadcastEnabled ? 2u : 0u) | (view->bridge ? 4u : 0u);
    for (size_t i = 0; i < sizeof(result->name) - 1 && i < sizeof(view->name) && view->name[i]; ++i) {
        result->name[i] = view->name[i];
    }
    for (unsigned i = 0; i < view->assignedAddressCount; ++i) {
        const auto &a = view->assignedAddresses[i];
        if (a.ss_family == AF_INET) {
            const auto &ip = reinterpret_cast<const sockaddr_in &>(a);
            const auto address = ntohl(ip.sin_addr.s_addr);
            const auto bits = ntohs(ip.sin_port);
            if (address && bits > 0 && bits <= 32) {
                result->first_ipv4 = address;
                result->first_ipv4_prefix = bits;
                break;
            }
        }
    }
    ZT_Node_freeQueryResult(c->node, const_cast<ZT_VirtualNetworkConfig *>(view));
    return 1;
}
size_t mzt_routes(const mzt_client *c, uint64_t network, mzt_route *out, size_t capacity) {
    if (!out || !capacity) return 0;
    const auto *view = ZT_Node_networkConfig(c->node, network);
    if (!view) return 0;
    size_t count = 0;
    if (view->status == ZT_NETWORK_STATUS_OK) {
        for (unsigned i = 0; i < view->routeCount && i < ZT_MAX_NETWORK_ROUTES && count < capacity; ++i) {
            const auto &route = view->routes[i];
            if (route.target.ss_family != AF_INET) continue;
            const auto &target = reinterpret_cast<const sockaddr_in &>(route.target);
            const auto bits = ntohs(target.sin_port);
            if (bits > 32) continue;
            uint32_t via = 0;
            if (route.via.ss_family == AF_INET) {
                via = ntohl(reinterpret_cast<const sockaddr_in &>(route.via).sin_addr.s_addr);
                if (!via) continue;
            } else if (route.via.ss_family != AF_UNSPEC) {
                continue;
            }
            out[count++] = {ntohl(target.sin_addr.s_addr), via, bits};
        }
    }
    ZT_Node_freeQueryResult(c->node, const_cast<ZT_VirtualNetworkConfig *>(view));
    return count;
}
size_t mzt_dns_ipv4(const mzt_client *c, uint64_t network, uint32_t *out, size_t capacity) {
    if (!out || !capacity) return 0;
    const auto *view = ZT_Node_networkConfig(c->node, network);
    if (!view) return 0;
    size_t count = 0;
    if (view->status == ZT_NETWORK_STATUS_OK) {
        for (size_t i = 0; i < ZT_MAX_DNS_SERVERS && count < capacity; ++i) {
            const auto &address = view->dns.server_addr[i];
            if (address.ss_family == AF_INET) {
                out[count++] = ntohl(reinterpret_cast<const sockaddr_in &>(address).sin_addr.s_addr);
            }
        }
    }
    ZT_Node_freeQueryResult(c->node, const_cast<ZT_VirtualNetworkConfig *>(view));
    return count;
}
int mzt_step(mzt_client *c, int64_t now) {
    if (c->storage_error) return -1;
    std::array<uint8_t, 4096> packet{};
    for (const int fd : {c->ipv4, c->ipv6}) {
        if (fd < 0) continue;
        for (unsigned i = 0; i < 64; ++i) {
            sockaddr_storage remote{};
            socklen_t len = sizeof(remote);
            const auto n = recvfrom(fd, packet.data(), packet.size(), MSG_TRUNC,
                                    reinterpret_cast<sockaddr *>(&remote), &len);
            if (n < 0) break;
            if (n == 0 || static_cast<size_t>(n) > packet.size()) continue;
            const auto rc = ZT_Node_processWirePacket(c->node, nullptr, now, fd, &remote,
                packet.data(), static_cast<unsigned>(n), &c->next_deadline);
            if (ZT_ResultCode_isFatal(rc)) return rc;
        }
    }
    if (now >= c->next_deadline) {
        return ZT_Node_processBackgroundTasks(c->node, nullptr, now, &c->next_deadline);
    }
    return 0;
}

int mzt_ipv4_frame(mzt_client *c, int64_t now, uint64_t network, uint64_t from,
                   uint64_t to, unsigned type, const uint8_t *data, size_t size) {
    if (!from || !to || to == from || !data || !size || size > 1500 ||
        (type != ether_arp && type != ether_ipv4)) return -1;
    mzt_network_view view{};
    if (!mzt_network(c, network, &view) || view.status != ZT_NETWORK_STATUS_OK || from != view.mac ||
        (view.mtu && size > view.mtu)) return -1;
    return ZT_Node_processVirtualNetworkFrame(c->node, nullptr, now, network, from, to, type, 0, data,
                                             static_cast<unsigned>(size), &c->next_deadline);
}

int mzt_subscribe_arp(mzt_client *c, uint64_t network, uint32_t address) {
    if (!address) return -1;
    return ZT_Node_multicastSubscribe(c->node, nullptr, network, broadcast, address);
}
