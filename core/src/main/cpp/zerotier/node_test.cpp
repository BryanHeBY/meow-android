#include "ZeroTierOne.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <tuple>
#include <vector>

namespace {
using Key = std::tuple<ZT_StateObjectType, uint64_t, uint64_t>;

struct Harness {
    std::map<Key, std::vector<uint8_t>> objects;
    unsigned frame_count = 0;
};

Key storage_key(ZT_StateObjectType type, const uint64_t *id) {
    switch (type) {
        case ZT_STATE_OBJECT_IDENTITY_PUBLIC:
        case ZT_STATE_OBJECT_IDENTITY_SECRET:
        case ZT_STATE_OBJECT_PLANET:
            // The SDK writes identities with the assigned address but reads
            // them before it knows that address. These are singleton objects.
            return {type, 0, 0};
        default:
            return {type, id[0], id[1]};
    }
}

void require(bool condition, const char *reason) {
    if (!condition) {
        std::fprintf(stderr, "%s\n", reason);
        std::exit(1);
    }
}

ZT_Node_Callbacks make_callbacks() {
    ZT_Node_Callbacks cb{};
    cb.statePutFunction = [](ZT_Node *, void *owner, void *, ZT_StateObjectType type,
                            const uint64_t *id, const void *data, int size) {
        auto &objects = static_cast<Harness *>(owner)->objects;
        const auto key = storage_key(type, id);
        if (size < 0) {
            objects.erase(key);
        } else if (size == 0) {
            objects[key].clear();
        } else {
            const auto *begin = static_cast<const uint8_t *>(data);
            objects[key].assign(begin, begin + size);
        }
    };
    cb.stateGetFunction = [](ZT_Node *, void *owner, void *, ZT_StateObjectType type,
                            const uint64_t *id, void *output, unsigned size) {
        auto &objects = static_cast<Harness *>(owner)->objects;
        const auto it = objects.find(storage_key(type, id));
        if (it == objects.end() || it->second.size() > size) return -1;
        std::copy(it->second.begin(), it->second.end(), static_cast<uint8_t *>(output));
        return static_cast<int>(it->second.size());
    };
    cb.wirePacketSendFunction = [](ZT_Node *, void *, void *, int64_t,
                                   const sockaddr_storage *, const void *, unsigned, unsigned) {
        return -1; // No Internet or actual user network in this test.
    };
    cb.virtualNetworkFrameFunction = [](ZT_Node *, void *owner, void *, uint64_t, void **,
                                        uint64_t, uint64_t, unsigned, unsigned,
                                        const void *, unsigned) {
        ++static_cast<Harness *>(owner)->frame_count;
    };
    cb.virtualNetworkConfigFunction = [](ZT_Node *, void *, void *, uint64_t, void **,
                                         ZT_VirtualNetworkConfigOperation,
                                         const ZT_VirtualNetworkConfig *) { return 0; };
    cb.eventCallback = [](ZT_Node *, void *, void *, ZT_Event, const void *) {};
    return cb;
}
} // namespace

int main() {
    Harness harness;
    const auto callbacks = make_callbacks();
    const ZT_Node_Config options{};
    ZT_Node *node = nullptr;
    constexpr uint64_t network = 0x123456789a000001;
    constexpr uint64_t moon = 0xabcdef1234;
    constexpr int64_t now = 1'700'000'000'000;

    require(ZT_Node_new(&node, &options, &harness, nullptr, &callbacks, now) ==
                ZT_RESULT_OK && node, "create client node");
    const auto address = ZT_Node_address(node);
    require(address != 0, "assign a node identity");
    require(ZT_Node_join(node, network, nullptr, nullptr) == ZT_RESULT_OK, "request network join");
    auto *cfg = ZT_Node_networkConfig(node, network);
    require(cfg && cfg->nwid == network, "observe requested network");
    require(cfg->status == ZT_NETWORK_STATUS_REQUESTING_CONFIGURATION,
            "an unapproved request must not appear ready");
    ZT_Node_freeQueryResult(node, cfg);
    require(ZT_Node_orbit(node, nullptr, moon, moon) == ZT_RESULT_OK, "request a Moon orbit");
    require(ZT_Node_deorbit(node, nullptr, moon) == ZT_RESULT_OK, "remove requested Moon orbit");
    require(ZT_Node_leave(node, network, nullptr, nullptr) == ZT_RESULT_OK, "leave network");
    require(ZT_Node_networkConfig(node, network) == nullptr, "forget left network");
    require(harness.frame_count == 0, "no forwarding on an unapproved network");
    ZT_Node_delete(node);

    node = nullptr;
    require(ZT_Node_new(&node, &options, &harness, nullptr, &callbacks, now + 100) ==
                ZT_RESULT_OK && node, "restart client node");
    require(ZT_Node_address(node) == address, "persist node identity across restarts");
    require(ZT_Node_networkConfig(node, network) == nullptr, "do not restore a left network");
    ZT_Node_delete(node);
}
