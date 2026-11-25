#include "client.h"
#include "ZeroTierOne.h"
#include "World.hpp"

#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <sys/stat.h>
#include <fcntl.h>

namespace {
void require(bool result, const char *why) {
    if (!result) {
        std::fprintf(stderr, "%s\n", why);
        std::exit(1);
    }
}

struct Protector {
    bool permit;
    unsigned calls = 0;
};

int protect(void *context, int fd) {
    auto &p = *static_cast<Protector *>(context);
    require((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0, "socket must not survive exec");
    require((fcntl(fd, F_GETFL) & O_NONBLOCK) != 0, "socket must not block the node worker");
    ++p.calls;
    return p.permit;
}
} // namespace

int main() {
    char tmp[] = "/tmp/meowz-zt-test-XXXXXX";
    require(mkdtemp(tmp) != nullptr, "create scratch directory");
    constexpr auto now = 1'700'000'000'000LL;
    constexpr uint64_t network = 0x123456789a000001;
    Protector rejected{false};
    require(mzt_open(tmp, protect, nullptr, &rejected, now) == nullptr, "reject unprotected UDP");
    require(rejected.calls == 1, "ask platform to protect before creating node");
    require(std::filesystem::is_empty(tmp), "no identity created without protection");

    Protector permitted{true};
    auto *client = mzt_open(tmp, protect, nullptr, &permitted, now);
    require(client && permitted.calls >= 1, "create node with protected UDP");
    int ipv4 = -1, ipv6 = -1;
    int64_t deadline = -1;
    mzt_poll_state(client, &ipv4, &ipv6, &deadline);
    require(ipv4 >= 0 && deadline == 0, "expose the initial protected UDP and startup deadline");
    require((fcntl(ipv4, F_GETFL) & O_NONBLOCK) != 0, "borrowed UDP descriptor must not block");
    if (ipv6 >= 0) {
        require((fcntl(ipv6, F_GETFL) & O_NONBLOCK) != 0, "borrowed IPv6 UDP descriptor must not block");
    }
    constexpr uint64_t moon_id = 0x123456789a;
    ZeroTier::Identity identity;
    identity.generate();
    ZeroTier::World::Root root;
    char public_identity[ZT_IDENTITY_STRING_BUFFER_LENGTH]{};
    root.identity = ZeroTier::Identity(identity.toString(false, public_identity));
    const auto keys = ZeroTier::ECC::generate();
    const auto moon = ZeroTier::World::make(ZeroTier::World::TYPE_MOON, moon_id, now, keys.pub, {root}, keys);
    ZeroTier::Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH> moon_bytes;
    moon.serialize(moon_bytes);
    const auto *encoded_moon = static_cast<const uint8_t *>(moon_bytes.data());
    require(mzt_moon_id(encoded_moon, moon_bytes.size()) == moon_id, "validate generated Moon");
    require(!mzt_moon_id(encoded_moon, moon_bytes.size() - 1), "reject truncated Moon");
    require(mzt_install_moon(client, moon_id + 1, encoded_moon, moon_bytes.size()) != 0,
            "reject mismatched World ID");
    require(mzt_install_moon(client, moon_id, encoded_moon, moon_bytes.size()) == 0, "persist Moon");
    const auto moon_file = std::filesystem::path(tmp) / "moon-000000123456789a";
    require(std::filesystem::exists(moon_file), "stored Moon under canonical file");
    require(mzt_orbit(client, moon_id, 0) == ZT_RESULT_OK, "load stored Moon");
    mzt_moon_root roots[4]{};
    require(mzt_moon_roots(client, moon_id, roots, 4) == 1 &&
            roots[0].address == root.identity.address().toInt() && roots[0].last_receive_ms == 0,
            "loaded root remains distinct from reachable root");
    const auto address = mzt_address(client);
    require(address != 0, "read node identity");
    const auto private_file = std::filesystem::path(tmp) / "identity.secret";
    struct stat actual{};
    require(stat(private_file.c_str(), &actual) == 0 && (actual.st_mode & 0777) == 0600,
            "identity is durable and mode 0600");
    require(mzt_join(client, network) == ZT_RESULT_OK, "request join");
    mzt_network_view view{};
    require(mzt_network(client, network, &view) == 1 && view.status == ZT_NETWORK_STATUS_REQUESTING_CONFIGURATION,
            "pending network is not connected");
    const uint8_t frame[] = {0x45};
    require(mzt_ipv4_frame(client, now, network, view.mac, 0xffffffffffff, 0x0800, frame, sizeof(frame)) != 0,
            "block frames before authorization");
    require(mzt_leave(client, network) == ZT_RESULT_OK, "leave");
    mzt_close(client);

    client = mzt_open(tmp, protect, nullptr, &permitted, now + 100);
    require(client && mzt_address(client) == address, "same private identity after restart");
    require(mzt_network(client, network, &view) == 0, "left network remains absent");
    require(mzt_moon_roots(client, moon_id, roots, 4) == 0, "restart does not auto-load Moon");
    require(mzt_orbit(client, moon_id, 0) == ZT_RESULT_OK &&
            mzt_moon_roots(client, moon_id, roots, 4) == 1, "restore cached Moon by explicit orbit");
    require(mzt_deorbit(client, moon_id) == ZT_RESULT_OK, "deorbit cached Moon after restart");
    require(mzt_moon_roots(client, moon_id, roots, 4) == 0, "world no longer loaded after deorbit");
    require(!std::filesystem::exists(moon_file), "deorbit removes cached Moon even if not loaded");
    mzt_close(client);
    client = mzt_open(tmp, protect, nullptr, &permitted, now + 200);
    require(client && !std::filesystem::exists(moon_file), "removed Moon does not come back on restart");
    mzt_close(client);
    std::filesystem::remove_all(tmp);
}
