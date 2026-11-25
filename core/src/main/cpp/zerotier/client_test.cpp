#include "client.h"
#include "ZeroTierOne.h"

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
    mzt_close(client);
    std::filesystem::remove_all(tmp);
}
