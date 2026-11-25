#ifndef MEOWZ_ZEROTIER_CLIENT_H
#define MEOWZ_ZEROTIER_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mzt_client mzt_client;

/* Return nonzero only after the host has exempted the socket from the VPN. */
typedef int (*mzt_protect)(void *context, int fd);
/* Callback may copy the bytes into a bounded queue; it must not call the client. */
typedef void (*mzt_frame)(void *context, uint64_t network, uint64_t from,
                          uint64_t to, unsigned type, const uint8_t *data, size_t size);
typedef struct {
    uint64_t mac;
    uint32_t first_ipv4; /* host byte order; zero if absent */
    int status;          /* native ZT_VirtualNetworkStatus */
    unsigned mtu;
    unsigned first_ipv4_prefix;
    unsigned flags;
    char name[128];
} mzt_network_view;

typedef struct {
    uint32_t target;
    uint32_t via; /* host byte order; zero for on-link */
    unsigned prefix;
} mzt_route;

typedef struct {
    uint64_t address;
    uint64_t last_receive_ms; /* zero if no authenticated packets received */
} mzt_moon_root;

typedef struct {
    uint64_t address;
    uint64_t last_receive_ms;
    uint32_t role; /* 0 leaf, 1 moon, 2 planet */
    int32_t latency_ms;
} mzt_peer_view;
size_t mzt_peers(const mzt_client *client, mzt_peer_view *out, size_t capacity);

/* Returns the number of roots for a world actually loaded into the node.
 * A loaded root may have last_receive_ms == 0; loading is not reachability. */
size_t mzt_moon_roots(mzt_client *client, uint64_t world, mzt_moon_root *out, size_t capacity);

/* Calls must be serialized on the owning worker. The directory must already
 * exist and be private app storage. No socket may send without protect(). */
mzt_client *mzt_open(const char *directory, mzt_protect protect, mzt_frame frame,
                     void *context, int64_t now);
void mzt_close(mzt_client *client);
uint64_t mzt_address(const mzt_client *client);
int mzt_online(const mzt_client *client);
int mzt_join(mzt_client *client, uint64_t network);
int mzt_leave(mzt_client *client, uint64_t network);
/* Inspect an explicitly approved local .moon definition without a running node.
 * Zero is invalid. An import authorizes its root keys; this is not a statement
 * that the roots are online or endorsed by the default planet. */
uint64_t mzt_moon_id(const uint8_t *bytes, size_t size);
int mzt_install_moon(mzt_client *client, uint64_t world, const uint8_t *bytes, size_t size);
int mzt_orbit(mzt_client *client, uint64_t world, uint64_t seed);
int mzt_deorbit(mzt_client *client, uint64_t world);
int mzt_network(const mzt_client *client, uint64_t network, mzt_network_view *result);
size_t mzt_routes(const mzt_client *client, uint64_t network, mzt_route *out, size_t capacity);
size_t mzt_dns_ipv4(const mzt_client *client, uint64_t network, uint32_t *out, size_t capacity);
/* Borrowed, nonblocking UDP sockets and SDK deadline, only on the owner thread. */
void mzt_poll_state(const mzt_client *client, int *ipv4, int *ipv6, int64_t *deadline);

/* Drain a bounded amount of UDP I/O and service deadlines. Zero means OK. */
int mzt_step(mzt_client *client, int64_t now);
int mzt_ipv4_frame(mzt_client *client, int64_t now, uint64_t network, uint64_t from,
                   uint64_t to, unsigned type, const uint8_t *data, size_t size);
/* ARP is subscribed by protocol and target IPv4, not as all Ethernet traffic. */
int mzt_subscribe_arp(mzt_client *client, uint64_t network, uint32_t address);

#ifdef __cplusplus
}
#endif
#endif
