// Native user networking for QEMU's framed Unix stream netdev. The rules-mode
// launcher loads cogbox's dyld socket filter into this process before main.
// No shell, subprocess, TAP device, vmnet entitlement or privileged daemon.
#include <libslirp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_FRAME 65536
#define MAX_POLLS 8192
static struct pollfd polls[MAX_POLLS];
static int poll_count, peer = -1;
static volatile sig_atomic_t quitting;
struct timer { SlirpTimerCb cb; void *opaque; int64_t at; struct timer *next; };
static struct timer *timers;

static void fail(const char *message) { perror(message); exit(70); }
static int64_t now_ns(void *opaque) {
    (void)opaque;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) fail("clock_gettime");
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
static void *timer_new(SlirpTimerCb cb, void *data, void *opaque) {
    (void)opaque;
    struct timer *t = calloc(1, sizeof(*t));
    if (!t) fail("calloc");
    *t = (struct timer){cb, data, INT64_MAX, timers}; timers = t;
    return t;
}
static void timer_free(void *timer, void *opaque) {
    (void)opaque;
    struct timer **p = &timers;
    while (*p && *p != timer) p = &(*p)->next;
    if (*p) { *p = (*p)->next; free(timer); }
}
static void timer_mod(void *timer, int64_t at, void *opaque) {
    (void)opaque; ((struct timer *)timer)->at = at;
}
static void notify(void *opaque) { (void)opaque; }
static void register_socket(int fd, void *opaque) { (void)fd; (void)opaque; }
static void guest_error(const char *message, void *opaque) {
    (void)opaque; fprintf(stderr, "cogbox-slirp: %s\n", message);
}
static void on_signal(int sig) { (void)sig; quitting = 1; }

// A partial frame cannot be dropped, and QEMU stops reading this stream while
// the guest cannot receive (a paused VM, a full virtio queue). Block until it
// drains, but keep every write cancelable, including later libslirp callbacks
// after a signal interrupts a frame. Nonblocking sends and a bounded poll also
// cover a signal arriving between the quit check and either syscall. A poll
// timeout retries the same bytes; it never drops a frame or closes the link.
static int send_all(const void *data, size_t size) {
    const unsigned char *p = data;
    while (size) {
        if (quitting) { errno = EINTR; return -1; }
        ssize_t n = send(peer, p, size, MSG_DONTWAIT);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd out = { .fd = peer, .events = POLLOUT };
            int result = poll(&out, 1, 100);
            if ((result < 0 && errno != EINTR) ||
                    (result > 0 && (out.revents & (POLLERR | POLLHUP | POLLNVAL)))) {
                quitting = 1; return -1;
            }
            continue;
        }
        if (n <= 0) { quitting = 1; return -1; }
        p += n; size -= (size_t)n;
    }
    return 0;
}
static ssize_t send_packet(const void *data, size_t size, void *opaque) {
    (void)opaque;
    if (peer < 0 || size > MAX_FRAME) return -1;
    uint32_t length = htonl((uint32_t)size);
    if (send_all(&length, sizeof(length)) || send_all(data, size)) return -1;
    return (ssize_t)size;
}
static int add_poll(int fd, int events, void *opaque) {
    (void)opaque;
    if (poll_count == MAX_POLLS) { errno = EMFILE; fail("slirp poll limit"); }
    short mask = 0;
    if (events & SLIRP_POLL_IN) mask |= POLLIN;
    if (events & SLIRP_POLL_OUT) mask |= POLLOUT;
    if (events & SLIRP_POLL_PRI) mask |= POLLPRI;
    polls[poll_count] = (struct pollfd){fd, mask, 0};
    return poll_count++;
}
static int get_events(int index, void *opaque) {
    (void)opaque;
    short mask = polls[index].revents;
    return ((mask & POLLIN) ? SLIRP_POLL_IN : 0) |
        ((mask & POLLOUT) ? SLIRP_POLL_OUT : 0) |
        ((mask & POLLPRI) ? SLIRP_POLL_PRI : 0) |
        ((mask & POLLERR) ? SLIRP_POLL_ERR : 0) |
        ((mask & (POLLHUP | POLLNVAL)) ? SLIRP_POLL_HUP : 0);
}
static struct in_addr address(const char *text) {
    struct in_addr result;
    if (inet_pton(AF_INET, text, &result) != 1) { errno = EINVAL; fail("IPv4 address"); }
    return result;
}
static void forward(Slirp *slirp, const char *spec) {
    char addr[INET_ADDRSTRLEN] = "127.0.0.1";
    const char *ports = spec, *slash = strchr(spec, '/');
    if (slash) {
        size_t length = (size_t)(slash - spec);
        if (!length || length >= sizeof(addr)) { errno = EINVAL; fail("forward address"); }
        memcpy(addr, spec, length); addr[length] = 0; ports = slash + 1;
    }
    unsigned host, guest; char extra;
    if (sscanf(ports, "%u:%u%c", &host, &guest, &extra) != 2 ||
        !host || host > 65535 || !guest || guest > 65535) {
        errno = EINVAL; fail("forward ports");
    }
    if (slirp_add_hostfwd(slirp, 0, address(addr), (int)host,
            address("10.0.2.15"), (int)guest)) fail("forward bind");
}
int main(int argc, char **argv) {
    const char *path = NULL, *forwards[32]; int count = 0, filtered = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--filtered")) { filtered = 1; continue; }
        if (!strcmp(argv[i], "--foreground") || !strcmp(argv[i], "-4")) continue;
        if (!strcmp(argv[i], "--socket") && i + 1 < argc) path = argv[++i];
        else if (!strcmp(argv[i], "-t") && i + 1 < argc && count < 32) forwards[count++] = argv[++i];
        else { fprintf(stderr, "cogbox-slirp: unsupported argument: %s\n", argv[i]); return 64; }
    }
    if (!path || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        fprintf(stderr, "cogbox-slirp: missing or overlong Unix socket path\n"); return 64;
    }
    if (filtered) {
        int (*ready)(void) = (int (*)(void))dlsym(RTLD_DEFAULT, "cogbox_filter_ready");
        if (!ready || !ready()) {
            fprintf(stderr, "cogbox-slirp: rules mode requires the loaded cogbox filter and rules file\n");
            return 70;
        }
        // The shared filter tracks protocol and connected UDP peers by fd.
        // Keep every new socket inside its 4096-entry table, even when the
        // invoking shell has raised its file limit above macOS's default.
        struct rlimit limit;
        if (getrlimit(RLIMIT_NOFILE, &limit)) fail("getrlimit");
        if (limit.rlim_cur > 4096) {
            limit.rlim_cur = 4096;
            if (setrlimit(RLIMIT_NOFILE, &limit)) fail("setrlimit");
        }
    }
    umask(0077);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_signal); signal(SIGINT, on_signal);
    // SA_RESTART would leave accept blocked during shutdown.
    siginterrupt(SIGTERM, 1); siginterrupt(SIGINT, 1);
    SlirpConfig config = { .version = 6, .in_enabled = true,
        .vnetwork = address("10.0.2.0"), .vnetmask = address("255.255.255.0"),
        .vhost = address("10.0.2.2"), .vdhcp_start = address("10.0.2.15"),
        .vnameserver = address("10.0.2.3"), .disable_host_loopback = true };
    SlirpCb callbacks = { .send_packet = send_packet, .guest_error = guest_error,
        .clock_get_ns = now_ns, .timer_new = timer_new, .timer_free = timer_free,
        .timer_mod = timer_mod, .notify = notify,
        .register_poll_socket = register_socket, .unregister_poll_socket = register_socket };
    Slirp *slirp = slirp_new(&config, &callbacks, NULL);
    if (!slirp) fail("slirp_new");
    for (int i = 0; i < count; i++) forward(slirp, forwards[i]);
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) fail("socket");
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strcpy(addr.sun_path, path);
    // Do not unlink an existing listener: a stale or conflicting launch fails.
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) || listen(listener, 1)) fail("listen");
    do { peer = accept(listener, NULL, NULL); } while (peer < 0 && errno == EINTR && !quitting);
    close(listener);
    if (peer < 0) { unlink(path); return quitting ? 0 : 70; }
    unsigned char frame[MAX_FRAME + 4]; size_t used = 0, wanted = 4;
    while (!quitting) {
        polls[0] = (struct pollfd){peer, POLLIN, 0}; poll_count = 1;
        uint32_t ms = 100;
        slirp_pollfds_fill_socket(slirp, &ms, add_poll, NULL);
        int64_t now = now_ns(NULL) / 1000000;
        for (struct timer *t = timers; t; t = t->next)
            if (t->at <= now + ms) ms = t->at <= now ? 0 : (uint32_t)(t->at - now);
        int result = poll(polls, (nfds_t)poll_count, (int)ms);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) fail("poll");
        slirp_pollfds_poll(slirp, 0, get_events, NULL);
        now = now_ns(NULL) / 1000000;
        // Callbacks can free timers. Restart iteration after each expiration.
        for (struct timer *t = timers; t;) {
            if (t->at <= now) { t->at = INT64_MAX; t->cb(t->opaque); t = timers; }
            else t = t->next;
        }
        if (polls[0].revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (!(polls[0].revents & POLLIN)) continue;
        ssize_t n = recv(peer, frame + used, wanted - used, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
        if (used != wanted) continue;
        if (wanted == 4) {
            uint32_t length; memcpy(&length, frame, 4); length = ntohl(length);
            if (length < 14 || length > MAX_FRAME) break;
            wanted = (size_t)length + 4;
        } else {
            slirp_input(slirp, frame + 4, (int)(wanted - 4)); used = 0; wanted = 4;
        }
    }
    slirp_cleanup(slirp); close(peer); unlink(path);
    return 0;
}
