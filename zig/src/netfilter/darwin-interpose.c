// dyld's two-level namespace requires explicit interposition. Only the
// dedicated, single-threaded slirp process loads this library; QEMU and the
// trusted L7/auth proxies always use the system socket functions.
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#define INTERPOSE(name) \
    extern __typeof__(name) cogbox_##name; \
    __attribute__((used, section("__DATA,__interpose"))) \
    static const struct { const void *replacement, *original; } interpose_##name = \
        { (const void *)&cogbox_##name, (const void *)&name };
INTERPOSE(socket)
INTERPOSE(close)
INTERPOSE(connect)
INTERPOSE(sendto)
INTERPOSE(sendmsg)
INTERPOSE(getaddrinfo)
INTERPOSE(gethostbyname)
INTERPOSE(gethostbyname2)

#include <string.h>
// dyld interposes dlsym results too. References from the interposing image
// itself retain the original target; use the table instead of RTLD_NEXT.
const void *cogbox_original(const char *symbol) {
#define ORIGINAL(name) if (!strcmp(symbol, #name)) return interpose_##name.original;
    ORIGINAL(socket) ORIGINAL(close) ORIGINAL(connect) ORIGINAL(sendto)
    ORIGINAL(sendmsg) ORIGINAL(getaddrinfo) ORIGINAL(gethostbyname) ORIGINAL(gethostbyname2)
    return NULL;
}
