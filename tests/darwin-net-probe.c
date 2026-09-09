// A persistent client exercises dyld interposition and SIGUSR1 reload in the
// same process. stdin selects TCP (t), UDP (u), or connected UDP (c).
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_len = sizeof(addr),
        .sin_port = htons((unsigned short)atoi(argv[2])) };
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) return 64;
    int command;
    while (1) {
        command = getchar();
        if (command == EOF) {
            if (ferror(stdin) && errno == EINTR) { clearerr(stdin); continue; }
            break;
        }
        if (command == '\n') continue;
        int fd = socket(AF_INET, command == 't' ? SOCK_STREAM : SOCK_DGRAM, 0);
        int result;
        if (command == 'u') result = (int)sendto(fd, "x", 1, 0, (struct sockaddr *)&addr, sizeof(addr));
        else {
            result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
            if (!result && command == 'c') result = (int)sendto(fd, "x", 1, 0, NULL, 0);
        }
        printf("%s\n", result < 0 ? "denied" : "allowed"); fflush(stdout);
        close(fd);
    }
    return 0;
}
