#include "util.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

void urandom_bytes(uint8_t* out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t off = 0;
        while (off < len) {
            ssize_t n = read(fd, out + off, len - off);
            if (n <= 0) break;
            off += (size_t)n;
        }
        close(fd);
        if (off == len) return;
    }
    srand((unsigned)(time(NULL) ^ getpid()));
    { size_t i; for (i = 0; i < len; i++) out[i] = (uint8_t)(rand() & 0xFF); }
}

uint32_t urandom_u32(void) {
    uint32_t v = 0;
    urandom_bytes((uint8_t*)&v, 4);
    return v;
}

int tcp_connect(const char *ip, int port, int timeout_sec) {
    struct sockaddr_in addr;
    struct timeval tv;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}
