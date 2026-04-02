/* mysql.c -- MySQL credential scanner (single-target-try)
   Extracted from bot/scanner_mysql.c, scaffolding removed.
   Uses shared crypto/sha1.h instead of inline SHA-1. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdint.h>

#include "mysql.h"
#include "../crypto/sha1.h"
#include "../core/util.h"

/* MySQL native auth: SHA1(pass) XOR SHA1(salt + SHA1(SHA1(pass))) */
static void mysql_native_auth(const uint8_t *salt, int salt_len,
                              const char *password, uint8_t out[20]) {
    uint8_t stage1[20], stage2[20], hash_salt[20];
    sha1_ctx ctx;
    int i;

    sha1_oneshot((const uint8_t *)password, strlen(password), stage1);
    sha1_oneshot(stage1, 20, stage2);
    sha1_init(&ctx);
    sha1_update(&ctx, salt, (size_t)salt_len);
    sha1_update(&ctx, stage2, 20);
    sha1_final(&ctx, hash_salt);
    for (i = 0; i < 20; i++)
        out[i] = stage1[i] ^ hash_salt[i];
}

int mysql_try(const char *ip, const char *user, const char *pass,
              const mysql_opts_t *opts, char *version_out, int versz) {
    int fd, n, pos;
    uint8_t buf[4096];
    uint8_t salt[20];
    int salt_len = 0;
    uint8_t auth_resp[20];
    uint8_t pkt[512];
    int pkt_len;

    if (version_out && versz > 0) version_out[0] = '\0';

    fd = tcp_connect(ip, opts->port, opts->timeout);
    if (fd < 0) return -1;

    /* 1. Read server greeting */
    n = (int)recv(fd, buf, sizeof(buf), 0);
    if (n < 40) { close(fd); return -1; }

    /* Parse greeting: [3 len][1 seq][1 proto_ver][version_string\0][4 thread_id][8 salt1][1 filler]... */
    pos = 4; /* skip packet header */
    if (buf[pos] == 0xFF) { close(fd); return -1; } /* ERR packet */

    /* Extract server version for reporting */
    {
        char *ver_start = (char *)buf + pos + 1; /* skip proto version byte */
        char *ver_end = strchr(ver_start, '\0');
        if (ver_end && ver_end - ver_start < versz) {
            memcpy(version_out, ver_start, (size_t)(ver_end - ver_start));
            version_out[ver_end - ver_start] = '\0';
        }
        pos = (int)(ver_end - (char *)buf) + 1;
    }

    pos += 4; /* thread_id */
    memcpy(salt, buf + pos, 8); salt_len = 8; pos += 8;
    pos++; /* filler */
    pos += 2; /* capability lower */
    pos++; /* charset */
    pos += 2; /* status */
    pos += 2; /* capability upper */
    pos++; /* auth plugin data len */
    pos += 10; /* reserved */

    /* salt part 2 (12 bytes) */
    if (pos + 12 <= n) {
        memcpy(salt + 8, buf + pos, 12);
        salt_len = 20;
    }

    /* 2. Build auth response */
    mysql_native_auth(salt, salt_len, pass, auth_resp);

    /* 3. Build handshake response packet */
    pkt_len = 4; /* skip header, fill later */
    /* Client capabilities (4 bytes LE):
     * CLIENT_LONG_PASSWORD(1) | CLIENT_FOUND_ROWS(2) | CLIENT_LONG_FLAG(4) |
     * CLIENT_PROTOCOL_41(0x200) | CLIENT_SECURE_CONNECTION(0x8000) |
     * CLIENT_PLUGIN_AUTH(0x80000) */
    pkt[pkt_len++] = 0x07; pkt[pkt_len++] = 0x82;
    pkt[pkt_len++] = 0x08; pkt[pkt_len++] = 0x00;
    /* Max packet size (4 bytes) */
    pkt[pkt_len++] = 0x00; pkt[pkt_len++] = 0x00; pkt[pkt_len++] = 0x00; pkt[pkt_len++] = 0x01; /* 16MB */
    /* Charset (1 byte) -- utf8 */
    pkt[pkt_len++] = 0x21;
    /* Reserved (23 bytes of zeros) */
    memset(pkt + pkt_len, 0, 23); pkt_len += 23;
    /* Username (null-terminated) */
    { int ul = (int)strlen(user); memcpy(pkt + pkt_len, user, (size_t)ul + 1); pkt_len += ul + 1; }
    /* Auth response length + data (CLIENT_SECURE_CONNECTION format) */
    pkt[pkt_len++] = 20; /* SHA1 = 20 bytes */
    memcpy(pkt + pkt_len, auth_resp, 20); pkt_len += 20;
    /* Auth plugin name (CLIENT_PLUGIN_AUTH) -- required by MySQL 8.0 */
    memcpy(pkt + pkt_len, "mysql_native_password", 22); pkt_len += 22; /* includes null terminator */

    /* Fill packet header: [3 len][1 seq=1] */
    { int payload_len = pkt_len - 4;
      pkt[0] = (uint8_t)payload_len; pkt[1] = (uint8_t)(payload_len >> 8); pkt[2] = (uint8_t)(payload_len >> 16);
      pkt[3] = 1; /* sequence number */
    }

    if (send(fd, pkt, (size_t)pkt_len, MSG_NOSIGNAL) <= 0) { close(fd); return -1; }

    /* 4. Read response */
    n = (int)recv(fd, buf, sizeof(buf), 0);
    if (n < 5) { close(fd); return -1; }

    if (buf[4] == 0x00) { close(fd); return 1; }  /* OK packet */
    if (buf[4] == 0xFF) { close(fd); return 0; }  /* ERR -- auth failed */

    if (buf[4] == 0xFE && n > 5) {
        /* Auth switch request: server wants mysql_native_password with new salt */
        char *plugin = (char *)buf + 5;
        int plugin_len = (int)strlen(plugin);
        int salt_start = 5 + plugin_len + 1;
        uint8_t new_salt[20];
        int new_salt_len = n - salt_start;
        if (new_salt_len > 20) new_salt_len = 20;
        if (new_salt_len > 0 && new_salt_len <= 20) {
            memcpy(new_salt, buf + salt_start, (size_t)new_salt_len);
            /* Strip trailing null from salt */
            if (new_salt_len > 0 && new_salt[new_salt_len - 1] == 0) new_salt_len--;

            uint8_t new_auth[20];
            mysql_native_auth(new_salt, new_salt_len, pass, new_auth);
            /* Send auth switch response: [3 len LE][1 seq=3][20 auth_data] */
            uint8_t resp_pkt[24];
            resp_pkt[0] = 20; resp_pkt[1] = 0; resp_pkt[2] = 0; resp_pkt[3] = 3;
            memcpy(resp_pkt + 4, new_auth, 20);
            send(fd, resp_pkt, 24, MSG_NOSIGNAL);

            n = (int)recv(fd, buf, sizeof(buf), 0);
            close(fd);
            if (n >= 5 && buf[4] == 0x00) return 1; /* OK! */
            if (n >= 5 && buf[4] == 0xFF) return 0;  /* ERR */
            return -1;
        }
        close(fd);
        return 0;
    }

    close(fd);
    return -1;
}
