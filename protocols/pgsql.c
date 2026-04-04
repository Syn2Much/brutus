/* pgsql.c -- PostgreSQL credential scanner (single-target-try)
   Extracted from bot/scanner_pgsql.c, scaffolding removed.
   Adds SCRAM-SHA-256 (auth type 10) support for PostgreSQL 10+.
   Uses shared crypto/ instead of inline implementations. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <stdint.h>

#include "pgsql.h"
#include "../crypto/md5.h"
#include "../crypto/sha256.h"
#include "../crypto/pbkdf2.h"
#include "../core/util.h"

/* ---- Base64 encode/decode (small, static, for SCRAM only) ---- */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(const uint8_t *in, int in_len, char *out, int out_max) {
    int i, o = 0;
    for (i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < in_len) v |= (uint32_t)in[i + 2];
        if (o + 4 > out_max) return -1;
        out[o++] = b64_table[(v >> 18) & 0x3F];
        out[o++] = b64_table[(v >> 12) & 0x3F];
        out[o++] = (i + 1 < in_len) ? b64_table[(v >> 6) & 0x3F] : '=';
        out[o++] = (i + 2 < in_len) ? b64_table[v & 0x3F] : '=';
    }
    if (o < out_max) out[o] = '\0';
    return o;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, int in_len, uint8_t *out, int out_max) {
    int i, o = 0;
    for (i = 0; i + 3 < in_len; i += 4) {
        int a = b64_val(in[i]), b = b64_val(in[i + 1]);
        int c = b64_val(in[i + 2]), d = b64_val(in[i + 3]);
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

/* ---- PostgreSQL MD5 auth ---- */

/* "md5" + md5(md5(password + username) + salt) */
static void pgsql_md5_auth(const char *user, const char *pass,
                           const uint8_t salt[4], char out[36]) {
    char inner_input[512], inner_hex[33], outer_input[37];
    /* inner = md5(password + username) */
    snprintf(inner_input, sizeof(inner_input), "%s%s", pass, user);
    md5_hex((const uint8_t *)inner_input, strlen(inner_input), inner_hex);
    /* outer = md5(inner_hex + salt) */
    memcpy(outer_input, inner_hex, 32);
    memcpy(outer_input + 32, salt, 4);
    md5_hex((const uint8_t *)outer_input, 36, out + 3);
    memcpy(out, "md5", 3);
    out[35] = '\0';
}

/* ---- Build PostgreSQL startup message ---- */

static int pgsql_build_startup(char *buf, int bufsz, const char *user,
                               const char *database) {
    int pos = 4; /* skip length field, fill later */
    (void)bufsz;
    /* Protocol version 3.0 */
    buf[pos++] = 0; buf[pos++] = 3; buf[pos++] = 0; buf[pos++] = 0;
    /* user parameter */
    memcpy(buf + pos, "user", 4); pos += 4; buf[pos++] = 0;
    { int ul = (int)strlen(user); memcpy(buf + pos, user, (size_t)ul); pos += ul; buf[pos++] = 0; }
    /* database parameter */
    memcpy(buf + pos, "database", 8); pos += 8; buf[pos++] = 0;
    { int dl = (int)strlen(database); memcpy(buf + pos, database, (size_t)dl); pos += dl; buf[pos++] = 0; }
    /* final terminator */
    buf[pos++] = 0;
    /* fill length (big-endian, includes self) */
    buf[0] = (char)(pos >> 24); buf[1] = (char)(pos >> 16);
    buf[2] = (char)(pos >> 8);  buf[3] = (char)pos;
    return pos;
}

/* ---- Fetch version after auth OK ---- */

static void pgsql_fetch_version(int fd, char *version_out, int versz) {
    char buf[2048];
    int n;
    struct pollfd pfd;

    /* Drain any remaining post-auth messages (ParameterStatus, BackendKeyData,
       ReadyForQuery). These may have been consumed by the auth recv, so use
       a short poll to avoid blocking. */
    pfd.fd = fd;
    pfd.events = POLLIN;
    while (poll(&pfd, 1, 200) > 0) {
        n = (int)recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        /* Check if ReadyForQuery was in this chunk */
        {
            int k;
            for (k = 0; k < n; k++) {
                if (buf[k] == 'Z' && k + 5 <= n) goto ready;
            }
        }
    }
ready:

    /* Send SELECT version() */
    {
        const char *q = "SELECT version()";
        int qlen = (int)strlen(q) + 1;
        char qmsg[128];
        qmsg[0] = 'Q';
        qmsg[1] = (char)((qlen + 4) >> 24);
        qmsg[2] = (char)((qlen + 4) >> 16);
        qmsg[3] = (char)((qlen + 4) >> 8);
        qmsg[4] = (char)(qlen + 4);
        memcpy(qmsg + 5, q, (size_t)qlen);
        send(fd, qmsg, (size_t)(5 + qlen), MSG_NOSIGNAL);

        n = (int)recv(fd, buf, sizeof(buf) - 1, 0);
        if (n > 10) {
            buf[n] = '\0';
            /* Wire protocol contains nulls, so strstr won't work.
               Search the raw buffer for "PostgreSQL" with memmem. */
            char *pg = (char *)memmem(buf, (size_t)n, "PostgreSQL", 10);
            if (pg) {
                char *end = strchr(pg, ',');
                if (!end) end = strchr(pg, ')');
                if (!end) end = pg + 30;
                int vl = (int)(end - pg);
                if (vl >= versz) vl = versz - 1;
                memcpy(version_out, pg, (size_t)vl);
                version_out[vl] = '\0';
            } else {
                strncpy(version_out, "authenticated", (size_t)versz - 1);
                version_out[versz - 1] = '\0';
            }
        }
    }
}

/* ---- Send PasswordMessage ---- */

static int pgsql_send_password(int fd, const char *data, int data_len) {
    char msg[512];
    int total = data_len + 4; /* length includes itself */
    msg[0] = 'p';
    msg[1] = (char)(total >> 24);
    msg[2] = (char)(total >> 16);
    msg[3] = (char)(total >> 8);
    msg[4] = (char)total;
    if (data_len + 5 > (int)sizeof(msg)) return -1;
    memcpy(msg + 5, data, (size_t)data_len);
    return (send(fd, msg, (size_t)(5 + data_len), MSG_NOSIGNAL) > 0) ? 0 : -1;
}

/* ---- Check AuthenticationOk in response ---- */

static int pgsql_check_auth_ok(const char *buf, int n) {
    if (n >= 9 && buf[0] == 'R' &&
        (uint8_t)buf[5] == 0 && (uint8_t)buf[6] == 0 &&
        (uint8_t)buf[7] == 0 && (uint8_t)buf[8] == 0)
        return 1;
    return 0;
}

/* ---- SCRAM-SHA-256 authentication ---- */

static int pgsql_scram_auth(int fd, const char *user, const char *pass,
                            const char *initial_resp, int initial_n) {
    char client_nonce_raw[24];
    char client_nonce[36]; /* base64 of 24 bytes ~ 32 chars */
    char client_first_bare[256];
    char buf[2048];
    int n;
    char server_first[512];
    char combined_nonce[128];
    uint8_t server_salt[128];
    int server_salt_len;
    int iterations;
    uint8_t salted_password[32];
    uint8_t client_key[32], stored_key[32];
    char client_final_without_proof[256];
    char auth_message[1024];
    uint8_t client_signature[32], client_proof[32];
    char client_proof_b64[64];
    char client_final[384];
    int i;

    (void)initial_resp;
    (void)initial_n;
    (void)user;

    /* a. Generate client nonce */
    urandom_bytes((uint8_t *)client_nonce_raw, sizeof(client_nonce_raw));
    b64_encode((uint8_t *)client_nonce_raw, sizeof(client_nonce_raw),
               client_nonce, sizeof(client_nonce));

    /* b. Build client-first-bare: "n=,r=<nonce>" (empty username in GS2 for SCRAM) */
    /*    Per RFC 5802, we use "n=<user>,r=<nonce>" */
    snprintf(client_first_bare, sizeof(client_first_bare), "n=,r=%s", client_nonce);

    /* c. Send SASLInitialResponse:
          'p' + int32(len) + "SCRAM-SHA-256\0" + int32(cfb_len) + client-first-bare
          The full client-first is "n,," + client_first_bare, but we send
          the GS2 header separately in the mechanism. */

    /* Build the message body (after the 'p' + length prefix):
       mechanism name (null-terminated) + int32 length of initial response + initial response */
    {
        const char *mech = "SCRAM-SHA-256";
        int mech_len = (int)strlen(mech) + 1; /* include null */
        /* client-first-message = "n,," + client_first_bare */
        char client_first_msg[300];
        int cfm_len;
        snprintf(client_first_msg, sizeof(client_first_msg), "n,,%s", client_first_bare);
        cfm_len = (int)strlen(client_first_msg);

        /* Body = mechanism + int32(cfm_len) + client_first_msg */
        int sasl_len = mech_len + 4 + cfm_len;
        int total = sasl_len + 4; /* length field includes itself */

        char pmsg[600];
        int p = 0;
        pmsg[p++] = 'p';
        pmsg[p++] = (char)(total >> 24);
        pmsg[p++] = (char)(total >> 16);
        pmsg[p++] = (char)(total >> 8);
        pmsg[p++] = (char)total;
        memcpy(pmsg + p, mech, (size_t)mech_len); p += mech_len;
        pmsg[p++] = (char)(cfm_len >> 24);
        pmsg[p++] = (char)(cfm_len >> 16);
        pmsg[p++] = (char)(cfm_len >> 8);
        pmsg[p++] = (char)cfm_len;
        memcpy(pmsg + p, client_first_msg, (size_t)cfm_len); p += cfm_len;

        if (send(fd, pmsg, (size_t)p, MSG_NOSIGNAL) <= 0) return -1;
    }

    /* d. Recv AuthenticationSASLContinue (R, auth_type=11) */
    n = (int)recv(fd, buf, sizeof(buf) - 1, 0);
    if (n < 9) return -1;
    if (buf[0] != 'R') return -1;
    {
        int auth_type = ((uint8_t)buf[5] << 24) | ((uint8_t)buf[6] << 16) |
                        ((uint8_t)buf[7] << 8) | (uint8_t)buf[8];
        if (auth_type != 11) return -1;
    }

    /* e. Parse server-first-message from the data after the 9-byte header */
    {
        int msg_len = ((uint8_t)buf[1] << 24) | ((uint8_t)buf[2] << 16) |
                      ((uint8_t)buf[3] << 8) | (uint8_t)buf[4];
        int data_len = msg_len - 4; /* subtract auth_type field size */
        if (data_len <= 0 || data_len >= (int)sizeof(server_first)) return -1;
        memcpy(server_first, buf + 9, (size_t)data_len);
        server_first[data_len] = '\0';
    }

    /* f. Parse server-first: r=<nonce>,s=<base64_salt>,i=<iterations> */
    {
        char *r_field = strstr(server_first, "r=");
        char *s_field = strstr(server_first, "s=");
        char *i_field = strstr(server_first, "i=");
        char *comma;
        if (!r_field || !s_field || !i_field) return -1;

        /* combined nonce */
        r_field += 2;
        comma = strchr(r_field, ',');
        if (!comma) return -1;
        { int rl = (int)(comma - r_field);
          if (rl >= (int)sizeof(combined_nonce)) return -1;
          memcpy(combined_nonce, r_field, (size_t)rl);
          combined_nonce[rl] = '\0'; }

        /* base64 salt */
        s_field += 2;
        comma = strchr(s_field, ',');
        if (!comma) return -1;
        { char salt_b64[128];
          int sl = (int)(comma - s_field);
          if (sl >= (int)sizeof(salt_b64)) return -1;
          memcpy(salt_b64, s_field, (size_t)sl);
          salt_b64[sl] = '\0';
          server_salt_len = b64_decode(salt_b64, sl, server_salt, sizeof(server_salt));
          if (server_salt_len <= 0) return -1; }

        /* iterations */
        i_field += 2;
        iterations = atoi(i_field);
        if (iterations <= 0) return -1;
    }

    /* g. Compute SaltedPassword = PBKDF2(SHA-256, pass, salt, iterations) */
    pbkdf2_sha256((const uint8_t *)pass, strlen(pass),
                  server_salt, (size_t)server_salt_len,
                  iterations, salted_password, 32);

    /* h. ClientKey = HMAC-SHA-256(SaltedPassword, "Client Key") */
    hmac_sha256(salted_password, 32,
                (const uint8_t *)"Client Key", 10,
                client_key);

    /* i. StoredKey = SHA-256(ClientKey) */
    sha256_oneshot(client_key, 32, stored_key);

    /* j. Build client-final-without-proof: "c=biws,r=<combined_nonce>"
          "biws" is base64("n,,") */
    snprintf(client_final_without_proof, sizeof(client_final_without_proof),
             "c=biws,r=%s", combined_nonce);

    /* k. AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof */
    snprintf(auth_message, sizeof(auth_message), "%s,%s,%s",
             client_first_bare, server_first, client_final_without_proof);

    /* l. ClientSignature = HMAC-SHA-256(StoredKey, AuthMessage) */
    hmac_sha256(stored_key, 32,
                (const uint8_t *)auth_message, strlen(auth_message),
                client_signature);

    /* m. ClientProof = ClientKey XOR ClientSignature */
    for (i = 0; i < 32; i++)
        client_proof[i] = client_key[i] ^ client_signature[i];

    /* n. Base64-encode ClientProof */
    b64_encode(client_proof, 32, client_proof_b64, sizeof(client_proof_b64));

    /* o. Build client-final-message */
    snprintf(client_final, sizeof(client_final), "%s,p=%s",
             client_final_without_proof, client_proof_b64);

    /* p. Send SASLResponse: 'p' + len + client-final-message */
    {
        int cflen = (int)strlen(client_final);
        int total = cflen + 4;
        char pmsg[512];
        int p = 0;
        pmsg[p++] = 'p';
        pmsg[p++] = (char)(total >> 24);
        pmsg[p++] = (char)(total >> 16);
        pmsg[p++] = (char)(total >> 8);
        pmsg[p++] = (char)total;
        memcpy(pmsg + p, client_final, (size_t)cflen);
        p += cflen;
        if (send(fd, pmsg, (size_t)p, MSG_NOSIGNAL) <= 0) return -1;
    }

    /* q. Recv AuthenticationSASLFinal (auth_type=12) -- just accept */
    n = (int)recv(fd, buf, sizeof(buf) - 1, 0);
    if (n < 9) return -1;
    if (buf[0] == 'E') return 0;  /* ErrorResponse = wrong password */
    if (buf[0] != 'R') return -1;
    {
        int auth_type = ((uint8_t)buf[5] << 24) | ((uint8_t)buf[6] << 16) |
                        ((uint8_t)buf[7] << 8) | (uint8_t)buf[8];
        if (auth_type != 12) {
            /* Might be an error or combined response */
            if (auth_type == 0) return 1; /* direct OK */
            return -1;
        }
    }

    /* r. Recv AuthenticationOk (auth_type=0) -- may be in same recv or separate */
    {
        /* Check if AuthOk was appended after SASLFinal in the same recv buffer */
        int msg_len = ((uint8_t)buf[1] << 24) | ((uint8_t)buf[2] << 16) |
                      ((uint8_t)buf[3] << 8) | (uint8_t)buf[4];
        int offset = 1 + msg_len; /* skip the 'R' byte + message body */
        if (offset + 9 <= n && buf[offset] == 'R') {
            int at2 = ((uint8_t)buf[offset + 5] << 24) | ((uint8_t)buf[offset + 6] << 16) |
                      ((uint8_t)buf[offset + 7] << 8) | (uint8_t)buf[offset + 8];
            if (at2 == 0) return 1;
        }
        /* Otherwise, read another packet */
        n = (int)recv(fd, buf, sizeof(buf) - 1, 0);
        if (n >= 9 && buf[0] == 'R') {
            int at3 = ((uint8_t)buf[5] << 24) | ((uint8_t)buf[6] << 16) |
                      ((uint8_t)buf[7] << 8) | (uint8_t)buf[8];
            if (at3 == 0) return 1;
        }
    }

    return -1;
}

/* ---- Main entry point ---- */

int pgsql_try(const char *ip, const char *user, const char *pass,
              const pgsql_opts_t *opts, char *version_out, int versz) {
    int fd, n;
    char buf[2048];
    const char *database = opts->database ? opts->database : "postgres";

    if (version_out && versz > 0) version_out[0] = '\0';

    fd = tcp_connect(ip, opts->port, opts->timeout);
    if (fd < 0) return -1;

    /* Send startup */
    {
        int slen = pgsql_build_startup(buf, sizeof(buf), user, database);
        if (send(fd, buf, (size_t)slen, MSG_NOSIGNAL) <= 0) { close(fd); return -1; }
    }

    /* Read response */
    n = (int)recv(fd, buf, sizeof(buf) - 1, 0);
    if (n < 9) { close(fd); return -1; }

    if (buf[0] == 'R') {
        int auth_type = ((uint8_t)buf[5] << 24) | ((uint8_t)buf[6] << 16) |
                        ((uint8_t)buf[7] << 8) | (uint8_t)buf[8];

        /* Trust auth -- no password */
        if (auth_type == 0) {
            if (version_out && versz > 0)
                strncpy(version_out, "trust-auth", (size_t)versz - 1);
            close(fd);
            return 1;
        }

        /* Cleartext password (type 3) */
        if (auth_type == 3) {
            int plen = (int)strlen(pass) + 1;
            if (pgsql_send_password(fd, pass, plen) < 0) { close(fd); return -1; }
            n = (int)recv(fd, buf, sizeof(buf) - 1, 0);
            if (n >= 9 && pgsql_check_auth_ok(buf, n)) {
                if (version_out && versz > 0) {
                    strncpy(version_out, "cleartext-auth", (size_t)versz - 1);
                    version_out[versz - 1] = '\0';
                }
                close(fd);
                return 1;
            }
            close(fd);
            return 0;
        }

        /* MD5 auth (type 5) */
        if (auth_type == 5 && n >= 13) {
            uint8_t salt[4];
            char md5_response[36];
            int plen;

            memcpy(salt, buf + 9, 4);
            pgsql_md5_auth(user, pass, salt, md5_response);

            plen = (int)strlen(md5_response) + 1;
            if (pgsql_send_password(fd, md5_response, plen) < 0) { close(fd); return -1; }

            n = (int)recv(fd, buf, sizeof(buf) - 1, 0);
            if (n < 5) { close(fd); return -1; }

            if (pgsql_check_auth_ok(buf, n)) {
                if (version_out) pgsql_fetch_version(fd, version_out, versz);
                close(fd);
                return 1;
            }
            if (buf[0] == 'E') { close(fd); return 0; }
            close(fd);
            return -1;
        }

        /* SCRAM-SHA-256 auth (type 10) */
        if (auth_type == 10) {
            int scram_result = pgsql_scram_auth(fd, user, pass, buf, n);
            if (scram_result == 1) {
                if (version_out) pgsql_fetch_version(fd, version_out, versz);
                close(fd);
                return 1;
            }
            close(fd);
            return (scram_result == 0) ? 0 : -1;
        }

        /* Unsupported auth type */
        close(fd);
        return 0;
    }

    if (buf[0] == 'E') {
        close(fd);
        return 0;
    }

    close(fd);
    return -1;
}
