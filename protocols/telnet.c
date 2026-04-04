/* telnet.c -- Telnet credential scanner (single-target-try)
   Handles IAC negotiation, waits for login/password prompts. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <poll.h>

#include "telnet.h"
#include "../core/util.h"

/* Telnet IAC constants */
#define IAC   0xFF
#define DONT  0xFE
#define DO    0xFD
#define WONT  0xFC
#define WILL  0xFB
#define SB    0xFA
#define SE    0xF0

/* Respond to IAC negotiations: refuse everything.
   WILL x -> DONT x, DO x -> WONT x, subnegotiations -> skip */
static void telnet_negotiate(int fd, const uint8_t *buf, int len) {
    uint8_t resp[3];
    int i = 0;

    while (i < len) {
        if ((uint8_t)buf[i] != IAC) { i++; continue; }
        if (i + 1 >= len) break;

        uint8_t cmd = buf[i + 1];

        if (cmd == SB) {
            /* skip subnegotiation until IAC SE */
            i += 2;
            while (i + 1 < len) {
                if ((uint8_t)buf[i] == IAC && (uint8_t)buf[i + 1] == SE) {
                    i += 2;
                    break;
                }
                i++;
            }
            continue;
        }

        if ((cmd == WILL || cmd == DO) && i + 2 < len) {
            resp[0] = IAC;
            resp[1] = (cmd == WILL) ? DONT : WONT;
            resp[2] = buf[i + 2];
            send(fd, resp, 3, MSG_NOSIGNAL);
            i += 3;
            continue;
        }

        if ((cmd == WONT || cmd == DONT) && i + 2 < len) {
            i += 3; /* acknowledge silently */
            continue;
        }

        i += 2;
    }
}

/* Strip IAC sequences from buf in-place, return new length */
static int telnet_strip_iac(uint8_t *buf, int len) {
    int r = 0, w = 0;

    while (r < len) {
        if ((uint8_t)buf[r] == IAC) {
            if (r + 1 >= len) break;
            uint8_t cmd = buf[r + 1];
            if (cmd == SB) {
                r += 2;
                while (r + 1 < len) {
                    if ((uint8_t)buf[r] == IAC && (uint8_t)buf[r + 1] == SE) {
                        r += 2;
                        break;
                    }
                    r++;
                }
            } else if (cmd == WILL || cmd == WONT || cmd == DO || cmd == DONT) {
                r += 3;
            } else {
                r += 2; /* IAC IAC (escaped 0xFF) or unknown */
            }
            continue;
        }
        buf[w++] = buf[r++];
    }
    return w;
}

/* Read from fd with poll timeout (ms), handle IAC, return stripped length.
   Appends to buf at offset *pos, up to bufsz. */
static int telnet_recv(int fd, uint8_t *buf, int bufsz, int *pos, int timeout_ms) {
    struct pollfd pfd;
    int n;

    pfd.fd = fd;
    pfd.events = POLLIN;

    if (poll(&pfd, 1, timeout_ms) <= 0)
        return 0;

    n = (int)recv(fd, buf + *pos, (size_t)(bufsz - *pos - 1), 0);
    if (n <= 0) return -1;

    /* handle IAC negotiations */
    telnet_negotiate(fd, buf + *pos, n);

    /* strip IAC sequences from the new data */
    n = telnet_strip_iac(buf + *pos, n);
    *pos += n;
    buf[*pos] = '\0';
    return n;
}

/* Case-insensitive substring search */
static int has_prompt(const char *buf, const char *needle) {
    const char *p = buf;
    int nlen = (int)strlen(needle);
    while (*p) {
        if (strncasecmp(p, needle, (size_t)nlen) == 0)
            return 1;
        p++;
    }
    return 0;
}

/* Wait for a prompt pattern, reading until timeout or match.
   Returns 1 if prompt found, 0 if timeout, -1 if connection lost. */
static int wait_for_prompt(int fd, uint8_t *buf, int bufsz, int *pos,
                           const char **patterns, int npatterns, int timeout_ms) {
    int elapsed = 0, step = 200, i;

    while (elapsed < timeout_ms) {
        /* check current buffer first */
        for (i = 0; i < npatterns; i++) {
            if (has_prompt((const char *)buf, patterns[i]))
                return 1;
        }

        int r = telnet_recv(fd, buf, bufsz, pos, step);
        if (r < 0) return -1;
        elapsed += step;
    }

    /* final check */
    for (i = 0; i < npatterns; i++) {
        if (has_prompt((const char *)buf, patterns[i]))
            return 1;
    }
    return 0;
}

/* Extract first line of banner from pre-login data */
static void extract_banner(const uint8_t *buf, int len, char *out, int outsz) {
    int i, j = 0;

    if (!out || outsz <= 0) return;
    out[0] = '\0';

    for (i = 0; i < len && j < outsz - 1; i++) {
        char c = (char)buf[i];
        if (c == '\n' || c == '\r') {
            if (j > 0) break; /* end of first non-empty line */
            continue;         /* skip leading newlines */
        }
        if (c >= 0x20 && c < 0x7F)
            out[j++] = c;
    }
    out[j] = '\0';
}

int telnet_try(const char *ip, const char *user, const char *pass,
               const telnet_opts_t *opts, char *banner_out, int bansz) {
    uint8_t buf[4096];
    int pos = 0;
    int fd;
    int timeout_ms = opts->timeout * 1000;

    static const char *login_prompts[] = { "login:", "username:", "user:" };
    static const char *pass_prompts[]  = { "password:" };
    static const char *success_strs[]  = {
        "welcome", "last login", "busybox", "#", "$ "
    };
    static const char *fail_strs[]     = {
        "login incorrect", "authentication fail", "login fail",
        "access denied", "permission denied", "invalid password",
        "incorrect password", "wrong password", "bad password"
    };

    if (banner_out && bansz > 0) banner_out[0] = '\0';

    fd = tcp_connect(ip, opts->port, opts->timeout);
    if (fd < 0) return -1;

    /* 1. wait for login prompt */
    if (wait_for_prompt(fd, buf, (int)sizeof(buf), &pos,
                        login_prompts, 3, timeout_ms) != 1) {
        close(fd);
        return -1; /* no login prompt */
    }

    /* grab banner from what we received before login prompt */
    if (banner_out && bansz > 0)
        extract_banner(buf, pos, banner_out, bansz);

    /* 2. send username */
    {
        char cmd[256];
        int len = snprintf(cmd, sizeof(cmd), "%s\r\n", user);
        if (send(fd, cmd, (size_t)len, MSG_NOSIGNAL) <= 0) {
            close(fd);
            return -1;
        }
    }

    /* 3. wait for password prompt */
    pos = 0;
    buf[0] = '\0';
    if (wait_for_prompt(fd, buf, (int)sizeof(buf), &pos,
                        pass_prompts, 1, timeout_ms) != 1) {
        close(fd);
        return -1; /* no password prompt */
    }

    /* 4. send password */
    {
        char cmd[256];
        int len = snprintf(cmd, sizeof(cmd), "%s\r\n", pass);
        if (send(fd, cmd, (size_t)len, MSG_NOSIGNAL) <= 0) {
            close(fd);
            return -1;
        }
    }

    /* 5. read response and determine hit/miss.
       PAM often imposes a multi-second delay before responding to wrong
       passwords, so we must wait for the full timeout period. */
    pos = 0;
    buf[0] = '\0';
    {
        int elapsed = 0, step = 300;
        while (elapsed < timeout_ms) {
            int r = telnet_recv(fd, buf, (int)sizeof(buf), &pos, step);
            if (r < 0) break;
            elapsed += step;

            if (pos > 0) {
                int i;
                /* check for failure first */
                for (i = 0; i < (int)(sizeof(fail_strs) / sizeof(fail_strs[0])); i++) {
                    if (has_prompt((const char *)buf, fail_strs[i])) {
                        close(fd);
                        return 0; /* miss */
                    }
                }
                /* check for success */
                for (i = 0; i < (int)(sizeof(success_strs) / sizeof(success_strs[0])); i++) {
                    if (has_prompt((const char *)buf, success_strs[i])) {
                        close(fd);
                        return 1; /* hit */
                    }
                }
            }
        }
    }

    close(fd);

    /* final check on accumulated buffer */
    if (pos > 0) {
        int i;
        for (i = 0; i < (int)(sizeof(fail_strs) / sizeof(fail_strs[0])); i++) {
            if (has_prompt((const char *)buf, fail_strs[i]))
                return 0;
        }
        for (i = 0; i < (int)(sizeof(success_strs) / sizeof(success_strs[0])); i++) {
            if (has_prompt((const char *)buf, success_strs[i]))
                return 1;
        }
    }

    /* got data but can't determine — assume hit (got past login) */
    if (pos > 0)
        return 1;

    return -1;
}
