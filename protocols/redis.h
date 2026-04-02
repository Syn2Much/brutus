#ifndef ARMSCAN_REDIS_H
#define ARMSCAN_REDIS_H

typedef struct {
    int timeout;
    int port;
    const char *exec_cmd;
} redis_opts_t;

#define REDIS_DEFAULTS { 5, 6379, NULL }

/* user can be NULL for legacy AUTH (password-only).
   Returns 1=hit, 0=miss, -1=error */
int redis_try(const char *ip, const char *user, const char *pass,
              const redis_opts_t *opts, char *version_out, int versz);

/* Check if target is an open (no-auth) instance.
   Returns 1=open, 0=auth-required, -1=error */
int redis_check_open(const char *ip, const redis_opts_t *opts);

#endif
