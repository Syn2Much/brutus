#ifndef BRUTUS_TELNET_H
#define BRUTUS_TELNET_H

typedef struct {
    int timeout;
    int port;
} telnet_opts_t;

#define TELNET_DEFAULTS { 5, 23 }

/* Try a single user:pass against a telnet login prompt.
   Returns 1=hit, 0=miss, -1=error.
   banner_out receives the pre-login banner (or first line) if non-NULL. */
int telnet_try(const char *ip, const char *user, const char *pass,
               const telnet_opts_t *opts, char *banner_out, int bansz);

#endif
