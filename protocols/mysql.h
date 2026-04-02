#ifndef BRUTUS_MYSQL_H
#define BRUTUS_MYSQL_H

typedef struct {
    int timeout;
    int port;
} mysql_opts_t;

#define MYSQL_DEFAULTS { 5, 3306 }

int mysql_try(const char *ip, const char *user, const char *pass,
              const mysql_opts_t *opts, char *version_out, int versz);

#endif
