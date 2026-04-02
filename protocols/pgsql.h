#ifndef BRUTUS_PGSQL_H
#define BRUTUS_PGSQL_H

typedef struct {
    int timeout;
    int port;
    const char *database;
} pgsql_opts_t;

#define PGSQL_DEFAULTS { 5, 5432, "postgres" }

int pgsql_try(const char *ip, const char *user, const char *pass,
              const pgsql_opts_t *opts, char *version_out, int versz);

#endif
