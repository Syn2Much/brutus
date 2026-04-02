#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include "core/threadpool.h"
#include "core/output.h"
#include "core/target.h"
#include "protocols/ssh.h"
#include "protocols/mysql.h"
#include "protocols/pgsql.h"
#include "protocols/redis.h"

typedef struct {
    const char *protocol;
    cred_list_t *creds;
    output_ctx_t *out;
    /* protocol-specific opts */
    ssh_opts_t   ssh_opts;
    mysql_opts_t mysql_opts;
    pgsql_opts_t pgsql_opts;
    redis_opts_t redis_opts;
    const char  *exec_cmd;
} scan_ctx_t;

/* ------------------------------------------------------------------ */
/* protocol workers                                                    */
/* ------------------------------------------------------------------ */

static void ssh_worker(void *item, void *ctx)
{
    const char  *ip = (const char *)item;
    scan_ctx_t  *sc = (scan_ctx_t *)ctx;
    int          err, i;
    ssh_session_t *s;

    s = ssh_connect(ip, &sc->ssh_opts, &err);
    if (!s) {
        if (err == SSH_ERR_KEX_NONE)
            output_error(sc->out, "ssh", ip, "kex-unsupported");
        else
            output_error(sc->out, "ssh", ip, "connect-failed");
        return;
    }

    for (i = 0; i < sc->creds->count; i++) {
        const char *user = sc->creds->list[i].user ? sc->creds->list[i].user : "root";
        const char *pass = sc->creds->list[i].pass;
        int r = ssh_auth(s, user, pass);
        if (r == 1) {
            output_hit(sc->out, "ssh", ip, user, pass, ssh_banner(s));
            if (sc->exec_cmd)
                ssh_exec(s, sc->exec_cmd);
            break;
        } else if (r < 0) {
            output_error(sc->out, "ssh", ip, "session-dead");
            break;
        }
        /* r == 0: wrong creds, try next */
    }

    ssh_close(s);
}

static void mysql_worker(void *item, void *ctx)
{
    const char *ip = (const char *)item;
    scan_ctx_t *sc = (scan_ctx_t *)ctx;
    char version[128] = "";
    int i;

    for (i = 0; i < sc->creds->count; i++) {
        const char *user = sc->creds->list[i].user ? sc->creds->list[i].user : "root";
        const char *pass = sc->creds->list[i].pass;
        int r = mysql_try(ip, user, pass, &sc->mysql_opts, version, sizeof(version));
        if (r == 1) {
            output_hit(sc->out, "mysql", ip, user, pass, version);
            break;
        } else if (r == 0) {
            output_miss(sc->out, "mysql", ip);
        } else {
            output_error(sc->out, "mysql", ip, "connect-error");
            break;
        }
    }
}

static void pgsql_worker(void *item, void *ctx)
{
    const char *ip = (const char *)item;
    scan_ctx_t *sc = (scan_ctx_t *)ctx;
    char version[128] = "";
    int i;

    for (i = 0; i < sc->creds->count; i++) {
        const char *user = sc->creds->list[i].user ? sc->creds->list[i].user : "root";
        const char *pass = sc->creds->list[i].pass;
        int r = pgsql_try(ip, user, pass, &sc->pgsql_opts, version, sizeof(version));
        if (r == 1) {
            output_hit(sc->out, "pgsql", ip, user, pass, version);
            break;
        } else if (r == 0) {
            output_miss(sc->out, "pgsql", ip);
        } else {
            output_error(sc->out, "pgsql", ip, "connect-error");
            break;
        }
    }
}

static void redis_worker(void *item, void *ctx)
{
    const char *ip = (const char *)item;
    scan_ctx_t *sc = (scan_ctx_t *)ctx;
    char version[128] = "";
    int i;

    /* quick open check first */
    if (redis_check_open(ip, &sc->redis_opts)) {
        output_hit(sc->out, "redis", ip, "", "", "open-no-auth");
        if (sc->exec_cmd) {
            redis_opts_t tmp = sc->redis_opts;
            tmp.exec_cmd = sc->exec_cmd;
            redis_try(ip, NULL, NULL, &tmp, version, sizeof(version));
        }
        return;
    }

    for (i = 0; i < sc->creds->count; i++) {
        const char *user = sc->creds->list[i].user;  /* may be NULL */
        const char *pass = sc->creds->list[i].pass;
        redis_opts_t opts = sc->redis_opts;
        if (sc->exec_cmd)
            opts.exec_cmd = sc->exec_cmd;
        int r = redis_try(ip, user, pass, &opts, version, sizeof(version));
        if (r == 1) {
            output_hit(sc->out, "redis", ip, user ? user : "", pass, version);
            break;
        } else if (r == 0) {
            output_miss(sc->out, "redis", ip);
        } else {
            output_error(sc->out, "redis", ip, "connect-error");
            break;
        }
    }
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static void str_list_append(str_list_t *dst, str_list_t *src)
{
    int i;
    for (i = 0; i < src->count; i++) {
        if (dst->count >= dst->cap) {
            dst->cap = dst->cap ? dst->cap * 2 : 64;
            dst->list = (char **)realloc(dst->list, sizeof(char *) * (size_t)dst->cap);
        }
        dst->list[dst->count++] = src->list[i];
        src->list[i] = NULL;  /* ownership transferred */
    }
}

static void cred_list_append(cred_list_t *dst, cred_list_t *src)
{
    int i;
    for (i = 0; i < src->count; i++) {
        if (dst->count >= dst->cap) {
            dst->cap = dst->cap ? dst->cap * 2 : 64;
            dst->list = (cred_t *)realloc(dst->list, sizeof(cred_t) * (size_t)dst->cap);
        }
        dst->list[dst->count++] = src->list[i];
        src->list[i].user = NULL;
        src->list[i].pass = NULL;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <protocol> [options]\n"
        "\n"
        "Protocols: ssh, mysql, pgsql, redis\n"
        "\n"
        "Options:\n"
        "  -T, --targets FILE       Target list (one IP/line)\n"
        "  -t, --target IP          Single target (repeatable)\n"
        "  -C, --creds FILE         Credential list (user:pass/line)\n"
        "  -c, --cred USER:PASS     Single credential (repeatable)\n"
        "  -j, --threads N          Thread count (default: 32)\n"
        "  -p, --port N             Override default port\n"
        "      --timeout N          Connect timeout seconds (default: 5)\n"
        "  -x, --exec CMD           Execute on hit (ssh, redis only)\n"
        "      --database DB        PostgreSQL database (default: postgres)\n"
        "  -o, --output FILE        Output file (default: stdout)\n"
        "  -f, --format FMT         human|json|csv (default: human)\n"
        "  -v, --verbose            Show misses + errors\n"
        "  -q, --quiet              Hits only\n"
        "  -h, --help\n",
        prog);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *protocol;
    int threads    = 32;
    int port       = -1;
    int timeout    = 5;
    int verbose    = 0;
    int quiet      = 0;
    const char *exec_cmd   = NULL;
    const char *database   = "postgres";
    const char *outfile    = NULL;
    const char *fmt_str    = "human";

    str_list_t  targets = { NULL, 0, 0 };
    cred_list_t creds   = { NULL, 0, 0 };

    output_fmt_t fmt;
    output_ctx_t out;
    scan_ctx_t   sc;
    threadpool_t tp;
    FILE *fp;
    struct timespec t_start, t_end;
    double elapsed;
    int i;

    void (*worker_fn)(void *, void *) = NULL;

    static struct option long_opts[] = {
        { "targets",  required_argument, NULL, 'T' },
        { "target",   required_argument, NULL, 't' },
        { "creds",    required_argument, NULL, 'C' },
        { "cred",     required_argument, NULL, 'c' },
        { "threads",  required_argument, NULL, 'j' },
        { "port",     required_argument, NULL, 'p' },
        { "timeout",  required_argument, NULL,  1  },
        { "exec",     required_argument, NULL, 'x' },
        { "database", required_argument, NULL,  2  },
        { "output",   required_argument, NULL, 'o' },
        { "format",   required_argument, NULL, 'f' },
        { "verbose",  no_argument,       NULL, 'v' },
        { "quiet",    no_argument,       NULL, 'q' },
        { "help",     no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    protocol = argv[1];
    if (strcmp(protocol, "-h") == 0 || strcmp(protocol, "--help") == 0) {
        usage(argv[0]);
        return 0;
    }

    if (strcmp(protocol, "ssh") != 0 && strcmp(protocol, "mysql") != 0 &&
        strcmp(protocol, "pgsql") != 0 && strcmp(protocol, "redis") != 0) {
        fprintf(stderr, "error: unknown protocol '%s'\n", protocol);
        usage(argv[0]);
        return 1;
    }

    /* shift argv so getopt sees options after protocol */
    optind = 2;

    int opt;
    while ((opt = getopt_long(argc, argv, "T:t:C:c:j:p:x:o:f:vqh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'T': {
            str_list_t tmp = target_load_file(optarg);
            if (tmp.count == 0)
                fprintf(stderr, "warning: no targets loaded from '%s'\n", optarg);
            str_list_append(&targets, &tmp);
            str_list_free(&tmp);
            break;
        }
        case 't': {
            str_list_t tmp = target_parse_inline(optarg);
            str_list_append(&targets, &tmp);
            str_list_free(&tmp);
            break;
        }
        case 'C': {
            cred_list_t tmp = cred_load_file(optarg);
            if (tmp.count == 0)
                fprintf(stderr, "warning: no credentials loaded from '%s'\n", optarg);
            cred_list_append(&creds, &tmp);
            cred_list_free(&tmp);
            break;
        }
        case 'c': {
            cred_list_t tmp = cred_parse_inline(optarg);
            cred_list_append(&creds, &tmp);
            cred_list_free(&tmp);
            break;
        }
        case 'j':
            threads = atoi(optarg);
            if (threads <= 0) threads = 1;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 1: /* --timeout */
            timeout = atoi(optarg);
            if (timeout <= 0) timeout = 1;
            break;
        case 'x':
            exec_cmd = optarg;
            break;
        case 2: /* --database */
            database = optarg;
            break;
        case 'o':
            outfile = optarg;
            break;
        case 'f':
            fmt_str = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'q':
            quiet = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* validate */
    if (targets.count == 0) {
        fprintf(stderr, "error: no targets specified (use -T or -t)\n");
        return 1;
    }
    if (creds.count == 0) {
        fprintf(stderr, "error: no credentials specified (use -C or -c)\n");
        return 1;
    }

    /* parse format */
    if (strcmp(fmt_str, "json") == 0)
        fmt = FMT_JSON;
    else if (strcmp(fmt_str, "csv") == 0)
        fmt = FMT_CSV;
    else
        fmt = FMT_HUMAN;

    /* open output */
    if (outfile) {
        fp = fopen(outfile, "w");
        if (!fp) {
            perror("fopen output");
            return 1;
        }
    } else {
        fp = stdout;
    }

    if (quiet) verbose = 0;
    output_init(&out, fp, fmt, verbose);

    /* set up scan context */
    memset(&sc, 0, sizeof(sc));
    sc.protocol = protocol;
    sc.creds    = &creds;
    sc.out      = &out;
    sc.exec_cmd = exec_cmd;

    if (strcmp(protocol, "ssh") == 0) {
        ssh_opts_t defaults = SSH_DEFAULTS;
        sc.ssh_opts = defaults;
        sc.ssh_opts.connect_timeout = timeout;
        if (port > 0) sc.ssh_opts.port = port;
        worker_fn = ssh_worker;
    } else if (strcmp(protocol, "mysql") == 0) {
        mysql_opts_t defaults = MYSQL_DEFAULTS;
        sc.mysql_opts = defaults;
        sc.mysql_opts.timeout = timeout;
        if (port > 0) sc.mysql_opts.port = port;
        worker_fn = mysql_worker;
    } else if (strcmp(protocol, "pgsql") == 0) {
        pgsql_opts_t defaults = PGSQL_DEFAULTS;
        sc.pgsql_opts = defaults;
        sc.pgsql_opts.timeout = timeout;
        sc.pgsql_opts.database = database;
        if (port > 0) sc.pgsql_opts.port = port;
        worker_fn = pgsql_worker;
    } else if (strcmp(protocol, "redis") == 0) {
        redis_opts_t defaults = REDIS_DEFAULTS;
        sc.redis_opts = defaults;
        sc.redis_opts.timeout = timeout;
        sc.redis_opts.exec_cmd = exec_cmd;
        if (port > 0) sc.redis_opts.port = port;
        worker_fn = redis_worker;
    }

    /* build void** target array */
    void **items = (void **)malloc(sizeof(void *) * (size_t)targets.count);
    for (i = 0; i < targets.count; i++)
        items[i] = (void *)targets.list[i];

    /* run */
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    tp_init(&tp, items, targets.count, threads, worker_fn, &sc);
    tp_run(&tp);
    tp_destroy(&tp);

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    elapsed = (double)(t_end.tv_sec - t_start.tv_sec) +
              (double)(t_end.tv_nsec - t_start.tv_nsec) / 1e9;

    /* summary to stderr */
    fprintf(stderr, "[%s] done: %d targets, %d hits, %d misses, %d errors, %.1fs elapsed\n",
            protocol, targets.count, out.hits, out.misses, out.errors, elapsed);

    /* cleanup */
    output_destroy(&out);
    if (outfile && fp)
        fclose(fp);
    free(items);
    str_list_free(&targets);
    cred_list_free(&creds);

    return 0;
}
