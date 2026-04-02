#ifndef ARMSCAN_OUTPUT_H
#define ARMSCAN_OUTPUT_H
#include <stdio.h>
#include <pthread.h>

typedef enum { FMT_HUMAN, FMT_JSON, FMT_CSV } output_fmt_t;

typedef struct {
    FILE *fp;
    output_fmt_t fmt;
    pthread_mutex_t lock;
    int verbose;
    int hits;   /* running count */
    int misses;
    int errors;
} output_ctx_t;

void output_init(output_ctx_t *ctx, FILE *fp, output_fmt_t fmt, int verbose);
void output_hit(output_ctx_t *ctx, const char *proto, const char *ip,
                const char *user, const char *pass, const char *version);
void output_miss(output_ctx_t *ctx, const char *proto, const char *ip);
void output_error(output_ctx_t *ctx, const char *proto, const char *ip, const char *msg);
void output_destroy(output_ctx_t *ctx);
#endif
