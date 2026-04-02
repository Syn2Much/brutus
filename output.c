#include "output.h"
#include <string.h>

void output_init(output_ctx_t *ctx, FILE *fp, output_fmt_t fmt, int verbose)
{
    ctx->fp = fp;
    ctx->fmt = fmt;
    ctx->verbose = verbose;
    ctx->hits = 0;
    ctx->misses = 0;
    ctx->errors = 0;
    pthread_mutex_init(&ctx->lock, NULL);
}

static void json_escape(FILE *fp, const char *s)
{
    if (!s) { fprintf(fp, "null"); return; }
    fputc('"', fp);
    while (*s) {
        switch (*s) {
        case '"':  fprintf(fp, "\\\""); break;
        case '\\': fprintf(fp, "\\\\"); break;
        case '\n': fprintf(fp, "\\n");  break;
        case '\r': fprintf(fp, "\\r");  break;
        case '\t': fprintf(fp, "\\t");  break;
        default:   fputc(*s, fp);       break;
        }
        s++;
    }
    fputc('"', fp);
}

static void csv_field(FILE *fp, const char *s)
{
    if (!s) return;
    if (strchr(s, ',') || strchr(s, '"') || strchr(s, '\n')) {
        fputc('"', fp);
        while (*s) {
            if (*s == '"') fputc('"', fp);
            fputc(*s, fp);
            s++;
        }
        fputc('"', fp);
    } else {
        fprintf(fp, "%s", s);
    }
}

void output_hit(output_ctx_t *ctx, const char *proto, const char *ip,
                const char *user, const char *pass, const char *version)
{
    pthread_mutex_lock(&ctx->lock);
    ctx->hits++;

    switch (ctx->fmt) {
    case FMT_HUMAN:
        fprintf(ctx->fp, "[%s] hit: %s %s:%s", proto, ip, user ? user : "", pass ? pass : "");
        if (version && version[0])
            fprintf(ctx->fp, " (%s)", version);
        fprintf(ctx->fp, "\n");
        break;

    case FMT_JSON:
        fprintf(ctx->fp, "{\"proto\":");
        json_escape(ctx->fp, proto);
        fprintf(ctx->fp, ",\"type\":\"hit\",\"ip\":");
        json_escape(ctx->fp, ip);
        fprintf(ctx->fp, ",\"user\":");
        json_escape(ctx->fp, user);
        fprintf(ctx->fp, ",\"pass\":");
        json_escape(ctx->fp, pass);
        fprintf(ctx->fp, ",\"version\":");
        json_escape(ctx->fp, version && version[0] ? version : "");
        fprintf(ctx->fp, "}\n");
        break;

    case FMT_CSV:
        csv_field(ctx->fp, proto);
        fprintf(ctx->fp, ",hit,");
        csv_field(ctx->fp, ip);
        fputc(',', ctx->fp);
        csv_field(ctx->fp, user);
        fputc(',', ctx->fp);
        csv_field(ctx->fp, pass);
        fputc(',', ctx->fp);
        csv_field(ctx->fp, version && version[0] ? version : "");
        fprintf(ctx->fp, "\n");
        break;
    }

    fflush(ctx->fp);
    pthread_mutex_unlock(&ctx->lock);
}

void output_miss(output_ctx_t *ctx, const char *proto, const char *ip)
{
    pthread_mutex_lock(&ctx->lock);
    ctx->misses++;

    if (ctx->verbose) {
        switch (ctx->fmt) {
        case FMT_HUMAN:
            fprintf(ctx->fp, "[%s] miss: %s\n", proto, ip);
            break;

        case FMT_JSON:
            fprintf(ctx->fp, "{\"proto\":");
            json_escape(ctx->fp, proto);
            fprintf(ctx->fp, ",\"type\":\"miss\",\"ip\":");
            json_escape(ctx->fp, ip);
            fprintf(ctx->fp, ",\"user\":null,\"pass\":null,\"version\":null}\n");
            break;

        case FMT_CSV:
            csv_field(ctx->fp, proto);
            fprintf(ctx->fp, ",miss,");
            csv_field(ctx->fp, ip);
            fprintf(ctx->fp, ",,,\n");
            break;
        }

        fflush(ctx->fp);
    }

    pthread_mutex_unlock(&ctx->lock);
}

void output_error(output_ctx_t *ctx, const char *proto, const char *ip, const char *msg)
{
    pthread_mutex_lock(&ctx->lock);
    ctx->errors++;

    if (ctx->verbose) {
        switch (ctx->fmt) {
        case FMT_HUMAN:
            fprintf(ctx->fp, "[%s] error: %s %s\n", proto, ip, msg ? msg : "");
            break;

        case FMT_JSON:
            fprintf(ctx->fp, "{\"proto\":");
            json_escape(ctx->fp, proto);
            fprintf(ctx->fp, ",\"type\":\"error\",\"ip\":");
            json_escape(ctx->fp, ip);
            fprintf(ctx->fp, ",\"user\":null,\"pass\":null,\"version\":");
            json_escape(ctx->fp, msg);
            fprintf(ctx->fp, "}\n");
            break;

        case FMT_CSV:
            csv_field(ctx->fp, proto);
            fprintf(ctx->fp, ",error,");
            csv_field(ctx->fp, ip);
            fprintf(ctx->fp, ",,,");
            csv_field(ctx->fp, msg);
            fprintf(ctx->fp, "\n");
            break;
        }

        fflush(ctx->fp);
    }

    pthread_mutex_unlock(&ctx->lock);
}

void output_destroy(output_ctx_t *ctx)
{
    pthread_mutex_destroy(&ctx->lock);
}
