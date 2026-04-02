#include "target.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define INIT_CAP 64

static char *trim(char *s)
{
    char *end;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static void str_list_push(str_list_t *l, const char *s)
{
    if (l->count >= l->cap) {
        l->cap = l->cap ? l->cap * 2 : INIT_CAP;
        l->list = (char **)realloc(l->list, sizeof(char *) * (size_t)l->cap);
    }
    l->list[l->count++] = strdup(s);
}

static void cred_list_push(cred_list_t *l, const char *user, const char *pass)
{
    if (l->count >= l->cap) {
        l->cap = l->cap ? l->cap * 2 : INIT_CAP;
        l->list = (cred_t *)realloc(l->list, sizeof(cred_t) * (size_t)l->cap);
    }
    l->list[l->count].user = user ? strdup(user) : NULL;
    l->list[l->count].pass = strdup(pass);
    l->count++;
}

str_list_t target_load_file(const char *path)
{
    str_list_t l = { NULL, 0, 0 };
    FILE *fp;
    char buf[1024];

    fp = fopen(path, "r");
    if (!fp) return l;

    while (fgets(buf, sizeof(buf), fp)) {
        char *line = trim(buf);
        if (*line == '\0' || *line == '#')
            continue;
        str_list_push(&l, line);
    }

    fclose(fp);
    return l;
}

str_list_t target_parse_inline(const char *spec)
{
    str_list_t l = { NULL, 0, 0 };
    char *copy, *tok, *saveptr;

    if (!spec || !*spec) return l;

    copy = strdup(spec);
    tok = strtok_r(copy, ",", &saveptr);
    while (tok) {
        char *t = trim(tok);
        if (*t)
            str_list_push(&l, t);
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    return l;
}

void str_list_free(str_list_t *l)
{
    int i;
    for (i = 0; i < l->count; i++)
        free(l->list[i]);
    free(l->list);
    l->list = NULL;
    l->count = 0;
    l->cap = 0;
}

cred_list_t cred_load_file(const char *path)
{
    cred_list_t l = { NULL, 0, 0 };
    FILE *fp;
    char buf[1024];

    fp = fopen(path, "r");
    if (!fp) return l;

    while (fgets(buf, sizeof(buf), fp)) {
        char *line = trim(buf);
        char *colon;
        if (*line == '\0' || *line == '#')
            continue;
        colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            cred_list_push(&l, line, colon + 1);
        } else {
            /* password-only (redis legacy) */
            cred_list_push(&l, NULL, line);
        }
    }

    fclose(fp);
    return l;
}

cred_list_t cred_parse_inline(const char *spec)
{
    cred_list_t l = { NULL, 0, 0 };
    char *copy, *tok, *saveptr;

    if (!spec || !*spec) return l;

    copy = strdup(spec);
    tok = strtok_r(copy, ",", &saveptr);
    while (tok) {
        char *t = trim(tok);
        if (*t) {
            char *colon = strchr(t, ':');
            if (colon) {
                *colon = '\0';
                cred_list_push(&l, t, colon + 1);
            } else {
                cred_list_push(&l, NULL, t);
            }
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    return l;
}

void cred_list_free(cred_list_t *l)
{
    int i;
    for (i = 0; i < l->count; i++) {
        free(l->list[i].user);
        free(l->list[i].pass);
    }
    free(l->list);
    l->list = NULL;
    l->count = 0;
    l->cap = 0;
}
