#ifndef BRUTUS_TARGET_H
#define BRUTUS_TARGET_H

typedef struct {
    char **list;
    int count;
    int cap;
} str_list_t;

typedef struct {
    char *user;  /* NULL for password-only (redis legacy) */
    char *pass;
} cred_t;

typedef struct {
    cred_t *list;
    int count;
    int cap;
} cred_list_t;

str_list_t target_load_file(const char *path);
str_list_t target_parse_inline(const char *spec);  /* comma-separated */
void str_list_free(str_list_t *l);

cred_list_t cred_load_file(const char *path);
cred_list_t cred_parse_inline(const char *spec);  /* comma-separated user:pass */
void cred_list_free(cred_list_t *l);
#endif
