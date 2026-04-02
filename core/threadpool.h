#ifndef BRUTUS_THREADPOOL_H
#define BRUTUS_THREADPOOL_H
#include <pthread.h>

typedef struct {
    void **items;
    int count;
    volatile int next;
    pthread_mutex_t lock;
    int num_threads;
    void (*worker)(void *item, void *ctx);
    void *ctx;
} threadpool_t;

void tp_init(threadpool_t *tp, void **items, int count, int num_threads,
             void (*worker)(void *item, void *ctx), void *ctx);
void tp_run(threadpool_t *tp);  /* blocks until done */
void tp_destroy(threadpool_t *tp);
#endif
