#include "threadpool.h"
#include <stdlib.h>

void tp_init(threadpool_t *tp, void **items, int count, int num_threads,
             void (*worker)(void *item, void *ctx), void *ctx)
{
    tp->items = items;
    tp->count = count;
    tp->next = 0;
    tp->num_threads = num_threads;
    tp->worker = worker;
    tp->ctx = ctx;
    pthread_mutex_init(&tp->lock, NULL);
}

static void *tp_thread(void *arg)
{
    threadpool_t *tp = (threadpool_t *)arg;

    for (;;) {
        int idx;

        pthread_mutex_lock(&tp->lock);
        idx = tp->next;
        if (idx < tp->count)
            tp->next = idx + 1;
        pthread_mutex_unlock(&tp->lock);

        if (idx >= tp->count)
            break;

        tp->worker(tp->items[idx], tp->ctx);
    }

    return NULL;
}

void tp_run(threadpool_t *tp)
{
    int i;
    int n = tp->num_threads;
    pthread_t *threads;

    if (n > tp->count)
        n = tp->count;
    if (n <= 0)
        return;

    threads = (pthread_t *)malloc(sizeof(pthread_t) * (size_t)n);
    if (!threads)
        return;

    for (i = 0; i < n; i++)
        pthread_create(&threads[i], NULL, tp_thread, tp);

    for (i = 0; i < n; i++)
        pthread_join(threads[i], NULL);

    free(threads);
}

void tp_destroy(threadpool_t *tp)
{
    pthread_mutex_destroy(&tp->lock);
}
