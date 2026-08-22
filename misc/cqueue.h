#ifndef __CQUEUE__
#define __CQUEUE__

#include <stdatomic.h>

typedef struct cqueue_item {
    void* data;
    struct cqueue_item* next;
} cqueue_item_t;

typedef struct {
    cqueue_item_t* item;
    cqueue_item_t* last_item;
    ssize_t size;
    atomic_int locked;
} cqueue_t;

cqueue_t* cqueue_create();
void cqueue_init(cqueue_t* queue);
void cqueue_free(cqueue_t*);
void cqueue_freecb(cqueue_t*, void(*free_cb)(void*));
int cqueue_append(cqueue_t*, void*);
int cqueue_prepend(cqueue_t*, void*);
void* cqueue_pop(cqueue_t*);
/* Take up to `max` entries the predicate accepts, in queue order, leaving
 * everything else where it is. Written for the broadcast fan-out, where several
 * independent output orders share one queue and a batch may only carry one of
 * them: popping from the head alone gives up as soon as another order's message
 * is next, and walking with pop+prepend would reverse what stays behind.
 *
 * Returns how many entries were written into `out`; the caller owns them. The
 * relative order of taken entries is preserved, and so is the order of those
 * left in place. Cost is one pass over the queue, so a caller that wants a whole
 * batch should ask for it in a single call rather than in a loop. */
size_t cqueue_take_matching(cqueue_t*, int (*accepts)(const void* data, void* ctx),
                            void* ctx, size_t max, void** out);
int cqueue_empty(cqueue_t*);
int cqueue_size(cqueue_t*);
cqueue_item_t* cqueue_first(cqueue_t*);
cqueue_item_t* cqueue_last(cqueue_t*);
int cqueue_lock(cqueue_t*);
int cqueue_incrementlock(cqueue_t*);
int cqueue_unlock(cqueue_t*);
void cqueue_clear(cqueue_t*);
void cqueue_clearcb(cqueue_t*, void(*free_cb)(void*));

cqueue_item_t* cqueue_item_create(void* data);
void cqueue_item_free(cqueue_item_t*);

#endif