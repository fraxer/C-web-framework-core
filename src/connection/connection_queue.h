#ifndef __CONNECTION_QUEUE__
#define __CONNECTION_QUEUE__

#include "connection_s.h"

int connection_queue_init();
void connection_queue_guard_append_item(connection_queue_item_t*);
void connection_queue_guard_append(connection_t*);

/* Next connection with work, with a reference held and WITHOUT connection_s_lock
 * — the runner locks what it needs. See __connection_queue_pop. */
connection_t* connection_queue_guard_pop();
void connection_queue_broadcast();
connection_queue_item_t* connection_queue_item_create();

#endif
