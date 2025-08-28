#ifndef __CONNECTION_QUEUE__
#define __CONNECTION_QUEUE__

#include "connection_s.h"

int connection_queue_init();
void connection_queue_guard_append(connection_queue_item_t*);
void connection_queue_guard_append2(connection_t*);
connection_t* connection_queue_guard_pop();
void connection_queue_broadcast();
connection_queue_item_t* connection_queue_item_create();

#endif
