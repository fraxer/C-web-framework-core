#ifndef __WEBSOCKETSINTERNAL__
#define __WEBSOCKETSINTERNAL__

#include "connection_s.h"
#include "websocketsrequest.h"
#include "websocketsresponse.h"

typedef void(*queue_handler)(void*);
typedef void*(*queue_data_create)(connection_t* connection, void* component, ratelimiter_t* ratelimiter);

int websockets_guard_read(connection_t* connection);
int websockets_guard_write(connection_t* connection);

/* Hand a finished response to the connection's output order and, if it is now
 * at the head, ask the event loop for a write turn. Takes connection_s_lock, so
 * callers must not hold it; takes ownership of the response either way.
 *
 * For producers that run off the read path — broadcast fan-out, and anything
 * else that builds a frame from a worker thread. docs/concurrency/00 §4.4. */
int websockets_response_post(websocketsresponse_t* response);
int websockets_deferred_handler(connection_t* connection, void* component, queue_handler runner, queue_handler handle, queue_data_create data_create, ratelimiter_t* ratelimiter);
void websockets_queue_request_handler(void*);
void* websockets_queue_data_request_create(connection_t* connection, void* component, ratelimiter_t* ratelimiter);

/* Reserve a place in an output order. Exposed for the RFC 8441 tunnel, whose
 * order lives on the stream rather than on the connection (docs/http2/09). */
connection_out_slot_t* __out_reserve_in(cqueue_t* queue);

#endif
