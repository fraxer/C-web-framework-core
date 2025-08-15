#ifndef __WEBSOCKETSINTERNAL__
#define __WEBSOCKETSINTERNAL__

#include "connection_s.h"
#include "websocketsrequest.h"
#include "websocketsresponse.h"

typedef int(*deferred_handler)(websocketsresponse_t* response);
typedef void(*queue_handler)(void*);
typedef void*(*queue_data_create)(connection_t* connection, void* component);

int websockets_guard_read(connection_t* connection);
int websockets_guard_write(connection_t* connection);
int websockets_deferred_handler(connection_t* connection, void* component, queue_handler runner, queue_handler handle, queue_data_create data_create);
void websockets_queue_request_handler(void*);
void* websockets_queue_data_request_create(connection_t* connection, void* component);

#endif
