#ifndef __WEBSOCKETSBROADCAST__
#define __WEBSOCKETSBROADCAST__

#include "broadcast.h"
#include "websocketsrequest.h"

/* Broadcast helpers that take the request rather than the connection.
 *
 * On HTTP/1.1 a WebSocket subscriber IS the connection, so passing the
 * connection identified it. Under RFC 8441 a connection may carry several
 * tunnels, each its own subscriber, and the request is what knows which one
 * this message came from (docs/http2/09, step 5). These wrappers pull that out
 * and fall back to plain connection-level behaviour when there is no tunnel,
 * so one handler works over both transports unchanged. */

int websockets_broadcast_add(const char* broadcast_name, websocketsrequest_t* request, void* id,
                             void(*response_handler)(response_t* response, const char* payload, size_t size));

void websockets_broadcast_remove(const char* broadcast_name, websocketsrequest_t* request);

#endif
