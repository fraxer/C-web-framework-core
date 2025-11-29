#ifndef __HTTP1_SERVER_HANDLERS__
#define __HTTP1_SERVER_HANDLERS__

#include "connection_s.h"
#include "server.h"

int set_tls(connection_t* connection);
int set_http(connection_t* connection);
int http_server_guard_read(connection_t* connection);
int http_server_guard_write(connection_t* connection);
void http_server_init_sni_callbacks(server_t* servers);

#endif
