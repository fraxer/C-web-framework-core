#ifndef __HTTP1_SERVER_HANDLERS__
#define __HTTP1_SERVER_HANDLERS__

#include "connection_s.h"

int set_tls(connection_t* connection);
int set_http1(connection_t* connection);
int http1_server_guard_read(connection_t* connection);
int http1_server_guard_write(connection_t* connection);

#endif
