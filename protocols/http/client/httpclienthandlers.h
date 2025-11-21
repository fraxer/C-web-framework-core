#ifndef __HTTP1_CLIENT_HANDLERS__
#define __HTTP1_CLIENT_HANDLERS__

#include "connection_c.h"

void set_client_tls(connection_t* connection);
void set_client_http(connection_t* connection);
int http_client_read(connection_t* connection);
int http_client_write(connection_t* connection);

#endif
