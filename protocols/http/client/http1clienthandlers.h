#ifndef __HTTP1_CLIENT_HANDLERS__
#define __HTTP1_CLIENT_HANDLERS__

#include "connection_c.h"

void set_client_tls(connection_t* connection);
void set_client_http1(connection_t* connection);
int http1_client_read(connection_t* connection);
int http1_client_write(connection_t* connection);

#endif
