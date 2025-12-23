#ifndef __HTTPCLIENTHANDLERS_ASYNC__
#define __HTTPCLIENTHANDLERS_ASYNC__

#include "connection.h"

// Async event handlers для HTTP клиента
int __httpclient_async_read(connection_t* connection);
int __httpclient_async_write(connection_t* connection);
int __httpclient_async_close(connection_t* connection);

#endif
