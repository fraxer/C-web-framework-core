#ifndef __LISTENTER__
#define __LISTENTER__

#include "connection_s.h"

void listener_read(connection_s_t*, char*, size_t);
int listener_connection_close(connection_s_t*);

#endif
