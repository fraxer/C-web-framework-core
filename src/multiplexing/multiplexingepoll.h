#ifndef __MULTIPLEXINGEPOLL__
#define __MULTIPLEXINGEPOLL__

#include "multiplexing.h"

typedef struct epoll_event epoll_event_t;

typedef struct epoll_config {
    int basefd;
    int timeout;
} epoll_config_t;

typedef struct mpxapi_epoll {
    mpxapi_t base;
    int fd;
} mpxapi_epoll_t;

void* mpx_epoll_init();

#endif