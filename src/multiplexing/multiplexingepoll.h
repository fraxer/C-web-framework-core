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
    /* Worker-level tick (~500 ms) for idle/PING/shutdown timeouts. Registered
     * in the same epoll as the connections, with ev.data.ptr = &timer_tag so the
     * dispatcher can tell a timer event from a connection event. -1 if unused. */
    int timerfd;
    char timer_tag;
} mpxapi_epoll_t;

void* mpx_epoll_init();

#endif