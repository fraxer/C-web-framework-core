#ifndef __MULTIPLEXING__
#define __MULTIPLEXING__

#include <stdatomic.h>
#include <sys/epoll.h>

#include "appconfig.h"
#include "connection.h"

enum mpxevents {
    MPXIN = EPOLLIN,
    MPXOUT = EPOLLOUT,
    MPXERR = EPOLLERR,
    MPXHUP = EPOLLHUP,
    MPXRDHUP = EPOLLRDHUP,
    MPXONESHOT = EPOLLONESHOT,
};

typedef struct mpxapi {
    atomic_int connection_count;
    void* config;
    /* This worker's connections, linked through connection_t::prev/next. The
     * worker timer sweep walks it to enforce idle/PING timeouts and graceful
     * shutdown. Maintained on control_add/del (worker thread only). */
    connection_t* conns;
    void(*free)(void*);
    int(*control_add)(connection_t*, int);
    int(*control_mod)(connection_t*, int);
    int(*control_del)(connection_t*);
    void(*process_events)(appconfig_t* appconfig, void* arg);
    /* Fired by the worker timer (one tick per worker, ~500 ms). NULL until the
     * server layer wires the h2 idle/PING/shutdown sweep onto it. */
    void(*on_tick)(struct mpxapi*);

#ifdef CWFR_HTTP3
    /* This worker's QUIC endpoints (quicendpoint_t*), so the tick can reach
     * them. Kept here rather than walked out of `conns` because the send queue
     * belongs to the endpoint, not to any one connection. */
    void* quic_endpoints;
#endif
} mpxapi_t;

mpxapi_t* mpx_create();
void mpx_free(mpxapi_t*);

#endif