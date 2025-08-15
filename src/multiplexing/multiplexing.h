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
    void(*free)(void*);
    int(*control_add)(connection_t*, int);
    int(*control_mod)(connection_t*, int);
    int(*control_del)(connection_t*);
    void(*process_events)(appconfig_t* appconfig, void* arg);
} mpxapi_t;

mpxapi_t* mpx_create();
void mpx_free(mpxapi_t*);

#endif