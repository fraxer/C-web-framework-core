#ifndef __CONNECTION_S__
#define __CONNECTION_S__

#include <stdatomic.h>

#include "connection.h"
#include "server.h"
#include "request.h"
#include "response.h"
#include "cqueue.h"

struct mpxapi;
struct connection_queue_item;

typedef enum {
    CONNECTION_DEC_RESULT_DESTROY = 0,
    CONNECTION_DEC_RESULT_DECREMENT
} connection_dec_result_e;

typedef struct connection_s {
    connection_t base;
    unsigned destroyed: 1;
    atomic_int ref_count;
    atomic_bool locked;
    struct mpxapi* api;
    server_t* server;
    response_t* response;
    cqueue_t* queue;

    int(*close)(struct connection_s*);
    void(*read)(struct connection_s*, char*, size_t);
    void(*write)(struct connection_s*, char*, size_t);
    int(*after_read_request)(struct connection_s*);
    int(*after_write_request)(struct connection_s*);
    int(*queue_append)(struct connection_queue_item*);
    void(*queue_append_broadcast)(struct connection_queue_item*);
    int(*queue_pop)(struct connection_s*);
    void(*switch_to_protocol)(struct connection_s*);
} connection_s_t;

connection_s_t* connection_s_create(connection_s_t* socket_connection);
connection_s_t* connection_s_alloc(int fd, struct mpxapi* api, in_addr_t ip, unsigned short int port);
void connection_s_free(connection_s_t*);
void connection_s_reset(connection_s_t*);
int connection_s_lock(connection_s_t*);
int connection_s_unlock(connection_s_t*);
int connection_s_trylockwrite(connection_s_t*);
void connection_s_inc(connection_s_t*);
connection_dec_result_e connection_s_dec(connection_s_t*);

#endif
