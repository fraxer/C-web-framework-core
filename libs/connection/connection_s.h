#ifndef __CONNECTION_S__
#define __CONNECTION_S__

#include <stdatomic.h>

#include "connection.h"
#include "multiplexingserver.h"
#include "server.h"
#include "request.h"
#include "response.h"
#include "cqueue.h"

struct connection_s;
struct mpxapi;

typedef enum {
    CONNECTION_DEC_RESULT_DESTROY = 0,
    CONNECTION_DEC_RESULT_DECREMENT
} connection_dec_result_e;

typedef struct listener {
    struct connection_s* connection;
    struct mpxapi* api;
    server_t* server;
    struct listener* next;
} listener_t;

typedef struct {
    unsigned destroyed: 1;
    atomic_int ref_count;
    atomic_bool locked;
    listener_t* listener;
    response_t* response;
    cqueue_t* queue;

    // int(*after_read_request)(struct connection*);
    // int(*after_write_request)(struct connection*);
    // int(*queue_append)(struct connection_queue_item*);
    // void(*queue_append_broadcast)(struct connection_queue_item*);
    // int(*queue_pop)(struct connection*);
    void(*switch_to_protocol)(struct connection*);
} connection_server_ctx_t;

typedef struct connection_queue_item_data {
    void(*free)(void*);
} connection_queue_item_data_t;

typedef struct connection_queue_item {
    void(*free)(struct connection_queue_item*);
    void(*run)(void*);
    void(*handle)(void*);
    connection_t* connection;
    connection_queue_item_data_t* data;
} connection_queue_item_t;

connection_t* connection_s_create(connection_t* socket_connection);
connection_t* connection_s_alloc(listener_t* listener, int fd, in_addr_t ip, unsigned short int port);
void connection_s_free(connection_t*);
void connection_s_reset(connection_t*);
int connection_s_lock(connection_t*);
int connection_s_unlock(connection_t*);
int connection_trylockwrite(connection_t*);
void connection_s_inc(connection_t*);
connection_dec_result_e connection_s_dec(connection_t*);

int connection_after_read_request(connection_t*);
int connection_after_write_request(connection_t*);
int connection_queue_append(connection_queue_item_t*);
void connection_queue_append_broadcast(connection_queue_item_t*);
int connection_queue_pop(connection_t*);
int connection_close(connection_t* connection);

#endif
