#ifndef __CONNECTION_S__
#define __CONNECTION_S__

#include <stdatomic.h>

#include "connection.h"
#include "multiplexingserver.h"
#include "server.h"
#include "request.h"
#include "response.h"
#include "cqueue.h"

struct mpxapi;

typedef enum {
    CONNECTION_DEC_RESULT_DESTROY = 0,
    CONNECTION_DEC_RESULT_DECREMENT
} connection_dec_result_e;

typedef struct listener {
    cqueue_t servers;
    struct connection* connection;
    struct mpxapi* api;
    struct listener* next;
} listener_t;

typedef struct requestparser {
    void(*free)(void*);
} requestparser_t;

typedef struct switch_to_protocol {
    int(*fn)(struct connection*, void* data);
    void(*data_free)(void*);
    void* data;
} switch_to_protocol_t;

typedef struct {
    connection_ctx_t base;

    listener_t* listener;
    void* parser;
    server_t* server;
    void* request;
    void* response;
    cqueue_t* queue;
    cqueue_t* broadcast_queue;

    switch_to_protocol_t switch_to_protocol;

    atomic_int ref_count;
    atomic_int broadcast_ref_count;
    atomic_bool destroyed;
    atomic_bool locked;
    unsigned need_write: 1;
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

connection_t* connection_s_create(int fd, in_addr_t ip, unsigned short int port, connection_server_ctx_t* ctx, char* buffer, size_t buffer_size);
connection_t* connection_s_alloc(listener_t* listener, int fd, in_addr_t ip, unsigned short int port, in_addr_t client_ip, unsigned short int client_port, char* buffer, size_t buffer_size);
connection_t* connection_s_create_local(server_t* server);
void connection_s_free_local(connection_t* connection);

int connection_s_lock(connection_t*);
int connection_s_unlock(connection_t*);
void connection_s_inc(connection_t*);
connection_dec_result_e connection_s_dec(connection_t*);

int connection_after_write(connection_t*);
int connection_queue_append(connection_queue_item_t*);
int connection_queue_append_broadcast(connection_t*);
int connection_after_read(connection_t*);
int connection_close(connection_t* connection);

#endif
