#include "websocketsbroadcast.h"

#include "websocketsserverhandlers.h"

int websockets_broadcast_add(const char* broadcast_name, websocketsrequest_t* request, void* id,
                             void(*response_handler)(response_t* response, const char* payload, size_t size)) {
    if (request == NULL) {
        broadcast_id_t* wrapped = id;
        if (wrapped != NULL && wrapped->free != NULL) wrapped->free(wrapped);
        return 0;
    }

    return broadcast_add_out(broadcast_name, request->connection, id, response_handler,
                             request->out_queue, request->out_owner, request->out_wake,
                             request->out_deflate);
}

void websockets_broadcast_remove(const char* broadcast_name, websocketsrequest_t* request) {
    if (request == NULL) return;

    broadcast_remove_out(broadcast_name, request->connection, request->out_owner);
}

void websockets_broadcast_send(const char* broadcast_name, websocketsrequest_t* request, const char* payload, size_t size, void* id, int(*compare_handler)(void* st1, void* st2)) {
    if (request == NULL) {
        broadcast_id_t* wrapped = id;
        if (wrapped != NULL && wrapped->free != NULL) wrapped->free(wrapped);
        return;
    }

    broadcast_send(broadcast_name, request->connection, request->out_owner, payload, size, id, compare_handler);
}

void websockets_broadcast_send_all(const char* broadcast_name, websocketsrequest_t* request, const char* payload, size_t size) {
    if (request == NULL) return;

    broadcast_send_all(broadcast_name, request->connection, request->out_owner, payload, size);
}
