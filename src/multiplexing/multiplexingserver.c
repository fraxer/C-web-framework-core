#include "log.h"
#include "socket.h"
#include "broadcast.h"
#include "multiplexing.h"
#include "multiplexingserver.h"
#include "server.h"
#include "http1serverhandlers.h"

static int BUFFER_SIZE = 16384;

static listener_t* __listeners_create(mpxapi_t* api, char* buffer, server_t* server);
static listener_t* __listener_create(mpxapi_t* api, char* buffer, server_t* server);
static listener_t* __listener_get(listener_t* listener, server_t* server);
static void __listeners_free(listener_t* listener);
static void __listener_free(listener_t* listener);
static int __listeners_listen(listener_t* listener);
static int __listener_read(connection_t* listener_connection);
static int __set_protocol(connection_t* connection);

int mpxserver_run(appconfig_t* appconfig, void(*thread_worker_threads_pause)(appconfig_t* config)) {
    int result = 0;
    mpxapi_t* api = mpx_create();
    if (api == NULL) return result;

    listener_t* listeners = NULL;
    char* buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) goto failed;

    listeners = __listeners_create(api, buffer, appconfig->server_chain->server);
    if (listeners == NULL)
        goto failed;

    if (!__listeners_listen(listeners))
        goto failed;

    while (1) {
        thread_worker_threads_pause(appconfig);

        api->process_events(appconfig, api);

        if (atomic_load(&appconfig->shutdown))
            if (api->connection_count == 0)
                break;
    }

    result = 1;

    failed:

    __listeners_free(listeners);

    if (buffer != NULL)
        free(buffer);

    api->free(api);

    return result;
}

int __listener_connection_close(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    connection_s_lock(connection);

    if (!ctx->listener->api->control_del(connection))
        log_error("Connection not removed from api\n");

    shutdown(connection->fd, SHUT_RDWR);
    close(connection->fd);

    if (connection_s_dec(connection) == CONNECTION_DEC_RESULT_DECREMENT)
        connection_s_unlock(connection);

    return 1;
}

listener_t* __listeners_create(mpxapi_t* api, char* buffer, server_t* first_server) {
    listener_t* listeners = NULL;
    listener_t* last_listener = NULL;
    int result = 0;
    for (server_t* server = first_server; server; server = server->next) {
        listener_t* l = __listener_get(listeners, server);
        if (l != NULL) {
            cqueue_append(&l->servers, server);
            continue;
        }

        listener_t* listener = __listener_create(api, buffer, server);
        if (listener == NULL) goto failed;

        if (listeners == NULL)
            listeners = listener;

        if (last_listener != NULL)
            last_listener->next = listener;

        last_listener = listener;
    }

    result = 1;

    failed:

    if (!result) {
        __listeners_free(listeners);
        listeners = NULL;
    }

    return listeners;
}

listener_t* __listener_create(mpxapi_t* api, char* buffer, server_t* server) {
    listener_t* listener = malloc(sizeof * listener);
    if (listener == NULL) return NULL;

    memset(listener, 0, sizeof * listener);

    int result = 0;
    connection_t* connection = NULL;

    const int socketfd = socket_listen_create(server->ip, server->port);
    if (socketfd == -1) goto failed;

    connection = connection_s_alloc(listener, socketfd, server->ip, server->port, buffer, BUFFER_SIZE);
    if (connection == NULL) goto failed;

    connection->read = __listener_read;
    connection->write = NULL;
    connection->close = __listener_connection_close;

    listener->connection = connection;
    listener->api = api;
    listener->next = NULL;
    cqueue_init(&listener->servers);

    if (!cqueue_append(&listener->servers, server))
        goto failed;

    result = 1;

    failed:

    if (!result) {
        __listener_free(listener);
        listener = NULL;
    }

    return listener;
}

listener_t* __listener_get(listener_t* listener, server_t* server) {
    while (listener) {
        if (listener->connection->ip == server->ip && listener->connection->port == server->port)
            return listener;

        listener = listener->next;
    }

    return NULL;
}

void __listeners_free(listener_t* listener) {
    while (listener) {
        listener_t* next = listener->next;
        __listener_free(listener);
        listener = next;
    }
}

void __listener_free(listener_t* listener) {
    if (listener == NULL) return;

    cqueue_clear(&listener->servers);
    free(listener);
}

int __listeners_listen(listener_t* listener) {
    while (listener) {
        if (!listener->api->control_add(listener->connection, MPXIN | MPXRDHUP))
            return 0;

        listener = listener->next;
    }

    return 1;
}

int __listener_read(connection_t* listener_connection) {
    const int fd = listener_connection->fd;
    const in_addr_t ip = listener_connection->ip;
    const unsigned short int port = listener_connection->port;
    connection_server_ctx_t* ctx = listener_connection->ctx;
    char* buffer = listener_connection->buffer;
    const size_t buffer_size = listener_connection->buffer_size;

    // TODO: make multi accept
    connection_t* connection = connection_s_create(fd, ip, port, ctx, buffer, buffer_size);
    if (connection == NULL) return 0;

    return __set_protocol(connection);
}

int __set_protocol(connection_t* connection) {
    connection_server_ctx_t* ctx = connection->ctx;

    int r = 0;
    if (ctx->server->openssl)
        r = set_tls(connection);
    else
        r = set_http1(connection);

    if (!r) {
        connection_free(connection);
        return 0;
    }

    return ctx->listener->api->control_add(connection, MPXIN | MPXRDHUP);
}