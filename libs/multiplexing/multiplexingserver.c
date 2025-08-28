#include "log.h"
#include "socket.h"
#include "broadcast.h"
#include "multiplexing.h"
#include "multiplexingserver.h"
#include "server.h"

static listener_t* __listeners_create(mpxapi_t* api, server_t* server);
static listener_t* __listener_create(mpxapi_t* api, server_t* server, socket_t* socket);
static int __socket_exist(socket_t* socket, server_t* server);
static void __listeners_free(listener_t* listener);
static void __listeners_stop(listener_t* listener);
static int __listeners_listen(listener_t* listener);
static void __connection_destroy(connection_s_t* connection);
static int __connection_create(connection_s_t* connection, server_t* server);

int mpxserver_run(appconfig_t* appconfig, void(*thread_worker_threads_pause)(appconfig_t* config)) {
    int result = 0;
    mpxapi_t* api = mpx_create();
    if (api == NULL) return result;

    listener_t* listeners = __listeners_create(api, appconfig->server_chain->server);
    if (listeners == NULL)
        goto failed;

    if (!__listeners_listen(listeners))
        goto failed;

    while (1) {
        thread_worker_threads_pause(appconfig);

        api->process_events(appconfig, api);

        if (atomic_load(&appconfig->shutdown)) {
            __listeners_stop(listeners);

            if (api->connection_count == 0)
                break;
        }
    }

    __listeners_free(listeners);

    result = 1;

    failed:

    api->free(api);

    return result;
}

void __listeners_stop(listener_t* listener) {
    if (listener == NULL) return;
    // if (listener->connection->destroyed) return;

    while (listener != NULL) {
        listener_t* next = listener->next;
        listener->connection->base.close(listener->connection);
        listener = next;
    }
}

int __listener_connection_close(connection_s_t* connection) {
    connection_s_lock(connection);

    if (!connection->destroyed) {
        if (!connection->listener->api->control_del(connection))
            log_error("Connection not removed from api\n");

        connection->destroyed = 1;

        shutdown(connection->base.fd, SHUT_RDWR);
    }

    connection_s_unlock(connection);

    return 1;
}

void __connection_destroy(connection_s_t* connection) {
    connection_s_lock(connection);

    if (connection->base.ssl != NULL) {
        SSL_shutdown(connection->base.ssl);
        SSL_clear(connection->base.ssl);
    }

    close(connection->base.fd);

    connection_s_dec(connection);

    return 1;
}

listener_t* __listeners_create(mpxapi_t* api, server_t* first_server) {
    socket_t* first_socket = NULL;
    socket_t* last_socket = NULL;
    listener_t* listeners = NULL;
    listener_t* last_listener = NULL;
    int result = 0;
    int close_sockets = 0;
    for (server_t* server = first_server; server; server = server->next) {
        if (__socket_exist(first_socket, server)) continue;

        socket_t* socket = socket_listen_create(server->ip, server->port);
        if (socket == NULL) goto failed;

        if (last_socket)
            last_socket->next = socket;

        if (first_socket == NULL)
            first_socket = socket;

        last_socket = socket;

        listener_t* listener = __listener_create(api, server, socket);
        if (listener == NULL)
            goto failed;

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
        close_sockets = 1;
    }

    socket_free(first_socket, close_sockets);

    return listeners;
}

listener_t* __listener_create(mpxapi_t* api, server_t* server, socket_t* socket) {
    listener_t* listener = malloc(sizeof * listener);
    if (listener == NULL) return NULL;

    int result = 0;

    connection_s_t* connection = connection_s_alloc(listener, socket->fd, socket->ip, socket->port);
    if (connection == NULL) goto failed;

    connection->base.read = __listener_read;
    connection->base.close = __listener_connection_close;

    listener->connection = connection;
    listener->api = api;
    listener->server = server;
    listener->next = NULL;

    result = 1;

    failed:

    if (!result) {
        __listener_free(listener);
        listener = NULL;
    }

    return listener;
}

int __socket_exist(socket_t* socket, server_t* server) {
    while (socket) {
        if (socket->ip == server->ip && socket->port == server->port)
            return 1;

        socket = socket->next;
    }

    return 0;
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

    __connection_destroy(listener->connection);

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

void __listener_read(connection_s_t* connection) {
    connection_s_t* connection = connection_s_create(connection);
    if (connection == NULL) return;

    __connection_create(connection, connection->listener->server);
}

int __connection_create(connection_s_t* connection, server_t* server) {
    if (server->openssl) {
        connection->base.ssl_ctx = server->openssl->ctx;
        protmgr_set_tls(connection);
    }
    else
        protmgr_set_http1(connection);

    return connection->listener->api->control_add(connection, MPXIN | MPXRDHUP);
}