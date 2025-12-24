#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/socket.h>

#include "log.h"
#include "httpclienthandlers.h"
#include "httpclientparser.h"
#include "httpclient.h"
#include "appconfig.h"
#include "server.h"
#include "httpcontext.h"
#include "idn_utils.h"
#include "connection_s.h"

#define HTTPCLIENT_BUFSIZ 16384

httpclient_t* __httpclient_create();
int __httpclient_init_parser(httpclient_t*);
int __httpclient_connection_close(connection_t*);
void __httpclient_free(httpclient_t*);
void __httpclient_set_method(httpclient_t*, route_methods_e);
int __httpclient_set_url(httpclient_t*, const char*);
httpresponse_t* __httpclient_send(httpclient_t*);
int __httpclient_create_connection(httpclient_t*);
connection_t* __httpclient_resolve(const char*, const short);
int __httpclient_establish_connection(httpclient_t*);
int __httpclient_connect(httpclient_t*);
int __httpclient_set_socket_keepalive(int fd);
int __httpclient_set_socket_timeout(int fd, int);
int __httpclient_alloc_ssl(httpclient_t* client);
int __httpclient_handshake(httpclient_t*);
int __httpclient_set_request_uri(httpclient_t*);
int __httpclient_set_header_host(httpclient_t*);
int __httpclient_try_set_content_length(httpclient_t*);
int __httpclient_send_recv_data(httpclient_t*);
int __httpclient_free_connection(httpclient_t*);
int __httpclient_is_redirect(httpclient_t*);

int run_middlewares(struct middleware_item* middleware_item, void* ctx);

// Self-invocation detection and direct handler call
server_t* __httpclient_is_self_invocation(httpclient_t*);
httpresponse_t* __httpclient_self_invoke(httpclient_t*, server_t*);

httpclient_t* httpclient_init(route_methods_e method, const char* url, int timeout) {
    httpclient_t* result = NULL;
    httpclient_t* client = __httpclient_create();
    if (client == NULL) return NULL;

    if (!__httpclient_init_parser(client))
        goto failed;

    client->ssl_ctx = SSL_CTX_new(TLS_method());
    if (client->ssl_ctx == NULL) goto failed;

    if (timeout > 0)
        client->timeout = timeout;

    if (!client->set_url(client, url)) goto failed;

    client->request = httprequest_create(client->connection);
    if (client->request == NULL) goto failed;

    client->response = httpresponse_create(client->connection);
    if (client->response == NULL) goto failed;

    client->set_method(client, method);

    result = client;

    failed:

    if (result == NULL)
        client->free(client);

    return result;
}

httpclient_t* __httpclient_create() {
    httpclient_t* client = malloc(sizeof * client);
    if (client == NULL) return NULL;

    client->method = ROUTE_NONE;
    client->use_ssl = 0;
    client->redirect_count = 0;
    client->port = 0;
    client->timeout = 10;
    client->host = NULL;
    client->ssl_ctx = NULL;
    client->connection = NULL;
    client->request = NULL;
    client->response = NULL;
    client->parser = NULL;
    client->send = __httpclient_send;
    client->error = NULL;
    client->set_method = __httpclient_set_method;
    client->set_url = __httpclient_set_url;
    client->free = __httpclient_free;
    client->buffer_size = BUF_SIZE;
    client->buffer = malloc(sizeof(char) * client->buffer_size);
    if (client->buffer == NULL) {
        free(client);
        return NULL;
    }

    return client;
}

int __httpclient_init_parser(httpclient_t* client) {
    client->parser = malloc(sizeof(httpclientparser_t));
    if (client->parser == NULL) return 0;

    httpclientparser_init(client->parser);

    return 1;
}

int __httpclient_connection_close(connection_t* connection) {
    if (connection->ssl != NULL) {
        SSL_shutdown(connection->ssl);
        SSL_clear(connection->ssl);
    }

    shutdown(connection->fd, SHUT_RDWR);
    close(connection->fd);

    return 0;
}

void __httpclient_free(httpclient_t* client) {
    if (client == NULL) return;

    httpclientparser_free(client->parser);

    if (client->request != NULL) {
        client->request->base.free(client->request);
        client->request = NULL;
    }

    if (client->response != NULL) {
        client->response->base.free(client->response);
        client->response = NULL;
    }

    if (client->ssl_ctx != NULL) {
        SSL_CTX_free(client->ssl_ctx);
        client->ssl_ctx = NULL;
    }

    if (client->host != NULL) {
        free(client->host);
        client->host = NULL;
    }

    if (client->buffer != NULL) {
        free(client->buffer);
        client->buffer = NULL;
    }

    free(client);
}

void __httpclient_set_method(httpclient_t* client, route_methods_e method) {
    client->method = method;
}

int __httpclient_set_url(httpclient_t* client, const char* url) {
    httpclientparser_reset(client->parser);

    client->parser->use_ssl = client->use_ssl;

    if (httpclientparser_parse(client->parser, url) != CLIENTPARSER_OK)
        return 0;

    client->use_ssl = httpclientparser_move_use_ssl(client->parser);

    if (client->parser->port > 0)
        client->port = httpclientparser_move_port(client->parser);

    if (client->parser->host)
        client->host = httpclientparser_move_host(client->parser);

    return 1;
}

httpresponse_t* __httpclient_send(httpclient_t* client) {
    int result = 0;

    client->redirect_count = 0;

    if (!__httpclient_try_set_content_length(client))
        goto failed;

    start:

    if (!__httpclient_set_header_host(client))
        goto failed;

    server_t* self_server = __httpclient_is_self_invocation(client);
    if (self_server != NULL)
        return __httpclient_self_invoke(client, self_server);

    if (!__httpclient_create_connection(client))
        goto failed;

    if (!__httpclient_set_request_uri(client))
        goto failed;

    if (!__httpclient_send_recv_data(client))
        goto failed;

    if (!__httpclient_free_connection(client))
        goto failed;

    switch (__httpclient_is_redirect(client)) {
        case CLIENTREDIRECT_NONE: break;
        case CLIENTREDIRECT_EXIST: {
            http_header_t* header = client->response->get_header(client->response, "Location");
            if (!(header && header->value_length > 0) || !client->set_url(client, header->value))
                goto failed;

            client->redirect_count++;
            client->response->base.reset(client->response);
            goto start;
        }
        case CLIENTREDIRECT_ERROR: goto failed;
    }

    result = 1;

    failed:

    if (client->connection != NULL)
        __httpclient_free_connection(client);

    if (!result) {
        client->response->status_code = 500;
    }

    return client->response;
}

int __httpclient_create_connection(httpclient_t* client) {
    connection_t* connection = __httpclient_resolve(client->host, client->port);
    if (connection == NULL)
        return 0;

    client->connection = connection;
    client->connection->buffer = client->buffer;
    client->connection->buffer_size = client->buffer_size;
    client->request->connection = connection;
    client->response->connection = connection;

    connection_client_ctx_t* ctx = connection->ctx;

    connection->ssl_ctx = client->ssl_ctx;
    connection->close = __httpclient_connection_close;
    ctx->request = (request_t*)client->request;
    ctx->response = (response_t*)client->response;

    if (!__httpclient_establish_connection(client)) {
        log_error("error establish connection\n");
        return 0;
    }

    return 1;
}

connection_t* __httpclient_resolve(const char* host, const short port) {
    if (host == NULL) {
        log_error("__httpclient_resolve: host is NULL\n");
        return NULL;
    }
    struct addrinfo addr;
    memset(&addr, 0, sizeof(struct addrinfo));
    addr.ai_family = AF_INET;
    addr.ai_socktype = SOCK_STREAM;
    addr.ai_flags = 0;
    addr.ai_protocol = IPPROTO_TCP;

    char port_string[7] = {0};
    sprintf(port_string, "%d", port);

    struct addrinfo* result = NULL;
    const int r = getaddrinfo(host, port_string, &addr, &result);
    if (r != 0) {
        log_error("__httpclient_resolve: http client can't resolve host: %s\n", gai_strerror(r));
        return NULL;
    }

    int fd = -1;
    struct addrinfo* rp = NULL;
    connection_t* connection = NULL;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd >= 0) {
            const in_addr_t ip = ((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr;
            connection = connection_c_create(fd, ip, port);
            if (connection == NULL) {
                close(fd);
                fd = -1;
            }
            else break;
        }
    }

    freeaddrinfo(result);

    if (connection == NULL)
        if (fd > 0)
            close(fd);

    return connection;
}

int __httpclient_establish_connection(httpclient_t* client) {
    if (!__httpclient_set_socket_timeout(client->connection->fd, client->timeout))
        return 0;

    // if (!__httpclient_set_socket_keepalive(client->connection->fd))
    //     return 0;

    if (!__httpclient_connect(client))
        return 0;

    if (client->use_ssl) {
        if (!__httpclient_alloc_ssl(client))
            return 0;

        if (!__httpclient_handshake(client))
            return 0;
    }
    else
        set_client_http(client->connection);

    return 1;
}

int __httpclient_connect(httpclient_t* client) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET; 
    addr.sin_port = htons(client->connection->port); 
    addr.sin_addr.s_addr = client->connection->ip;

    if (connect(client->connection->fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_error("connect error %d %d\n", client->connection->fd, errno);
        return 0;
    }

    return 1;
}

int __httpclient_set_socket_keepalive(int fd) {
    int kenable = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &kenable, sizeof(kenable));

    int keepcnt = 15;
    setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

    int keepidle = 5;
    setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));

    int keepintvl = 5;
    setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));

    return 1;
}

int __httpclient_set_socket_timeout(int fd, int timeout) {
    struct timeval tm;      
    tm.tv_sec = timeout;
    tm.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tm, sizeof(tm)) < 0)
        return 0;

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tm, sizeof(tm)) < 0)
        return 0;
    
    return 1;
}

int __httpclient_alloc_ssl(httpclient_t* client) {
    connection_t* connection = client->connection;

    if (connection->ssl != NULL) return 1;

    int result = 0;

    connection->ssl = SSL_new(connection->ssl_ctx);
    if (connection->ssl == NULL)
        goto failed;

    if (!SSL_set_fd(connection->ssl, connection->fd))
        goto failed;

    SSL_set_connect_state(connection->ssl);
    SSL_set_post_handshake_auth(connection->ssl, 1);
    SSL_set_tlsext_host_name(connection->ssl, client->host);

    result = 1;

    failed:

    if (result == 0) {
        if (connection->ssl) {
            SSL_free(connection->ssl);
            connection->ssl = NULL;
        }
    }

    return result;
}

int __httpclient_handshake(httpclient_t* client) {
    set_client_tls(client->connection);
    client->connection->write(client->connection);

    connection_client_ctx_t* ctx = client->connection->ctx;
    if (ctx->request == NULL || client->connection->fd == 0)
        return 0;

    return 1;
}

int __httpclient_set_request_uri(httpclient_t* client) {
    httprequest_t* request = (httprequest_t*)client->request;

    if (request->uri) free((void*)request->uri);
    request->uri = httpclientparser_move_uri(client->parser);
    request->uri_length = strlen(request->uri);

    if (request->path) free((void*)request->path);
    request->path = httpclientparser_move_path(client->parser);
    request->path_length = strlen(request->path);

    queries_free(request->query_);
    request->query_ = httpclientparser_move_query(client->parser);
    request->last_query = httpclientparser_move_last_query(client->parser);
    request->method = client->method;

    return 1;
}

int __httpclient_set_header_host(httpclient_t* client) {
    httprequest_t* request = (httprequest_t*)client->request;
    request->remove_header(request, "Host");

    char host[128];
    if (client->port == 80 || client->port == 443)
        snprintf(host, sizeof(host), "%s", client->host);
    else
        snprintf(host, sizeof(host), "%s:%d", client->host, client->port);

    request->add_header(request, "Host", host);

    return 1;
}

int __httpclient_try_set_content_length(httpclient_t* client) {
    if (client->request->transfer_encoding == TE_CHUNKED)
        return 1;

    client->request->remove_header(client->request, "Content-Length");
    const size_t file_size = client->request->payload_.file.size;

    if (file_size == 0 && client->request->transfer_encoding != TE_CHUNKED) {
        client->request->add_header(client->request, "Content-Length", "0");
        return 1;
    }

    char content_string[32];
    sprintf(content_string, "%ld", file_size);

    client->request->add_header(client->request, "Content-Length", content_string);

    return 1;
}

int __httpclient_send_recv_data(httpclient_t* client) {
    if (!client->connection->write(client->connection))
        return 0;

    if (!client->connection->read(client->connection))
        return 0;

    return 1;
}

int __httpclient_free_connection(httpclient_t* client) {
    connection_t* connection = client->connection;
    if (connection == NULL) return 1;

    connection_client_ctx_t* ctx = connection->ctx;

    ctx->request = NULL;
    ctx->response = NULL;
    connection->close(connection);
    connection_free(connection);
    client->connection = NULL;

    return 1;
}

int __httpclient_is_redirect(httpclient_t* client) {
    if (client->response->status_code != 301 && client->response->status_code != 302)
        return CLIENTREDIRECT_NONE;

    if (client->redirect_count > 9)
        return CLIENTREDIRECT_MANY_REDIRECTS;

    http_header_t* header = client->response->get_header(client->response, "Location");
    if (!(header && header->value_length > 0))
        return CLIENTREDIRECT_ERROR;

    return CLIENTREDIRECT_EXIST;
}

server_t* __httpclient_is_self_invocation(httpclient_t* client) {
    appconfig_t* config = appconfig();
    if (!config || !config->server_chain) {
        log_error("Invalid appconfig\n");
        return NULL;
    }

    const char* host = client->host;
    if (!host) {
        log_error("Invalid domain in client host\n");
        return NULL;
    }

    // Convert to ASCII/Punycode for matching
    char* ascii_host = idn_to_ascii(host);
    if (ascii_host == NULL) {
        log_warning("Invalid domain in client host: %s\n", host);
        return NULL;
    }

    const size_t ascii_length = strlen(ascii_host);
    const int vector_struct_size = 6;
    const int substring_count = 20;
    const int vector_size = substring_count * vector_struct_size;
    int ovector[vector_size];
    server_t* found_server = NULL;
    server_t* server = config->server_chain->server;
    while (server) {
        if (server->port != client->port) {
            server = server->next;
            continue;
        }

        domain_t* server_domain = server->domain;
        while (server_domain) {
            const int matches_count = pcre_exec(server_domain->pcre_template, NULL, ascii_host, ascii_length, 0, 0, ovector, vector_size);
            if (matches_count > 0) {
                found_server = server;  // Self-invocation detected
                goto cleanup;
            }

            server_domain = server_domain->next;
        }

        server = server->next;
    }

    cleanup:

    free(ascii_host);

    return found_server;
}

httpresponse_t* __httpclient_self_invoke(httpclient_t* client, server_t* server) {
    if (server == NULL) {
        log_error("Self-invoke: server is NULL\n");
        client->response->status_code = 500;
        return client->response;
    }

    if (!__httpclient_set_request_uri(client)) {
        log_error("Self-invoke: failed to set request URI\n");
        client->response->status_code = 500;
        return client->response;
    }

    const char* path = client->request->path;
    if (path == NULL) {
        log_error("Self-invoke: URI not found\n");
        client->response->status_code = 500;
        return client->response;
    }

    const int vector_struct_size = 6;
    const int substring_count = 20;
    const int vector_size = substring_count * vector_struct_size;
    route_t* route = server->http.route;
    route_t* matched_route = NULL;

    while (route) {
        if (route->is_primitive) {
            if (route_compare_primitive(route, path, strlen(path))) {
                matched_route = route;
                break;
            }
        } else {
            int ovector[vector_size];
            int rc = pcre_exec(route->location, NULL, path, strlen(path), 0, 0, ovector, vector_size);
            if (rc >= 0) {
                matched_route = route;
                break;
            }
        }
        route = route->next;
    }

    if (!matched_route) {
        log_error("Self-invoke: route not found for %s\n", path);
        client->response->status_code = 404;
        return client->response;
    }

    void(*handler)(void*) = matched_route->handler[client->method];
    if (handler == NULL) {
        log_error("Self-invoke: handler not found for method %d\n", client->method);
        client->response->status_code = 405;
        return client->response;
    }

    connection_t* connection = connection_s_create_local(server);
    if (connection == NULL) {
        log_error("Self-invoke: failed to create local connection\n");
        client->response->status_code = 500;
        return client->response;
    }

    client->request->connection = connection;
    client->response->connection = connection;

    httpctx_t ctx;
    httpctx_init(&ctx, client->request, client->response);

    if (run_middlewares(server->http.middleware, &ctx))
        handler(&ctx);

    httpctx_clear(&ctx);

    client->request->connection = NULL;
    client->response->connection = NULL;

    connection_s_free_local(connection);

    return client->response;
}
