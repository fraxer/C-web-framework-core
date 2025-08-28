#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "openssl.h"
#include "route.h"
#include "appconfig.h"
#include "connection_queue.h"
#include "http1request.h"
#include "http1response.h"
#include "http1requestparser.h"
#include "http1responseparser.h"
#include "http1internal.h"
#include "httpcontext.h"
#include "middleware.h"

typedef struct connection_queue_http1_data {
    connection_queue_item_data_t base;
    http1request_t* request;
} connection_queue_http1_data_t;

void http1_read(connection_t*, char*, size_t);
void http1_write(connection_t*);
ssize_t http1_read_internal(connection_t*, char*, size_t);
ssize_t http1_write_internal(connection_t*, const char*, size_t);
ssize_t http1_write_chunked(connection_t*, const char*, size_t, int);
void http1_handle(connection_t* connection, http1request_t* request);
void http1_client_handle(connection_t*);
int http1_write_request_head(connection_t*);
int http1_write_body(connection_t*, char*, size_t, size_t);
int http1_get_resource(connection_t* connection, http1request_t* request);
void http1_get_file(connection_t*);
int http1_get_redirect(connection_t*);
int http1_apply_redirect(connection_t*);
char* http1_get_fullpath(connection_t*);
int http1_queue_handler_add(connection_t* connection, http1request_t* request, void(*handle)(void*));
void http1_queue_handler(void*);
void* http1_queue_data_create(http1request_t* request);
void http1_queue_data_free(void* arg);


int http_run_header_filters(http1response_t* response);
int http_run_body_filters(http1response_t* response);


void http1_wrap_read(connection_t* connection, char* buffer, size_t buffer_size) {
    if (!connection_lock(connection))
        return;

    http1_read(connection, buffer, buffer_size);
    connection_unlock(connection);
}

void http1_wrap_write(connection_t* connection, char* buffer, size_t buffer_size) {
    (void)buffer;
    (void)buffer_size;

    if (!connection_lock(connection))
        return;

    http1_write(connection);
    connection_unlock(connection);
}

void http1_read(connection_t* connection, char* buffer, size_t buffer_size) {
    http1requestparser_t* parser = ((http1request_t*)connection->request)->parser;
    http1response_t* response = (http1response_t*)connection->response;
    http1parser_set_connection(parser, connection);
    http1parser_set_buffer(parser, buffer);

    while (1) {
        int bytes_readed = http1_read_internal(connection, buffer, buffer_size);

        switch (bytes_readed) {
        case -1:
            return;
        case 0:
            connection->keepalive = 0;
            connection->after_read_request(connection);
            return;
        default:
            http1parser_set_bytes_readed(parser, bytes_readed);

            switch (http1parser_run(parser)) {
            case HTTP1PARSER_ERROR:
            case HTTP1PARSER_OUT_OF_MEMORY:
                response->def(response, 500);
                connection->after_read_request(connection);
                return;
            case HTTP1PARSER_PAYLOAD_LARGE:
                response->def(response, 413);
                connection->after_read_request(connection);
                return;
            case HTTP1PARSER_BAD_REQUEST:
                response->def(response, 400);
                connection->after_read_request(connection);
                return;
            case HTTP1PARSER_HOST_NOT_FOUND:
                response->def(response, 404);
                connection->after_read_request(connection);
                return;
            case HTTP1PARSER_CONTINUE:
                break;
            case HTTP1PARSER_COMPLETE:
                http1_handle(connection, parser->request);
                http1parser_reset(parser);
                return;
            }
        }
    }
}

void http1_write(connection_t* connection) {
    http1response_t* response = (http1response_t*)connection->response;

    if (http_run_header_filters(response) == CWF_EVENT_AGAIN) return;

    if (http_run_body_filters(response) == CWF_EVENT_AGAIN) return;

    connection->after_write_request(connection);
}

void http1_client_read(connection_t* connection, char* buffer, size_t buffer_size) {
    http1response_t* response = (http1response_t*)connection->response;
    http1responseparser_t* parser = response->parser;
    http1responseparser_set_connection(parser, connection);
    http1responseparser_set_buffer(parser, buffer);

    while (1) {
        int bytes_readed = http1_read_internal(connection, buffer, buffer_size);
        switch (bytes_readed) {
        case -1:
            connection->after_read_request(connection);
            return;
        case 0:
            connection->keepalive = 0;
            connection->after_read_request(connection);
            return;
        default:
            http1responseparser_set_bytes_readed(parser, bytes_readed);

            switch (http1responseparser_run(parser)) {
            case HTTP1PARSER_ERROR:
            case HTTP1PARSER_OUT_OF_MEMORY:
                response->def(response, 500);
                connection->after_read_request(connection);
                return;
            case HTTP1PARSER_PAYLOAD_LARGE:
                response->def(response, 413);
                connection->after_read_request(connection);
                return;
            case HTTP1PARSER_BAD_REQUEST:
                response->def(response, 400);
                connection->after_read_request(connection);
                return;
            case HTTP1PARSER_HOST_NOT_FOUND:
                response->def(response, 404);
                connection->after_read_request(connection);
                return;
            case HTTP1PARSER_CONTINUE:
                break;
            case HTTP1RESPONSEPARSER_COMPLETE:
                http1responseparser_reset(parser);
                http1_client_handle(connection);
                return;
            }
        }
    }
}

void http1_client_write(connection_t* connection, char* buffer, size_t buffer_size) {
    http1request_t* request = (http1request_t*)connection->request;

    if (http1_write_request_head(connection) == -1) goto write;

    if (request->payload_.file.size == 0) {
        http1_write_body(connection, buffer, 0, 0);
        goto write;
    }

    // payload
    while (request->payload_.file.fd > -1 && request->payload_.pos < request->payload_.file.size) {
        size_t payload_size = request->payload_.file.size - request->payload_.pos;
        ssize_t pos = request->payload_.pos;
        size_t size = payload_size > buffer_size ? buffer_size : payload_size;
        lseek(request->payload_.file.fd, pos, SEEK_SET);

        ssize_t readed = read(request->payload_.file.fd, buffer, size);
        if (readed < 0) goto write;

        ssize_t writed = http1_write_body(connection, buffer, payload_size, readed);
        if (writed < 0) goto write;

        request->payload_.pos += writed;
    }

    write:

    connection->after_write_request(connection);
}

ssize_t http1_read_internal(connection_t* connection, char* buffer, size_t size) {
    return connection->ssl ?
        openssl_read(connection->ssl, buffer, size) :
        recv(connection->fd, buffer, size, 0);
}

ssize_t http1_write_internal(connection_t* connection, const char* response, size_t size) {
    return connection->ssl ?
        openssl_write(connection->ssl, response, size) :
        send(connection->fd, response, size, MSG_NOSIGNAL);
}

ssize_t http1_write_chunked(connection_t* connection, const char* data, size_t length, int end) {
    const size_t buf_length = 10 + length + 2 + 5;
    char* buf = malloc(buf_length);
    if (buf == NULL) return -1;

    int pos = 0;
    pos = snprintf(buf, buf_length, "%x\r\n", (unsigned int)length);
    memcpy(buf + pos, data, length); pos += length;
    memcpy(buf + pos, "\r\n", 2); pos += 2;

    if (end) {
        memcpy(buf + pos, "0\r\n\r\n", 5); pos += 5;
    }

    const ssize_t writed = http1_write_internal(connection, buf, pos);

    free(buf);

    return writed;
}

int http1_write_request_head(connection_t* connection) {
    http1request_t* request = (http1request_t*)connection->request;

    http1request_head_t head = http1request_create_head(request);
    if (head.data == NULL) return -1;

    ssize_t writed = http1_write_internal(connection, head.data, head.size);

    free(head.data);

    return writed;
}

int http1_write_body(connection_t* connection, char* buffer, size_t payload_size, size_t size) {
    http1response_t* response = (http1response_t*)connection->response;
    ssize_t writed = -1;

    if (response->transfer_encoding == TE_CHUNKED) {
        const int end = payload_size <= size;

        if (response->content_encoding == CE_GZIP) {
            gzip_t* const gzip = &connection->gzip;
            char compress_buffer[GZIP_BUFFER];

            if (!gzip_deflate_init(gzip)) {
                log_error("gzip_deflate_init error\n");
                return -1;
            }

            gzip_set_in(gzip, buffer, size);

            const int gzip_end = (GZIP_BUFFER > payload_size && end) || end;
            do {
                const size_t compress_writed = gzip_deflate(gzip, compress_buffer, GZIP_BUFFER, gzip_end);
                if (gzip_deflate_has_error(gzip))
                    return -1;

                writed = http1_write_chunked(connection, compress_buffer, compress_writed, gzip_is_end(gzip));
                if (writed < 0)
                    return writed;

                if (gzip_is_end(gzip))
                    break;
            } while (gzip_want_continue(gzip));

            if (end && !gzip_deflate_free(gzip))
                return -1;

            writed = size;
        } else {
            writed = http1_write_chunked(connection, buffer, size, end);
        }
    }
    else {
        writed = http1_write_internal(connection, buffer, size);
    }

    return writed;
}

void http1_handle(connection_t* connection, http1request_t* request) {
    // http1request_t* request = (http1request_t*)connection->request;
    http1response_t* response = (http1response_t*)connection->response;

    if (request->method == ROUTE_NONE) {
        response->def(response, 400);
        connection->after_read_request(connection);
        return;
    }

    if (http1_apply_redirect(connection)) {
        connection->after_read_request(connection);
        return;
    }

    char file_full_path[PATH_MAX];
    const file_status_e status_code = http1_get_file_full_path(connection->server, file_full_path, PATH_MAX, request->path, request->path_length);
    if (status_code == FILE_OK) {
        if (!http1request_has_payload(request))
            http1_response_file(response, file_full_path);
        else
            response->def(response, 400);
    }
    else if (http1_get_resource(connection, request) == 0)
        return;
    else
        response->def(response, status_code);

    connection->after_read_request(connection);
}

void http1_client_handle(connection_t* connection) {
    connection->after_read_request(connection);
}

int http1_get_resource(connection_t* connection, http1request_t* request) {
    for (route_t* route = connection->server->http.route; route; route = route->next) {
        if (route->is_primitive && route_compare_primitive(route, request->path, request->path_length)) {
            if (route->handler[request->method] == NULL) return -1;

            if (!http1_queue_handler_add(connection, request, route->handler[request->method]))
                return -1;

            return 0;
        }

        int vector_size = route->params_count > 0 ? route->params_count * 6 : 20 * 6;
        int vector[vector_size];

        // find resource by template
        int matches_count = pcre_exec(route->location, NULL, request->path, request->path_length, 0, 0, vector, vector_size);

        if (matches_count > 1) {
            int i = 1; // escape full string match

            for (route_param_t* param = route->param; param; param = param->next, i++) {
                size_t substring_length = vector[i * 2 + 1] - vector[i * 2];

                http1_query_t* query = http1_query_create(param->string, param->string_len, &request->path[vector[i * 2]], substring_length);

                if (query == NULL || query->key == NULL || query->value == NULL) return -1;

                http1parser_append_query(request, query);
            }

            if (route->handler[request->method] == NULL) return -1;

            if (!http1_queue_handler_add(connection, request, route->handler[request->method]))
                return -1;

            return 0;
        }
        else if (matches_count == 1) {
            if (route->handler[request->method] == NULL) return -1;

            if (!http1_queue_handler_add(connection, request, route->handler[request->method]))
                return -1;

            return 0;
        }
    }

    return -1;
}

void http1_get_file(connection_t* connection) {
    http1request_t* request = (http1request_t*)connection->request;
    http1response_t* response = (http1response_t*)connection->response;

    response->filen(response, request->path, request->path_length);
}

int http1_apply_redirect(connection_t* connection) {
    http1request_t* request = (http1request_t*)connection->request;
    http1response_t* response = (http1response_t*)connection->response;

    switch (http1_get_redirect(connection)) {
    case REDIRECT_OUT_OF_MEMORY:
        response->def(response, 500);
        return 1;
    case REDIRECT_LOOP_CYCLE:
        response->def(response, 508);
        return 1;
    case REDIRECT_FOUND:
        http1response_redirect(response, request->uri, 301);
        return 1;
    case REDIRECT_NOT_FOUND:
    default:
        break;
    }

    return 0;
}

int http1_get_redirect(connection_t* connection) {
    http1request_t* request = (http1request_t*)connection->request;

    int loop_cycle = 1;
    int find_new_location = 0;

    redirect_t* redirect = connection->server->http.redirect;
    while (redirect) {
        if (loop_cycle >= 10) return REDIRECT_LOOP_CYCLE;

        int vector_size = redirect->params_count * 6;
        int vector[vector_size];
        int matches_count = pcre_exec(redirect->location, NULL, request->path, request->path_length, 0, 0, vector, vector_size);

        if (matches_count < 0) {
            redirect = redirect->next;
            continue;
        }

        find_new_location = 1;

        char* new_uri = redirect_get_uri(redirect, request->path, vector);
        if (new_uri == NULL) return REDIRECT_OUT_OF_MEMORY;

        if (request->uri) free((void*)request->uri);
        request->uri = NULL;

        if (request->path) free((void*)request->path);
        request->path = NULL;

        if (http1response_redirect_is_external(new_uri)) {
            request->uri = new_uri;
            connection->keepalive = 0;
            return REDIRECT_FOUND;
        }

        if (!http1parser_set_uri(request, new_uri, strlen(new_uri)))
            return REDIRECT_OUT_OF_MEMORY;

        redirect = connection->server->http.redirect;

        loop_cycle++;
    }

    return find_new_location ? REDIRECT_FOUND : REDIRECT_NOT_FOUND;
}

int http1_queue_handler_add(connection_t* connection, http1request_t* request, void(*handle)(void*)) {
    connection_queue_item_t* item = connection_queue_item_create();
    if (item == NULL) return 0;

    item->run = http1_queue_handler;
    item->handle = handle;
    item->connection = connection;
    item->data = http1_queue_data_create(request);

    if (item->data == NULL) {
        item->free(item);
        return 0;
    }

    connection_queue_append(item);

    return 1;
}

void* http1_queue_data_create(http1request_t* request) {
    connection_queue_http1_data_t* data = malloc(sizeof * data);
    if (data == NULL) return NULL;

    data->base.free = http1_queue_data_free;
    data->request = request;

    return data;
}

void http1_queue_data_free(void* arg) {
    if (arg == NULL) return;

    connection_queue_http1_data_t* data = arg;

    if (data->request != NULL)
        http1request_free(data->request);

    free(data);
}

void http1_queue_handler(void* arg) {
    connection_queue_item_t* item = arg;
    connection_queue_http1_data_t* data = (connection_queue_http1_data_t*)item->data;

    // create ctx
    httpctx_t* ctx = httpctx_create(data->request, item->connection->response);
    if (ctx == NULL) return; // close connection

    if (run_middlewares(item->connection->listener->server->http.middleware, ctx))
        item->handle(ctx);

    httpctx_free(ctx);

    connection_queue_pop(item->connection);
}

int http_run_header_filters(http1response_t* response) {
    if (response->headers_sended)
        return CWF_OK;

    response->event_again = 0;
    response->cur_filter = response->filter;

    while (1) {
        const int r = response->cur_filter->handler_header(response);
        switch (r)
        {
        case CWF_ERROR: /* close connection */
            return r;
        case CWF_EVENT_AGAIN:
            response->event_again = 1;
            return r;
        case CWF_OK:
            response->headers_sended = 1;
            return r;
        }
    }

    return CWF_OK;
}

int http_run_body_filters(http1response_t* response) {
    if (response->event_again)
        response->event_again = 0;

    while (1) {
        response->cur_filter = response->filter;

        int r = response->cur_filter->handler_body(response, NULL);
        switch (r)
        {
        case CWF_OK:
            return CWF_OK;
        case CWF_ERROR: /* close connection */
            return r;
        case CWF_EVENT_AGAIN:
            response->event_again = 1;
            return r;
        case CWF_DATA_AGAIN:
            continue;
        }
    }

    return CWF_OK;
}
