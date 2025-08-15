#include "http1clienthandlers.h"

#include "log.h"
#include "http1request.h"
#include "http1responseparser.h"

static int __tls_read(connection_t* connection);
static int __tls_write(connection_t* connection);
static int __write_request_head(connection_t*);
static ssize_t __write_chunked(connection_t*, const char*, size_t, int);
static int __write_body(connection_t*, char*, size_t, size_t);
static int __handshake(connection_t* connection);

int __tls_read(connection_t* connection) {
    (void)connection;
    return 1;
}

int __tls_write(connection_t* connection) {
    return __handshake(connection);
}

void set_client_tls(connection_t* connection) {
    connection->read = __tls_read;
    connection->write = __tls_write;
}

void set_client_http1(connection_t* connection) {
    connection->read = http1_client_read;
    connection->write = http1_client_write;
}

int http1_client_read(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    http1response_t* response = ctx->response;
    http1responseparser_t* parser = response->parser;
    http1responseparser_set_connection(parser, connection);
    http1responseparser_set_buffer(parser, connection->buffer);

    while (1) {
        int bytes_readed = connection_data_read(connection);

        switch (bytes_readed) {
        case -1:
            return 0;
        case 0:
            connection->keepalive = 0;
            return 1;
        default:
            http1responseparser_set_bytes_readed(parser, bytes_readed);

            switch (http1responseparser_run(parser)) {
            case HTTP1PARSER_ERROR:
            case HTTP1PARSER_OUT_OF_MEMORY:
                return 0;
            case HTTP1PARSER_PAYLOAD_LARGE:
                response->def(response, 413);
                return 1;
            case HTTP1PARSER_BAD_REQUEST:
                response->def(response, 400);
                return 1;
            case HTTP1PARSER_HOST_NOT_FOUND:
                response->def(response, 404);
                return 1;
            case HTTP1PARSER_CONTINUE:
                break;
            case HTTP1RESPONSEPARSER_COMPLETE:
                http1responseparser_reset(parser);
                return 1;
            }
        }
    }

    return 0;
}

int http1_client_write(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    http1request_t* request = ctx->request;

    if (__write_request_head(connection) == -1) return 0;

    if (request->payload_.file.size == 0) {
        __write_body(connection, connection->buffer, 0, 0);
        return 1;
    }

    // payload
    while (request->payload_.file.fd > -1 && request->payload_.pos < request->payload_.file.size) {
        size_t payload_size = request->payload_.file.size - request->payload_.pos;
        ssize_t pos = request->payload_.pos;
        size_t size = payload_size > connection->buffer_size ? connection->buffer_size : payload_size;
        lseek(request->payload_.file.fd, pos, SEEK_SET);

        ssize_t readed = read(request->payload_.file.fd, connection->buffer, size);
        if (readed < 0) return 0;

        ssize_t writed = __write_body(connection, connection->buffer, payload_size, readed);
        if (writed < 0) return 0;

        request->payload_.pos += writed;
    }

    return 1;
}

ssize_t __write_chunked(connection_t* connection, const char* data, size_t length, int end) {
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

    const ssize_t writed = connection_data_write(connection, buf, pos);

    free(buf);

    return writed;
}

int __write_request_head(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    http1request_t* request = ctx->request;

    http1request_head_t head = http1request_create_head(request);
    if (head.data == NULL) return -1;

    ssize_t writed = connection_data_write(connection, head.data, head.size);

    free(head.data);

    return writed;
}

int __write_body(connection_t* connection, char* buffer, size_t payload_size, size_t size) {
    connection_client_ctx_t* ctx = connection->ctx;
    http1response_t* response = ctx->response;
    ssize_t writed = -1;

    if (response->transfer_encoding == TE_CHUNKED) {
        const int end = payload_size <= size;

        if (response->content_encoding == CE_GZIP) {
            gzip_t* const gzip = &ctx->gzip;
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

                writed = __write_chunked(connection, compress_buffer, compress_writed, gzip_is_end(gzip));
                if (writed < 0)
                    return writed;

                if (gzip_is_end(gzip))
                    break;
            } while (gzip_want_continue(gzip));

            if (end && !gzip_deflate_free(gzip))
                return -1;

            writed = size;
        } else {
            writed = __write_chunked(connection, buffer, size, end);
        }
    }
    else {
        writed = connection_data_write(connection, buffer, size);
    }

    return writed;
}

int __handshake(connection_t* connection) {
    int result = SSL_do_handshake(connection->ssl);
    if (result == 1) {
        set_client_http1(connection);
        return 1;
    }

    switch (SSL_get_error(connection->ssl, result)) {
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
        return 0;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_ACCEPT:
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_ZERO_RETURN:
        return 1;
    }

    return 0;
}