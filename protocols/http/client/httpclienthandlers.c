#include "httpclienthandlers.h"

#include "log.h"
#include "httprequest.h"
#include "httpresponseparser.h"

static int __tls_read(connection_t* connection);
static int __tls_write(connection_t* connection);
static int __write_request_head(connection_t*);
static ssize_t __write_chunked(connection_t*, const char*, size_t, int);
static ssize_t __write_body(connection_t*, char*, size_t, size_t);
static ssize_t __write_all(connection_t*, const char*, size_t);
static int __handshake(connection_t* connection);

// Writes the full buffer, looping over partial sends. Returns the number of
// bytes written (== size on success) or -1 on error / peer-closed (0 from the
// underlying write is treated as failure to avoid an infinite loop). Used for
// data that is not re-readable from a file, where a partial send would corrupt
// the request (head) or the transfer framing (chunk).
ssize_t __write_all(connection_t* connection, const char* data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const ssize_t writed = connection_data_write(connection, data + offset, size - offset);
        if (writed <= 0)
            return -1;
        offset += (size_t)writed;
    }
    return (ssize_t)offset;
}

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

void set_client_http(connection_t* connection) {
    connection->read = http_client_read;
    connection->write = http_client_write;
}

int http_client_read(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    httpresponse_t* response = ctx->response;
    httpresponseparser_t* parser = response->parser;
    httpresponseparser_set_connection(parser, connection);
    httpresponseparser_set_buffer(parser, connection->buffer);

    while (1) {
        ssize_t bytes_readed = connection_data_read(connection);

        switch (bytes_readed) {
        case -1:
            return 0;
        case 0:
            connection->keepalive = 0;
            return 1;
        default:
            httpresponseparser_set_bytes_readed(parser, bytes_readed);

            switch (httpresponseparser_run(parser)) {
            case HTTP1PARSER_CONTINUE:
                break;
            case HTTP1RESPONSEPARSER_COMPLETE:
                httpresponseparser_reset(parser);
                return 1;
            default:
                // Malformed / oversized / unreadable server response. This is a
                // client reading a server reply, so we must NOT call
                // send_default here — that writes an HTML error page back to the
                // server (server-side semantics). Treat any parse failure as a
                // read error; the caller turns it into a 500.
                return 0;
            }
        }
    }

    return 0;
}

int http_client_write(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    httprequest_t* request = ctx->request;

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

    // A partial chunk-frame write would desync the chunked transfer encoding,
    // so flush the whole frame (looping over partial sends).
    const ssize_t writed = __write_all(connection, buf, (size_t)pos);

    free(buf);

    return writed;
}

int __write_request_head(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    httprequest_t* request = ctx->request;

    httprequest_head_t head = httprequest_create_head(request);
    if (head.data == NULL) return -1;

    // A partial head write would corrupt the request irrecoverably, so flush it
    // in full (looping over partial sends) before freeing the buffer.
    ssize_t writed = __write_all(connection, head.data, head.size);

    free(head.data);

    return (int)writed;
}

ssize_t __write_body(connection_t* connection, char* buffer, size_t payload_size, size_t size) {
    connection_client_ctx_t* ctx = connection->ctx;
    httpresponse_t* response = ctx->response;
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

            // Return the number of file bytes consumed, not the chunked wire
            // bytes (frame headers/CRLF are not file data) — the caller advances
            // the payload file position by this value.
            writed = (ssize_t)size;
        } else {
            writed = __write_chunked(connection, buffer, size, end);
            if (writed < 0)
                return writed;
            writed = (ssize_t)size;
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
        set_client_http(connection);
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