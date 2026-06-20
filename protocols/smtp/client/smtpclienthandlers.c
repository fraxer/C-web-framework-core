#include <string.h>

#include "smtpclienthandlers.h"
#include "openssl.h"
#include "smtprequest.h"
#include "smtpresponse.h"
#include "smtpresponseparser.h"

static int __handshake(connection_t* connection);
static ssize_t __write_all(connection_t* connection, const char* data, size_t size);

void set_smtp_client_command(connection_t* connection) {
    connection->read = smtp_client_read;
    connection->write = smtp_client_write_command;
}

void set_smtp_client_content(connection_t* connection) {
    connection->read = smtp_client_read;
    connection->write = smtp_client_write_content;
}

void set_smtp_client_tls(connection_t* connection) {
    connection->read = tls_smtp_client_read;
    connection->write = tls_smtp_client_write;
}

int tls_smtp_client_read(connection_t* connection) {
    (void)connection;
    return 1;
}

int tls_smtp_client_write(connection_t* connection) {
    return __handshake(connection);
}


int smtp_client_read(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    smtpresponseparser_t* parser = ((smtpresponse_t*)ctx->response)->parser;
    smtpresponseparser_set_connection(parser, connection);
    smtpresponseparser_set_buffer(parser, connection->buffer);

    while (1) {
        const ssize_t bytes_readed = connection_data_read(connection);

        switch (bytes_readed) {
        case -1:
            return 0;
        case 0:
            connection->keepalive = 0;
            return 1;
        default:
            smtpresponseparser_set_bytes_readed(parser, bytes_readed);

            switch (smtpresponseparser_run(parser)) {
            case SMTPRESPONSEPARSER_ERROR:
                return 0;
            case SMTPRESPONSEPARSER_CONTINUE:
                break;
            case SMTPRESPONSEPARSER_COMPLETE:
                smtpresponseparser_reset(parser);
                return 1;
            }
        }
    }

    return 0;
}

/* Flush the whole buffer, looping over partial sends. Returns the number of
 * bytes written (== size on success) or -1 on error / peer-closed (a 0 from
 * the underlying write is treated as failure to avoid an infinite loop). A
 * single send() can return a short count, and a truncated SMTP command or
 * message body would corrupt the session, so the remainder is retried until
 * the full payload is queued. Mirrors __write_all in httpclienthandlers.c. */
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

int smtp_client_write_command(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    smtprequest_t* request = ctx->request;

    /* A write error must surface as 0 (close): connection_data_write returns
     * -1 on failure, which is truthy and would otherwise keep the connection
     * open after a broken write. */
    if (__write_all(connection, request->command, strlen(request->command)) == -1)
        return 0;

    return 1;
}

int smtp_client_write_content(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    smtprequest_data_t* request = ctx->request;

    if (__write_all(connection, request->content, request->content_size) == -1)
        return 0;

    return 1;
}

int __handshake(connection_t* connection) {
    int result = SSL_do_handshake(connection->ssl);
    if (result == 1) {
        set_smtp_client_command(connection);
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
