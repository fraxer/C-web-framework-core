#include <string.h>

#include "smtpclienthandlers.h"
#include "openssl.h"
#include "smtprequest.h"
#include "smtpresponse.h"
#include "smtpresponseparser.h"

static int __handshake(connection_t* connection);

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
        const int bytes_readed = connection_data_read(connection);

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

int smtp_client_write_command(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    smtprequest_t* request = ctx->request;

    return connection_data_write(connection, request->command, strlen(request->command));
}

int smtp_client_write_content(connection_t* connection) {
    connection_client_ctx_t* ctx = connection->ctx;
    smtprequest_data_t* request = ctx->request;

    return connection_data_write(connection, request->content, request->content_size);
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
