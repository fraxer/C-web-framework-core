#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>

#include "log.h"
#include "httpclienthandlers_async.h"
#include "httpclient.h"
#include "connection_c_async.h"
#include "httpresponseparser.h"
#include "httprequest.h"
#include "httpclienthandlers.h"
#include "multiplexing.h"

// Forward declarations
extern uint64_t __get_current_time_ms(void);
extern void __httpclient_async_complete(httpclient_t* client, int success);
extern int __httpclient_alloc_ssl(httpclient_t* client);

// Close handler
int __httpclient_async_close(connection_t* connection) {
    if (connection->ssl != NULL) {
        SSL_shutdown(connection->ssl);
        SSL_clear(connection->ssl);
    }

    shutdown(connection->fd, SHUT_RDWR);
    close(connection->fd);

    return 0;
}

// Write handler (state machine)
int __httpclient_async_write(connection_t* connection) {
    connection_client_async_ctx_t* conn_ctx = connection->ctx;
    httpclient_t* client = conn_ctx->client;
    httpclient_async_ctx_t* ctx = client->async_ctx;

    // Проверка timeout
    // uint64_t now = __get_current_time_ms();
    // if (now - ctx->start_time_ms > ctx->timeout_ms) {
    //     log_error("Async HTTP client timeout\n");
    //     __httpclient_async_complete(client, 0);
    //     return 0;
    // }

    // State machine
    switch (ctx->state) {
        case ASYNC_STATE_CONNECTING: {
            // Проверить успешность connect
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(connection->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
                log_error("Async connect failed: %d\n", error);
                __httpclient_async_complete(client, 0);
                return 0;
            }

            // Connect успешен
            if (client->use_ssl) {
                // Начать TLS handshake
                if (!__httpclient_alloc_ssl(client)) {
                    __httpclient_async_complete(client, 0);
                    return 0;
                }
                ctx->state = ASYNC_STATE_TLS_HANDSHAKE;
                set_client_tls(connection);
                // Fallthrough для начала handshake
            } else {
                // Без SSL - сразу к отправке запроса
                ctx->state = ASYNC_STATE_WRITING_REQUEST;
                set_client_http(connection);
                // Fallthrough для начала отправки
            }
        }
        // fallthrough

        case ASYNC_STATE_TLS_HANDSHAKE: {
            if (!client->use_ssl) break;  // Skip если не SSL

            int result = SSL_do_handshake(connection->ssl);
            if (result == 1) {
                // Handshake завершен
                ctx->state = ASYNC_STATE_WRITING_REQUEST;
                set_client_http(connection);
                // Fallthrough для отправки запроса
            } else {
                int ssl_error = SSL_get_error(connection->ssl, result);
                switch (ssl_error) {
                    case SSL_ERROR_WANT_READ:
                        // Переключиться на ожидание чтения
                        ctx->api->control_mod(connection, MPXIN | MPXRDHUP);
                        return 1;
                    case SSL_ERROR_WANT_WRITE:
                        // Продолжаем ждать EPOLLOUT
                        return 1;
                    default:
                        log_error("TLS handshake error: %d\n", ssl_error);
                        __httpclient_async_complete(client, 0);
                        return 0;
                }
            }
        }
        // fallthrough

        case ASYNC_STATE_WRITING_REQUEST: {
            // Подготовить буфер с запросом если ещё не подготовлен
            if (ctx->write_buffer_pos == 0) {
                // Сформировать headers
                httprequest_head_t head = httprequest_create_head(client->request);
                if (!head.data) {
                    __httpclient_async_complete(client, 0);
                    return 0;
                }

                if (head.size > ctx->write_buffer_size) {
                    // Расширить буфер
                    char* new_buf = realloc(ctx->write_buffer, head.size);
                    if (!new_buf) {
                        free(head.data);
                        __httpclient_async_complete(client, 0);
                        return 0;
                    }
                    ctx->write_buffer = new_buf;
                    ctx->write_buffer_size = head.size;
                }

                memcpy(ctx->write_buffer, head.data, head.size);
                ctx->write_buffer_pos = head.size;
                free(head.data);
            }

            // Отправить данные (non-blocking)
            ssize_t written = connection_data_write(connection,
                                                     ctx->write_buffer,
                                                     ctx->write_buffer_pos);
            if (written < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Буфер переполнен, ждем следующего EPOLLOUT
                    return 1;
                }
                log_error("Async write error: %d\n", errno);
                __httpclient_async_complete(client, 0);
                return 0;
            }

            if (written < ctx->write_buffer_pos) {
                // Отправлено частично, сдвинуть буфер
                memmove(ctx->write_buffer, ctx->write_buffer + written,
                        ctx->write_buffer_pos - written);
                ctx->write_buffer_pos -= written;
                return 1;  // Ждем следующего EPOLLOUT
            }

            // Все отправлено
            ctx->write_completed = 1;
            ctx->state = ASYNC_STATE_READING_RESPONSE;

            // Переключиться на ожидание чтения
            ctx->api->control_mod(connection, MPXIN | MPXRDHUP);
            return 1;
        }

        default:
            // В других состояниях write не ожидается
            return 1;
    }

    return 1;
}

// Read handler
int __httpclient_async_read(connection_t* connection) {
    connection_client_async_ctx_t* conn_ctx = connection->ctx;
    httpclient_t* client = conn_ctx->client;
    httpclient_async_ctx_t* ctx = client->async_ctx;

    // Проверка timeout
    uint64_t now = __get_current_time_ms();
    if (now - ctx->start_time_ms > ctx->timeout_ms) {
        log_error("Async HTTP client read timeout\n");
        __httpclient_async_complete(client, 0);
        return 0;
    }

    // Если во время TLS handshake нужно чтение
    if (ctx->state == ASYNC_STATE_TLS_HANDSHAKE) {
        return __httpclient_async_write(connection);  // Продолжить handshake
    }

    if (ctx->state != ASYNC_STATE_READING_RESPONSE) {
        // Неожиданное чтение
        return 1;
    }

    // Использовать существующий response parser
    httpresponse_t* response = client->response;
    httpresponseparser_t* parser = response->parser;

    int bytes_read = connection_data_read(connection);

    switch (bytes_read) {
        case -1:
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Нет данных, ждем следующего EPOLLIN
                return 1;
            }
            log_error("Async read error: %d\n", errno);
            __httpclient_async_complete(client, 0);
            return 0;

        case 0:
            // Соединение закрыто
            if (ctx->read_completed) {
                __httpclient_async_complete(client, 1);
            } else {
                log_error("Connection closed before response complete\n");
                __httpclient_async_complete(client, 0);
            }
            return 0;

        default:
            httpresponseparser_set_bytes_readed(parser, bytes_read);

            switch (httpresponseparser_run(parser)) {
                case HTTP1PARSER_ERROR:
                case HTTP1PARSER_OUT_OF_MEMORY:
                case HTTP1PARSER_PAYLOAD_LARGE:
                case HTTP1PARSER_BAD_REQUEST:
                case HTTP1PARSER_HOST_NOT_FOUND:
                    __httpclient_async_complete(client, 0);
                    return 0;

                case HTTP1PARSER_CONTINUE:
                    // Продолжаем чтение
                    return 1;

                case HTTP1RESPONSEPARSER_COMPLETE:
                    // Ответ получен полностью
                    ctx->read_completed = 1;
                    ctx->state = ASYNC_STATE_COMPLETE;
                    __httpclient_async_complete(client, 1);
                    return 0;  // Закрыть соединение
            }
    }

    return 1;
}
