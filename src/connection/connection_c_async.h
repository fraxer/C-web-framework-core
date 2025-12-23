#ifndef __CONNECTION_C_ASYNC__
#define __CONNECTION_C_ASYNC__

#include "connection.h"

struct mpxapi;
struct httpclient;

typedef struct {
    connection_ctx_t base;

    struct mpxapi* api;                   // Ссылка на epoll API
    struct httpclient* client;            // Обратная ссылка на HTTP клиент

    unsigned int destroyed:1;             // Флаг уничтожения
    unsigned int registered:1;            // Зарегистрирован в epoll
} connection_client_async_ctx_t;

// Создание async клиентского соединения
connection_t* connection_c_async_create(int fd, in_addr_t ip, unsigned short int port, struct mpxapi* api);

// Освобождение async клиентского соединения
void connection_c_async_free(connection_t* connection);

// Закрытие async клиентского соединения
int connection_c_async_close(connection_t* connection);

#endif
