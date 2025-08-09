#ifndef __SOCKET__
#define __SOCKET__

#include <arpa/inet.h>

typedef struct socket {
    int fd;
    in_addr_t ip;
    unsigned short int port;
    struct socket* next;
} socket_t;

socket_t* socket_alloc(void);
socket_t* socket_listen_create(in_addr_t ip, unsigned short int port);
void socket_free(socket_t* socket, int close_sockets);
int socket_set_nonblocking(int socket);
int socket_set_keepalive(int socket);
int socket_error_type(int error_code);

#endif
