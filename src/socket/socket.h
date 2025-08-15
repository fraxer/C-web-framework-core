#ifndef __SOCKET__
#define __SOCKET__

#include <arpa/inet.h>

int socket_listen_create(in_addr_t ip, unsigned short int port);
int socket_set_nonblocking(int socket);
int socket_set_keepalive(int socket);
int socket_set_timeouts(int socket);

#endif
