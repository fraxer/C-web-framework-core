#ifndef __SOCKET__
#define __SOCKET__

#include <arpa/inet.h>

#include "ipaddr.h"

/* Bind and listen on `ip`:`port`, either family. An IPv6 socket is created
 * v6-only, for the same reason the QUIC endpoint's is (src/udp/udpsocket.h): a
 * dual-stack socket reports v4 peers as v4-mapped addresses, which would have
 * to be un-mapped in every place that compares a connection's address with a
 * vhost's, and behaves differently depending on net.ipv6.bindv6only. Two
 * families means two vhost entries and two sockets, which is what the rest of
 * the config already looks like. */
int socket_listen_create(const ipaddr_t* ip, unsigned short int port);
int socket_set_nonblocking(int socket);
int socket_set_nodelay(int socket);
int socket_set_keepalive(int socket);
int socket_set_timeouts(int socket);

#endif
