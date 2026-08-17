#define _GNU_SOURCE
#include <stdlib.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "log.h"
#include "socket.h"

static int __socket_set_options(int socket);

int socket_set_nonblocking(int socket) {
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        log_error("Socket error: fcntl failed (F_GETFL)\n");
        return -1;
    }

    flags |= O_NONBLOCK;
    if (fcntl(socket, F_SETFL, flags) == -1) {
        log_error("Socket error: fcntl failed (F_SETFL)\n");
        return -1;
    }

    return 0;
}

int socket_set_keepalive(int socket) {
    int kenable = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &kenable, sizeof(kenable)) == -1) return -1;

    // Максимальное количество контрольных зондов
    int keepcnt = 3;
    if (setsockopt(socket, SOL_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt)) == -1) return -1;

    // Время (в секундах) соединение должно оставаться бездействующим
    // до того, как TCP начнет отправлять контрольные зонды
    int keepidle = 5;
    if (setsockopt(socket, SOL_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle)) == -1) return -1;

    // Время (в секундах) между отдельными зондами
    int keepintvl = 5;
    if (setsockopt(socket, SOL_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl)) == -1) return -1;

    return 0;
}

int socket_set_nodelay(int socket) {
    int nodelay = 1;
    if (setsockopt(socket, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) == -1) {
        log_error("Socket error: Failed to set TCP_NODELAY\n");
        return -1;
    }

    return 0;
}

int socket_set_timeouts(int socket) {
    struct timeval timeout;

    // Таймаут на отправку данных (10 секунд)
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
        log_error("Socket error: Failed to set send timeout\n");
        return -1;
    }

    // Таймаут на прием данных (10 секунд)
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
        log_error("Socket error: Failed to set receive timeout\n");
        return -1;
    }

    return 0;
}

int socket_listen_create(const ipaddr_t* ip, unsigned short int port) {
    struct sockaddr_storage sa;
    const socklen_t sa_len = ipaddr_to_sockaddr(ip, port, &sa);

    char authority[IPADDR_AUTHORITY_STRLEN];
    ipaddr_authority(ip, port, authority, sizeof authority);

    if (sa_len == 0) {
        log_error("Socket error: no address to listen on for port %d\n", port);
        return -1;
    }

    const int fd = socket(sa.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        log_error("Socket error: Can't create socket on %s\n", authority);
        return -1;
    }

    int result = -1;
    if (__socket_set_options(fd) == -1) {
        log_error("Socket error: Can't set options for socket on %s\n", authority);
        goto failed;
    }

    /* v6-only, see socket.h. Without it a wildcard IPv6 bind also takes IPv4,
     * and the same config would then mean different things depending on a
     * sysctl. */
    if (sa.ss_family == AF_INET6) {
        int on = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on) == -1) {
            log_error("Socket error: Can't set IPV6_V6ONLY on %s\n", authority);
            goto failed;
        }
    }

    if (bind(fd, (struct sockaddr*)&sa, sa_len) == -1) {
        log_error("Socket bind error on %s\n", authority);
        goto failed;
    }

    if (socket_set_nonblocking(fd) == -1) {
        log_error("Socket error: Can't make socket nonblocking on %s\n", authority);
        goto failed;
    }

    if (listen(fd, SOMAXCONN) == -1) {
        log_error("Socket error: listen socket failed on %s\n", authority);
        goto failed;
    }

    result = fd;

    failed:

    if (result == -1)
        close(fd);

    return result;
}

static int __socket_set_options(int socket) {
    int enableaddr = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enableaddr, sizeof(enableaddr)) == -1) return -1;

    int enableport = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &enableport, sizeof(enableport)) == -1)
        log_error("Socket error: Failed to set SO_REUSEPORT\n");

    return 0;
}
