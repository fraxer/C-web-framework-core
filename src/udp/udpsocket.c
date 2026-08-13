#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "udpsocket.h"

/* Room for the local-address cmsg of either family, the ECN byte, the
 * receive-queue overflow counter and the arrival timestamp. */
#define UDP_CONTROL_SIZE (CMSG_SPACE(sizeof(struct in6_pktinfo)) + \
                          CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint32_t)) + \
                          CMSG_SPACE(sizeof(struct timespec)))

struct udp_rx_batch {
    size_t count;
    size_t datagram_size;

    struct mmsghdr* msgs;
    struct iovec* iov;
    uint8_t* buffers;
    uint8_t* control;
    udp_datagram_t* datagrams;
};

static int __set_nonblocking(int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int udp_socket_create(const struct sockaddr* addr, socklen_t addrlen,
                      const udp_socket_options_t* options) {
    if (addr == NULL) return -1;

    const int family = addr->sa_family;
    if (family != AF_INET && family != AF_INET6) {
        log_error("Udp socket error: unsupported address family %d\n", family);
        return -1;
    }

    const int fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        log_error("Udp socket error: socket() failed (errno %d)\n", errno);
        return -1;
    }

    int result = -1;
    int on = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) == -1) {
        log_error("Udp socket error: SO_REUSEADDR failed (errno %d)\n", errno);
        goto failed;
    }

    if (options != NULL && options->reuseport)
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) == -1)
            log_error("Udp socket error: SO_REUSEPORT failed (errno %d)\n", errno);

    if (family == AF_INET6) {
        /* One socket per family: a dual-stack socket delivers v4 traffic with
         * v4-mapped addresses, which makes the local-address cmsg ambiguous and
         * differs between kernels. */
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on) == -1) {
            log_error("Udp socket error: IPV6_V6ONLY failed (errno %d)\n", errno);
            goto failed;
        }

        if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof on) == -1) {
            log_error("Udp socket error: IPV6_RECVPKTINFO failed (errno %d)\n", errno);
            goto failed;
        }

        /* RFC 9000 §14: set DF. Without it the network fragments oversized
         * datagrams, and a QUIC packet reassembled from fragments is both a
         * performance trap and a well-known evasion vector. */
        int mtu = IPV6_PMTUDISC_DO;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &mtu, sizeof mtu) == -1)
            log_error("Udp socket error: IPV6_MTU_DISCOVER failed (errno %d)\n", errno);
    }
    else {
        if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof on) == -1) {
            log_error("Udp socket error: IP_PKTINFO failed (errno %d)\n", errno);
            goto failed;
        }

        int mtu = IP_PMTUDISC_DO;
        if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mtu, sizeof mtu) == -1)
            log_error("Udp socket error: IP_MTU_DISCOVER failed (errno %d)\n", errno);
    }

    /* Ask the kernel to tell us what it drops. A failure here is not fatal:
     * the counter is diagnostics, and a kernel without it (or a container that
     * forbids it) should still serve traffic. */
    if (setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, &on, sizeof on) == -1)
        log_error("Udp socket error: SO_RXQ_OVFL failed (errno %d)\n", errno);

    /* And when it took each datagram, for the same reason: the drop counter
     * says the queue overflowed, the timestamp says how long it was already
     * standing before it did. Diagnostics too, so not fatal either. */
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof on) == -1)
        log_error("Udp socket error: SO_TIMESTAMPNS failed (errno %d)\n", errno);

    if (options != NULL && options->rcvbuf > 0)
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &options->rcvbuf,
                       sizeof options->rcvbuf) == -1)
            log_error("Udp socket error: SO_RCVBUF failed (errno %d)\n", errno);

    if (options != NULL && options->sndbuf > 0)
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &options->sndbuf,
                       sizeof options->sndbuf) == -1)
            log_error("Udp socket error: SO_SNDBUF failed (errno %d)\n", errno);

    if (__set_nonblocking(fd) == -1) {
        log_error("Udp socket error: cannot make socket nonblocking (errno %d)\n", errno);
        goto failed;
    }

    if (bind(fd, addr, addrlen) == -1) {
        log_error("Udp socket error: bind failed (errno %d)\n", errno);
        goto failed;
    }

    result = fd;

    failed:

    if (result == -1) close(fd);

    return result;
}

udp_rx_batch_t* udp_rx_batch_create(size_t count, size_t datagram_size) {
    if (count == 0 || datagram_size == 0) return NULL;

    udp_rx_batch_t* batch = malloc(sizeof * batch);
    if (batch == NULL) return NULL;

    memset(batch, 0, sizeof * batch);

    batch->count = count;
    batch->datagram_size = datagram_size;

    batch->msgs = calloc(count, sizeof * batch->msgs);
    batch->iov = calloc(count, sizeof * batch->iov);
    batch->datagrams = calloc(count, sizeof * batch->datagrams);
    batch->buffers = malloc(count * datagram_size);
    batch->control = malloc(count * UDP_CONTROL_SIZE);

    if (batch->msgs == NULL || batch->iov == NULL || batch->datagrams == NULL ||
        batch->buffers == NULL || batch->control == NULL) {
        udp_rx_batch_free(batch);
        return NULL;
    }

    /* Wired once. recvmmsg only writes msg_len, msg_namelen, msg_controllen and
     * msg_flags, so the pointers stay valid across calls. */
    for (size_t i = 0; i < count; i++) {
        batch->iov[i].iov_base = batch->buffers + i * datagram_size;
        batch->iov[i].iov_len = datagram_size;

        struct msghdr* hdr = &batch->msgs[i].msg_hdr;
        hdr->msg_name = &batch->datagrams[i].peer;
        hdr->msg_namelen = sizeof batch->datagrams[i].peer;
        hdr->msg_iov = &batch->iov[i];
        hdr->msg_iovlen = 1;
        hdr->msg_control = batch->control + i * UDP_CONTROL_SIZE;
        hdr->msg_controllen = UDP_CONTROL_SIZE;

        batch->datagrams[i].data = batch->buffers + i * datagram_size;
    }

    return batch;
}

void udp_rx_batch_free(udp_rx_batch_t* batch) {
    if (batch == NULL) return;

    free(batch->msgs);
    free(batch->iov);
    free(batch->datagrams);
    free(batch->buffers);
    free(batch->control);
    free(batch);
}

/* Pull the destination address and ECN out of the control messages. */
static void __parse_control(struct msghdr* hdr, udp_datagram_t* dgram) {
    dgram->local_valid = 0;
    dgram->ecn = 0;
    dgram->drops = 0;
    dgram->drops_valid = 0;
    dgram->stamp_us = 0;
    dgram->stamp_valid = 0;

    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(hdr); cmsg != NULL;
         cmsg = CMSG_NXTHDR(hdr, cmsg)) {

        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo info;
            memcpy(&info, CMSG_DATA(cmsg), sizeof info);

            struct sockaddr_in* sa = (struct sockaddr_in*)&dgram->local;
            memset(sa, 0, sizeof * sa);
            sa->sin_family = AF_INET;
            /* ipi_addr, not ipi_spec_dst: we want the address the datagram was
             * actually addressed to, which is what the peer will expect to see
             * as the source of the reply. */
            sa->sin_addr = info.ipi_addr;
            dgram->local_valid = 1;
        }
        else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo info;
            memcpy(&info, CMSG_DATA(cmsg), sizeof info);

            struct sockaddr_in6* sa = (struct sockaddr_in6*)&dgram->local;
            memset(sa, 0, sizeof * sa);
            sa->sin6_family = AF_INET6;
            sa->sin6_addr = info.ipi6_addr;
            sa->sin6_scope_id = info.ipi6_ifindex;
            dgram->local_valid = 1;
        }
        else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL) {
            memcpy(&dgram->drops, CMSG_DATA(cmsg), sizeof dgram->drops);
            dgram->drops_valid = 1;
        }
        else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPNS) {
            struct timespec ts;
            memcpy(&ts, CMSG_DATA(cmsg), sizeof ts);

            dgram->stamp_us = (uint64_t)ts.tv_sec * 1000000ULL +
                              (uint64_t)ts.tv_nsec / 1000ULL;
            dgram->stamp_valid = 1;
        }
        /* ECN (IP_RECVTOS / IPV6_RECVTCLASS) is phase 9. The socket does not ask
         * for it, so there is deliberately no branch here: a placeholder that
         * never runs is a placeholder nobody notices is wrong. */
    }
}

int udp_rx_batch_recv(udp_rx_batch_t* batch, int fd) {
    if (batch == NULL) return -1;

    /* Reset the fields the kernel overwrites; the rest of the wiring persists. */
    for (size_t i = 0; i < batch->count; i++) {
        struct msghdr* hdr = &batch->msgs[i].msg_hdr;
        hdr->msg_namelen = sizeof batch->datagrams[i].peer;
        hdr->msg_controllen = UDP_CONTROL_SIZE;
        hdr->msg_flags = 0;
        batch->msgs[i].msg_len = 0;
    }

    const int n = recvmmsg(fd, batch->msgs, (unsigned int)batch->count, 0, NULL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;

        /* A previous send provoked an ICMP error and the kernel is reporting it
         * on the next receive. It belongs to one peer, not to the socket. */
        if (errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ENETUNREACH ||
            errno == EMSGSIZE)
            return 0;

        log_error("Udp socket error: recvmmsg failed (errno %d)\n", errno);
        return -1;
    }

    for (int i = 0; i < n; i++) {
        udp_datagram_t* dgram = &batch->datagrams[i];

        dgram->len = batch->msgs[i].msg_len;
        dgram->peer_len = batch->msgs[i].msg_hdr.msg_namelen;

        /* MSG_TRUNC means the datagram was larger than the buffer. QUIC has no
         * use for a partial datagram -- the AEAD tag is at the end -- so mark it
         * empty and let the caller count it as a drop. */
        if (batch->msgs[i].msg_hdr.msg_flags & MSG_TRUNC)
            dgram->len = 0;

        __parse_control(&batch->msgs[i].msg_hdr, dgram);
    }

    return n;
}

udp_datagram_t* udp_rx_batch_get(udp_rx_batch_t* batch, size_t index) {
    if (batch == NULL || index >= batch->count) return NULL;

    return &batch->datagrams[index];
}

ssize_t udp_send(int fd, const uint8_t* data, size_t len,
                 const struct sockaddr* peer, socklen_t peer_len,
                 const struct sockaddr_storage* local) {
    if (data == NULL || peer == NULL) return -1;

    struct iovec iov = { .iov_base = (void*)data, .iov_len = len };
    uint8_t control[UDP_CONTROL_SIZE];

    struct msghdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.msg_name = (void*)peer;
    hdr.msg_namelen = peer_len;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;

    /* Pin the source address to the one the peer sent to. Without this the
     * kernel picks by route, and on a host with several addresses the reply
     * arrives from an address the peer never contacted -- which it discards,
     * producing a connection that hangs with no error anywhere. */
    if (local != NULL && local->ss_family == peer->sa_family) {
        memset(control, 0, sizeof control);
        hdr.msg_control = control;

        if (local->ss_family == AF_INET) {
            hdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

            struct cmsghdr* cmsg = CMSG_FIRSTHDR(&hdr);
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

            struct in_pktinfo info;
            memset(&info, 0, sizeof info);
            info.ipi_spec_dst = ((const struct sockaddr_in*)local)->sin_addr;
            memcpy(CMSG_DATA(cmsg), &info, sizeof info);
        }
        else if (local->ss_family == AF_INET6) {
            hdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

            struct cmsghdr* cmsg = CMSG_FIRSTHDR(&hdr);
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

            const struct sockaddr_in6* sa6 = (const struct sockaddr_in6*)local;
            struct in6_pktinfo info;
            memset(&info, 0, sizeof info);
            info.ipi6_addr = sa6->sin6_addr;
            memcpy(CMSG_DATA(cmsg), &info, sizeof info);
        }
        else {
            hdr.msg_control = NULL;
        }
    }

    const ssize_t sent = sendmsg(fd, &hdr, MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;

        return -1;
    }

    return sent;
}
