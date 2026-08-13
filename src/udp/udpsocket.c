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
 * receive-queue overflow counter, the arrival timestamp -- and, on the send
 * side, the segment size that goes out alongside the local address. */
#define UDP_CONTROL_SIZE (CMSG_SPACE(sizeof(struct in6_pktinfo)) + \
                          CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint32_t)) + \
                          CMSG_SPACE(sizeof(struct timespec)) + \
                          CMSG_SPACE(sizeof(uint16_t)))

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

/* Pin the source address to the one the peer sent to. Without this the kernel
 * picks by route, and on a host with several addresses the reply arrives from
 * an address the peer never contacted -- which it discards, producing a
 * connection that hangs with no error anywhere.
 *
 * Writes into `control`, which must hold UDP_CONTROL_SIZE bytes and outlive the
 * send, and leaves msg_control NULL when there is nothing to pin. */
static void __msg_set_local(struct msghdr* hdr, uint8_t* control,
                            const struct sockaddr_storage* local,
                            sa_family_t peer_family) {
    hdr->msg_control = NULL;
    hdr->msg_controllen = 0;

    if (local == NULL || local->ss_family != peer_family) return;

    memset(control, 0, UDP_CONTROL_SIZE);
    hdr->msg_control = control;

    if (local->ss_family == AF_INET) {
        hdr->msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

        struct cmsghdr* cmsg = CMSG_FIRSTHDR(hdr);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

        struct in_pktinfo info;
        memset(&info, 0, sizeof info);
        info.ipi_spec_dst = ((const struct sockaddr_in*)local)->sin_addr;
        memcpy(CMSG_DATA(cmsg), &info, sizeof info);
    }
    else if (local->ss_family == AF_INET6) {
        hdr->msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

        struct cmsghdr* cmsg = CMSG_FIRSTHDR(hdr);
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
        hdr->msg_control = NULL;
        hdr->msg_controllen = 0;
    }
}

/* Segmentation offload: one message carries many datagrams, and the kernel
 * cuts it into them. Not in glibc's headers everywhere, and it is a stable
 * kernel constant (Linux 4.18+). */
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

/* The kernel refuses more than this many segments in one message. */
#define UDP_TX_MAX_SEGMENTS 64

struct udp_tx_batch {
    size_t msg_capacity;     /* messages */
    size_t datagram_size;    /* the largest single datagram */
    size_t arena_size;

    size_t used;             /* bytes of arena taken */
    size_t queued;           /* messages built */
    size_t datagrams;        /* what those messages will put on the wire */

    struct mmsghdr* msgs;
    struct iovec* iov;
    uint8_t* arena;
    uint8_t* control;
    struct sockaddr_storage* peers;
    struct sockaddr_storage* locals;
    int* local_valid;

    /* Per message: the segment size the kernel is told to cut at (0 when the
     * message is a single datagram) and how many datagrams it holds. */
    uint16_t* seg_size;
    size_t* segments;

    /* The message still accepting datagrams, or -1. Only the newest one can
     * be: segments must be contiguous in the arena. */
    int open;

    /* Offload is allowed until the kernel says otherwise, and then never
     * again for this batch -- one refusal is enough to know. */
    int gso;
};

udp_tx_batch_t* udp_tx_batch_create(size_t count, size_t datagram_size) {
    if (count == 0 || datagram_size == 0) return NULL;

    udp_tx_batch_t* batch = malloc(sizeof * batch);
    if (batch == NULL) return NULL;

    memset(batch, 0, sizeof * batch);
    batch->msg_capacity = count;
    batch->datagram_size = datagram_size;
    batch->arena_size = count * datagram_size;
    batch->open = -1;
    batch->gso = 1;

    batch->msgs = calloc(count, sizeof * batch->msgs);
    batch->iov = calloc(count, sizeof * batch->iov);
    batch->arena = malloc(batch->arena_size);
    batch->control = malloc(count * UDP_CONTROL_SIZE);
    batch->peers = calloc(count, sizeof * batch->peers);
    batch->locals = calloc(count, sizeof * batch->locals);
    batch->local_valid = calloc(count, sizeof * batch->local_valid);
    batch->seg_size = calloc(count, sizeof * batch->seg_size);
    batch->segments = calloc(count, sizeof * batch->segments);

    if (batch->msgs == NULL || batch->iov == NULL || batch->arena == NULL ||
        batch->control == NULL || batch->peers == NULL || batch->locals == NULL ||
        batch->local_valid == NULL || batch->seg_size == NULL ||
        batch->segments == NULL) {
        udp_tx_batch_free(batch);
        return NULL;
    }

    /* Wired once. The address of a message never moves; where in the arena its
     * bytes start is decided per datagram. */
    for (size_t i = 0; i < count; i++) {
        struct msghdr* hdr = &batch->msgs[i].msg_hdr;
        hdr->msg_name = &batch->peers[i];
        hdr->msg_iov = &batch->iov[i];
        hdr->msg_iovlen = 1;
    }

    return batch;
}

void udp_tx_batch_free(udp_tx_batch_t* batch) {
    if (batch == NULL) return;

    free(batch->msgs);
    free(batch->iov);
    free(batch->arena);
    free(batch->control);
    free(batch->peers);
    free(batch->locals);
    free(batch->local_valid);
    free(batch->seg_size);
    free(batch->segments);
    free(batch);
}

size_t udp_tx_batch_count(const udp_tx_batch_t* batch) {
    /* Datagrams, not messages: with offload one message is many datagrams, and
     * every caller of this counts packets. */
    return batch != NULL ? batch->datagrams : 0;
}

/* May this datagram join the message still open? Everything the kernel folds
 * into one skb has to agree: the destination, the source we pin, and the
 * segment size -- which may only differ for the *last* datagram, and that one
 * closes the run. */
static int __tx_joins_open(const udp_tx_batch_t* batch, size_t len,
                           const struct sockaddr* peer, socklen_t peer_len,
                           const struct sockaddr_storage* local) {
    if (!batch->gso || batch->open < 0) return 0;

    const size_t i = (size_t)batch->open;

    if (batch->segments[i] >= UDP_TX_MAX_SEGMENTS) return 0;
    if (batch->msgs[i].msg_hdr.msg_namelen != peer_len) return 0;
    if (memcmp(&batch->peers[i], peer, peer_len) != 0) return 0;

    const int valid = local != NULL && local->ss_family == peer->sa_family;
    if (batch->local_valid[i] != valid) return 0;
    if (valid && memcmp(&batch->locals[i], local, sizeof * local) != 0) return 0;

    /* Equal to the run's segment size continues it; smaller ends it; larger
     * cannot belong to it at all. */
    return len <= batch->seg_size[i];
}

int udp_tx_batch_add(udp_tx_batch_t* batch, const uint8_t* data, size_t len,
                     const struct sockaddr* peer, socklen_t peer_len,
                     const struct sockaddr_storage* local) {
    if (batch == NULL || data == NULL || peer == NULL || len == 0) return -1;
    if (len > batch->datagram_size || peer_len > sizeof(struct sockaddr_storage))
        return 0;

    if (batch->used + len > batch->arena_size) return 0;

    if (__tx_joins_open(batch, len, peer, peer_len, local)) {
        const size_t i = (size_t)batch->open;

        memcpy(batch->arena + batch->used, data, len);
        batch->used += len;
        batch->iov[i].iov_len += len;
        batch->segments[i]++;
        batch->datagrams++;

        /* A short segment can only be the last one. */
        if (len < batch->seg_size[i]) batch->open = -1;

        return 1;
    }

    if (batch->queued >= batch->msg_capacity) return 0;

    const size_t i = batch->queued;
    struct msghdr* hdr = &batch->msgs[i].msg_hdr;

    memcpy(batch->arena + batch->used, data, len);
    batch->iov[i].iov_base = batch->arena + batch->used;
    batch->iov[i].iov_len = len;
    batch->used += len;

    memcpy(&batch->peers[i], peer, peer_len);
    hdr->msg_namelen = peer_len;

    batch->local_valid[i] = local != NULL && local->ss_family == peer->sa_family;
    if (batch->local_valid[i]) memcpy(&batch->locals[i], local, sizeof * local);

    batch->seg_size[i] = (uint16_t)len;
    batch->segments[i] = 1;
    batch->msgs[i].msg_len = 0;
    batch->queued++;
    batch->datagrams++;

    /* Open for company: the next datagram of this size to the same peer joins
     * it, a shorter one joins and closes it, a longer one starts its own. */
    batch->open = (int)i;

    return 1;
}

/* Fill in the control message(s) for one built message and hand it its
 * segment size when it carries several datagrams. */
static void __tx_prepare(udp_tx_batch_t* batch, size_t i, int with_gso) {
    struct msghdr* hdr = &batch->msgs[i].msg_hdr;
    uint8_t* control = batch->control + i * UDP_CONTROL_SIZE;

    __msg_set_local(hdr, control, batch->local_valid[i] ? &batch->locals[i] : NULL,
                    ((const struct sockaddr*)&batch->peers[i])->sa_family);

    if (!with_gso || batch->segments[i] < 2) return;

    const size_t local_len = hdr->msg_controllen;
    if (local_len == 0) memset(control, 0, CMSG_SPACE(sizeof(uint16_t)));

    hdr->msg_control = control;
    hdr->msg_controllen = local_len + CMSG_SPACE(sizeof(uint16_t));

    struct cmsghdr* cmsg = local_len > 0
        ? CMSG_NXTHDR(hdr, CMSG_FIRSTHDR(hdr)) : CMSG_FIRSTHDR(hdr);
    if (cmsg == NULL) {
        hdr->msg_controllen = local_len;
        return;
    }

    cmsg->cmsg_level = IPPROTO_UDP;   /* == SOL_UDP, without the linux header */
    cmsg->cmsg_type = UDP_SEGMENT;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));

    const uint16_t seg = batch->seg_size[i];
    memcpy(CMSG_DATA(cmsg), &seg, sizeof seg);
}

/* Send one message's datagrams one at a time, for the kernel that refuses
 * offload. The segments are contiguous in the arena, so they can be walked
 * back out of it without having been kept anywhere else. */
static int __tx_send_split(udp_tx_batch_t* batch, size_t i, int fd, size_t* out_bytes) {
    const uint8_t* p = batch->iov[i].iov_base;
    size_t left = batch->iov[i].iov_len;
    const size_t seg = batch->seg_size[i] > 0 ? batch->seg_size[i] : left;
    int sent = 0;

    while (left > 0) {
        const size_t take = left < seg ? left : seg;

        const ssize_t n = udp_send(fd, p, take,
                                   (const struct sockaddr*)&batch->peers[i],
                                   batch->msgs[i].msg_hdr.msg_namelen,
                                   batch->local_valid[i] ? &batch->locals[i] : NULL);
        if (n > 0) {
            sent++;
            if (out_bytes != NULL) *out_bytes += (size_t)n;
        }

        p += take;
        left -= take;
    }

    return sent;
}

int udp_tx_batch_flush(udp_tx_batch_t* batch, int fd, size_t* out_bytes) {
    if (out_bytes != NULL) *out_bytes = 0;
    if (batch == NULL) return -1;

    const size_t queued = batch->queued;
    if (queued == 0) return 0;

    /* Emptied whatever the kernel says: what it refuses is a lost packet, and
     * QUIC has loss recovery for exactly that. */
    batch->queued = 0;
    batch->datagrams = 0;
    batch->used = 0;
    batch->open = -1;

    for (size_t i = 0; i < queued; i++)
        __tx_prepare(batch, i, batch->gso);

    const int n = sendmmsg(fd, batch->msgs, (unsigned int)queued, MSG_NOSIGNAL);
    if (n < 0) {
        /* A kernel (or a container) without segmentation offload says so here,
         * and there is no probing it beforehand -- so the first refusal is the
         * probe. Everything queued is resent one datagram at a time, and this
         * batch never offers offload again. */
        if (batch->gso && (errno == EIO || errno == EINVAL || errno == ENOTSUP ||
                           errno == EOPNOTSUPP)) {
            log_error("Udp socket error: no segmentation offload (errno %d), "
                      "falling back to one datagram per send\n", errno);
            batch->gso = 0;

            int split_sent = 0;
            for (size_t i = 0; i < queued; i++)
                split_sent += __tx_send_split(batch, i, fd, out_bytes);

            return split_sent;
        }

        /* A full socket buffer or an ICMP error reported on the next send is a
         * lost packet, not a broken endpoint -- the same reasoning as the
         * receive path. */
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
            errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ENETUNREACH ||
            errno == EMSGSIZE || errno == EPERM)
            return 0;

        log_error("Udp socket error: sendmmsg failed (errno %d)\n", errno);
        return -1;
    }

    /* The count is datagrams, not messages: everything above this function
     * counts packets on the wire, and one message may be twenty of them. */
    size_t accepted = 0;
    for (int i = 0; i < n; i++) {
        accepted += batch->segments[i];
        if (out_bytes != NULL) *out_bytes += batch->msgs[i].msg_len;
    }

    return (int)accepted;
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

    __msg_set_local(&hdr, control, local, peer->sa_family);

    const ssize_t sent = sendmsg(fd, &hdr, MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;

        return -1;
    }

    return sent;
}
