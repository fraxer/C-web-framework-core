#ifndef __QUICCLIENT__
#define __QUICCLIENT__

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#include "quic.h"
#include "quiccrypto.h"
#include "quicrange.h"
#include "quicrecvbuf.h"
#include "quicsendbuf.h"
#include "quictls.h"

/* A minimal QUIC client, for testing this server.
 *
 * ## Why the project contains a client at all
 *
 * Two reasons, and neither is "for completeness":
 *
 *  - **There is no other one here.** The system curl is built without HTTP/3,
 *    and ngtcp2, quiche and aioquic are not installed. Without a client, the
 *    server's handshake can only be checked against itself, and a
 *    self-consistent mistake passes that check perfectly.
 *
 *  - **Loss recovery is only testable against a peer you control.** RFC 9002 is
 *    defined entirely in elapsed time and packet ordering, so the interesting
 *    cases -- a packet lost, two reordered, an acknowledgement that crosses a
 *    loss declaration -- need a peer that can be told to drop and reorder on
 *    command. That is what docs/http3/08-testing.md §2 asks for, and it is what
 *    this grows into.
 *
 * Deliberately not a general-purpose client. It speaks enough QUIC to complete
 * a handshake and exchange a little data, and it borrows every codec from the
 * server's own modules -- the only thing written twice is the *client* side of
 * the packet loop, which is what has to be independent for the test to mean
 * anything. */

/* Streams the test drives. A handful is plenty: HTTP/3 needs one control
 * stream, one request stream, and room for whatever the server opens back --
 * its control stream and both QPACK streams. */
#define CLIENT_MAX_STREAMS 16

typedef struct clientstream {
    uint64_t      id;
    int           used;

    quicsendbuf_t out;
    int           fin_queued;

    quicrecvbuf_t in;
    int           in_fin;
} clientstream_t;

typedef struct quicclient {
    int fd;
    struct sockaddr_in server;

    SSL_CTX* ssl_ctx;
    quictls_t tls;

    /* Our chosen connection id, and the server's once it tells us. `odcid` is
     * the random id we put in the first Initial: the Initial keys of both ends
     * derive from it, which is what lets a server decrypt a packet from a
     * client it has never heard of. */
    quiccid_t odcid;
    quiccid_t scid;          /* ours, what the server addresses us by */
    quiccid_t dcid;          /* the server's, once known */

    quickeys_t rx[QUIC_ENC_COUNT];
    quickeys_t tx[QUIC_ENC_COUNT];

    quicsendbuf_t crypto_out[QUIC_ENC_COUNT];
    uint64_t next_pn[QUIC_ENC_COUNT];
    quicrange_t received[QUIC_ENC_COUNT];
    int        ack_pending[QUIC_ENC_COUNT];

    int handshake_complete;
    int handshake_done_received;   /* the server's HANDSHAKE_DONE */
    int got_server_initial;
    int got_server_handshake;

    clientstream_t streams[CLIENT_MAX_STREAMS];

    /* Key update (RFC 9001 §6), from the initiating side. The server only ever
     * responds to one, so the client has to be the one that starts it.
     *
     * `rx_prev` matters more here than it looks: between our update and the
     * server noticing it, the server is still sending in the old phase, and
     * without the retained generation those packets -- typically the ACK for
     * the very packet that carried the update -- would be dropped. */
    int      key_phase;
    quickeys_t rx_prev;
    int      key_update_done;
    int      read_after_update;      /* a packet opened in the new phase */

    /* Path validation (RFC 9000 §8.2), from the challenging side. The server
     * has no way to show that it answers a PATH_CHALLENGE other than by
     * answering one, so the client has to be able to ask. */
    uint8_t path_challenge_data[8];
    int     path_challenge_queued;   /* built into the next packet */
    int     path_challenge_sent;
    int     path_response_received;
    int     path_response_matched;   /* the echo came back byte for byte */

    int verbose;
} quicclient_t;

/* Move both directions to the next key generation and flip the Key Phase bit
 * (§6.1). Only meaningful once 1-RTT keys exist. Returns 0 on failure. */
int quicclient_key_update(quicclient_t* client);

/* Queue a PATH_CHALLENGE with random data. Only meaningful once 1-RTT keys
 * exist -- the frame is not permitted at any earlier level. Returns 0 if the
 * connection is not ready or a challenge is already outstanding. */
int quicclient_path_challenge(quicclient_t* client);

/* Set up and send the first Initial. Returns 0 on failure. */
int quicclient_connect(quicclient_t* client, const char* host, uint16_t port,
                       const char* server_name, int verbose);

/* Drive the exchange until the handshake completes or `timeout_ms` elapses.
 * Returns 1 if it completed. */
int quicclient_run(quicclient_t* client, int timeout_ms);

/* ---- Streams ---- *
 *
 * Deliberately minimal, and honest about it: send-side flow control is not
 * enforced and no MAX_DATA is ever sent back. A test exchange is a request of a
 * few hundred bytes and a response the server's own windows already bound, so
 * neither can bite; a general-purpose client would need both. */

/* Queue bytes on a stream, opening it on first use. `fin` ends it. */
int quicclient_stream_write(quicclient_t* client, uint64_t id,
                            const uint8_t* data, size_t len, int fin);

/* Bytes ready to read on a stream, and reading them. */
size_t quicclient_stream_readable(quicclient_t* client, uint64_t id);
size_t quicclient_stream_read(quicclient_t* client, uint64_t id,
                              uint8_t* dst, size_t cap);

/* Has the server finished its half of this stream? */
int quicclient_stream_fin(quicclient_t* client, uint64_t id);

/* One turn of the loop: send what is queued, then receive for up to
 * `timeout_ms`. Unlike quicclient_run it has no completion condition of its
 * own -- the caller decides when it has what it wanted. Returns 0 if the
 * connection failed. */
int quicclient_pump(quicclient_t* client, int timeout_ms);

void quicclient_free(quicclient_t* client);

#endif
