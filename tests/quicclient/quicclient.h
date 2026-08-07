#ifndef __QUICCLIENT__
#define __QUICCLIENT__

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#include "quic.h"
#include "quiccrypto.h"
#include "quicrange.h"
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

    int verbose;
} quicclient_t;

/* Set up and send the first Initial. Returns 0 on failure. */
int quicclient_connect(quicclient_t* client, const char* host, uint16_t port,
                       const char* server_name, int verbose);

/* Drive the exchange until the handshake completes or `timeout_ms` elapses.
 * Returns 1 if it completed. */
int quicclient_run(quicclient_t* client, int timeout_ms);

void quicclient_free(quicclient_t* client);

#endif
