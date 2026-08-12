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

/* Streams the test drives.
 *
 * A handful covers one exchange -- HTTP/3 needs one control stream, one request
 * stream, and room for whatever the server opens back. The rest of the room is
 * for the parallel-stream scenarios of docs/http3/08-testing.md §2: the send
 * path's round-robin between streams, and the stream credit that MAX_STREAMS
 * renews, are only exercised by a peer that has many open at once. Slots are
 * reusable (quicclient_stream_release), so a run that opens hundreds one after
 * another needs no more than this. */
#define CLIENT_MAX_STREAMS 64

typedef struct clientstream {
    uint64_t      id;
    int           used;

    quicsendbuf_t out;
    int           fin_queued;

    quicrecvbuf_t in;
    int           in_fin;

    /* The peer abandoned its send side (RESET_STREAM, §19.4). Nothing more is
     * coming, and `in_final_size` is how much was ever going to -- which is the
     * only way to tell a cancelled response from a truncated one. */
    int           in_reset;
    uint64_t      in_reset_error;
    uint64_t      in_final_size;

    /* A STOP_SENDING we owe the peer (§19.5): we are not going to read this
     * stream, and saying so is what stops it spending the window on us. */
    int           stop_sending_queued;
    uint64_t      stop_sending_error;
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

    /* Connection ids the server issued (RFC 9000 §5.1.1). Kept so the test can
     * address the server by one of them: an id that does not route is
     * indistinguishable from one that was never issued, and only using it
     * tells the two apart. */
    struct {
        uint64_t  seq;
        quiccid_t cid;
        uint8_t   token[16];
    } server_cids[8];
    size_t server_cid_count;

    uint64_t retire_seq;
    int      retire_queued;

    /* The server sent CONNECTION_CLOSE. A test that provokes a protocol error
     * on purpose needs to tell "it closed" from "it stopped answering", and
     * those look identical without this. */
    int      close_received;
    uint64_t close_error;

    /* A stateless reset arrived (RFC 9000 §10.3): the server has no state for
     * this connection any more. Recognised by the 16-byte token at the end,
     * matched against the ones it handed out in NEW_CONNECTION_ID -- the packet
     * itself is indistinguishable from a 1-RTT packet with a short id, which is
     * the entire design.
     *
     * Worth having in a test client for two reasons: without it a reset reads
     * as "decryption failed" and sends the reader hunting for a crypto bug, and
     * nothing else in this project ever checked that the tokens we advertise
     * are the ones we later send. */
    int      reset_received;

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

    /* And the other direction: the server challenges us after a rebinding, and
     * the migration only completes if we answer. */
    uint8_t path_challenge_in[8];
    int     path_challenge_received;
    int     path_response_queued;

    int      ping_queued;
    uint64_t datagrams_received;

    /* ---- The one piece of loss recovery a client cannot do without ---- *
     *
     * RFC 9002 §6.2.2.1: "it is the client's responsibility to send packets to
     * unblock the server until it is certain that the server has finished its
     * address validation". The server genuinely cannot always help itself
     * during a handshake -- with half a ClientHello it has nothing to say, so
     * it has nothing ack-eliciting in flight, so it arms no probe timer of its
     * own and waits. If the client waits too, both wait out the idle timeout.
     *
     * Deliberately not RFC loss recovery: there is no sent-packet list here and
     * incoming ACKs are not matched against one (that is quicloss, and the
     * client is minimal by design). It is the cruder rule that a probe exists
     * for -- the peer has gone quiet, poke it -- with the flight resent rather
     * than a bare PING, per §6.2.4.
     *
     * Bounded twice over, so it cannot become a machine that holds connections
     * open: it is armed only until HANDSHAKE_DONE arrives, and it gives up
     * after CLIENT_MAX_PROBES. */
    uint64_t pto_deadline_us;        /* 0 = disarmed */
    unsigned pto_count;              /* consecutive probes, for the backoff */
    uint64_t pto_fired;              /* total, for tests to assert on */

    /* Retry (RFC 9000 §8.1.2). The token from a Retry packet, echoed in every
     * Initial afterwards, and the state needed to start the handshake over --
     * a Retry throws away everything derived from the first Destination
     * Connection ID, including the TLS session. */
    const char* server_name;
    uint8_t  retry_token[256];
    size_t   retry_token_len;
    int      retry_seen;
    int      new_token_received;     /* the server handed us one for next time */
    uint8_t  new_token[256];
    size_t   new_token_len;
    quiccid_t retry_scid;            /* what the server chose in the Retry */
    int      retry_scid_confirmed;   /* it matched retry_source_connection_id */

    /* ---- Network impairment (docs/http3/08-testing.md §2) ---- *
     *
     * Loss recovery is defined entirely in elapsed time and packet ordering, so
     * the interesting cases only happen on a path that loses and reorders.
     * Nothing on a loopback ever does, which means every recovery path in the
     * server has so far been exercised only by argument.
     *
     * Seeded on purpose: a failure that cannot be repeated is a failure that
     * cannot be debugged, and "it passed last time" is the characteristic
     * property of a randomised protocol test that is quietly broken. */
    /* Split by direction, because the two test different things and only one of
     * them tests the server.
     *
     * **Inbound** loss makes the *server* recover: it must notice, retransmit
     * and keep the exchange going. That is the interesting direction.
     *
     * **Outbound** loss makes the *client* recover -- and this client has no
     * loss recovery at all (no quicloss, by design: see the header comment).
     * Anything it loses is gone for good, so outbound loss is a way to test
     * that the server survives a peer that goes quiet, not a way to test
     * recovery. Worth having, worth not confusing with the other. */
    unsigned net_loss_in_pct;
    unsigned net_loss_pct;
    unsigned net_dup_pct;
    unsigned net_reorder_pct;
    uint64_t net_rng;

    /* One datagram held back to be sent after the next one. */
    uint8_t  net_held[2048];
    size_t   net_held_len;

    uint64_t net_dropped_out;
    uint64_t net_dropped_in;
    uint64_t net_reordered;
    uint64_t net_duplicated;

    /* ---- In-process transport (docs/http3/08-testing.md §2) ---- *
     *
     * Set instead of `fd`: every datagram goes to this callback and every one
     * that arrives comes in through quicclient_deliver, so the whole exchange
     * is a sequence of calls the test makes in an order it chooses. That is
     * what buys the two things a socket cannot give -- a clock the test winds
     * forward (quic_time_set_source) and a path that loses, reorders and
     * delays by a rule rather than by luck.
     *
     * The impairment fields above still work in this mode, but the stand does
     * not use them: an emulator that sees both directions can delay, and delay
     * is what turns "eventually" into a number. */
    void (*out)(void* arg, const uint8_t* data, size_t len);
    void*  out_arg;

    int verbose;
} quicclient_t;

/* Impair the path in both directions. Percentages are per datagram; `seed` of 0
 * picks a fixed default, never a time-based one. Call before connecting. */
void quicclient_impair(quicclient_t* client, unsigned loss_out_pct, unsigned loss_in_pct,
                       unsigned reorder_pct, unsigned dup_pct, uint64_t seed);

/* Queue a PING: the smallest non-probing frame there is, which is what §9.3
 * requires before a server will treat a new address as the peer's. */
int quicclient_ping(quicclient_t* client);

/* ---- Probe timer ---- *
 *
 * Driven for you by quicclient_run and quicclient_pump. The in-process stand
 * calls these directly, because there the caller owns the clock and there is no
 * loop to hide them in. */

/* When the probe timer next fires, or 0 if it is disarmed. */
uint64_t quicclient_next_timeout(const quicclient_t* client);

/* Fire it if it is due: resend the handshake flight and back the timer off.
 * Returns 0 if the connection failed. Harmless at any other moment. */
int quicclient_tick(quicclient_t* client);

/* Move to a new source port, as a NAT rebinding would (RFC 9000 §9). The old
 * socket is closed and a fresh one bound, so the server sees the connection
 * arriving from an address it has never validated. Returns 0 on failure. */
int quicclient_rebind(quicclient_t* client);

/* Address the server by one of the ids it issued, instead of the one from the
 * handshake. Returns 0 if there is no such id. */
int quicclient_use_cid(quicclient_t* client, size_t index);

/* Queue a RETIRE_CONNECTION_ID for `seq`. */
int quicclient_retire_cid(quicclient_t* client, uint64_t seq);

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

/* The same, with the path impaired from the very first Initial: impairment set
 * after connecting would leave the handshake -- where recovery is least
 * forgiving, since there is no data to carry retransmissions -- untouched. */
int quicclient_connect_impaired(quicclient_t* client, const char* host, uint16_t port,
                                const char* server_name, int verbose,
                                unsigned loss_out_pct, unsigned loss_in_pct,
                                unsigned reorder_pct, unsigned dup_pct, uint64_t seed);

/* The same, presenting an address validation token the server handed out on an
 * earlier connection (a NEW_TOKEN). What it buys is visible only against a
 * server that would otherwise send a Retry: with the token the round trip is
 * skipped, without it there is one. */
int quicclient_connect_token(quicclient_t* client, const char* host, uint16_t port,
                             const char* server_name, int verbose,
                             const uint8_t* token, size_t token_len);

/* The NEW_TOKEN the server issued on this connection, or 0 if it issued none. */
size_t quicclient_take_token(const quicclient_t* client, uint8_t* out, size_t cap);

/* Drive the exchange until the handshake completes or `timeout_ms` elapses.
 * Returns 1 if it completed. */
int quicclient_run(quicclient_t* client, int timeout_ms);

/* ---- In-process transport ---- *
 *
 * The same client with no socket under it, for the deterministic stand of
 * docs/http3/08-testing.md §2. There is no loop here at all: the caller owns
 * the clock and the order of events, and these three calls are the only way
 * bytes move. */

/* Start the handshake against a peer that is not on the network: the first
 * Initial is handed to `out` instead of being sent. Returns 0 on failure. */
int quicclient_connect_inproc(quicclient_t* client, const char* server_name, int verbose,
                              void (*out)(void* arg, const uint8_t* data, size_t len),
                              void* out_arg);

/* One datagram from the peer. Returns 0 if the connection failed -- which
 * includes a stateless reset, exactly as the socket path reports it. */
int quicclient_deliver(quicclient_t* client, const uint8_t* data, size_t len);

/* Put whatever is queued -- acknowledgements, CRYPTO, stream data, a PING --
 * into a datagram and hand it to `out`. Returns 0 on failure.
 *
 * Separate from quicclient_deliver because the two are separate decisions for
 * the caller: a stand that answers every datagram immediately is a stand where
 * delayed acknowledgements never happen. */
int quicclient_flush(quicclient_t* client);

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

/* Did the server abandon its half instead (§19.4)? `out_error` and
 * `out_final_size` are filled when it did and may be NULL. */
int quicclient_stream_reset(const quicclient_t* client, uint64_t id,
                            uint64_t* out_error, uint64_t* out_final_size);

/* Tell the server to stop sending on this stream (§19.5). It goes out with the
 * next flush; §3.5 obliges the peer to answer with RESET_STREAM. */
int quicclient_stop_sending(quicclient_t* client, uint64_t id, uint64_t error);

/* Done with this stream: free its buffers and the slot.
 *
 * The peer's stream credit is renewed per stream, not per byte, so a scenario
 * that opens more streams than the initial allowance has to let go of the ones
 * it has finished with -- otherwise it runs out of slots here long before the
 * server runs out of credit, and the test would be measuring the harness. */
void quicclient_stream_release(quicclient_t* client, uint64_t id);

/* One turn of the loop: send what is queued, then receive for up to
 * `timeout_ms`. Unlike quicclient_run it has no completion condition of its
 * own -- the caller decides when it has what it wanted. Returns 0 if the
 * connection failed. */
int quicclient_pump(quicclient_t* client, int timeout_ms);

void quicclient_free(quicclient_t* client);

#endif
