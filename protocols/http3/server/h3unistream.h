#ifndef __H3UNISTREAM__
#define __H3UNISTREAM__

#include <stddef.h>
#include <stdint.h>

#include "h3error.h"

/* Unidirectional stream types (RFC 9114 §6.2, RFC 9204 §4.2).
 *
 * A QUIC unidirectional stream starts with a varint that says what the rest of
 * the stream carries. Four values are defined for HTTP/3:
 *
 *   0x00  control stream        -- SETTINGS, GOAWAY, MAX_PUSH_ID, ...
 *   0x01  push stream           -- server -> client only (RFC 9114 §6.2.2)
 *   0x02  QPACK encoder stream  -- the peer's insertions into our decoder
 *   0x03  QPACK decoder stream  -- the peer's acks for our encoder
 *
 * Two rules differ from every reflex HTTP/2 built, and each is enforced here so
 * the session layer above cannot get them wrong:
 *
 *  - **An unknown type is not fatal.** RFC 9114 §6.2.3 lets a recipient either
 *    ignore it or send STOP_SENDING(H3_STREAM_CREATION_ERROR) and discard. This
 *    server chooses the latter, so a future stream type does not stall a stream
 *    we then have to forget to drain. Compare with QUIC transport frame types,
 *    where unknown IS fatal -- the two layers look alike and behave oppositely.
 *
 *  - **The three service streams are critical and unique.** Control and both
 *    QPACK streams: one of each per peer, and closing any (FIN or RESET_STREAM)
 *    is a connection error of type H3_CLOSED_CRITICAL_STREAM (§6.2.6). A second
 *    of any is H3_STREAM_CREATION_ERROR. Push streams are neither unique nor
 *    critical -- a server may open many -- and from a client they are simply
 *    illegal (only a server pushes), so this server treats a client-sent push
 *    stream as H3_STREAM_CREATION_ERROR on first sight.
 *
 * The parser is resumable across feeds for the same reason h3frame is: a QUIC
 * stream hands over bytes in whatever sizes the network produced, and the
 * stream-type varint can straddle two of them. Once the type is known the parser
 * is done -- the rest of the stream is type-specific content, decoded elsewhere. */

#define H3_UNI_STREAM_CONTROL        0x00u
#define H3_UNI_STREAM_PUSH           0x01u
#define H3_UNI_STREAM_QPACK_ENCODER  0x02u
#define H3_UNI_STREAM_QPACK_DECODER  0x03u

/* Grease stream types: 0x1f * N + 0x21 (RFC 9287). They exist to be ignored, and
 * this server sends one so a peer's handling of them is exercised in the wild. */
static inline int h3uni_type_is_grease(uint64_t type) {
    return type >= 0x21 && (type - 0x21) % 0x1f == 0;
}

/* One of the four HTTP/3 stream types above. */
int h3uni_type_is_known(uint64_t type);

/* The control stream and both QPACK streams: closing one is fatal to the
 * connection. Push streams are not critical -- a closed push stops one push. */
int h3uni_type_is_critical(uint64_t type);

/* ---- Parsing the type prefix ---- */

typedef enum {
    H3UNI_CONTINUE = 0,   /* need more bytes; the varint is incomplete */
    H3UNI_READY,          /* the type is in parser->type; classify and act */
    H3UNI_ERR_ENCODING    /* malformed input (NULL/empty); a real varint never
                           * errors -- any value is a legal stream type */
} h3uni_status_e;

typedef struct h3uni_parser {
    /* The type prefix is a single varint that may straddle a feed. */
    uint8_t  varint_buf[8];
    size_t   varint_len;
    size_t   varint_need;

    int      done;        /* the prefix has been read; further feeds are no-ops */

    uint64_t type;        /* valid once H3UNI_READY has been reported */
} h3uni_parser_t;

void h3uni_parser_init(h3uni_parser_t* p);

/* Feed bytes, advancing *pp. Reports READY once (the prefix is one varint) and
 * is then done; the caller stops feeding and switches to type-specific parsing. */
h3uni_status_e h3uni_parser_feed(h3uni_parser_t* p, const uint8_t** pp,
                                 const uint8_t* end);

/* ---- Per-direction duplicate tracking ---- *
 *
 * Of the four stream types only three are unique per peer: control and the two
 * QPACK streams. Push streams are many-per-server, and from a client illegal, so
 * they are classified directly and never tracked. The tracker below records the
 * three unique types for one direction; an h3 session keeps two, one for the
 * peer's streams and one for its own. */

typedef struct h3uni_seen {
    uint8_t bits;   /* bitmask over {control, qpack_encoder, qpack_decoder} */
} h3uni_seen_t;

static inline void h3uni_seen_init(h3uni_seen_t* seen) {
    if (seen != NULL) seen->bits = 0;
}

/* Record that a unique type arrived from this direction. Returns 1 on the first
 * sighting (accepted) and 0 on a duplicate (the caller raises
 * H3_STREAM_CREATION_ERROR). Non-unique and unknown types are not tracked, and
 * return 1 unchanged so the caller can call this unconditionally. */
int h3uni_seen_mark(h3uni_seen_t* seen, uint64_t type);

/* ---- Policy: what to do with a freshly-read type prefix ---- *
 *
 * The server's verdict on a stream-type the client opened. Combines the rules
 * above so the session code is a switch, not a tangle of predicates. Updates
 * `seen` for the unique types. */

typedef enum {
    /* A known service stream the session must now own (control or a QPACK
     * stream). verdict.type says which. */
    H3UNI_ROUTE = 0,
    /* A grease stream: read and discard the rest; never route. */
    H3UNI_IGNORE,
    /* An unknown type: send STOP_SENDING(verdict.error) on the stream and
     * discard the stream -- not fatal to the connection. */
    H3UNI_STOP_DROP,
    /* A duplicate of a unique type, or a push stream from a client: fatal to the
     * connection. Raise CONNECTION_CLOSE(verdict.error). */
    H3UNI_CONN_ERROR
} h3uni_action_e;

typedef struct {
    h3uni_action_e action;
    uint64_t type;    /* H3UNI_ROUTE: the stream type to route on */
    uint64_t error;   /* H3UNI_STOP_DROP / H3UNI_CONN_ERROR: the h3 app code */
} h3uni_verdict_t;

/* `seen` tracks the peer's unique streams and is updated for ROUTE. Returns a
 * verdict the session acts on verbatim. */
h3uni_verdict_t h3uni_server_classify(h3uni_seen_t* seen, uint64_t type);

/* ---- Writing the type prefix (the server's outbound uni-streams) ---- */

/* Write a stream-type varint. Returns bytes written, or 0 if it does not fit. */
size_t h3uni_write_type(uint8_t* dst, size_t cap, uint64_t type);

#endif
