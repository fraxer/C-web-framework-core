#ifndef __H3FRAME__
#define __H3FRAME__

#include <stddef.h>
#include <stdint.h>

/* HTTP/3 framing (RFC 9114 §7).
 *
 * A frame is `Type (varint) | Length (varint) | Payload`, and that is the whole
 * of it -- there are no flags, no stream ids and no windows, because QUIC took
 * all three. What is left is a great deal simpler than HTTP/2's frame layer,
 * with three differences that are easy to get wrong precisely because HTTP/2
 * conditioned the opposite reflex:
 *
 *  - **An unknown frame type is ignored**, not an error. The length is there so
 *    it can be skipped. In QUIC an unknown *transport* frame ends the
 *    connection, because there is no length to skip past; writing both layers
 *    the same way breaks one of them.
 *
 *  - **The HTTP/2 codepoints are reserved and must be rejected.** 0x02, 0x06,
 *    0x08 and 0x09 were PRIORITY, PING, WINDOW_UPDATE and CONTINUATION.
 *    §11.2.1 requires H3_FRAME_UNEXPECTED for them, specifically so that a
 *    proxy translating between the versions cannot pass one through unnoticed.
 *
 *  - **DATA has no size limit.** A response body is one frame, however large,
 *    so the payload cannot be buffered before it is handed on. The parser
 *    reports the header and then streams the payload.
 *
 * Resumable across feeds, like h2frame: a QUIC stream delivers bytes in
 * whatever sizes the network produced, and a frame header can straddle two
 * of them. */

typedef enum {
    H3_FRAME_DATA          = 0x00,
    H3_FRAME_HEADERS       = 0x01,
    H3_FRAME_CANCEL_PUSH   = 0x03,
    H3_FRAME_SETTINGS      = 0x04,
    H3_FRAME_PUSH_PROMISE  = 0x05,
    H3_FRAME_GOAWAY        = 0x07,
    H3_FRAME_MAX_PUSH_ID   = 0x0d,
    H3_FRAME_PRIORITY_UPDATE_REQUEST = 0xf0700,
    H3_FRAME_PRIORITY_UPDATE_PUSH    = 0xf0701
} h3_frame_type_e;

/* Reserved in HTTP/3 because HTTP/2 used them (§11.2.1). */
static inline int h3_frame_type_is_reserved_h2(uint64_t type) {
    return type == 0x02 || type == 0x06 || type == 0x08 || type == 0x09;
}

/* Types of the form 0x1f * N + 0x21 exist to be ignored (§7.2.8), and this
 * server sends one so that a peer's handling of them is exercised in the wild
 * rather than only in its own tests. */
static inline int h3_frame_type_is_grease(uint64_t type) {
    return type >= 0x21 && (type - 0x21) % 0x1f == 0;
}

typedef enum {
    /* Need more bytes. */
    H3FRAME_CONTINUE = 0,
    /* Type and length are known; the payload follows. For frames the parser
     * accumulates (everything but DATA) this is not reported -- READY is. */
    H3FRAME_HEAD,
    /* A complete small frame: `payload` is valid until the next feed. */
    H3FRAME_READY,
    /* DATA: `payload` holds however much of the body arrived in this feed, and
     * `remaining` says how much of the frame is still to come. Reported
     * repeatedly until the frame is done. */
    H3FRAME_DATA_CHUNK,
    /* A frame type this server ignores; already skipped. */
    H3FRAME_SKIPPED,
    H3FRAME_ERR_ENCODING,   /* -> H3_FRAME_ERROR */
    H3FRAME_ERR_RESERVED,   /* an HTTP/2 codepoint -> H3_FRAME_UNEXPECTED */
    H3FRAME_ERR_TOO_LARGE,  /* over the accumulation limit -> H3_EXCESSIVE_LOAD */
    H3FRAME_ERR_OOM
} h3frame_status_e;

/* Largest frame the parser will accumulate whole. DATA is exempt -- it is
 * streamed -- so this bounds only the control frames, where a peer announcing
 * a gigabyte of SETTINGS is an attack rather than a use case. */
#define H3FRAME_MAX_ACCUMULATED (1024 * 1024)

typedef enum {
    H3FRAME_STAGE_TYPE = 0,
    H3FRAME_STAGE_LENGTH,
    H3FRAME_STAGE_PAYLOAD,
    H3FRAME_STAGE_SKIP
} h3frame_stage_e;

typedef struct h3frame_parser {
    h3frame_stage_e stage;

    /* A varint may straddle a feed, so its bytes accumulate here until the
     * length the first byte announced has arrived. */
    uint8_t  varint_buf[8];
    size_t   varint_len;
    size_t   varint_need;

    uint64_t type;
    uint64_t length;
    uint64_t remaining;    /* of the current payload */

    uint8_t* accum;        /* accumulated payload, for everything but DATA */
    size_t   accum_len;
    size_t   accum_cap;

    /* What the last feed produced, valid while the status says so. */
    const uint8_t* payload;
    size_t   payload_len;
} h3frame_parser_t;

void h3frame_parser_init(h3frame_parser_t* p);
void h3frame_parser_free(h3frame_parser_t* p);

/* Feed bytes, advancing `*pp`. Call repeatedly while the status is a result
 * rather than H3FRAME_CONTINUE: one feed can produce several frames. An empty
 * feed (`*pp == end`, NULL/NULL included) is legal and reports CONTINUE -- a
 * QUIC STREAM frame carrying only FIN has no bytes. */
h3frame_status_e h3frame_parser_feed(h3frame_parser_t* p,
                                     const uint8_t** pp, const uint8_t* end);

/* Is the parser between frames -- nothing half-read? RFC 9114 §7.1: a stream
 * that ends cleanly in the middle of a frame is a connection error of type
 * H3_FRAME_ERROR, and this is how a caller detects that on FIN. Both the
 * stage and a half-assembled varint count: the type/length varint of the next
 * frame may itself have been cut in half. */
static inline int h3frame_parser_at_boundary(const h3frame_parser_t* p) {
    return p != NULL && p->stage == H3FRAME_STAGE_TYPE && p->varint_len == 0;
}

/* ---- Writing ---- */

/* Write a frame header. Returns bytes written, or 0 if it does not fit. */
size_t h3frame_write_header(uint8_t* dst, size_t cap, uint64_t type, uint64_t length);

/* Write a complete frame. */
size_t h3frame_write(uint8_t* dst, size_t cap, uint64_t type,
                     const uint8_t* payload, size_t len);

/* ---- SETTINGS (§7.2.4) ---- */

#define H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY 0x01
#define H3_SETTINGS_MAX_FIELD_SECTION_SIZE   0x06
#define H3_SETTINGS_QPACK_BLOCKED_STREAMS    0x07
#define H3_SETTINGS_ENABLE_CONNECT_PROTOCOL  0x08

typedef struct h3settings {
    uint64_t qpack_max_table_capacity;
    uint64_t max_field_section_size;
    uint64_t qpack_blocked_streams;
    int      enable_connect_protocol;
} h3settings_t;

void h3settings_defaults(h3settings_t* settings);

typedef enum {
    H3SETTINGS_OK = 0,
    H3SETTINGS_ERR_ENCODING,    /* -> H3_FRAME_ERROR */
    /* A duplicate identifier, or one of the HTTP/2 codepoints §7.2.4.1
     * reserves -- both are H3_SETTINGS_ERROR. */
    H3SETTINGS_ERR_SETTINGS
} h3settings_status_e;

h3settings_status_e h3settings_decode(const uint8_t* payload, size_t len,
                                      h3settings_t* out);

/* Encode our own settings, plus one reserved identifier. */
size_t h3settings_encode(uint8_t* dst, size_t cap, const h3settings_t* settings);

#endif
