#ifndef __H2FRAME__
#define __H2FRAME__

#include <stddef.h>
#include <stdint.h>

/* HTTP/2 frame layer (RFC 9113 §4, §6).
 *
 * Pure parsing/encoding with no connection state. The resumable parser is
 * modeled on protocols/websocket/.../websocketsparser: it keeps per-frame
 * state across feed() calls so a frame split across two recv() wakeups is
 * assembled correctly. The HTTP/2 connection layer (Phase 3+) drives this.
 *
 * Frame layout (9-byte header + payload):
 *   +------------------+--------+--------+----------------------+
 *   | Length (24)      | Type 8 | Flags8 |R| Stream ID (31)     |
 *   +------------------+--------+--------+----------------------+
 * Length covers only the payload (incl. pad length byte + padding, per spec). */

#define H2_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_CONNECTION_PREFACE_LEN 24
#define H2_FRAME_HEADER_LEN 9
#define H2_MAX_FRAME_SIZE_DEFAULT 16384u
#define H2_MAX_FRAME_SIZE_LIMIT   16777215u /* RFC §4.2 absolute max */

typedef enum {
    H2_FRAME_DATA          = 0,
    H2_FRAME_HEADERS       = 1,
    H2_FRAME_PRIORITY      = 2,
    H2_FRAME_RST_STREAM    = 3,
    H2_FRAME_SETTINGS      = 4,
    H2_FRAME_PUSH_PROMISE  = 5,
    H2_FRAME_PING          = 6,
    H2_FRAME_GOAWAY        = 7,
    H2_FRAME_WINDOW_UPDATE = 8,
    H2_FRAME_CONTINUATION  = 9,
} h2_frame_type_e;

#define H2_FLAG_END_STREAM  0x01
#define H2_FLAG_ACK         0x01 /* SETTINGS / PING */
#define H2_FLAG_END_HEADERS 0x04
#define H2_FLAG_PADDED      0x08
#define H2_FLAG_PRIORITY    0x20

/* A fully-assembled frame. `payload` is borrowed from the parser and remains
 * valid only until the parser is fed again or freed. */
typedef struct {
    uint32_t length;
    uint8_t  type;
    uint8_t  flags;
    uint32_t stream_id;
    const uint8_t* payload;
    size_t   payload_len;
} h2_frame_t;

typedef enum {
    H2PARSE_CONTINUE,    /* all bytes consumed; need more */
    H2PARSE_FRAME_READY, /* one complete frame assembled — read with h2frame_parser_get */
    H2PARSE_BAD_FRAME,   /* reserved bit set / oversize / bad stream-id+type / bad type size */
    H2PARSE_PREFACE_BAD, /* connection preface magic mismatch */
    H2PARSE_OOM,
} h2parse_status_e;

typedef enum {
    H2FRAME_STAGE_PREFACE,
    H2FRAME_STAGE_HEADER,
    H2FRAME_STAGE_PAYLOAD,
} h2frame_stage_e;

typedef struct {
    h2frame_stage_e stage;
    int preface_required;  /* consume the 24-byte client preface before any frame */
    size_t preface_pos;

    uint8_t header[H2_FRAME_HEADER_LEN];
    size_t header_pos;

    uint32_t length;
    uint8_t  type;
    uint8_t  flags;
    uint32_t stream_id;

    uint8_t* payload;
    size_t   payload_pos;
    size_t   payload_cap;

    uint32_t max_frame_size;
    int oom;
} h2frame_parser_t;

/* Lifecycle. preface_required: set for a server reading a client connection
 * (consume the 24-byte preface first). max_frame_size: advertised peer limit. */
void h2frame_parser_init(h2frame_parser_t* p, int preface_required, uint32_t max_frame_size);
void h2frame_parser_free(h2frame_parser_t* p);

/* Feed bytes; *pp advances by the number consumed. Returns:
 *  - CONTINUE: bytes consumed, need more (*pp == end)
 *  - FRAME_READY: one frame assembled; *pp points just past it; the parser is
 *    already positioned for the next frame — feed again to continue
 *  - BAD_FRAME / PREFACE_BAD / OOM: terminal; *pp left at the point of failure */
h2parse_status_e h2frame_parser_feed(h2frame_parser_t* p, const uint8_t** pp, const uint8_t* end);

/* Copy the last assembled frame's view into `out` (valid after FRAME_READY). */
void h2frame_parser_get(const h2frame_parser_t* p, h2_frame_t* out);

/* ---- Encoder ----
 * Write a frame (header + payload) into dst. Returns total bytes written
 * (H2_FRAME_HEADER_LEN + payload_len), or 0 if cap is too small or payload
 * exceeds the absolute frame-size limit. */
size_t h2frame_encode(uint8_t* dst, size_t cap, uint8_t type, uint8_t flags,
                      uint32_t stream_id, const uint8_t* payload, size_t payload_len);

#endif
