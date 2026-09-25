/* Fuzz targets for everything that parses the network before authentication
 * (docs/http3/08-testing.md §5).
 *
 * Every function reached from here is fed by a peer that has proved nothing: a
 * QUIC packet header is read before decryption, transport parameters arrive
 * inside a handshake that has not finished, and an HTTP/3 frame or QPACK block
 * comes from a stream anyone may open. A crash in any of them is remotely
 * triggerable, which is why §5 calls this mandatory rather than desirable.
 *
 * One file, several entry points, chosen by FUZZ_TARGET at compile time: the
 * targets differ by three lines each, and a file apiece would multiply the
 * build wiring by seven for no gain in clarity.
 *
 * The signature is libFuzzer's on purpose. This machine has no clang, so the
 * driver next door (fuzz_main.c) runs them with gcc's coverage instrumentation
 * instead; when clang is installed, the same objects link against
 * -fsanitize=fuzzer with nothing changed here. */

#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include "appconfig.h"
#include "connection_s.h"
#include "cookieparser.h"
#include "cqueue.h"
#include "domain.h"
#include "h2frame.h"
#include "h2session.h"
#include "h2stream.h"
#include "multiplexing.h"
#include "hpack.h"
#include "httpcommon.h"
#include "json.h"
#include "websocketsparser.h"
#include "websocketsprotocoldefault.h"
#include "ws_deflate.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "httprequestparser.h"
#include "huffman.h"
#include "multipartparser.h"
#include "urlencodedparser.h"

/* The QUIC and HTTP/3 headers only for the targets that use them. Everything
 * else here -- the HTTP/1.1 parsers, HPACK, Huffman -- is built whether the
 * HTTP/3 stack is in the build or not, and a build without it must not fail on
 * an include for a library it never links. That is also what lets these targets
 * build on a stock OSS-Fuzz base image, where OpenSSL is older than the 3.5
 * that INCLUDE_HTTP3 needs. */
#if FUZZ_TARGET == FUZZ_QUIC_PACKET || FUZZ_TARGET == FUZZ_QUIC_FRAME || \
    FUZZ_TARGET == FUZZ_QUIC_TP     || FUZZ_TARGET == FUZZ_H3_FRAME   || \
    FUZZ_TARGET == FUZZ_QPACK_DECODE || FUZZ_TARGET == FUZZ_QPACK_STREAMS || \
    FUZZ_TARGET == FUZZ_H3_PRIORITY || FUZZ_TARGET == FUZZ_QPACK_DYNAMIC || \
    FUZZ_TARGET == FUZZ_QPACK_SESSION || FUZZ_TARGET == FUZZ_QUIC_STREAM || \
    FUZZ_TARGET == FUZZ_H3_REQUEST
#include "h3frame.h"
#include "h3priority.h"
#include "qpack.h"
#include "qpack_statictable.h"
#include "quicframe.h"
#include "quicpacket.h"
#include "quictp.h"
#include "varint.h"
#endif

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#if FUZZ_TARGET == FUZZ_REQUEST || FUZZ_TARGET == FUZZ_REQUEST_SEQUENCE || \
    FUZZ_TARGET == FUZZ_WEBSOCKET || FUZZ_TARGET == FUZZ_WEBSOCKET_SEQUENCE || \
    FUZZ_TARGET == FUZZ_H2_SESSION || FUZZ_TARGET == FUZZ_H2_CONNECTION || \
    FUZZ_TARGET == FUZZ_H3_REQUEST || FUZZ_TARGET == FUZZ_HTTP_RESPONSE || \
    FUZZ_TARGET == FUZZ_SMTP_RESPONSE || FUZZ_TARGET == FUZZ_H1_CONNECTION || \
    FUZZ_TARGET == FUZZ_MAIL_MESSAGE

/* The parser asks the running configuration what the largest acceptable body
 * is, and there is no configuration here. Overridden the way
 * tests/unit/test_httprequestparser.c overrides it -- a weak definition in the
 * executable, which the framework's own call resolves to.
 *
 * Without it the target reports a crash on its very first well-formed
 * Content-Length, in env() rather than in anything the parser does, and the
 * first thing this target found was exactly that: its own missing setup. A
 * fuzz target that crashes on valid input tests nothing beyond the fixture. */
static appconfig_t* __fuzz_appconfig = NULL;

static void __fuzz_appconfig_init(void) {
    if (__fuzz_appconfig != NULL) return;

    __fuzz_appconfig = calloc(1, sizeof *__fuzz_appconfig);
    if (__fuzz_appconfig == NULL) return;

    __fuzz_appconfig->env.main.client_max_body_size = 10485760;
    __fuzz_appconfig->env.main.tmp = "/tmp";
    __fuzz_appconfig->env.main.log.enabled = false;
    __fuzz_appconfig->env.main.workers = 1;
    __fuzz_appconfig->env.main.threads = 1;
}

__attribute__((weak)) appconfig_t* appconfig(void) {
    __fuzz_appconfig_init();
    return __fuzz_appconfig;
}

__attribute__((weak)) env_t* env(void) {
    __fuzz_appconfig_init();
    return __fuzz_appconfig != NULL ? &__fuzz_appconfig->env : NULL;
}

__attribute__((weak)) void appconfig_set(appconfig_t* config) {
    (void)config;
}


static char __fuzz_domain_template[] = "localhost";

static domain_t __fuzz_domain = {
    .is_literal = 1,
    .template = __fuzz_domain_template,
    .ascii_template = __fuzz_domain_template,
    .ascii_length = sizeof __fuzz_domain_template - 1,
    .next = NULL
};

static server_t __fuzz_server = {
    .ip = { .family = AF_INET, .u = { .v4 = { .s_addr = 0x0100007F } } },  /* 127.0.0.1 */
    .port = 8080,
    .domain = &__fuzz_domain,
    .next = NULL
};

static cqueue_item_t __fuzz_queue_item = { .data = &__fuzz_server, .next = NULL };

/* A multiplexing API that does nothing and says it worked.
 *
 * Needed because a request that finishes parsing does not stop there: the
 * session dispatches it, the dispatcher posts a response, and posting asks the
 * event loop to re-arm the socket. There is no event loop here and no socket
 * worth arming, and the alternative -- leaving the pointer NULL -- crashes in
 * connection_after_read() on the first complete request, which is the fixture
 * failing rather than anything under test.
 *
 * Returning success rather than failure on purpose: a failed re-arm is a path
 * the callers up the h2 stack turn into a connection error, and taking it on
 * every request would close the connection before the state this target exists
 * to reach has anywhere to accumulate. */
static int __fuzz_mpx_ok(connection_t* connection, int flags) {
    (void)connection; (void)flags;
    return 1;
}

static int __fuzz_mpx_del(connection_t* connection) {
    (void)connection;
    return 1;
}

static mpxapi_t __fuzz_mpxapi = {
    .control_add = __fuzz_mpx_ok,
    .control_mod = __fuzz_mpx_ok,
    .control_del = __fuzz_mpx_del,
};

static listener_t __fuzz_listener = {
    .servers = { .item = &__fuzz_queue_item, .last_item = &__fuzz_queue_item, .size = 1, .locked = 0 },
    .connection = NULL,
    .api = &__fuzz_mpxapi,
    .next = NULL
};

#endif

#if FUZZ_TARGET == FUZZ_H1_CONNECTION || FUZZ_TARGET == FUZZ_H2_CONNECTION

#include "connection_queue.h"

/* The worker threads' side of a connection target. Handlers -- a pipelined
 * HTTP/1.1 request, a WebSocket message on an RFC 8441 tunnel -- are run
 * through the connection queue: the connection is parked and queued, and a
 * worker picks it up. There are no threads here, so this is one iteration of
 * thread_handler's loop, run when the schedule says so. The pop is the
 * non-blocking one: connection_queue_guard_pop would sleep a second on an
 * empty queue. 1 when there was something to run. */
connection_t* __connection_queue_pop(void);

static int __fuzz_worker(void) {
    connection_t* connection = __connection_queue_pop();
    if (connection == NULL) return 0;

    connection_server_ctx_t* ctx = connection->ctx;
    cqueue_lock(ctx->queue);
    connection_queue_item_t* item = cqueue_pop(ctx->queue);
    cqueue_unlock(ctx->queue);
    if (item == NULL) {
        cqueue_lock(ctx->broadcast_queue);
        item = cqueue_pop(ctx->broadcast_queue);
        cqueue_unlock(ctx->broadcast_queue);
    }
    if (item != NULL) {
        item->run(item);
        item->free(item);
    }
    connection_s_dec(connection);
    return 1;
}

#endif

#if FUZZ_TARGET == FUZZ_URLENCODED || FUZZ_TARGET == FUZZ_MULTIPART

/* Both body parsers scan a buffer but read the field values back out of a file
 * descriptor with pread, so the target needs a real, seekable one. memfd is
 * what tests/unit/test_multipartparser.c uses for the same reason, and at
 * fuzzing rates it matters that nothing touches a filesystem. */
static int __fuzz_payload_fd(const uint8_t* data, size_t size) {
    const int fd = memfd_create("fuzz_payload", 0);
    if (fd < 0) return -1;

    if (size > 0 && write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return -1;
    }

    lseek(fd, 0, SEEK_SET);
    return fd;
}

#endif

#if FUZZ_TARGET == FUZZ_MULTIPART || FUZZ_TARGET == FUZZ_REQUEST_SEQUENCE || \
    FUZZ_TARGET == FUZZ_WEBSOCKET_SEQUENCE || FUZZ_TARGET == FUZZ_H3_REQUEST || \
    FUZZ_TARGET == FUZZ_HTTP_RESPONSE

/* FNV-1a over what a parse produced, so that deliveries of the same bytes in
 * different reads can be compared without keeping every result around. */
static uint64_t __fuzz_fnv(uint64_t h, const void* data, size_t len) {
    const unsigned char* p = data;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t __fuzz_fnv_headers(uint64_t h, const http_header_t* header) {
    for (; header != NULL; header = header->next) {
        h = __fuzz_fnv(h, header->key, header->key_length);
        h = __fuzz_fnv(h, "\0", 1);
        h = __fuzz_fnv(h, header->value, header->value_length);
        h = __fuzz_fnv(h, "\n", 1);
    }
    return h;
}

#endif

#if FUZZ_TARGET == FUZZ_QUIC_PACKET

/* A datagram as it arrives from the socket: coalesced packets, arbitrary
 * lengths, connection ids of any size the peer felt like. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    size_t off = 0;
    quicpkt_t pkt;
    quicpkt_status_e status = QUICPKT_OK;

    /* The local id length is ours, not the peer's, so it is a parameter rather
     * than input -- but a short-header packet is parsed against it, so both the
     * usual 8 and the degenerate 0 are worth walking. */
    const size_t cid_len = size > 0 && (data[0] & 1) ? 0 : 8;

    while (quicpkt_next(data, size, &off, cid_len, &pkt, &status) == 1) {
        if (status != QUICPKT_OK) break;
    }

    return 0;
}

#elif FUZZ_TARGET == FUZZ_QUIC_FRAME

/* A decrypted packet payload. Reached only after AEAD, but "authenticated" here
 * means the peer holds the keys -- it says nothing about the bytes being
 * well-formed, and a peer that has completed a handshake is still a peer.
 *
 * ACK gets more than the usual "did not crash" check.  Its ranges are
 * attacker-controlled relative arithmetic used by loss recovery; accepting an
 * overlapping, ascending or wrapped range could make the server discard data
 * that never reached the peer. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    size_t off = 0;
    quicframe_t frame;

    for (;;) {
        const quicframe_status_e st = quicframe_next(data, size, &off, &frame);
        if (st != QUICFRAME_OK) break;

        if (frame.type == QUIC_FRAME_ACK || frame.type == QUIC_FRAME_ACK_ECN) {
            quicack_iter_t it;
            quicack_block_t block;
            quicack_iter_init(&frame, &it);

            uint64_t previous_smallest = 0;
            uint64_t count = 0;
            int r;
            while ((r = quicack_iter_next(&it, &block)) == 1) {
                if (block.smallest > block.largest) __builtin_trap();
                if (count > 0 && (block.largest >= previous_smallest ||
                                  previous_smallest - block.largest < 2))
                    __builtin_trap();

                previous_smallest = block.smallest;
                count++;
            }

            /* quicframe_next promises that a successful ACK has already been
             * validated completely.  The iterator must therefore neither
             * fail nor expose fewer/more ranges than the peer declared. */
            if (r != 0 || count != frame.u.ack.range_count + 1)
                __builtin_trap();
        }
    }

    return 0;
}

#elif FUZZ_TARGET == FUZZ_QUIC_TP

/* Transport parameters, read out of the peer's TLS extension. Both directions
 * are decoded because the asymmetric parameters differ (§18.2), and the branch
 * that rejects a client-only parameter is exactly the kind that is written once
 * and never exercised. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    quictp_t tp;

    quictp_defaults(&tp);
    (void)quictp_decode(data, size, 1, &tp);

    quictp_defaults(&tp);
    (void)quictp_decode(data, size, 0, &tp);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_H3_FRAME

/* HTTP/3 frames as they arrive on a request stream. Fed in two pieces, split at
 * a byte the input itself chooses: the parser is resumable, and the states that
 * only exist across a split (a varint cut in half) are unreachable by feeding
 * the whole buffer at once. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;

    const size_t split = data[0] % (size > 1 ? size : 1);

    h3frame_parser_t p;
    h3frame_parser_init(&p);

    const uint8_t* pp = data;
    const uint8_t* mid = data + split;
    const uint8_t* end = data + size;

    /* Anything at or past the first error status ends the stream, exactly as
     * h3stream does; everything below it is a frame the parser produced. */
    while (pp < mid) {
        const h3frame_status_e st = h3frame_parser_feed(&p, &pp, mid);
        if (st == H3FRAME_CONTINUE || st >= H3FRAME_ERR_ENCODING) break;
    }

    while (pp < end) {
        const h3frame_status_e st = h3frame_parser_feed(&p, &pp, end);
        if (st == H3FRAME_CONTINUE || st >= H3FRAME_ERR_ENCODING) break;
    }

    (void)h3frame_parser_at_boundary(&p);

    h3frame_parser_free(&p);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_QPACK_DECODE

/* The most valuable target of the list (§5): a field section is attacker-shaped
 * data run through a Huffman decoder and a static-table lookup, and every
 * length in it is a varint the peer wrote. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    qpack_decoder_t* d = qpack_decoder_create(0, 0);
    if (d == NULL) return 0;

    qpack_header_t* headers = NULL;
    size_t count = 0;

    if (qpack_decode_block(d, data, size, 1048576, &headers, &count) == QPACK_OK)
        qpack_headers_free(headers, count);

    qpack_decoder_free(d);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_QPACK_DYNAMIC

/* Two coupled QPACK streams: an encoder instruction stream changes a real
 * dynamic table while a field section may be blocked on its insert count. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3) return 0;
    const size_t instruction_len = (size_t)data[0] % (size - 1);
    const size_t step = (size_t)data[1] + 1;
    const uint8_t* instructions = data + 2;
    const uint8_t* block = instructions + instruction_len;
    const size_t block_len = size - 2 - instruction_len;

    qpack_decoder_t* d = qpack_decoder_create(256, 8);
    if (d == NULL) return 0;

    qpack_header_t* fields = NULL;
    size_t count = 0;
    const qpack_status_e before = qpack_decode_block(
        d, block, block_len, 1048576, &fields, &count);
    if (before == QPACK_OK) qpack_headers_free(fields, count);

    size_t consumed_total = 0;
    size_t offered = 0;
    while (consumed_total < instruction_len) {
        const size_t remaining = instruction_len - offered;
        offered += remaining < step ? remaining : step;
        size_t consumed = 0;
        const qpack_status_e status = qpack_decoder_read_encoder(
            d, instructions + consumed_total, offered - consumed_total, &consumed);
        if (status != QPACK_OK) break;
        if (consumed > offered - consumed_total) __builtin_trap();
        consumed_total += consumed;
        if (offered == instruction_len && consumed == 0) break;
    }

    if (qpack_decoder_bytes(d) > qpack_decoder_capacity(d) ||
        qpack_decoder_capacity(d) > 256) __builtin_trap();

    fields = NULL;
    count = 0;
    const qpack_status_e after = qpack_decode_block(
        d, block, block_len, 1048576, &fields, &count);
    if (after == QPACK_OK) qpack_headers_free(fields, count);
    if (before == QPACK_OK && after == QPACK_BLOCKED) __builtin_trap();

    const uint8_t* pending = NULL;
    const size_t pending_len = qpack_decoder_pending(d, &pending);
    if (pending_len > 0) {
        qpack_decoder_consume(d, pending_len / 2);
        qpack_decoder_consume(d, qpack_decoder_pending(d, &pending));
    }
    qpack_decoder_free(d);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_QPACK_SESSION

/* Our QPACK encoder talking to our QPACK decoder, both service streams in
 * between, driven by a script the input writes. qpack_dynamic feeds the
 * decoder bytes a peer chose; this one asks whether the two halves agree when
 * everything on the wire is correct -- which is what a real connection needs,
 * and what a table that drifts apart on one side breaks without either parser
 * ever seeing a malformed byte.
 *
 * Each script byte is an operation, followed by its arguments:
 *
 *   0 capacity   Set Dynamic Table Capacity
 *   1-4 insert   literal name, static name, dynamic name, duplicate
 *   5 section    prepare + encode a field section on a stream, blocking or
 *                confirmed-only, and keep it for later decoding
 *   6 encoder    deliver some encoder-stream bytes to the decoder
 *   7 decode     try the oldest section of a stream: BLOCKED, or decode it,
 *                compare every field and acknowledge it if it used the table
 *   8 decoder    deliver some decoder-stream bytes to the encoder
 *   9 cancel     the decoder cancels a stream and forgets its sections
 *
 * An encoder call may refuse (a table pinned by outstanding sections, an
 * entry larger than the capacity); that is policy. What may not happen:
 * either stream reader rejecting what the other side wrote, a section that
 * decodes to other fields than it was encoded from, more streams able to
 * block than SETTINGS allowed, or -- once everything has been delivered,
 * decoded and acknowledged -- two tables that do not agree. */

#define QS_STREAMS 8
#define QS_SECTIONS 64
#define QS_FIELDS 4

typedef struct {
    int stream;
    uint8_t* block;
    size_t len;
    qpack_header_t fields[QS_FIELDS];
    size_t count;
    uint64_t ric;
} qs_section_t;

typedef struct {
    qpack_encoder_t* e;
    qpack_decoder_t* d;
    qs_section_t sections[QS_SECTIONS];   /* in encode order */
    size_t section_count;
    uint8_t enc_wire[65536];              /* delivered, not yet consumed */
    size_t enc_wire_len;
    uint8_t dec_wire[65536];
    size_t dec_wire_len;
    /* A cancelled stream is gone for good: its id is never used again, so a
     * slot moves on to a fresh id. Reusing one would let the cancellation,
     * still in flight, release a section encoded after it -- a case a real
     * connection cannot produce. */
    uint64_t generation[QS_STREAMS];
    const uint8_t* p;
    const uint8_t* end;
} qs_t;

static const char* const qs_names[] = {
    "x-a", "x-b", "content-type", "cookie", ":path", "user-agent", "accept"
};

static uint8_t qs_byte(qs_t* q) { return q->p < q->end ? *q->p++ : 0; }

static uint64_t qs_stream_id(const qs_t* q, int slot) {
    return ((uint64_t)slot + QS_STREAMS * q->generation[slot]) * 4;
}

/* A value of 0..15 bytes from the script. */
static size_t qs_value(qs_t* q, const char** out) {
    size_t n = qs_byte(q) % 16;
    if (n > (size_t)(q->end - q->p)) n = (size_t)(q->end - q->p);
    *out = (const char*)q->p;
    q->p += n;
    return n;
}

static void qs_section_free(qs_section_t* s) {
    free(s->block);
    for (size_t i = 0; i < s->count; i++) {
        free(s->fields[i].name);
        free(s->fields[i].value);
    }
    memset(s, 0, sizeof *s);
}

static void qs_section_drop(qs_t* q, size_t i) {
    qs_section_free(&q->sections[i]);
    memmove(q->sections + i, q->sections + i + 1,
            (q->section_count - i - 1) * sizeof *q->sections);
    q->section_count--;
    memset(&q->sections[q->section_count], 0, sizeof q->sections[0]);
}

static void qs_deliver_encoder(qs_t* q, size_t want) {
    const uint8_t* pending = NULL;
    size_t n = qpack_encoder_pending(q->e, &pending);
    if (n > want) n = want;
    if (n > sizeof q->enc_wire - q->enc_wire_len) n = sizeof q->enc_wire - q->enc_wire_len;
    if (n != 0) memcpy(q->enc_wire + q->enc_wire_len, pending, n);
    q->enc_wire_len += n;
    qpack_encoder_consume(q->e, n);

    size_t consumed = 0;
    if (qpack_decoder_read_encoder(q->d, q->enc_wire, q->enc_wire_len, &consumed) != QPACK_OK)
        __builtin_trap();                 /* our decoder refused our encoder */
    if (consumed > q->enc_wire_len) __builtin_trap();
    memmove(q->enc_wire, q->enc_wire + consumed, q->enc_wire_len - consumed);
    q->enc_wire_len -= consumed;
}

static void qs_deliver_decoder(qs_t* q, size_t want) {
    const uint8_t* pending = NULL;
    size_t n = qpack_decoder_pending(q->d, &pending);
    if (n > want) n = want;
    if (n > sizeof q->dec_wire - q->dec_wire_len) n = sizeof q->dec_wire - q->dec_wire_len;
    if (n != 0) memcpy(q->dec_wire + q->dec_wire_len, pending, n);
    q->dec_wire_len += n;
    qpack_decoder_consume(q->d, n);

    size_t consumed = 0;
    if (qpack_encoder_read_decoder_state(q->e, q->dec_wire, q->dec_wire_len, &consumed) != QPACK_OK)
        __builtin_trap();                 /* our encoder refused our decoder */
    if (consumed > q->dec_wire_len) __builtin_trap();
    memmove(q->dec_wire, q->dec_wire + consumed, q->dec_wire_len - consumed);
    q->dec_wire_len -= consumed;
    if (q->e->known_received_count > q->e->insert_count) __builtin_trap();
}

/* The oldest undecoded section of a stream: sections of one stream are
 * decoded in order, as a request's headers come before its trailers. */
static int qs_oldest(const qs_t* q, int stream) {
    for (size_t i = 0; i < q->section_count; i++)
        if (q->sections[i].stream == stream) return (int)i;
    return -1;
}

/* Returns 1 when the section was decoded, 0 when it is still blocked. */
static int qs_decode(qs_t* q, size_t i) {
    qs_section_t* s = &q->sections[i];
    qpack_header_t* out = NULL;
    size_t count = 0;
    const qpack_status_e st = qpack_decode_block(q->d, s->block, s->len, 1 << 20, &out, &count);
    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "decode stream %d ric %llu: status %d, count %zu/%zu, "
                "decoder inserts %llu bytes %zu cap %zu, encoder inserts %llu bytes %zu cap %zu\n",
                s->stream, (unsigned long long)s->ric, st, count, s->count,
                (unsigned long long)qpack_decoder_insert_count(q->d), qpack_decoder_bytes(q->d),
                qpack_decoder_capacity(q->d), (unsigned long long)q->e->insert_count,
                q->e->bytes, q->e->capacity);
    if (st == QPACK_BLOCKED) {
        if (s->ric <= qpack_decoder_insert_count(q->d)) __builtin_trap();
        return 0;
    }
    if (st != QPACK_OK || count != s->count) __builtin_trap();
    for (size_t k = 0; k < count; k++)
        if (out[k].name_len != s->fields[k].name_len ||
            out[k].value_len != s->fields[k].value_len ||
            memcmp(out[k].name, s->fields[k].name, out[k].name_len) != 0 ||
            memcmp(out[k].value, s->fields[k].value, out[k].value_len) != 0 ||
            out[k].never_indexed != s->fields[k].never_indexed)
            __builtin_trap();
    qpack_headers_free(out, count);

    /* §4.4.1: acknowledged only when the section referenced the table. */
    if (s->ric != 0 && qpack_decoder_ack_section(q->d, qs_stream_id(q, s->stream)) != QPACK_OK)
        __builtin_trap();
    qs_section_drop(q, i);
    return 1;
}

static void qs_encode(qs_t* q) {
    const uint8_t how = qs_byte(q);
    const int stream = how % QS_STREAMS;
    const int confirmed = (how & 0x80) != 0;
    if (q->section_count == QS_SECTIONS) return;

    qs_section_t* s = &q->sections[q->section_count];
    memset(s, 0, sizeof *s);
    s->count = (size_t)(how >> 3 & 3) + 1;
    for (size_t k = 0; k < s->count; k++) {
        const uint8_t pick = qs_byte(q);
        const char* name = qs_names[pick % (sizeof qs_names / sizeof qs_names[0])];
        const char* value;
        const size_t value_len = qs_value(q, &value);
        s->fields[k].name = strdup(name);
        s->fields[k].name_len = strlen(name);
        s->fields[k].value = malloc(value_len + 1);
        if (s->fields[k].name == NULL || s->fields[k].value == NULL) { qs_section_free(s); return; }
        memcpy(s->fields[k].value, value, value_len);
        s->fields[k].value[value_len] = '\0';
        s->fields[k].value_len = value_len;
        s->fields[k].never_indexed = (pick & 0x80) != 0;
    }

    if (qpack_encoder_prepare_fields(q->e, s->fields, s->count) == QPACK_ERR_MEMORY) {
        qs_section_free(s);
        return;
    }
    uint8_t block[4096];
    const size_t n = confirmed
        ? qpack_encode_block_for_stream_confirmed(q->e, qs_stream_id(q, stream), s->fields,
                                                  s->count, block, sizeof block)
        : qpack_encode_block_for_stream(q->e, qs_stream_id(q, stream), s->fields, s->count,
                                        block, sizeof block);
    if (n == 0) { qs_section_free(s); return; }
    s->block = malloc(n);
    if (s->block == NULL) { qs_section_free(s); return; }
    memcpy(s->block, block, n);
    s->len = n;
    s->stream = stream;
    const qpack_status_e ric_status = qpack_required_insert_count(q->d, block, n, &s->ric);
    if (ric_status != QPACK_OK && ric_status != QPACK_BLOCKED) __builtin_trap();
    if (s->ric > q->e->insert_count) __builtin_trap();
    if (confirmed && s->ric > q->e->known_received_count) __builtin_trap();
    q->section_count++;

    /* §2.1.2: no more streams able to block than SETTINGS allowed. */
    size_t blocking = 0;
    for (int st = 0; st < QS_STREAMS; st++)
        for (size_t i = 0; i < q->section_count; i++)
            if (q->sections[i].stream == st &&
                q->sections[i].ric > q->e->known_received_count) { blocking++; break; }
    if (blocking > q->e->max_blocked) __builtin_trap();
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    const size_t max_capacity = (size_t)data[0] * 16;       /* 0..4080 */
    const size_t max_blocked = data[1] % 5;

    qs_t* q = calloc(1, sizeof *q);
    if (q == NULL) return 0;
    q->e = qpack_encoder_create(max_capacity, max_blocked);
    q->d = qpack_decoder_create(max_capacity, max_blocked);
    q->p = data + 2;
    q->end = data + size;
    if (q->e == NULL || q->d == NULL) goto out;

    for (size_t steps = 0; q->p < q->end && steps < 4096; steps++) {
        const uint8_t op = qs_byte(q);
        const char* value;
        if (getenv("FUZZ_TRACE") != NULL)
            fprintf(stderr, "op %d: encoder inserts %llu bytes %zu cap %zu krc %llu sections %zu\n",
                    op % 10, (unsigned long long)q->e->insert_count, q->e->bytes, q->e->capacity,
                    (unsigned long long)q->e->known_received_count, q->e->section_count);
        switch (op % 10) {
        case 0:
            (void)qpack_encoder_set_capacity(q->e, (size_t)qs_byte(q) * 16);
            break;
        case 1: {
            const char* name = qs_names[qs_byte(q) % (sizeof qs_names / sizeof qs_names[0])];
            const size_t n = qs_value(q, &value);
            (void)qpack_encoder_insert_literal(q->e, name, strlen(name), value, n, NULL);
            break;
        }
        case 2: {
            const uint8_t idx = qs_byte(q);
            const size_t n = qs_value(q, &value);
            (void)qpack_encoder_insert_static_name(q->e, idx % QPACK_STATIC_TABLE_SIZE, value, n, NULL);
            break;
        }
        case 3: {
            const uint8_t rel = qs_byte(q);
            const size_t n = qs_value(q, &value);
            (void)qpack_encoder_insert_dynamic_name(q->e, rel % 8, value, n, NULL);
            break;
        }
        case 4:
            (void)qpack_encoder_duplicate(q->e, qs_byte(q) % 8, NULL);
            break;
        case 5:
            qs_encode(q);
            break;
        case 6:
            qs_deliver_encoder(q, (size_t)qs_byte(q) + 1);
            break;
        case 7: {
            const int i = qs_oldest(q, qs_byte(q) % QS_STREAMS);
            if (i >= 0) (void)qs_decode(q, (size_t)i);
            break;
        }
        case 8:
            qs_deliver_decoder(q, (size_t)qs_byte(q) + 1);
            break;
        case 9: {
            const int stream = qs_byte(q) % QS_STREAMS;
            if (qpack_decoder_cancel_stream(q->d, qs_stream_id(q, stream)) != QPACK_OK)
                __builtin_trap();
            for (int i; (i = qs_oldest(q, stream)) >= 0;) qs_section_drop(q, (size_t)i);
            q->generation[stream]++;
            break;
        }
        }
    }

    /* Everything delivered, decoded, acknowledged: the halves must agree. */
    qs_deliver_encoder(q, SIZE_MAX);
    if (q->enc_wire_len != 0) __builtin_trap();     /* a truncated instruction */
    while (q->section_count > 0)
        if (!qs_decode(q, 0)) __builtin_trap();      /* all inserts have arrived */
    qs_deliver_decoder(q, SIZE_MAX);
    if (q->dec_wire_len != 0) __builtin_trap();
    if (q->e->insert_count != qpack_decoder_insert_count(q->d) ||
        q->e->capacity != qpack_decoder_capacity(q->d) ||
        q->e->bytes != qpack_decoder_bytes(q->d) ||
        q->e->entry_count != q->d->entry_count ||
        q->e->section_count != 0)
        __builtin_trap();

out:
    for (size_t i = 0; i < q->section_count; i++) qs_section_free(&q->sections[i]);
    qpack_encoder_free(q->e);
    qpack_decoder_free(q->d);
    free(q);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_QUIC_STREAM

#include "quicmemory.h"
#include "quicrange.h"
#include "quicrecvbuf.h"

/* The two pieces of QUIC transport state a peer shapes most directly, each
 * against a model small enough to be obviously right.
 *
 * quicrecvbuf -- a stream's bytes arrive as STREAM frames in any order, with
 * retransmissions that overlap, duplicate or contradict what came before, a FIN
 * and a RESET_STREAM that fix the final size. The model is a byte array with a
 * "have" bit per offset and the first arrival kept, which is what the buffer
 * promises ("only the parts not already held are copied"). After every
 * operation: the same status (FINAL_SIZE_ERROR per RFC 9000 §4.5, the buffered
 * cap as FLOW_CONTROL_ERROR), the same readable prefix, the same buffered
 * count, reads that return exactly the model's bytes, completion when and only
 * when the final size has been read -- and, freed, every byte of the global
 * QUIC memory budget handed back.
 *
 * quicrange -- the sets behind ACK ranges and duplicate detection, against a
 * bitset over a window that may sit at 0, in the middle of the range, or at
 * UINT64_MAX, where the adjacency arithmetic can wrap. Spans stay sorted,
 * disjoint and merged when adjacent, within max_spans, and every value above
 * what eviction has forgotten is a member exactly when the model says so.
 *
 * First byte: which structure, and its parameters. */

#define QS_U 2048   /* offsets modelled */

typedef struct {
    uint8_t byte[QS_U];
    uint8_t have[QS_U];
    uint64_t read_off, max_offset, final_size;
    int fin;
} qsm_t;

static size_t qsm_readable(const qsm_t* m) {
    size_t n = 0;
    while (m->read_off + n < QS_U && m->have[m->read_off + n]) n++;
    return n;
}

static size_t qsm_buffered(const qsm_t* m) {
    size_t n = 0;
    for (uint64_t i = m->read_off; i < QS_U; i++) n += m->have[i];
    return n;
}

static void __quic_recvbuf(const uint8_t* data, size_t size) {
    const size_t limit = (size_t)data[0] * 8;         /* 0 = no cap */
    const size_t baseline = quicmemory_current();
    qsm_t* m = calloc(1, sizeof *m);
    if (m == NULL) return;
    quicrecvbuf_t buf;
    quicrecvbuf_init(&buf, limit);

    size_t p = 1;
    while (p + 4 <= size) {
        const uint8_t op = data[p++];
        const uint64_t offset = (uint64_t)(data[p] | data[p + 1] << 8) % QS_U;
        const size_t len = data[p + 2] % 128;
        p += 3;

        if (op % 4 <= 1) {                           /* STREAM, with FIN if op is 1 */
            const int fin = op % 4 == 1;
            size_t n = len;
            if (offset + n > QS_U) n = (size_t)(QS_U - offset);
            if (n > size - p) n = size - p;
            const uint8_t* bytes = data + p;
            p += n;
            const uint64_t end = offset + n;

            quicrecvbuf_status_e want = QUICRECVBUF_OK;
            size_t fresh = 0;
            for (uint64_t i = offset; i < end; i++)
                if (i >= m->read_off && !m->have[i]) fresh++;
            if ((m->fin && end > m->final_size) || (fin && m->fin && end != m->final_size) ||
                (fin && end < m->max_offset))
                want = QUICRECVBUF_FINAL_SIZE;
            else if (limit != 0 && fresh > 0 && qsm_buffered(m) + fresh > limit)
                want = QUICRECVBUF_TOO_MUCH;

            const quicrecvbuf_status_e got = quicrecvbuf_insert(&buf, offset, bytes, n, fin);
            if (got != want) __builtin_trap();
            if (got != QUICRECVBUF_OK) break;        /* the connection closes here */

            if (fin) { m->fin = 1; m->final_size = end; }
            if (end > m->max_offset) m->max_offset = end;
            for (uint64_t i = offset; i < end; i++)
                if (i >= m->read_off && !m->have[i]) {
                    m->have[i] = 1;
                    m->byte[i] = bytes[i - offset];
                }
        } else if (op % 4 == 2) {                    /* the application reads */
            uint8_t out[128];
            const size_t n = quicrecvbuf_read(&buf, out, len);
            const size_t ready = qsm_readable(m);
            if (n != (len < ready ? len : ready)) __builtin_trap();
            for (size_t i = 0; i < n; i++)
                if (out[i] != m->byte[m->read_off + i]) __builtin_trap();
            for (size_t i = 0; i < n; i++) m->have[m->read_off + i] = 0;
            m->read_off += n;
        } else {                                      /* RESET_STREAM */
            const uint64_t final_size = offset;
            const quicrecvbuf_status_e want =
                (m->fin && m->final_size != final_size) || final_size < m->max_offset
                ? QUICRECVBUF_FINAL_SIZE : QUICRECVBUF_OK;
            if (quicrecvbuf_set_final_size(&buf, final_size) != want) __builtin_trap();
            if (want != QUICRECVBUF_OK) break;
            m->fin = 1;
            m->final_size = final_size;
            if (final_size > m->max_offset) m->max_offset = final_size;
        }

        if (quicrecvbuf_readable(&buf) != qsm_readable(m) ||
            buf.buffered != qsm_buffered(m) || buf.max_offset != m->max_offset ||
            buf.read_off != m->read_off ||
            quicrecvbuf_complete(&buf) != (m->fin && m->read_off >= m->final_size))
            __builtin_trap();
    }

    quicrecvbuf_free(&buf);
    if (quicmemory_current() != baseline) __builtin_trap();    /* budget leaked */
    free(m);
}

static void __quic_range(const uint8_t* data, size_t size) {
    static const uint64_t bases[] = { 0, UINT64_C(1) << 62, UINT64_MAX - (QS_U - 1) };
    const uint64_t base = bases[(data[0] >> 1) % 3];
    const size_t max_spans = (size_t)(data[0] >> 3) % 9;       /* 0 = unbounded */

    uint8_t* model = calloc(QS_U, 1);
    if (model == NULL) return;
    quicrange_t r;
    quicrange_init(&r, max_spans);

    for (size_t p = 1; p + 5 <= size; p += 5) {
        const uint8_t op = data[p];
        const uint64_t a = (uint64_t)(data[p + 1] | data[p + 2] << 8) % QS_U;
        const uint64_t b = (uint64_t)(data[p + 3] | data[p + 4] << 8) % QS_U;
        const uint64_t lo = a < b ? a : b, hi = a < b ? b : a;

        switch (op % 3) {
        case 0:
            if (!quicrange_add(&r, base + lo, base + hi)) goto out;
            memset(model + lo, 1, hi - lo + 1);
            break;
        case 1:
            if (!quicrange_remove(&r, base + lo, base + hi)) goto out;
            memset(model + lo, 0, hi - lo + 1);
            break;
        case 2:
            quicrange_trim_below(&r, base + lo);     /* at or below, per quicrange.h */
            memset(model, 0, lo + 1);
            break;
        }

        /* The cap is enforced by add, the only operation the capped set (the
         * ACK ranges in quicack.c) is given; remove may split past it. */
        if (op % 3 == 0 && max_spans != 0 && r.count > max_spans) __builtin_trap();
        for (size_t i = 0; i < r.count; i++) {
            if (r.spans[i].start > r.spans[i].end) __builtin_trap();
            /* Disjoint and not adjacent, without the `end + 1` that wraps. */
            if (i > 0 && (r.spans[i].start == 0 || r.spans[i - 1].end >= r.spans[i].start - 1))
                __builtin_trap();
        }
        for (uint64_t v = 0; v < QS_U; v++) {
            /* Eviction forgets on purpose; what it forgot counts as seen. */
            if (r.has_evicted && base + v <= r.evicted_upto) {
                model[v] = (uint8_t)quicrange_contains(&r, base + v);
                continue;
            }
            if (quicrange_contains(&r, base + v) != model[v]) __builtin_trap();
        }
        if (!quicrange_empty(&r) &&
            (quicrange_min(&r) != r.spans[0].start || quicrange_max(&r) != r.spans[r.count - 1].end))
            __builtin_trap();
    }

out:
    quicrange_free(&r);
    free(model);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    if (data[0] & 1) __quic_range(data, size);
    else __quic_recvbuf(data, size);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_H3_REQUEST

#include "h3stream.h"

/* An HTTP/3 request stream: the per-stream state machine of RFC 9114 §4.1 --
 * HEADERS, then DATA, then optionally trailers, with unknown frame types
 * ignored anywhere and everything else refused -- fed the way h3conn feeds it,
 * one QUIC read at a time, with FIN on the last.
 *
 * Raw mode: the stream as the input spells it, delivered in one read, one byte
 * per read and in reads of 1..256 bytes. The three must agree on every event
 * and on the request that came out: method, target, fields, trailers, body.
 *
 * Generated mode: a well-formed request -- a static-table-only field section,
 * a body cut into DATA frames, trailers, grease frames between them -- and at
 * most one deliberate violation, each with the answer §4.1 requires:
 *
 *   none                         DONE, body byte for byte, one REQUEST_READY
 *   DATA before HEADERS          H3_FRAME_UNEXPECTED
 *   HEADERS after trailers       H3_FRAME_UNEXPECTED
 *   SETTINGS on a request stream H3_FRAME_UNEXPECTED
 *   an HTTP/2 codepoint (0x06)   H3_FRAME_UNEXPECTED (§11.2.1)
 *   the last frame cut short     H3_FRAME_ERROR (§7.1)
 *   content-length != body       H3_MESSAGE_ERROR (§4.1.2)
 *   FIN before any HEADERS       H3_REQUEST_INCOMPLETE
 *
 * in all three deliveries. */

typedef struct {
    uint64_t digest;
    int ready;          /* REQUEST_READY events */
    int status;         /* the terminal one, or NEED_MORE */
} h3r_result_t;

static int __h3r_terminal(h3stream_status_e st) {
    return st != H3STREAM_NEED_MORE && st != H3STREAM_BODY_CHUNK &&
           st != H3STREAM_REQUEST_READY && st != H3STREAM_QPACK_BLOCKED;
}

static uint64_t __h3r_request_digest(uint64_t h, httprequest_t* r) {
    h = __fuzz_fnv(h, &r->method, sizeof r->method);
    if (r->path != NULL) h = __fuzz_fnv(h, r->path, r->path_length);
    h = __fuzz_fnv_headers(h, r->header_);
    h = __fuzz_fnv_headers(h, r->trailer_);
    const file_t* body = &r->payload_.file;
    if (body->fd >= 0) {
        char chunk[4096];
        for (off_t off = 0;;) {
            const ssize_t n = pread(body->fd, chunk, sizeof chunk, off);
            if (n <= 0) break;
            h = __fuzz_fnv(h, chunk, (size_t)n);
            off += n;
        }
    }
    return h;
}

/* chunk 0: one read; seed 0: reads of `chunk`; else reads of 1..256 bytes. */
static h3r_result_t __h3r_run(const uint8_t* data, size_t size, size_t chunk, uint64_t seed) {
    h3r_result_t r = { .digest = 1469598103934665603ULL, .ready = 0, .status = H3STREAM_NEED_MORE };
    h3stream_t* st = h3stream_create(NULL, 0);
    qpack_decoder_t* qdec = qpack_decoder_create(0, 0);
    if (st == NULL || qdec == NULL) { h3stream_free(st); qpack_decoder_free(qdec); return r; }

    uint64_t rng = seed * 0x9E3779B97F4A7C15ULL + 1;
    size_t off = 0;
    do {
        size_t n = chunk == 0 ? size : chunk;
        if (chunk != 0 && seed != 0) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            n = 1 + (size_t)(rng % 256);
        }
        if (n > size - off) n = size - off;
        const int fin = off + n == size;
        const uint8_t* p = data + off;
        const uint8_t* end = p + n;
        off += n;

        for (int passes = 0; passes <= (int)n + 1; passes++) {
            const h3stream_status_e ev = h3stream_feed(st, qdec, &p, end, fin);
            if (ev == H3STREAM_REQUEST_READY) {
                r.ready++;
                if (p < end || fin) continue;
                break;
            }
            if (__h3r_terminal(ev)) r.status = ev;
            break;
        }
        if (__h3r_terminal(r.status)) break;
    } while (off < size);

    if (st->request != NULL && r.status == H3STREAM_DONE)
        r.digest = __h3r_request_digest(r.digest, st->request);
    h3stream_free(st);
    qpack_decoder_free(qdec);
    return r;
}

static int __h3r_frame(uint8_t* out, size_t cap, size_t* len, uint64_t type,
                       const uint8_t* payload, size_t plen) {
    const size_t a = varint_write(out + *len, cap - *len, type);
    if (a == 0) return 0;
    const size_t b = varint_write(out + *len + a, cap - *len - a, plen);
    if (b == 0 || plen > cap - *len - a - b) return 0;
    if (plen != 0) memcpy(out + *len + a + b, payload, plen);
    *len += a + b + plen;
    return 1;
}

enum { H3R_NONE, H3R_DATA_FIRST, H3R_HEADERS_AFTER_TRAILERS, H3R_SETTINGS,
       H3R_H2_CODEPOINT, H3R_TRUNCATED, H3R_LENGTH_MISMATCH, H3R_NO_HEADERS, H3R_VIOLATIONS };

static const h3stream_status_e __h3r_expected[H3R_VIOLATIONS] = {
    H3STREAM_DONE, H3STREAM_ERR_FRAME_UNEXPECTED, H3STREAM_ERR_FRAME_UNEXPECTED,
    H3STREAM_ERR_FRAME_UNEXPECTED, H3STREAM_ERR_FRAME_UNEXPECTED, H3STREAM_ERR_FRAME,
    H3STREAM_ERR_MESSAGE, H3STREAM_ERR_REQUEST_INCOMPLETE,
};

/* Layout: [mode][violation][body pieces][grease] then the body bytes. */
static size_t __h3r_generate(const uint8_t* data, size_t size, uint8_t* out, size_t cap,
                             int* violation) {
    *violation = data[1] % H3R_VIOLATIONS;
    const size_t pieces = (size_t)(data[2] % 4);
    /* No trailers after a truncated frame: DATA behind trailers is already a
     * different error (H3_FRAME_UNEXPECTED), and one violation at a time. */
    const int grease = data[3] & 1;
    const int trailers = (data[3] & 2) != 0 && *violation != H3R_TRUNCATED;
    const uint8_t* body = data + 4;
    const size_t body_len = size - 4 > 2000 ? 2000 : size - 4;

    char cl[24];
    snprintf(cl, sizeof cl, "%zu", *violation == H3R_LENGTH_MISMATCH ? body_len + 1 : body_len);
    const qpack_header_t fields[] = {
        { ":method", 7, "POST", 4, 0 }, { ":scheme", 7, "https", 5, 0 },
        { ":authority", 10, "localhost", 9, 0 }, { ":path", 5, "/upload", 7, 0 },
        { "content-length", 14, cl, strlen(cl), 0 },
    };
    uint8_t block[256];
    qpack_encoder_t* e = qpack_encoder_create(0, 0);
    const size_t blen = e != NULL ? qpack_encode_block(e, fields, 5, block, sizeof block) : 0;
    qpack_encoder_free(e);
    if (blen == 0) return 0;

    static const qpack_header_t trailer_fields[] = { { "x-checksum", 10, "abc", 3, 0 } };
    uint8_t tblock[64];
    qpack_encoder_t* te = qpack_encoder_create(0, 0);
    const size_t tlen = te != NULL ? qpack_encode_block(te, trailer_fields, 1, tblock, sizeof tblock) : 0;
    qpack_encoder_free(te);

    static const uint8_t greasy[] = { 'g', 'r', 'e', 'a', 's', 'e' };
    size_t len = 0;
    int ok = 1;
    if (grease) ok = ok && __h3r_frame(out, cap, &len, 0x21 + 0x1f * 3, greasy, sizeof greasy);
    if (*violation == H3R_DATA_FIRST) ok = ok && __h3r_frame(out, cap, &len, 0x00, body, 1);
    if (*violation == H3R_NO_HEADERS) return ok ? len : 0;
    ok = ok && __h3r_frame(out, cap, &len, 0x01, block, blen);
    if (*violation == H3R_SETTINGS) ok = ok && __h3r_frame(out, cap, &len, 0x04, NULL, 0);
    if (*violation == H3R_H2_CODEPOINT) ok = ok && __h3r_frame(out, cap, &len, 0x06, greasy, 4);

    const size_t n = pieces + 1;
    for (size_t i = 0; i < n && ok; i++) {
        const size_t from = body_len * i / n, to = body_len * (i + 1) / n;
        ok = __h3r_frame(out, cap, &len, 0x00, body + from, to - from);
        if (grease && ok) ok = __h3r_frame(out, cap, &len, 0x21, NULL, 0);
    }
    if ((trailers || *violation == H3R_HEADERS_AFTER_TRAILERS) && tlen > 0) {
        ok = ok && __h3r_frame(out, cap, &len, 0x01, tblock, tlen);
        if (*violation == H3R_HEADERS_AFTER_TRAILERS)
            ok = ok && __h3r_frame(out, cap, &len, 0x01, tblock, tlen);
    }
    /* A DATA frame announcing six bytes, of which the stream carries four. */
    if (*violation == H3R_TRUNCATED && ok &&
        __h3r_frame(out, cap, &len, 0x00, greasy, sizeof greasy))
        len -= 2;
    return ok ? len : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;

    if (!(data[0] & 1)) {
        const uint64_t seed = (uint64_t)data[0] + 1;
        const h3r_result_t whole = __h3r_run(data + 1, size - 1, 0, 0);
        const h3r_result_t bytes = __h3r_run(data + 1, size - 1, 1, 0);
        const h3r_result_t split = __h3r_run(data + 1, size - 1, 1, seed);
        if (whole.status != bytes.status || whole.status != split.status ||
            whole.ready != bytes.ready || whole.ready != split.ready ||
            whole.digest != bytes.digest || whole.digest != split.digest)
            __builtin_trap();
        return 0;
    }

    static uint8_t wire[8192];
    int violation = H3R_NONE;
    const size_t len = __h3r_generate(data, size, wire, sizeof wire, &violation);
    if (len == 0 && violation != H3R_NO_HEADERS) return 0;

    const h3r_result_t runs[3] = {
        __h3r_run(wire, len, 0, 0), __h3r_run(wire, len, 1, 0),
        __h3r_run(wire, len, 1, (uint64_t)data[0] + 1),
    };
    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "violation %d: %zu bytes, status %d/%d/%d (want %d), ready %d\n",
                violation, len, runs[0].status, runs[1].status, runs[2].status,
                (int)__h3r_expected[violation], runs[0].ready);
    for (int i = 0; i < 3; i++) {
        if (runs[i].status != (int)__h3r_expected[violation]) __builtin_trap();
        if (violation == H3R_NONE && runs[i].ready != 1) __builtin_trap();
    }
    if (violation == H3R_NONE &&
        (runs[0].digest != runs[1].digest || runs[0].digest != runs[2].digest))
        __builtin_trap();
    return 0;
}

#elif FUZZ_TARGET == FUZZ_QPACK_STREAMS

/* Both QPACK service streams, which are resumable parsers -- so they are fed in
 * pieces, and the piece size comes from the input rather than being fixed. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;

    const size_t step = (size_t)data[0] + 1;

    qpack_decoder_t* d = qpack_decoder_create(0, 0);
    if (d == NULL) return 0;

    size_t pos = 1;
    while (pos < size) {
        const size_t chunk = size - pos < step ? size - pos : step;
        size_t consumed = 0;

        if (qpack_decoder_read_encoder(d, data + pos, chunk, &consumed) != QPACK_OK)
            break;

        if (consumed == 0) break;   /* needs more bytes than this chunk holds */
        pos += consumed;
    }

    qpack_decoder_free(d);

    pos = 1;
    while (pos < size) {
        const size_t chunk = size - pos < step ? size - pos : step;
        size_t consumed = 0;

        if (qpack_encoder_read_decoder(data + pos, chunk, &consumed) != QPACK_OK)
            break;

        if (consumed == 0) break;
        pos += consumed;
    }

    return 0;
}

#elif FUZZ_TARGET == FUZZ_HUFFMAN

/* Reached from QPACK and HPACK both, on names and values alike. The output cap
 * is deliberately smaller than the input can expand to, because the branch that
 * refuses a decode for want of room is the one a caller must not mistake for a
 * truncation. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uint8_t out[4096];

    (void)huffman_decode(out, sizeof out, data, size);
    (void)huffman_decode(out, 8, data, size);

    /* And the round trip, which asserts nothing but walks the encoder with
     * arbitrary bytes -- the encoder is reached with header values the peer
     * chose too. */
    const size_t source_len = size > 2048 ? 2048 : size;
    uint8_t enc[8192];
    const ssize_t n = huffman_encode(enc, sizeof enc, data, source_len);
    if (n >= 0) {
        const ssize_t decoded = huffman_decode(out, sizeof out, enc, (size_t)n);
        if (decoded != (ssize_t)source_len || memcmp(out, data, source_len) != 0)
            __builtin_trap();
    }

    return 0;
}

#elif FUZZ_TARGET == FUZZ_HPACK

/* HTTP/2's field section: the half of the pair that the QPACK target next door
 * does not reach. HPACK differs in the way that matters here -- it carries its
 * dynamic table updates inside the block itself (RFC 7541 §6.3), so the peer
 * rewrites the decoder's state with the same bytes that state is used to
 * decode.
 *
 * Decoded twice on one decoder on purpose. A block is not self-contained: an
 * indexed field may name an entry a previous block inserted, and an eviction
 * during a size update moves the index space under the reader. Only the second
 * pass sees a table that is not empty, and that is the state a connection
 * actually spends its life in.
 *
 * Then again on a decoder with no room at all. Every insert there must be
 * refused rather than evict its way down to a table that still cannot hold the
 * entry that caused the eviction -- the case where an off-by-one leaves the
 * table describing entries it no longer owns. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    hpack_header_t* headers = NULL;
    size_t count = 0;

    hpack_decoder_t* d = hpack_decoder_create(4096);
    if (d == NULL) return 0;

    for (int pass = 0; pass < 2; pass++) {
        if (hpack_decoder_decode(d, data, size, 1048576, &headers, &count) == HPACK_OK)
            hpack_headers_free(headers, count);

        headers = NULL;
        count = 0;
    }

    hpack_decoder_free(d);

    d = hpack_decoder_create(0);
    if (d == NULL) return 0;

    if (hpack_decoder_decode(d, data, size, 1048576, &headers, &count) == HPACK_OK)
        hpack_headers_free(headers, count);

    hpack_decoder_free(d);

    headers = NULL;
    count = 0;

    /* The round trip, for the reason the huffman target next door gives for
     * doing the same: the encoder is reached with names and values the peer
     * chose -- a request header echoed into a response, a Location built from
     * a request path -- so it is fed what came out of the decoder rather than
     * anything invented here. Without this the encoder half of hpack.c is
     * never entered at all; measured, it was thirteen functions at zero.
     *
     * Both Huffman settings: which one ships is the encoder's decision, and
     * both branches exist. What comes back out is decoded again, because an
     * encoder that emits a block its own decoder rejects is a bug that no
     * amount of decoding alone would show. */
    d = hpack_decoder_create(4096);
    if (d == NULL) return 0;

    if (hpack_decoder_decode(d, data, size, 1048576, &headers, &count) == HPACK_OK) {
        hpack_encoder_t* e = hpack_encoder_create(4096);
        hpack_decoder_t* back = hpack_decoder_create(4096);

        if (e != NULL && back != NULL) {
            for (int huffman = 0; huffman < 2; huffman++) {
                uint8_t* encoded = NULL;
                size_t encoded_len = 0;

                if (hpack_encoder_encode(e, headers, count, huffman, &encoded, &encoded_len) != HPACK_OK)
                    continue;

                hpack_header_t* again = NULL;
                size_t again_count = 0;
                if (hpack_decoder_decode(back, encoded, encoded_len, 1048576,
                                         &again, &again_count) != HPACK_OK)
                    __builtin_trap();
                if (again_count != count) __builtin_trap();
                for (size_t i = 0; i < count; i++) {
                    if (headers[i].name_len != again[i].name_len ||
                        headers[i].value_len != again[i].value_len ||
                        memcmp(headers[i].name, again[i].name, headers[i].name_len) != 0 ||
                        memcmp(headers[i].value, again[i].value, headers[i].value_len) != 0)
                        __builtin_trap();
                }
                hpack_headers_free(again, again_count);

                free(encoded);
            }

        }

        hpack_encoder_free(e);
        hpack_decoder_free(back);

        hpack_headers_free(headers, count);
    }

    hpack_decoder_free(d);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_H2_FRAME

/* HTTP/2 frames as they arrive on a connection. The layer under this one,
 * HPACK, has a target of its own; this is everything above it, and on this
 * server it is reachable two ways -- ALPN advertises h2 on every TLS context,
 * and a plaintext connection can arrive as h2c, preface first.
 *
 * Three things beside the bytes decide what the parser does, and all three
 * come out of the input rather than being fixed: whether the 24-byte client
 * preface is still owed, what SETTINGS said the frame-size limit is, and where
 * the stream of bytes is cut. The limit matters because the parser allocates
 * against it; the cut matters because the parser is resumable, and the states
 * that only exist across a split -- a frame header arriving in two pieces --
 * are unreachable when the whole buffer is handed over at once. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;

    const int preface_required = data[0] & 1;

    /* The RFC's range plus the degenerate ends: 0 and 1 are not legal
     * SETTINGS values, but nothing stops a peer sending them, and the branch
     * that refuses a frame for exceeding the limit is the one worth reaching. */
    static const uint32_t limits[] = { 0, 1, 16384u, 65535u, 16777215u };
    const uint32_t max_frame_size = limits[(data[0] >> 1) % (sizeof limits / sizeof *limits)];

    const uint8_t* const body = data + 2;
    const size_t body_len = size - 2;
    const size_t split = body_len > 0 ? (size_t)data[1] % (body_len + 1) : 0;

    h2frame_parser_t p;
    h2frame_parser_init(&p, preface_required, max_frame_size);

    const uint8_t* pp = body;
    const uint8_t* const mid = body + split;
    const uint8_t* const end = body + body_len;

    for (int half = 0; half < 2; half++) {
        const uint8_t* const stop = half == 0 ? mid : end;

        while (pp < stop) {
            const h2parse_status_e st = h2frame_parser_feed(&p, &pp, stop);

            if (st == H2PARSE_FRAME_READY) {
                /* Reading the frame out is part of the contract and touches
                 * the payload pointer the parser just published. */
                h2_frame_t frame;
                h2frame_parser_get(&p, &frame);

                /* Straight back through the encoder, for the reason the hpack
                 * and huffman targets give: a frame the server forwards or
                 * echoes is one the peer shaped. */
                uint8_t out[512];
                if (frame.payload_len <= sizeof out - H2_FRAME_HEADER_LEN)
                    (void)h2frame_encode(out, sizeof out, frame.type, frame.flags,
                                         frame.stream_id, frame.payload, frame.payload_len);
                continue;
            }

            /* CONTINUE means this half is spent; anything else is terminal. */
            break;
        }
    }

    h2frame_parser_free(&p);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_JSON

/* The framework's JSON parser. Reachable from the network wherever a handler
 * asks for the request body as JSON (httprequest.h: get_payload_json), and
 * the largest single parser in the tree by a wide margin.
 *
 * json_parse() takes a C string rather than a pointer and a length, so the
 * input is copied and terminated -- which also means an embedded NUL ends the
 * document early, and the fuzzer is free to place one. That is the API's
 * behaviour, not the target's simplification.
 *
 * Parsing alone would leave most of the file cold: what the parser builds is a
 * tree, and reading it back is where the accessors and the iterators live. So
 * the tree is walked to a bounded depth, and then stringified -- a document
 * that survives parsing but crashes on the way out is still a crash, and it is
 * the direction a response takes. */

static void __fuzz_json_walk(const json_token_t* token, int depth) {
    if (token == NULL || depth > 12) return;

    if (json_is_object(token)) {
        (void)json_object_size(token);
        for (json_it_t it = json_init_it(token); !json_end_it(&it); json_next_it(&it)) {
            (void)json_it_key(&it);
            __fuzz_json_walk(json_it_value(&it), depth + 1);
        }
        return;
    }

    if (json_is_array(token)) {
        (void)json_array_size(token);
        for (json_it_t it = json_init_it(token); !json_end_it(&it); json_next_it(&it))
            __fuzz_json_walk(json_it_value(&it), depth + 1);
        return;
    }

    int ok = 0;
    if (json_is_string(token)) (void)json_string(token);
    if (json_is_number(token)) {
        (void)json_int(token, &ok);
        (void)json_uint(token, &ok);
        (void)json_double(token, &ok);
    }
    if (json_is_bool(token)) (void)json_bool(token);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* text = malloc(size + 1);
    if (text == NULL) return 0;

    memcpy(text, data, size);
    text[size] = '\0';

    json_doc_t* doc = json_parse(text);
    free(text);

    if (doc == NULL) return 0;

    __fuzz_json_walk(json_root(doc), 0);

    const char* serialized = json_stringify(doc);
    (void)json_stringify_size(doc);
    if (serialized != NULL) {
        json_doc_t* parsed = json_parse(serialized);
        if (parsed == NULL) __builtin_trap();
        const char* again = json_stringify(parsed);
        if (again == NULL || strcmp(serialized, again) != 0) __builtin_trap();
        json_free(parsed);
    }

    /* Copying, and then building a document out of what was parsed.
     *
     * The builder half of this file is what an application calls, not what the
     * network reaches -- but the values it is called with routinely come from
     * the network all the same: a handler that echoes a field, or puts a
     * submitted string into its reply, hands attacker bytes straight to
     * json_create_string(). Measured, parsing alone left forty-one of the
     * ninety-two functions here cold, and this is the half that was missing. */
    json_doc_t* copy = json_root_create_object();
    if (copy != NULL) {
        (void)json_copy(doc, copy);

        json_token_t* root = json_root(copy);
        if (root != NULL && json_is_object(root)) {
            /* Keyed with a string the input chose, which is the shape the echo
             * takes: the key is as much the peer's as the value is. */
            const json_token_t* src = json_root(doc);
            const char* text_value = src != NULL && json_is_string(src) ? json_string(src) : "";

            json_token_t* leaf = json_create_string(text_value);
            if (leaf != NULL && !json_object_set(root, text_value, leaf))
                json_token_free_tree(leaf);
        }

        (void)json_stringify(copy);
        json_free(copy);
    }

    json_free(doc);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_WEBSOCKET_SEQUENCE

#include <zlib.h>

/* One WebSocket connection: a stream of frames, fed to the parser the way
 * websocketsserverhandlers.c feeds it -- HANDLE_AND_CONTINUE handles the frame
 * and calls prepare_remains, COMPLETE handles it and resets, CONTINUE waits for
 * the next read -- in a single read, one byte per read, and in reads of
 * 1..256 bytes. Every completed message and every control frame is an event;
 * the three event sequences must agree.
 *
 * Two modes, by the top bit of the first byte.
 *
 * Raw: the rest is the byte stream as it is. With permessage-deflate on,
 * garbage inflates to errors at points that depend on how much input a read
 * delivered, so the sequences are compared only when all three runs end
 * without an error.
 *
 * Generated: the rest describes messages -- text or binary, compressed or not,
 * split into 1..4 fragments, a ping, pong or close between fragments -- and
 * the frames are built here: masked, with minimal length encoding, compressed
 * by a zlib stream that keeps or drops its window between messages as
 * client_no_context_takeover says. Then what must come out is known, not just
 * that the runs agree: every message byte for byte, in order, with the control
 * frames where they were sent. A text message that is not UTF-8, or a message
 * over client_max_body_size (which the input picks), must not be delivered,
 * and nothing after it may be; the runs may differ only in where inside that
 * message they stopped, and then only in control frames. */

#define WS_SEQ_MAX_EVENTS 64

typedef struct {
    uint64_t digest;                    /* every event, in order */
    uint64_t data[WS_SEQ_MAX_EVENTS];   /* data messages alone */
    size_t data_count;
    size_t events;
    int status;                         /* the last parser status */
    int failed;
} ws_seq_result_t;

static int __ws_seq_failed(int status) {
    return status != WSPARSER_CONTINUE && status != WSPARSER_COMPLETE &&
           status != WSPARSER_HANDLE_AND_CONTINUE;
}

static uint64_t __ws_seq_event(uint64_t h, unsigned char type,
                               const void* payload, size_t len) {
    h = __fuzz_fnv(h, &type, 1);
    h = __fuzz_fnv(h, &len, sizeof len);
    return __fuzz_fnv(h, payload, len);
}

static void __ws_seq_record(ws_seq_result_t* r, unsigned char type,
                            const void* payload, size_t len, int is_data) {
    const uint64_t e = __ws_seq_event(1469598103934665603ULL, type, payload, len);
    r->digest = __fuzz_fnv(r->digest, &e, sizeof e);
    r->events++;
    if (is_data && r->data_count < WS_SEQ_MAX_EVENTS) r->data[r->data_count] = e;
    if (is_data) r->data_count++;
}

/* What __handle() does, minus the dispatch: a control frame is answered (here:
 * recorded), a final data frame hands its message over (here: recorded and
 * freed, which is what ownership passing to the queue amounts to). */
static void __ws_seq_handle(websocketsparser_t* parser, ws_seq_result_t* r) {
    switch (parser->frame.opcode) {
    case WSOPCODE_CLOSE:
    case WSOPCODE_PING:
    case WSOPCODE_PONG:
        __ws_seq_record(r, (unsigned char)(0x80 | parser->frame.opcode),
                        bufferdata_get(&parser->buf), bufferdata_writed(&parser->buf), 0);
        return;
    }
    if (!parser->frame.fin) return;

    websocketsrequest_t* request = parser->request;
    if (request == NULL) __builtin_trap();

    uint64_t h = 1469598103934665603ULL;
    size_t len = 0;
    const int fd = request->protocol->payload.fd;
    char chunk[4096];
    for (;;) {
        const ssize_t n = fd >= 0 ? pread(fd, chunk, sizeof chunk, (off_t)len) : 0;
        if (n < 0) __builtin_trap();
        if (n == 0) break;
        h = __fuzz_fnv(h, chunk, (size_t)n);
        len += (size_t)n;
    }
    /* The payload is hashed in pieces, so the event is built from the hash and
     * the length rather than from the bytes; __ws_seq_expect does the same. */
    const unsigned char type = (unsigned char)request->type;
    uint64_t e = __fuzz_fnv(1469598103934665603ULL, &type, 1);
    e = __fuzz_fnv(e, &len, sizeof len);
    e = __fuzz_fnv(e, &h, sizeof h);
    r->digest = __fuzz_fnv(r->digest, &e, sizeof e);
    r->events++;
    if (r->data_count < WS_SEQ_MAX_EVENTS) r->data[r->data_count] = e;
    r->data_count++;

    websocketsrequest_free(request);
    parser->request = NULL;
}

/* chunk 0: one read of everything; seed 0: reads of `chunk` bytes; otherwise
 * reads of 1..256 bytes from a PRNG. */
static ws_seq_result_t __ws_seq_run(const uint8_t* data, size_t size, int compress_on,
                                    int no_takeover, size_t chunk, uint64_t seed) {
    ws_seq_result_t r = { .digest = 1469598103934665603ULL, .status = WSPARSER_CONTINUE };
    const size_t cap = chunk == 0 ? (size ? size : 1) : seed != 0 ? 256 : chunk;
    char* buffer = malloc(cap + 1);
    if (buffer == NULL) return r;

    connection_t connection;
    connection_server_ctx_t ctx;
    memset(&connection, 0, sizeof connection);
    memset(&ctx, 0, sizeof ctx);
    connection.buffer = buffer;
    connection.buffer_size = cap;
    connection.fd = -1;
    connection.ctx = (connection_ctx_t*)&ctx;

    websocketsparser_t* parser =
        websocketsparser_create(&connection, websockets_protocol_default_create);
    if (parser == NULL) { free(buffer); return r; }
    if (compress_on) {
        parser->ws_deflate.config.client_no_context_takeover = no_takeover;
        if (!ws_deflate_start(&parser->ws_deflate)) {
            websocketsparser_free(parser);
            free(buffer);
            return r;
        }
        parser->ws_deflate_enabled = 1;
    }

    uint64_t rng = seed * 0x9E3779B97F4A7C15ULL + 1;
    for (size_t off = 0; off < size && !r.failed;) {
        size_t n = cap;
        if (chunk != 0 && seed != 0) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            n = 1 + (size_t)(rng % 256);
        }
        if (n > size - off) n = size - off;
        memcpy(buffer, data + off, n);
        buffer[n] = 0;
        websocketsparser_set_bytes_readed(parser, n);
        parser->pos_start = 0;
        parser->pos = 0;

        for (size_t frames = 0; frames <= n + 1; frames++) {
            r.status = websocketsparser_run(parser);
            if (r.status == WSPARSER_HANDLE_AND_CONTINUE) {
                if (parser->pos > n) __builtin_trap();
                __ws_seq_handle(parser, &r);
                websocketsparser_prepare_remains(parser);
                if (parser->pos_start > n) __builtin_trap();
                continue;
            }
            if (r.status == WSPARSER_COMPLETE) {
                __ws_seq_handle(parser, &r);
                websocketsparser_reset(parser);
            }
            if (__ws_seq_failed(r.status)) r.failed = 1;
            break;
        }
        off += n;
    }

    websocketsparser_free(parser);
    free(buffer);
    return r;
}

/* ---- The generator ---- */

typedef struct {
    uint8_t* data;
    size_t len;
    size_t cap;
} ws_seq_buf_t;

static int __ws_seq_put(ws_seq_buf_t* b, const void* data, size_t len) {
    if (len == 0) return 1;
    if (b->len + len > b->cap) {
        size_t cap = b->cap ? b->cap : 1024;
        while (cap < b->len + len) cap *= 2;
        uint8_t* grown = realloc(b->data, cap);
        if (grown == NULL) return 0;
        b->data = grown;
        b->cap = cap;
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return 1;
}

static int __ws_seq_frame(ws_seq_buf_t* b, uint8_t first, const uint8_t* payload,
                          size_t len, uint64_t* rng) {
    uint8_t head[14];
    size_t hl = 0;
    head[hl++] = first;
    if (len < 126) {
        head[hl++] = (uint8_t)(0x80 | len);
    } else if (len <= 0xffff) {
        head[hl++] = 0x80 | 126;
        head[hl++] = (uint8_t)(len >> 8);
        head[hl++] = (uint8_t)len;
    } else {
        head[hl++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) head[hl++] = (uint8_t)((uint64_t)len >> (8 * i));
    }
    *rng ^= *rng << 13; *rng ^= *rng >> 7; *rng ^= *rng << 17;
    uint8_t mask[4];
    memcpy(mask, rng, 4);
    memcpy(head + hl, mask, 4);
    hl += 4;
    if (!__ws_seq_put(b, head, hl)) return 0;

    for (size_t i = 0; i < len; i++) {
        const uint8_t c = payload[i] ^ mask[i % 4];
        if (!__ws_seq_put(b, &c, 1)) return 0;
    }
    return 1;
}

/* RFC 3629, by length: a NUL is a character like any other. */
static int __ws_seq_utf8(const uint8_t* s, size_t len) {
    for (size_t i = 0; i < len;) {
        const uint8_t c = s[i];
        if (c < 0x80) { i++; continue; }
        size_t n;
        uint32_t cp;
        if ((c & 0xe0) == 0xc0) { n = 1; cp = c & 0x1f; }
        else if ((c & 0xf0) == 0xe0) { n = 2; cp = c & 0x0f; }
        else if ((c & 0xf8) == 0xf0) { n = 3; cp = c & 0x07; }
        else return 0;
        if (i + n >= len) return 0;
        for (size_t k = 1; k <= n; k++) {
            if ((s[i + k] & 0xc0) != 0x80) return 0;
            cp = (cp << 6) | (s[i + k] & 0x3f);
        }
        if ((n == 1 && cp < 0x80) || (n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000))
            return 0;
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
        i += n + 1;
    }
    return 1;
}

typedef struct {
    ws_seq_result_t result;     /* the events that must come out */
    int fails;                  /* a message that must not be delivered */
} ws_seq_expect_t;

/* Builds the frame stream into `wire` and the expected events into `ex`.
 * Layout after the mode byte: [limit][mask seed] then per message
 * [header][length][extra length if header bit 6][payload...]. */
static int __ws_seq_generate(const uint8_t* data, size_t size, int compress_on,
                             int no_takeover, size_t limit,
                             ws_seq_buf_t* wire, ws_seq_expect_t* ex) {
    uint64_t rng = (size > 1 ? data[1] : 0) * 0x2545F4914F6CDD1DULL + 7;
    z_stream z;
    memset(&z, 0, sizeof z);
    if (compress_on && deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8,
                                Z_DEFAULT_STRATEGY) != Z_OK)
        return 0;

    int ok = 1;
    size_t p = 2;
    uint8_t* packed = NULL;
    for (int m = 0; m < 16 && p < size && ok; m++) {
        const uint8_t h = data[p++];
        size_t len = p < size ? data[p++] : 0;
        if ((h & 0x40) && p < size) len += (size_t)data[p++] * 256;
        if (len > size - p) len = size - p;
        const uint8_t* payload = data + p;
        p += len;

        const int text = !(h & 1);
        const int compressed = compress_on && (h & 2);
        const size_t fragments = ((h >> 2) & 3) + 1;
        const int control = (h >> 4) & 3;

        /* What goes on the wire: the payload, or its deflate stream without
         * the 00 00 ff ff tail (RFC 7692 §7.2.1). */
        const uint8_t* body = payload;
        size_t body_len = len;
        if (compressed) {
            if (no_takeover) deflateReset(&z);
            const size_t bound = deflateBound(&z, len) + 16;
            free(packed);
            packed = malloc(bound);
            if (packed == NULL) { ok = 0; break; }
            z.next_in = (Bytef*)payload;
            z.avail_in = (uInt)len;
            z.next_out = packed;
            z.avail_out = (uInt)bound;
            if (deflate(&z, Z_SYNC_FLUSH) != Z_OK || z.avail_in != 0) { ok = 0; break; }
            body_len = bound - z.avail_out;
            if (body_len < 4 || memcmp(packed + body_len - 4, "\x00\x00\xff\xff", 4) != 0) {
                ok = 0;
                break;
            }
            body_len -= 4;
            body = packed;
        }

        /* Fragment sizes: as even as the division allows. */
        size_t largest = 0;
        for (size_t f = 0; f < fragments; f++) {
            const size_t from = body_len * f / fragments;
            const size_t to = body_len * (f + 1) / fragments;
            if (to - from > largest) largest = to - from;
        }
        const int bad = (text && !__ws_seq_utf8(payload, len)) || len > limit || largest > limit;

        for (size_t f = 0; f < fragments && ok; f++) {
            const size_t from = body_len * f / fragments;
            const size_t to = body_len * (f + 1) / fragments;
            uint8_t first = f == 0 ? (text ? 0x01 : 0x02) : 0x00;
            if (f == fragments - 1) first |= 0x80;
            if (f == 0 && compressed) first |= 0x40;
            ok = __ws_seq_frame(wire, first, body + from, to - from, &rng);

            /* A control frame between the first two fragments (RFC 6455
             * §5.4 allows them inside a fragmented message). */
            if (ok && control != 0 && (f == 0 ? fragments > 1 : 0)) {
                static const uint8_t opcodes[] = { 0, 0x9, 0xA, 0x8 };
                const uint8_t cp[2] = { 0x03, 0xe8 };  /* also a close code: 1000 */
                ok = __ws_seq_frame(wire, (uint8_t)(0x80 | opcodes[control]), cp, 2, &rng);
                if (ok && !ex->fails)
                    __ws_seq_record(&ex->result, (uint8_t)(0x80 | opcodes[control]), cp, 2, 0);
            }
        }
        if (!ok || ex->fails) continue;
        if (bad) { ex->fails = 1; continue; }

        uint64_t hash = __fuzz_fnv(1469598103934665603ULL, payload, len);
        const unsigned char type = text ? WEBSOCKETS_TEXT : WEBSOCKETS_BINARY;
        uint64_t e = __fuzz_fnv(1469598103934665603ULL, &type, 1);
        e = __fuzz_fnv(e, &len, sizeof len);
        e = __fuzz_fnv(e, &hash, sizeof hash);
        ex->result.digest = __fuzz_fnv(ex->result.digest, &e, sizeof e);
        ex->result.events++;
        if (ex->result.data_count < WS_SEQ_MAX_EVENTS) ex->result.data[ex->result.data_count] = e;
        ex->result.data_count++;
    }

    free(packed);
    if (compress_on) deflateEnd(&z);
    return ok;
}

static int __ws_seq_same(const ws_seq_result_t* a, const ws_seq_result_t* b) {
    return a->digest == b->digest && a->events == b->events &&
           a->data_count == b->data_count && a->status == b->status;
}

/* A run that had to stop: the messages before the bad one, exactly, and no
 * message after it. Control frames sent inside the bad message may or may not
 * have been handled, depending on where the run noticed. */
static void __ws_seq_check_prefix(const ws_seq_result_t* run, const ws_seq_expect_t* ex) {
    if (!run->failed || run->data_count != ex->result.data_count) __builtin_trap();
    const size_t n = run->data_count < WS_SEQ_MAX_EVENTS ? run->data_count : WS_SEQ_MAX_EVENTS;
    for (size_t i = 0; i < n; i++)
        if (run->data[i] != ex->result.data[i]) __builtin_trap();
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    const int generated = (data[0] & 0x80) != 0;
    const int compress_on = data[0] & 1;
    const int no_takeover = (data[0] & 2) != 0;
    const uint64_t seed = (uint64_t)(data[0] >> 2) + 1;

    if (!generated) {
        const ws_seq_result_t whole = __ws_seq_run(data + 1, size - 1, compress_on, no_takeover, 0, 0);
        const ws_seq_result_t bytes = __ws_seq_run(data + 1, size - 1, compress_on, no_takeover, 1, 0);
        const ws_seq_result_t split = __ws_seq_run(data + 1, size - 1, compress_on, no_takeover, 1, seed);
        /* Without compression an error is a property of the bytes, not of
         * the reads: it must happen at the same place in every run. */
        const int comparable = !compress_on || (!whole.failed && !bytes.failed && !split.failed);
        if (getenv("FUZZ_TRACE") != NULL) {
            const ws_seq_result_t* runs[3] = { &whole, &bytes, &split };
            for (int i = 0; i < 3; i++)
                fprintf(stderr, "run %d: events=%zu data=%zu status=%d failed=%d\n", i,
                        runs[i]->events, runs[i]->data_count, runs[i]->status, runs[i]->failed);
        }
        if (comparable && (!__ws_seq_same(&whole, &bytes) || !__ws_seq_same(&whole, &split)))
            __builtin_trap();
        return 0;
    }

    /* The limit is per message: 16..4080 bytes, or the configured 10 MiB. */
    env_t* e = env();
    const size_t saved_limit = e->main.client_max_body_size;
    const size_t limit = data[1] != 0 ? (size_t)data[1] * 16 : saved_limit;
    e->main.client_max_body_size = limit;

    ws_seq_buf_t wire = { 0 };
    ws_seq_expect_t ex;
    memset(&ex, 0, sizeof ex);
    ex.result.digest = 1469598103934665603ULL;

    if (__ws_seq_generate(data, size, compress_on, no_takeover, limit, &wire, &ex) && wire.len > 0) {
        const ws_seq_result_t runs[3] = {
            __ws_seq_run(wire.data, wire.len, compress_on, no_takeover, 0, 0),
            __ws_seq_run(wire.data, wire.len, compress_on, no_takeover, 1, 0),
            __ws_seq_run(wire.data, wire.len, compress_on, no_takeover, 1, seed),
        };
        /* FUZZ_TRACE=1 when replaying one input: what each run produced. */
        if (getenv("FUZZ_TRACE") != NULL) {
            fprintf(stderr, "expected: events=%zu data=%zu fails=%d wire=%zu\n",
                    ex.result.events, ex.result.data_count, ex.fails, wire.len);
            for (int i = 0; i < 3; i++)
                fprintf(stderr, "run %d: events=%zu data=%zu status=%d failed=%d same=%d\n",
                        i, runs[i].events, runs[i].data_count, runs[i].status,
                        runs[i].failed, runs[i].digest == ex.result.digest);
        }
        for (int i = 0; i < 3; i++) {
            if (ex.fails) {
                __ws_seq_check_prefix(&runs[i], &ex);
            } else {
                if (runs[i].failed || runs[i].status != WSPARSER_COMPLETE) __builtin_trap();
                if (runs[i].digest != ex.result.digest || runs[i].events != ex.result.events)
                    __builtin_trap();
            }
        }
    }

    free(wire.data);
    e->main.client_max_body_size = saved_limit;
    return 0;
}

#elif FUZZ_TARGET == FUZZ_WEBSOCKET

/* WebSocket frames off the wire. Not reachable on every deployment -- a server
 * with no websocket route never gets here -- but the code ships with the
 * framework, and what it does is decode a length and a mask the peer chose and
 * then copy that many bytes.
 *
 * Fed as one read rather than two. The parser keeps its position in the
 * connection buffer and the harness in tests/unit/test_websocketsparser.c
 * drives it the same way; splitting reads is worth a target of its own later,
 * since mask-key continuity across a split is its own state. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 16384) size = 16384;

    connection_t conn;
    connection_server_ctx_t ctx;
    char buffer[16384];

    memset(&conn, 0, sizeof conn);
    memset(&ctx, 0, sizeof ctx);
    memcpy(buffer, data, size);

    conn.buffer = buffer;
    conn.buffer_size = sizeof buffer;
    conn.ctx = (connection_ctx_t*)&ctx;

    websocketsparser_t* parser =
        websocketsparser_create(&conn, websockets_protocol_default_create);
    if (parser == NULL) return 0;

    websocketsparser_set_bytes_readed(parser, size);
    parser->pos_start = 0;
    parser->pos = 0;

    (void)websocketsparser_run(parser);

    websocketsparser_free(parser);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_WS_DEFLATE

/* permessage-deflate: the negotiation header and the inflate that follows it.
 *
 * Both halves are the peer's. The header arrives as Sec-WebSocket-Extensions
 * and carries the window bits the inflate context is then built with; the body
 * is compressed data, which is the one thing on this list where a few bytes of
 * input legitimately become many megabytes of output. The output buffer here
 * is deliberately modest for that reason -- the branch that refuses to finish
 * for want of room is the one a caller must not mistake for a complete
 * message.
 *
 * The first byte says how much of the input is the header, so the fuzzer moves
 * the split itself. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;

    size_t header_len = (size_t)data[0] % 128;
    if (header_len > size - 1) header_len = size - 1;

    char header[128];
    for (size_t i = 0; i < header_len; i++) {
        const char ch = (char)data[1 + i];
        header[i] = ch == '\0' ? ' ' : ch;
    }
    header[header_len] = '\0';

    ws_deflate_t d;
    ws_deflate_init(&d);

    /* A header the peer sent may be rejected; the defaults left by init() are
     * what the connection would then run with, so both go on to inflate. */
    (void)ws_deflate_parse_header(header, &d.config);

    if (!ws_deflate_start(&d)) {
        ws_deflate_free(&d);
        return 0;
    }

    const uint8_t* body = data + 1 + header_len;
    const size_t body_len = size - 1 - header_len;

    /* RFC 7692 strips the final empty block off the wire and the caller puts
     * it back, which the header comment for ws_deflate_decompress spells out.
     * A target that skipped it would only ever see truncated streams. */
    char* in = malloc(body_len + 4);
    if (in != NULL) {
        memcpy(in, body, body_len);
        memcpy(in + body_len, "\x00\x00\xff\xff", 4);

        char out[65536];
        (void)ws_deflate_decompress(&d, in, body_len + 4, out, sizeof out);
        while (ws_deflate_has_more(&d))
            if (ws_deflate_decompress(&d, "", 0, out, sizeof out) <= 0) break;

        free(in);
    }

    /* And the way out, with the same bytes: a message the server sends back is
     * built from what it received. */
    char comp[8192];
    (void)ws_deflate_compress(&d, (const char*)body, body_len > 4096 ? 4096 : body_len,
                              comp, sizeof comp, 1);

    ws_deflate_free(&d);

    /* A fresh paired context checks two successive messages, once with and
     * once without context takeover. The random inflate above cannot be used
     * as the oracle: malformed compressed input may have poisoned its state. */
    for (int no_takeover = 0; no_takeover < 2; no_takeover++) {
        ws_deflate_t pair;
        ws_deflate_init(&pair);
        pair.config.server_no_context_takeover = no_takeover;
        pair.config.client_no_context_takeover = no_takeover;
        if (!ws_deflate_start(&pair)) { ws_deflate_free(&pair); continue; }

        const size_t bounded = body_len > 4096 ? 4096 : body_len;
        for (int message = 0; message < 2; message++) {
            const size_t start = message == 0 ? 0 : bounded / 2;
            const size_t length = message == 0 ? bounded / 2 : bounded - start;
            char packed[8192];
            char unpacked[4096];
            const ssize_t packed_len = ws_deflate_compress(
                &pair, (const char*)body + start, length, packed, sizeof packed - 4, 1);
            if (packed_len < 0 || pair.deflate_stream.avail_in != 0)
                __builtin_trap();
            memcpy(packed + packed_len, "\x00\x00\xff\xff", 4);
            const ssize_t plain_len = ws_deflate_decompress(
                &pair, packed, (size_t)packed_len + 4, unpacked, sizeof unpacked);
            if (plain_len != (ssize_t)length ||
                memcmp(unpacked, body + start, length) != 0)
                __builtin_trap();
            ws_deflate_reset_deflate(&pair);
            ws_deflate_reset_inflate(&pair);
        }
        ws_deflate_free(&pair);
    }

    return 0;
}

#elif FUZZ_TARGET == FUZZ_H2_CONNECTION

#include "wscontext.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>

/* A whole HTTP/2 connection through the entry points the event loop uses:
 * h2_server_set_http2() builds the session and writes the server preface,
 * h2_server_guard_read() takes what the client sent off a socket,
 * h2_server_guard_write() pushes out what is queued. The socket is one end of
 * a socketpair with a small send buffer, so writes are short and EAGAIN is
 * ordinary; the other end is the client, which sends the input and reads the
 * server's bytes in amounts a PRNG picks. Reads, writes and the client's own
 * reads interleave in an order the first input byte decides.
 *
 * h2_session feeds the frame layer directly and cannot see the write path at
 * all -- its fd is -1. This target is about that path, so it checks what the
 * server actually put on the wire, the way a strict client would:
 *
 *   - it is a sequence of frames, SETTINGS first, none longer than the
 *     largest SETTINGS_MAX_FRAME_SIZE the client allowed;
 *   - every header block decodes with one HPACK decoder kept for the whole
 *     connection, and pseudo-fields come first;
 *   - HEADERS and DATA only on streams the client opened, DATA after HEADERS,
 *     nothing after END_STREAM or RST_STREAM on that stream;
 *   - DATA never exceeds what the client let the server send: 65535 plus the
 *     client's WINDOW_UPDATEs for the connection, and the largest initial
 *     window the client advertised plus its updates for the stream -- an
 *     upper bound, so a window the client shrank later cannot raise a false
 *     alarm;
 *   - a PING ACK echoes a PING the client sent, SETTINGS ACKs do not outnumber
 *     the client's SETTINGS, GOAWAY's last stream id never grows.
 *
 * Requests are answered from a directory with a small file and one larger
 * than the default 64 KiB window, so a response has to wait for credit. */

#define H2C_STREAMS 256

typedef struct {
    uint32_t id;
    int64_t credit;         /* what the client allowed on this stream, at most */
    int64_t sent;
    int opened, headers, ended;
} h2c_stream_t;

typedef struct {
    /* What the client said, taken from the bytes it actually got onto the socket. */
    uint8_t cbuf[1 << 16];
    size_t clen;
    int cpreface;           /* 0 unseen, 1 seen, -1 not a preface: stop tracking */
    int64_t max_initial;
    uint32_t max_frame;
    int64_t conn_credit;
    size_t settings_sent;
    uint8_t pings[64][8];
    size_t ping_count;

    /* What the server wrote. */
    uint8_t sbuf[1 << 17];
    size_t slen;
    int first_frame;
    int64_t conn_sent;
    size_t frames[10];      /* by type, for FUZZ_TRACE */
    size_t settings_acks;
    uint32_t goaway_last;
    int goaway_seen;
    uint8_t* block;         /* header block being assembled */
    size_t block_len;
    uint32_t block_stream;
    int block_active;
    hpack_decoder_t* hpack;

    h2c_stream_t streams[H2C_STREAMS];
} h2c_t;

static h2c_stream_t* __h2c_stream(h2c_t* c, uint32_t id, int create) {
    for (size_t i = 0; i < H2C_STREAMS; i++) {
        h2c_stream_t* st = &c->streams[(id + i) % H2C_STREAMS];
        if (st->id == id) return st;
        if (st->id == 0) {
            if (!create) return NULL;
            st->id = id;
            st->credit = c->max_initial;
            return st;
        }
    }
    return NULL;
}

static uint32_t __h2c_u32(const uint8_t* p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* The client side: frames the client managed to send. Only what loosens the
 * server's limits is tracked, so a malformed client frame costs precision,
 * never a false report. */
static void __h2c_client_sent(h2c_t* c, const uint8_t* data, size_t len) {
    if (c->cpreface < 0) return;
    if (len > sizeof c->cbuf - c->clen) { c->cpreface = -1; return; }
    memcpy(c->cbuf + c->clen, data, len);
    c->clen += len;

    size_t p = 0;
    if (c->cpreface == 0) {
        if (c->clen < 24) return;
        if (memcmp(c->cbuf, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) != 0) { c->cpreface = -1; return; }
        c->cpreface = 1;
        p = 24;
    }
    while (c->clen - p >= 9) {
        const uint8_t* f = c->cbuf + p;
        const size_t flen = (size_t)f[0] << 16 | (size_t)f[1] << 8 | f[2];
        if (c->clen - p - 9 < flen) break;
        const uint8_t type = f[3], flags = f[4];
        const uint32_t sid = __h2c_u32(f + 5) & 0x7fffffff;
        const uint8_t* pl = f + 9;

        if (type == 0x4 && !(flags & 1) && sid == 0 && flen % 6 == 0) {       /* SETTINGS */
            c->settings_sent++;
            for (size_t i = 0; i < flen; i += 6) {
                const uint16_t id = (uint16_t)(pl[i] << 8 | pl[i + 1]);
                const uint32_t v = __h2c_u32(pl + i + 2);
                if (id == 4 && v <= 0x7fffffff && (int64_t)v > c->max_initial) {
                    /* Every stream may now be credited up to the new value. */
                    for (size_t k = 0; k < H2C_STREAMS; k++)
                        if (c->streams[k].id != 0)
                            c->streams[k].credit += (int64_t)v - c->max_initial;
                    c->max_initial = v;
                }
                if (id == 5 && v > c->max_frame && v <= 0xffffff) c->max_frame = v;
            }
        } else if (type == 0x8 && flen == 4) {                                   /* WINDOW_UPDATE */
            const int64_t inc = __h2c_u32(pl) & 0x7fffffff;
            if (sid == 0) c->conn_credit += inc;
            else {
                h2c_stream_t* st = __h2c_stream(c, sid, 1);
                if (st != NULL) st->credit += inc;
            }
        } else if (type == 0x1 && sid != 0) {                                    /* HEADERS */
            h2c_stream_t* st = __h2c_stream(c, sid, 1);
            if (st != NULL) st->opened = 1;
        } else if (type == 0x6 && !(flags & 1) && flen == 8 && c->ping_count < 64) {
            memcpy(c->pings[c->ping_count++], pl, 8);                            /* PING */
        }
        p += 9 + flen;
    }
    memmove(c->cbuf, c->cbuf + p, c->clen - p);
    c->clen -= p;
}

static int __h2c_block_append(h2c_t* c, const uint8_t* data, size_t len) {
    uint8_t* grown = realloc(c->block, c->block_len + len + 1);
    if (grown == NULL) return 0;
    c->block = grown;
    if (len != 0) memcpy(c->block + c->block_len, data, len);
    c->block_len += len;
    return 1;
}

static void __h2c_header_block(h2c_t* c) {
    hpack_header_t* headers = NULL;
    size_t count = 0;
    if (hpack_decoder_decode(c->hpack, c->block, c->block_len, 1 << 20, &headers, &count)
            != HPACK_OK)
        __builtin_trap();                     /* our encoder wrote what no decoder reads */
    int regular = 0;
    for (size_t i = 0; i < count; i++) {
        if (headers[i].name_len > 0 && headers[i].name[0] == ':') {
            if (regular) __builtin_trap();    /* pseudo-field after a regular one */
        } else {
            regular = 1;
        }
    }
    hpack_headers_free(headers, count);
    c->block_len = 0;
    c->block_active = 0;
}

/* The server side: every byte the client read, checked as it arrives. */
static void __h2c_server_sent(h2c_t* c, const uint8_t* data, size_t len) {
    if (len > sizeof c->sbuf - c->slen) __builtin_trap();
    memcpy(c->sbuf + c->slen, data, len);
    c->slen += len;

    size_t p = 0;
    while (c->slen - p >= 9) {
        const uint8_t* f = c->sbuf + p;
        const size_t flen = (size_t)f[0] << 16 | (size_t)f[1] << 8 | f[2];
        if (getenv("FUZZ_TRACE") != NULL && c->slen - p - 9 >= flen)
            fprintf(stderr, "server frame type %u flags 0x%02x stream %u len %zu\n",
                    f[3], f[4], __h2c_u32(f + 5) & 0x7fffffff, flen);
        if (flen > c->max_frame) __builtin_trap();
        if (c->slen - p - 9 < flen) break;
        const uint8_t type = f[3], flags = f[4];
        const uint32_t sid = __h2c_u32(f + 5) & 0x7fffffff;
        const uint8_t* pl = f + 9;

        if (c->first_frame) {
            if (type != 0x4 || (flags & 1)) __builtin_trap();   /* §3.4: SETTINGS first */
            c->first_frame = 0;
        }
        if (c->block_active && (type != 0x9 || sid != c->block_stream))
            __builtin_trap();                 /* §6.10: CONTINUATION must follow */

        h2c_stream_t* st = sid != 0 ? __h2c_stream(c, sid, 0) : NULL;
        if (type < 10) c->frames[type]++;
        switch (type) {
        case 0x0:                                                        /* DATA */
        case 0x1: {                                                      /* HEADERS */
            if (sid == 0 || st == NULL || !st->opened || st->ended) __builtin_trap();
            size_t body = flen, off = 0;
            if (flags & 0x8) {                                           /* PADDED */
                if (flen == 0 || (size_t)pl[0] + 1 > flen) __builtin_trap();
                body -= (size_t)pl[0] + 1;
                off = 1;
            }
            if (type == 0x0) {
                if (!st->headers) __builtin_trap();
                st->sent += (int64_t)flen;
                c->conn_sent += (int64_t)flen;
                if (st->sent > st->credit || c->conn_sent > c->conn_credit) __builtin_trap();
            } else {
                if (flags & 0x20) {                                      /* PRIORITY */
                    if (body < 5) __builtin_trap();
                    body -= 5;
                    off += 5;
                }
                st->headers = 1;
                if (!__h2c_block_append(c, pl + off, body)) break;
                c->block_stream = sid;
                if (flags & 0x4) __h2c_header_block(c);
                else c->block_active = 1;
            }
            if (flags & 0x1) st->ended = 1;
            break;
        }
        case 0x9:                                                        /* CONTINUATION */
            if (!c->block_active || sid != c->block_stream) __builtin_trap();
            if (!__h2c_block_append(c, pl, flen)) break;
            if (flags & 0x4) __h2c_header_block(c);
            break;
        case 0x3:                                                        /* RST_STREAM */
            if (sid == 0 || flen != 4) __builtin_trap();
            if (st != NULL) st->ended = 1;
            break;
        case 0x4:                                                        /* SETTINGS */
            if (sid != 0 || flen % 6 != 0) __builtin_trap();
            if (flags & 1) {
                if (flen != 0 || ++c->settings_acks > c->settings_sent) __builtin_trap();
            }
            break;
        case 0x6:                                                        /* PING */
            if (sid != 0 || flen != 8) __builtin_trap();
            if (flags & 1) {
                size_t i = 0;
                while (i < c->ping_count && memcmp(c->pings[i], pl, 8) != 0) i++;
                if (i == c->ping_count && c->ping_count < 64) __builtin_trap();
            }
            break;
        case 0x7: {                                                      /* GOAWAY */
            if (sid != 0 || flen < 8) __builtin_trap();
            const uint32_t last = __h2c_u32(pl) & 0x7fffffff;
            if (c->goaway_seen && last > c->goaway_last) __builtin_trap();
            c->goaway_seen = 1;
            c->goaway_last = last;
            break;
        }
        case 0x8:                                                        /* WINDOW_UPDATE */
            if (flen != 4 || (__h2c_u32(pl) & 0x7fffffff) == 0) __builtin_trap();
            break;
        case 0x2:                                                        /* PRIORITY */
            if (flen != 5) __builtin_trap();
            break;
        case 0x5:                                                        /* PUSH_PROMISE */
            __builtin_trap();                 /* never offered, never sent */
        default:
            break;
        }
        p += 9 + flen;
    }
    memmove(c->sbuf, c->sbuf + p, c->slen - p);
    c->slen -= p;
}

static char __h2c_root[64];

static void __h2c_root_remove(void) {
    char path[128];
    snprintf(path, sizeof path, "%s/index.html", __h2c_root);
    unlink(path);
    snprintf(path, sizeof path, "%s/big.bin", __h2c_root);
    unlink(path);
    rmdir(__h2c_root);
}

/* The vhost serves WebSocket, so an RFC 8441 extended CONNECT opens a tunnel
 * rather than getting 501. Every message is answered, so the tunnel's write
 * path -- WebSocket frames inside DATA frames -- runs too. */
static void __h2c_ws_answer(void* arg) {
    wsctx_t* ctx = arg;
    ctx->response->send_text(ctx->response, "ok");
}

/* Once per process: a document root with one small and one large file,
 * removed again when the process exits normally. */
static void __h2c_root_init(void) {
    if (__h2c_root[0] != '\0') return;
    __fuzz_server.websockets.configured = 1;
    __fuzz_server.websockets.default_handler = __h2c_ws_answer;
    if (!connection_queue_init()) abort();
    snprintf(__h2c_root, sizeof __h2c_root, "/tmp/cwfr-fuzz-h2c-%d", (int)getpid());
    if (mkdir(__h2c_root, 0700) != 0) return;
    atexit(__h2c_root_remove);
    char path[128];
    static char big[100000];
    memset(big, 'x', sizeof big);
    snprintf(path, sizeof path, "%s/index.html", __h2c_root);
    FILE* f = fopen(path, "wb");
    if (f != NULL) { fputs("<html>small</html>", f); fclose(f); }
    snprintf(path, sizeof path, "%s/big.bin", __h2c_root);
    f = fopen(path, "wb");
    if (f != NULL) { fwrite(big, 1, sizeof big, f); fclose(f); }
    __fuzz_server.root = __h2c_root;
    __fuzz_server.root_length = strlen(__h2c_root);
}

static int __h2c_pump(h2c_t* c, int fd, size_t want) {
    uint8_t buf[4096];
    int got = 0;
    while (want > 0) {
        const ssize_t n = recv(fd, buf, want < sizeof buf ? want : sizeof buf, 0);
        if (n <= 0) break;
        /* FUZZ_H2C_DUMP=<file>: the raw server byte stream, for a replay. */
        const char* dump = getenv("FUZZ_H2C_DUMP");
        if (dump != NULL) {
            FILE* f = fopen(dump, "ab");
            if (f != NULL) { fwrite(buf, 1, (size_t)n, f); fclose(f); }
        }
        __h2c_server_sent(c, buf, (size_t)n);
        want -= (size_t)n;
        got = 1;
    }
    return got;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    __h2c_root_init();

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0) return 0;
    const int small = 4096;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);

    h2c_t* c = calloc(1, sizeof *c);
    char* buffer = malloc(16384);
    if (c == NULL || buffer == NULL) { free(c); free(buffer); close(sv[0]); close(sv[1]); return 0; }
    c->max_initial = 65535;
    c->max_frame = 16384;
    c->conn_credit = 65535;
    c->first_frame = 1;
    c->hpack = hpack_decoder_create(1 << 16);

    /* The server's own constructor, so the context has its queues and reset
     * hook: the write path ends in connection_after_write(), which uses both. */
    const ipaddr_t loopback = ipaddr_from_v4(0x0100007F);
    connection_t* connection = connection_s_alloc(&__fuzz_listener, sv[0], &loopback, 8080,
                                                  &loopback, 40000, buffer, 16384);
    if (connection == NULL) {
        hpack_decoder_free(c->hpack); free(c); free(buffer); close(sv[0]); close(sv[1]);
        return 0;
    }
    connection_server_ctx_t* ctx = connection->ctx;
    ctx->server = &__fuzz_server;

    int alive = h2_server_set_http2(connection) && c->hpack != NULL;

    uint64_t rng = (uint64_t)data[0] * 0x9E3779B97F4A7C15ULL + 1;
    const uint8_t* p = data + 1;
    const uint8_t* end = data + size;
    for (size_t steps = 0; alive && steps < 100000; steps++) {
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
        const unsigned op = (unsigned)(rng % 4);
        const size_t amount = 1 + (size_t)((rng >> 8) % 512);
        if (p == end && op == 0) break;
        switch (op) {
        case 0: {                                     /* the client sends */
            size_t n = (size_t)(end - p) < amount ? (size_t)(end - p) : amount;
            /* Half the time exactly up to the end of its next frame: a client
             * writes frames, and a RST_STREAM or PING that arrives on its own,
             * while the server is part-way through a frame of its own, is the
             * interleaving that matters. Random cuts rarely produce it. */
            if ((rng >> 20) & 1) {
                size_t at = (size_t)(p - (data + 1));
                size_t boundary = at < 24 ? 24 : 24;
                while (boundary <= at && boundary + 9 <= size - 1) {
                    const uint8_t* f = data + 1 + boundary;
                    boundary += 9 + ((size_t)f[0] << 16 | (size_t)f[1] << 8 | f[2]);
                }
                if (boundary > at && boundary - at < n) n = boundary - at;
            }
            const ssize_t w = send(sv[1], p, n, MSG_NOSIGNAL);
            if (w > 0) { __h2c_client_sent(c, p, (size_t)w); p += w; }
            break;
        }
        case 1: alive = h2_server_guard_read(connection); break;
        case 2:
            /* Handlers queued since the last write have run by now. */
            while (__fuzz_worker()) {}
            alive = h2_server_guard_write(connection);
            break;
        case 3: (void)__h2c_pump(c, sv[1], amount * 8); break;
        }
    }

    /* Drain: whatever the server still has to say, until it stops. */
    for (int idle = 0; idle < 3;) {
        if (alive) alive = h2_server_guard_read(connection);
        while (__fuzz_worker()) {}
        if (alive) alive = h2_server_guard_write(connection);
        idle = __h2c_pump(c, sv[1], SIZE_MAX) ? 0 : idle + 1;
    }

    /* Quiet and still alive, the server must have stopped on a frame
     * boundary. A DATA frame is only started with window for all of it, so a
     * frame left half-written -- a stream dropped mid-frame, say -- is one the
     * client will wait on forever. */
    if (alive && c->slen != 0) __builtin_trap();

    /* Teardown as in h2_session: the loop that would retire responses and
     * clear handler flags is not here. */
    if (getenv("FUZZ_TRACE") != NULL) {
        size_t ended = 0;
        for (size_t i = 0; i < H2C_STREAMS; i++) ended += c->streams[i].ended;
        fprintf(stderr, "server frames: DATA %zu HEADERS %zu RST %zu SETTINGS %zu PING %zu "
                "GOAWAY %zu WINDOW_UPDATE %zu CONTINUATION %zu; DATA bytes %lld; "
                "streams ended %zu; client credit %lld\n",
                c->frames[0], c->frames[1], c->frames[3], c->frames[4], c->frames[6],
                c->frames[7], c->frames[8], c->frames[9], (long long)c->conn_sent, ended,
                (long long)c->conn_credit);
    }

    /* The response pool goes with the session. (h2_server_take_response is no
     * way to empty it: on an empty pool it makes a new response.) */
    while (__fuzz_worker()) {}
    h2session_t* s = ctx->parser;
    if (s != NULL) {
        for (h2stream_t* st = s->streams; st != NULL; st = st->next)
            atomic_store_explicit(&st->handler_pending, 0, memory_order_release);
    }
    connection_s_free_local(connection);   /* frees the session with the context */

    hpack_decoder_free(c->hpack);
    free(c->block);
    free(c);
    free(buffer);
    close(sv[0]);
    close(sv[1]);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_H1_CONNECTION

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <zlib.h>

#include <openssl/evp.h>

#include "helpers.h"
#include "httpgzipcache.h"
#include "httpserverhandlers.h"
#include "route.h"
#include "websocketsswitch.h"

/* A whole HTTP/1.1 connection serving static files, through the entry points
 * the event loop uses: set_http(), http_server_guard_read() and
 * http_server_guard_write() on one end of a socketpair with small buffers, so
 * writes are short and EAGAIN is ordinary. The other end is a strict client.
 *
 * request_sequence stops at the parser; this is everything after it -- the
 * dispatcher, the file lookup and the filter chain (not_modified, range, data,
 * gzip, chunked, write) -- which no other target reaches.
 *
 * The client builds its requests from the input, so what each answer must be
 * is known: a file of known bytes, a Range header in a form whose outcome RFC
 * 9110 §14 fixes or in a mangled one, If-None-Match and If-Modified-Since
 * (§13.1), Accept-Encoding (§12.5.3), Connection: close, one request at a time
 * or pipelined. The server's gzip is set up three ways by the input: compressed
 * as it goes, from the in-memory cache, or from a ".gz" next to the file.
 *
 * Every response is checked the way a strict client would read it:
 *   - framing: one status line, well-formed fields, Content-Length or chunked
 *     (never both), no body for HEAD and 304, nothing after a close;
 *   - 200: the file, or its gzip that inflates to the file, and gzip only when
 *     the request allowed it; a satisfiable Range in an unambiguous form must
 *     not be ignored;
 *   - 206: each part is the matching slice of the representation, and lies
 *     inside what was asked for -- exactly what was asked for, where the form
 *     leaves no choice;
 *   - 416: Content-Range "bytes *" + the length, and only when nothing asked
 *     for was satisfiable;
 *   - 304 exactly when a validator matched, never otherwise;
 *   - Last-Modified is the file's, and the ETag carries "-gzip" exactly when a
 *     200 is compressed, and stays the same for the same representation.
 *
 * FUZZ_TRACE=1 prints each request and the status it got. */

#define H1C_T0 ((time_t)1700000000)
#define H1C_FILES 4
#define H1C_REQUESTS 12

typedef struct {
    const char* name;
    size_t size;
    uint8_t* data;
} h1c_file_t;

static h1c_file_t __h1c_files[H1C_FILES] = {
    { "empty.txt", 0, NULL },
    { "small.txt", 700, NULL },       /* below the gzip threshold */
    { "page.txt", 50000, NULL },      /* compressible, with a ".gz" beside it */
    { "noise.txt", 20000, NULL },     /* compressible type, incompressible bytes */
};
static uint8_t* __h1c_gz;             /* page.txt.gz as written */
static size_t __h1c_gz_len;
static char __h1c_root[64];
static char __h1c_date[64];           /* the Last-Modified of every file */

/* The event loop's side of the socket: what the server last asked epoll to
 * wait for. The HTTP/1.1 handlers are only ever called for an event they armed
 * -- __write without a response to write is an error, and rightly -- so the
 * shared stub that says yes to everything and remembers nothing will not do.
 * A one-shot arming is used up by the event it delivers. */
static int __h1c_armed;

static int __h1c_mpx_arm(connection_t* connection, int flags) {
    (void)connection;
    __h1c_armed = flags;
    return 1;
}

static int __h1c_mpx_del(connection_t* connection) {
    (void)connection;
    __h1c_armed = 0;
    return 1;
}

static mpxapi_t __h1c_mpxapi = {
    .control_add = __h1c_mpx_arm,
    .control_mod = __h1c_mpx_arm,
    .control_del = __h1c_mpx_del,
};

static int __h1c_event(connection_t* connection, int event) {
    if (!(__h1c_armed & event)) return 1;                 /* epoll would not call */
    /* multiplexingepoll.c: a connection marked destroyed -- the write path's
     * way of saying "close after this response" -- is closed on its next
     * event, whatever the event is. */
    const connection_server_ctx_t* ctx = connection->ctx;
    if (atomic_load(&ctx->destroyed)) return 0;
    if (__h1c_armed & MPXONESHOT) __h1c_armed = 0;
    const int alive = event == MPXIN ? http_server_guard_read(connection)
                                     : http_server_guard_write(connection);
    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "server %s -> %d, armed 0x%x\n",
                event == MPXIN ? "read" : "write", alive, __h1c_armed);
    return alive;
}

/* What an application does to accept WebSocket on a route: its handler calls
 * switch_to_websockets(). The target serves it on /ws. */
static void __h1c_ws_handler(void* arg) {
    switch_to_websockets(arg);
}

/* The two switches http_policy_init() reads, set per input. */
static int __h1c_static, __h1c_cache;

long long env_get_llong(const char* key, long long default_value) {
    if (key != NULL && strcmp(key, "gzip_cache_size") == 0)
        return __h1c_cache ? 1 << 20 : 0;
    return default_value;
}

int env_get_bool(const char* key, int default_value) {
    if (key != NULL && strcmp(key, "gzip_static") == 0) return __h1c_static;
    return default_value;
}

static size_t __h1c_gzip(const uint8_t* in, size_t len, uint8_t** out) {
    z_stream z;
    memset(&z, 0, sizeof z);
    if (deflateInit2(&z, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return 0;
    const size_t cap = deflateBound(&z, len) + 64;
    *out = malloc(cap);
    if (*out == NULL) { deflateEnd(&z); return 0; }
    z.next_in = (Bytef*)in;
    z.avail_in = (uInt)len;
    z.next_out = *out;
    z.avail_out = (uInt)cap;
    const int r = deflate(&z, Z_FINISH);
    deflateEnd(&z);
    if (r != Z_STREAM_END) { free(*out); *out = NULL; return 0; }
    return cap - z.avail_out;
}

/* 1 when `in` is exactly one gzip member that inflates to `want`. */
static int __h1c_gunzip_equals(const uint8_t* in, size_t len, const uint8_t* want, size_t want_len) {
    z_stream z;
    memset(&z, 0, sizeof z);
    if (inflateInit2(&z, 15 + 16) != Z_OK) return 0;
    uint8_t* out = malloc(want_len + 1);
    if (out == NULL) { inflateEnd(&z); return 0; }
    z.next_in = (Bytef*)in;
    z.avail_in = (uInt)len;
    z.next_out = out;
    z.avail_out = (uInt)(want_len + 1);
    const int r = inflate(&z, Z_FINISH);
    const int ok = r == Z_STREAM_END && z.avail_in == 0 && z.total_out == want_len &&
                   (want_len == 0 || memcmp(out, want, want_len) == 0);
    inflateEnd(&z);
    free(out);
    return ok;
}

static void __h1c_root_remove(void) {
    char path[160];
    for (size_t i = 0; i < H1C_FILES; i++) {
        snprintf(path, sizeof path, "%s/%s", __h1c_root, __h1c_files[i].name);
        unlink(path);
    }
    snprintf(path, sizeof path, "%s/page.txt.gz", __h1c_root);
    unlink(path);
    rmdir(__h1c_root);
}

static int __h1c_write_file(const char* name, const uint8_t* data, size_t len, time_t mtime) {
    char path[160];
    snprintf(path, sizeof path, "%s/%s", __h1c_root, name);
    FILE* f = fopen(path, "wb");
    if (f == NULL) return 0;
    const int ok = len == 0 || fwrite(data, 1, len, f) == len;
    fclose(f);
    const struct timeval times[2] = { { mtime, 0 }, { mtime, 0 } };
    return ok && utimes(path, times) == 0;
}

/* Once per process: the document root, removed again at a normal exit. */
static void __h1c_root_init(void) {
    if (__h1c_root[0] != '\0') return;
    snprintf(__h1c_root, sizeof __h1c_root, "/tmp/cwfr-fuzz-h1c-%d", (int)getpid());
    if (mkdir(__h1c_root, 0700) != 0) abort();
    atexit(__h1c_root_remove);

    uint64_t x = 0x9E3779B97F4A7C15ULL;
    for (size_t i = 0; i < H1C_FILES; i++) {
        h1c_file_t* f = &__h1c_files[i];
        f->data = malloc(f->size + 1);
        if (f->data == NULL) abort();
        if (i == 3) {
            for (size_t k = 0; k < f->size; k++) {
                x ^= x << 13; x ^= x >> 7; x ^= x << 17;
                f->data[k] = (uint8_t)x;
            }
        } else {
            for (size_t k = 0; k < f->size; k++)
                f->data[k] = (uint8_t)("line of the page, number "[k % 25] + (k / 997) % 3);
        }
        if (!__h1c_write_file(f->name, f->data, f->size, H1C_T0)) abort();
    }

    /* Newer than its source, or __try_gzip_static rightly refuses it. */
    __h1c_gz_len = __h1c_gzip(__h1c_files[2].data, __h1c_files[2].size, &__h1c_gz);
    if (__h1c_gz_len == 0 || !__h1c_write_file("page.txt.gz", __h1c_gz, __h1c_gz_len, H1C_T0 + 10))
        abort();

    if (http_format_date(H1C_T0, __h1c_date, sizeof __h1c_date) == 0) abort();

    __fuzz_server.root = __h1c_root;
    __fuzz_server.root_length = strlen(__h1c_root);
    __fuzz_listener.api = &__h1c_mpxapi;
    if (!connection_queue_init()) abort();

    route_t* ws = route_create("/ws");
    if (ws == NULL || !route_set_http_handler(ws, "GET", __h1c_ws_handler, NULL)) abort();
    __fuzz_server.http.route = ws;

    /* No mime table here, so every file is text/plain -- which main.gzip lists. */
    static char type[] = "text/plain";
    static env_gzip_str_t gzip_type = { .mimetype = type, .next = NULL };
    env()->main.gzip = &gzip_type;
}

/* A byte range as the client asked for it: a == -1 is the suffix form "-b",
 * b == -1 the open form "a-". */
typedef struct {
    long long a, b;
} h1c_spec_t;

typedef struct {
    int upgrade;             /* a WebSocket handshake to /ws (RFC 6455 §4.1) */
    int ws_status;           /* ... the status it must get: 101, 400 or 426 */
    int ws_offered_ext;      /* ... it offered Sec-WebSocket-Extensions */
    char ws_accept[32];      /* ... and the accept value a 101 must carry */
    int file, head, post, close;
    int expect;              /* Expect: 100-continue, on a POST with a body */
    int continued;           /* ... and the 100 has been seen */
    int ae_gzip;             /* the Accept-Encoding sent allows gzip */
    int ranged;              /* a Range field was sent */
    int exact;               /* ... one range, outcome fixed by the RFC */
    int clean;               /* ... ascending, disjoint: honoured as sent */
    size_t nspecs;           /* 0 for a mangled one */
    h1c_spec_t specs[4];
    int inm;
    char inm_value[256];
    int ims, ims_valid;
    time_t ims_time;
} h1c_req_t;

typedef struct {
    int status;
    int has_clen, chunked, gzip, conn_close;
    int upgrade_ws, conn_upgrade, has_ws_ext;
    char ws_accept[200], ws_version[200];
    unsigned long long clen;
    char crange[200], ctype[200], etag[200], lastmod[200];
    int has_crange, has_etag, has_lastmod;
    uint8_t* body;
    size_t body_len;
} h1c_resp_t;

typedef struct {
    int raw;
    size_t depth;                    /* requests in flight at most */

    uint8_t* out;                    /* what the client still has to send */
    size_t out_len, out_pos, out_cap;

    h1c_req_t reqs[H1C_REQUESTS];
    size_t queued, answered;
    int close_sent;                  /* a request with Connection: close went out */
    int closing;                     /* the server said or was asked to close */
    int eof;
    int switched;                    /* a 101 came: the rest is WebSocket */

    uint8_t* in;                     /* what the server sent, not yet parsed */
    size_t in_len, in_cap;

    char etag[H1C_FILES][2][200];    /* seen ETags: [file][gzip] */
    uint8_t* repr[H1C_FILES];        /* a gzip representation seen in a 200 */
    size_t repr_len[H1C_FILES];
} h1c_t;

static void __h1c_append(uint8_t** buf, size_t* len, size_t* cap, const void* data, size_t n) {
    if (*len + n > *cap) {
        size_t c = *cap ? *cap : 4096;
        while (c < *len + n) c *= 2;
        uint8_t* grown = realloc(*buf, c);
        if (grown == NULL) abort();
        *buf = grown;
        *cap = c;
    }
    memcpy(*buf + *len, data, n);
    *len += n;
}

static uint8_t __h1c_byte(const uint8_t** p, const uint8_t* end) {
    return *p < end ? *(*p)++ : 0;
}

/* Offsets that matter for a file of `size` bytes, and one past the parser's
 * ten-digit limit's edge. */
static long long __h1c_offset(uint8_t b, size_t size) {
    switch (b % 10) {
    case 0: return 0;
    case 1: return 1;
    case 2: return (long long)size / 2;
    case 3: return size > 0 ? (long long)size - 1 : 0;
    case 4: return (long long)size;
    case 5: return (long long)size + 1;
    case 6: return (long long)size + 1000;
    case 7: return 9999999999LL;
    default: return (long long)((b * 2654435761u) % (size + 2));
    }
}

static int __h1c_spec_text(char* dst, size_t cap, const h1c_spec_t* s) {
    if (s->a < 0) return snprintf(dst, cap, "-%lld", s->b);
    if (s->b < 0) return snprintf(dst, cap, "%lld-", s->a);
    return snprintf(dst, cap, "%lld-%lld", s->a, s->b);
}

/* RFC 9110 §14.1.2 against a representation of `len` bytes: 1 and the
 * inclusive [first, last] when satisfiable. */
static int __h1c_resolve(const h1c_spec_t* s, unsigned long long len,
                         unsigned long long* first, unsigned long long* last) {
    if (s->a < 0) {
        if (s->b <= 0 || len == 0) return 0;
        const unsigned long long n = (unsigned long long)s->b < len ? (unsigned long long)s->b : len;
        *first = len - n;
        *last = len - 1;
        return 1;
    }
    if ((unsigned long long)s->a >= len) return 0;
    *first = (unsigned long long)s->a;
    *last = s->b < 0 || (unsigned long long)s->b >= len ? len - 1 : (unsigned long long)s->b;
    return 1;
}

/* RFC 6455 §4.2.2 item 5.4: base64(SHA-1(key + GUID)), computed here with
 * OpenSSL rather than with the code under test. */
static void __h1c_ws_accept(const char* key, size_t key_len, char* out) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t buf[256 + sizeof guid];
    memcpy(buf, key, key_len);
    memcpy(buf + key_len, guid, sizeof guid - 1);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_Digest(buf, key_len + sizeof guid - 1, digest, &dlen, EVP_sha1(), NULL);
    EVP_EncodeBlock((unsigned char*)out, digest, (int)dlen);
}

/* A handshake with each of its parts right or wrong, and the answer that
 * RFC 6455 §4.2.1-4.2.2 fixes for it. */
static int __h1c_generate_upgrade(h1c_t* c, h1c_req_t* r, const uint8_t** p, const uint8_t* end) {
    r->upgrade = 1;
    const uint8_t b = __h1c_byte(p, end);

    static const struct { const char* value; int ok; } upgrades[] = {
        { "websocket", 1 }, { "WebSocket", 1 }, { "h2c", 0 }, { NULL, 0 },
    };
    static const struct { const char* value; int ok; } connections[] = {
        { "Upgrade", 1 }, { "keep-alive, Upgrade", 1 }, { "keep-alive", 0 }, { NULL, 0 },
    };
    static const char* const versions[] = { "13", "13", "8", NULL };
    const int up = b % 4, co = (b >> 2) % 4, ve = (b >> 4) % 4;

    /* The key: 16 bytes from the input, base64 -- or one of the wrong shapes. */
    char key[260];
    int key_ok = 0;
    const uint8_t kb = __h1c_byte(p, end);
    switch (kb % 6) {
    case 0: case 1: case 2: {
        uint8_t raw[16];
        for (size_t i = 0; i < sizeof raw; i++) raw[i] = __h1c_byte(p, end);
        EVP_EncodeBlock((unsigned char*)key, raw, sizeof raw);
        key_ok = 1;
        break;
    }
    case 3: {                                      /* long: the old stack overflow */
        const size_t len = 92 + __h1c_byte(p, end) % 160;          /* < sizeof key */
        memset(key, 'A', len);
        key[len] = '\0';
        break;
    }
    case 4: snprintf(key, sizeof key, "c2hvcnQ="); break;          /* 5 bytes */
    default: key[0] = '\0'; break;                                  /* none */
    }

    const int valid = upgrades[up].ok && connections[co].ok && key_ok;
    r->ws_status = !valid ? 400 : (ve < 2 ? 101 : 426);
    if (r->ws_status == 101) __h1c_ws_accept(key, strlen(key), r->ws_accept);

    char req[768];
    int n = snprintf(req, sizeof req, "GET /ws HTTP/1.1\r\nHost: localhost\r\n");
    if (upgrades[up].value != NULL)
        n += snprintf(req + n, sizeof req - (size_t)n, "Upgrade: %s\r\n", upgrades[up].value);
    if (connections[co].value != NULL)
        n += snprintf(req + n, sizeof req - (size_t)n, "Connection: %s\r\n", connections[co].value);
    if (versions[ve] != NULL)
        n += snprintf(req + n, sizeof req - (size_t)n, "Sec-WebSocket-Version: %s\r\n", versions[ve]);
    if (key[0] != '\0')
        n += snprintf(req + n, sizeof req - (size_t)n, "Sec-WebSocket-Key: %s\r\n", key);
    if (b & 0x80) {
        static const char* const offers[] = {
            "permessage-deflate", "permessage-deflate; client_max_window_bits",
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            "permessage-deflate; server_max_window_bits=9", "x-unknown",
        };
        r->ws_offered_ext = 1;
        n += snprintf(req + n, sizeof req - (size_t)n, "Sec-WebSocket-Extensions: %s\r\n",
                      offers[__h1c_byte(p, end) % 5]);
    }
    n += snprintf(req + n, sizeof req - (size_t)n, "\r\n");

    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "request %zu:\n%.*s", c->queued, n, req);

    __h1c_append(&c->out, &c->out_len, &c->out_cap, req, (size_t)n);
    c->queued++;
    return 1;
}

/* One request from the input onto the client's output. 0 when the input has
 * run out. */
static int __h1c_generate(h1c_t* c, const uint8_t** p, const uint8_t* end) {
    if (*p >= end || c->queued == H1C_REQUESTS || c->close_sent || c->closing || c->switched)
        return 0;
    /* After a handshake that may switch, nothing is HTTP until its answer is in. */
    if (c->queued > 0 && c->reqs[c->queued - 1].upgrade && c->answered < c->queued) return 0;

    h1c_req_t* r = &c->reqs[c->queued];
    memset(r, 0, sizeof *r);
    const uint8_t b0 = __h1c_byte(p, end);

    if (b0 >= 0xE0) return __h1c_generate_upgrade(c, r, p, end);
    r->file = b0 % H1C_FILES;
    r->head = (b0 >> 2) % 5 == 0;
    r->post = (b0 >> 2) % 5 == 1;
    const size_t size = __h1c_files[r->file].size;

    char req[1024];
    int n = snprintf(req, sizeof req, "%s /%s HTTP/1.1\r\nHost: localhost\r\n",
                     r->head ? "HEAD" : r->post ? "POST" : "GET", __h1c_files[r->file].name);

    /* A POST carries a body the server has to step over to find the next
     * request; with Expect it may first say 100 Continue (RFC 9110 §10.1.1). */
    uint8_t body[64];
    size_t body_len = 0;
    if (r->post) {
        const uint8_t b = __h1c_byte(p, end);
        body_len = b % sizeof body;
        r->expect = (b & 0x40) != 0;
        for (size_t i = 0; i < body_len; i++) body[i] = __h1c_byte(p, end);
        n += snprintf(req + n, sizeof req - (size_t)n, "Content-Length: %zu\r\n%s", body_len,
                      r->expect ? "Expect: 100-continue\r\n" : "");
    }

    /* Range. */
    char range[256] = "";
    const uint8_t kind = __h1c_byte(p, end) % 8;
    if (kind >= 3 && kind <= 5) {
        h1c_spec_t* s = &r->specs[0];
        s->a = kind == 5 ? -1 : __h1c_offset(__h1c_byte(p, end), size);
        s->b = kind == 4 ? -1 : __h1c_offset(__h1c_byte(p, end), size);
        if (kind == 3 && s->a > s->b) { const long long t = s->a; s->a = s->b; s->b = t; }
        r->nspecs = 1;
        r->exact = 1;
    } else if (kind == 6) {
        r->nspecs = 2 + __h1c_byte(p, end) % 3;
        r->clean = 1;
        for (size_t i = 0; i < r->nspecs; i++) {
            h1c_spec_t* s = &r->specs[i];
            const uint8_t form = __h1c_byte(p, end) % 3;
            s->a = form == 2 ? -1 : __h1c_offset(__h1c_byte(p, end), size);
            s->b = form == 1 ? -1 : __h1c_offset(__h1c_byte(p, end), size);
            if (form == 0 && s->a > s->b) { const long long t = s->a; s->a = s->b; s->b = t; }
            /* Clean: explicit, ascending, disjoint ranges, where only the last
             * may be open or a suffix -- the only lists the RFC leaves the
             * server no latitude on besides serving them as they are. */
            if (i + 1 < r->nspecs && form != 0) r->clean = 0;
            if (i > 0) {
                const h1c_spec_t* prev = &r->specs[i - 1];
                if (s->a >= 0 && s->a <= prev->b) r->clean = 0;
            }
        }
    }
    if (r->nspecs > 0) {
        size_t at = (size_t)snprintf(range, sizeof range, "bytes=");
        for (size_t i = 0; i < r->nspecs; i++) {
            if (i > 0) at += (size_t)snprintf(range + at, sizeof range - at,
                                               __h1c_byte(p, end) & 1 ? ", " : ",");
            at += (size_t)__h1c_spec_text(range + at, sizeof range - at, &r->specs[i]);
        }
    } else if (kind == 7) {
        /* Mangled: anything the parser may accept or ignore. */
        static const char alphabet[] = "0123456789-, =b";
        size_t at = (size_t)snprintf(range, sizeof range, "%s",
                                     __h1c_byte(p, end) & 1 ? "bytes=" : "bytes=0");
        const size_t len = __h1c_byte(p, end) % 16;
        for (size_t i = 0; i < len; i++)
            range[at++] = alphabet[__h1c_byte(p, end) % (sizeof alphabet - 1)];
        range[at] = '\0';
    }
    if (range[0] != '\0') {
        r->ranged = 1;
        n += snprintf(req + n, sizeof req - (size_t)n, "Range: %s\r\n", range);
    }

    /* Validators. The ETags offered are the ones this connection has seen. */
    const uint8_t cond = __h1c_byte(p, end) % 6;
    if (cond == 2 || cond == 4 || cond == 5) {
        r->inm = 1;
        const uint8_t pick = __h1c_byte(p, end);
        const char* seen = c->etag[r->file][pick & 1];
        if (cond == 5) snprintf(r->inm_value, sizeof r->inm_value, "*");
        else if (seen[0] == '\0' || (pick >> 1) % 4 == 0)
            snprintf(r->inm_value, sizeof r->inm_value, "\"nope\"");
        else if ((pick >> 1) % 4 == 1)
            snprintf(r->inm_value, sizeof r->inm_value, "\"x\", %s", seen);
        else if ((pick >> 1) % 4 == 2 && strncmp(seen, "W/", 2) == 0)
            snprintf(r->inm_value, sizeof r->inm_value, "%s", seen + 2);   /* weak compare */
        else
            snprintf(r->inm_value, sizeof r->inm_value, "%s", seen);
        n += snprintf(req + n, sizeof req - (size_t)n, "If-None-Match: %s\r\n", r->inm_value);
    }
    if (cond == 3 || cond == 4) {
        r->ims = 1;
        const uint8_t pick = __h1c_byte(p, end) % 4;
        char date[64] = "yesterday";
        if (pick < 3) {
            r->ims_valid = 1;
            r->ims_time = H1C_T0 + (pick == 0 ? -1000 : pick == 1 ? 0 : 1000);
            http_format_date(r->ims_time, date, sizeof date);
        }
        n += snprintf(req + n, sizeof req - (size_t)n, "If-Modified-Since: %s\r\n", date);
    }

    /* Accept-Encoding, and whether RFC 9110 §12.5.3 lets it take gzip. */
    static const struct { const char* value; int gzip; } encodings[] = {
        { NULL, 0 }, { "gzip", 1 }, { "gzip;q=0", 0 }, { "deflate, gzip;q=0.5", 1 },
        { "identity", 0 }, { "*", 1 }, { "*;q=0", 0 }, { "GZIP", 1 },
    };
    const uint8_t ae = __h1c_byte(p, end) % 8;
    r->ae_gzip = encodings[ae].gzip;
    if (encodings[ae].value != NULL)
        n += snprintf(req + n, sizeof req - (size_t)n, "Accept-Encoding: %s\r\n", encodings[ae].value);

    if (__h1c_byte(p, end) % 8 == 0 || *p >= end) {
        r->close = 1;
        n += snprintf(req + n, sizeof req - (size_t)n, "Connection: close\r\n");
    }
    n += snprintf(req + n, sizeof req - (size_t)n, "\r\n");

    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "request %zu:\n%.*s", c->queued, n, req);

    __h1c_append(&c->out, &c->out_len, &c->out_cap, req, (size_t)n);
    if (body_len > 0) __h1c_append(&c->out, &c->out_len, &c->out_cap, body, body_len);
    c->queued++;
    if (r->close) c->close_sent = 1;
    return 1;
}

/* RFC 9110 §13.1.2: weak comparison, a list, or "*". */
static int __h1c_inm_matches(const char* list, const char* etag) {
    const char* e = strncmp(etag, "W/", 2) == 0 ? etag + 2 : etag;
    const size_t elen = strlen(e);
    const char* s = list;
    while (*s != '\0') {
        while (*s == ' ' || *s == ',') s++;
        const char* t = s;
        while (*t != '\0' && *t != ',') t++;
        const char* te = t;
        while (te > s && te[-1] == ' ') te--;
        if (te - s == 1 && *s == '*') return 1;
        const char* v = strncmp(s, "W/", 2) == 0 ? s + 2 : s;
        if ((size_t)(te - v) == elen && memcmp(v, e, elen) == 0) return 1;
        s = t;
    }
    return 0;
}

static int __h1c_parse_crange(const char* v, unsigned long long* a, unsigned long long* b,
                              unsigned long long* total, int* star) {
    char back[96];
    *star = 0;
    if (sscanf(v, "bytes */%llu", total) == 1) {
        snprintf(back, sizeof back, "bytes */%llu", *total);
        *star = 1;
        return strcmp(back, v) == 0;
    }
    if (sscanf(v, "bytes %llu-%llu/%llu", a, b, total) != 3) return 0;
    snprintf(back, sizeof back, "bytes %llu-%llu/%llu", *a, *b, *total);
    return strcmp(back, v) == 0 && *a <= *b && *b < *total;
}

typedef struct {
    unsigned long long a, b, total;
    const uint8_t* data;
} h1c_part_t;

/* multipart/byteranges (RFC 9110 §14.6), read strictly: every part's length
 * comes from its own Content-Range, so bytes that look like the boundary inside
 * a part are just bytes. Returns the part count, 0 when malformed. */
static size_t __h1c_multipart(const h1c_resp_t* rs, h1c_part_t* parts, size_t max) {
    const char* bp = strstr(rs->ctype, "boundary=");
    if (bp == NULL) return 0;
    const char* boundary = bp + 9;
    const size_t blen = strlen(boundary);
    const uint8_t* s = rs->body;
    const uint8_t* e = rs->body + rs->body_len;
    size_t count = 0;

    if (e - s >= 2 && s[0] == '\r' && s[1] == '\n') s += 2;
    for (;;) {
        if ((size_t)(e - s) < 2 + blen || s[0] != '-' || s[1] != '-' ||
            memcmp(s + 2, boundary, blen) != 0) return 0;
        s += 2 + blen;
        if (e - s >= 2 && s[0] == '-' && s[1] == '-') {
            s += 2;
            if (e - s >= 2 && s[0] == '\r' && s[1] == '\n') s += 2;
            return s == e && count > 0 ? count : 0;
        }
        if (e - s < 2 || s[0] != '\r' || s[1] != '\n' || count == max) return 0;
        s += 2;

        int have_range = 0;
        h1c_part_t* part = &parts[count];
        for (;;) {
            const uint8_t* eol = memchr(s, '\n', (size_t)(e - s));
            if (eol == NULL || eol == s || eol[-1] != '\r') return 0;
            const size_t len = (size_t)(eol - 1 - s);
            if (len == 0) { s = eol + 1; break; }
            char line[160];
            if (len >= sizeof line) return 0;
            memcpy(line, s, len);
            line[len] = '\0';
            if (strncasecmp(line, "Content-Range: ", 15) == 0) {
                int star = 0;
                if (!__h1c_parse_crange(line + 15, &part->a, &part->b, &part->total, &star) || star)
                    return 0;
                have_range = 1;
            }
            s = eol + 1;
        }
        if (!have_range) return 0;
        const unsigned long long n = part->b - part->a + 1;
        if ((unsigned long long)(e - s) < n + 2) return 0;
        part->data = s;
        s += n;
        if (s[0] != '\r' || s[1] != '\n') return 0;
        s += 2;
        count++;
    }
}

/* Every byte of [a, b] lies inside some range the request asked for. */
static int __h1c_covered(const h1c_req_t* r, unsigned long long len,
                         unsigned long long a, unsigned long long b) {
    unsigned long long pos = a;
    while (pos <= b) {
        int moved = 0;
        for (size_t i = 0; i < r->nspecs; i++) {
            unsigned long long f, l;
            if (__h1c_resolve(&r->specs[i], len, &f, &l) && f <= pos && pos <= l) {
                if (l >= b) return 1;
                pos = l + 1;
                moved = 1;
            }
        }
        if (!moved) return 0;
    }
    return 1;
}

static void __h1c_check(h1c_t* c, const h1c_req_t* r, const h1c_resp_t* rs) {
    const h1c_file_t* f = &__h1c_files[r->file];

    if (r->upgrade) {
        if (getenv("FUZZ_TRACE") != NULL)
            fprintf(stderr, "  -> %d (handshake, expected %d)\n", rs->status, r->ws_status);
        if (rs->status != r->ws_status) __builtin_trap();
        if (rs->status == 101) {
            if (!rs->upgrade_ws || !rs->conn_upgrade) __builtin_trap();
            if (strcmp(rs->ws_accept, r->ws_accept) != 0) __builtin_trap();
            if (rs->has_ws_ext && !r->ws_offered_ext) __builtin_trap();   /* §9.1 */
            c->switched = 1;
            return;
        }
        if (rs->upgrade_ws) __builtin_trap();                           /* no switch */
        if (rs->status == 426 && strcmp(rs->ws_version, "13") != 0) __builtin_trap();
        return;
    }

    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "  -> %d, %zu body bytes%s%s%s\n", rs->status, rs->body_len,
                rs->gzip ? ", gzip" : "", rs->has_crange ? ", " : "", rs->has_crange ? rs->crange : "");

    if (rs->status != 200 && rs->status != 206 && rs->status != 304 && rs->status != 416 &&
        !(rs->status == 412 && r->post))
        __builtin_trap();
    if (rs->gzip && !r->ae_gzip) __builtin_trap();                  /* §12.5.3 */
    if (rs->has_clen && rs->chunked) __builtin_trap();              /* RFC 9112 §6.1 */
    if (!rs->has_lastmod || strcmp(rs->lastmod, __h1c_date) != 0) __builtin_trap();
    if (!rs->has_etag) __builtin_trap();

    /* One ETag per representation, the gzip one marked. */
    const size_t etlen = strlen(rs->etag);
    const int gz_tag = etlen >= 6 && strcmp(rs->etag + etlen - 6, "-gzip\"") == 0;
    char* seen = c->etag[r->file][gz_tag];
    if (seen[0] == '\0') snprintf(seen, sizeof c->etag[0][0], "%s", rs->etag);
    else if (strcmp(seen, rs->etag) != 0) __builtin_trap();
    if (strcmp(c->etag[r->file][0], c->etag[r->file][1]) == 0) __builtin_trap();

    /* §13.1.2 and §13.1.3: If-None-Match wins; If-Modified-Since only without
     * it, and only for GET and HEAD. A matching If-None-Match on any other
     * method is 412, not 304. */
    const int inm_match = r->inm && __h1c_inm_matches(r->inm_value, rs->etag);
    const int ims_match = !r->post && !r->inm && r->ims && r->ims_valid && r->ims_time >= H1C_T0;
    if (r->post) {
        if (rs->status == 304) __builtin_trap();
        if (rs->status == 412 && !inm_match) __builtin_trap();
        if (rs->status == 412) return;
    } else if ((rs->status == 304) != (inm_match || ims_match)) {
        __builtin_trap();
    }
    if (rs->status == 304) {
        if (rs->body_len != 0) __builtin_trap();
        return;
    }

    if (rs->status == 200) {
        /* A Range in a form the server must understand was ignored. */
        if (!r->post && (r->exact || r->clean)) __builtin_trap();
        if (gz_tag != rs->gzip) __builtin_trap();
        if (r->head) {
            if (rs->body_len != 0) __builtin_trap();
            if (!rs->gzip && rs->has_clen && rs->clen != f->size) __builtin_trap();
            return;
        }
        if (rs->gzip) {
            if (!__h1c_gunzip_equals(rs->body, rs->body_len, f->data, f->size)) __builtin_trap();
            if (c->repr[r->file] == NULL && rs->body_len > 0) {
                c->repr[r->file] = malloc(rs->body_len);
                if (c->repr[r->file] != NULL) {
                    memcpy(c->repr[r->file], rs->body, rs->body_len);
                    c->repr_len[r->file] = rs->body_len;
                }
            }
        } else if (rs->body_len != f->size ||
                   (f->size > 0 && memcmp(rs->body, f->data, f->size) != 0)) {
            __builtin_trap();
        }
        return;
    }

    if (!r->ranged) __builtin_trap();
    /* §14.2: range handling is defined for GET only, and a server MUST ignore
     * Range on a method it is not defined for. HEAD mirrors GET (§9.3.2). */
    if (r->post) __builtin_trap();

    /* The representation the ranges apply to: the file, or -- when the server
     * swapped in a stored gzip -- that gzip, as far as this client knows it. */
    const uint8_t* repr = f->data;
    unsigned long long repr_len = f->size;
    int repr_known = 1;
    if (rs->gzip) {
        repr_known = 0;
        if (__h1c_static && r->file == 2) {
            repr = __h1c_gz; repr_len = __h1c_gz_len; repr_known = 1;
        } else if (c->repr[r->file] != NULL && __h1c_cache) {
            repr = c->repr[r->file]; repr_len = c->repr_len[r->file]; repr_known = 1;
        }
    }

    if (rs->status == 416) {
        unsigned long long a, b, total;
        int star = 0;
        if (!rs->has_crange || !__h1c_parse_crange(rs->crange, &a, &b, &total, &star) || !star)
            __builtin_trap();
        if (repr_known && total != repr_len) __builtin_trap();
        if (rs->body_len != 0) __builtin_trap();
        for (size_t i = 0; i < r->nspecs; i++) {
            unsigned long long first, last;
            if (__h1c_resolve(&r->specs[i], total, &first, &last)) __builtin_trap();
        }
        return;
    }

    /* 206. */
    h1c_part_t parts[8];
    size_t count = 0;
    const int multipart = strncasecmp(rs->ctype, "multipart/byteranges", 20) == 0;
    if (multipart) {
        if (r->exact) __builtin_trap();                  /* §14.6: one range, one part */
        if (r->head) {
            if (rs->body_len != 0) __builtin_trap();
            return;
        }
        count = __h1c_multipart(rs, parts, 8);
        if (count == 0) __builtin_trap();
    } else {
        int star = 0;
        if (!rs->has_crange || !__h1c_parse_crange(rs->crange, &parts[0].a, &parts[0].b,
                                                   &parts[0].total, &star) || star)
            __builtin_trap();
        if (rs->has_clen && rs->clen != parts[0].b - parts[0].a + 1) __builtin_trap();
        if (r->head) {
            if (rs->body_len != 0) __builtin_trap();
        } else if (rs->body_len != parts[0].b - parts[0].a + 1) {
            __builtin_trap();
        }
        parts[0].data = r->head ? NULL : rs->body;
        count = 1;
    }

    for (size_t i = 0; i < count; i++) {
        const h1c_part_t* part = &parts[i];
        if (part->total != parts[0].total) __builtin_trap();
        if (repr_known && part->total != repr_len) __builtin_trap();
        if (part->data != NULL && repr_known &&
            memcmp(part->data, repr + part->a, part->b - part->a + 1) != 0) __builtin_trap();
        if (r->nspecs > 0 && !__h1c_covered(r, part->total, part->a, part->b)) __builtin_trap();
    }

    /* Where the form leaves no choice, the parts are exactly the satisfiable
     * ranges in the order asked. */
    if ((r->exact || r->clean) && !r->head) {
        size_t k = 0;
        for (size_t i = 0; i < r->nspecs; i++) {
            unsigned long long first, last;
            if (!__h1c_resolve(&r->specs[i], parts[0].total, &first, &last)) continue;
            if (k == count || parts[k].a != first || parts[k].b != last) __builtin_trap();
            k++;
        }
        if (k != count) __builtin_trap();
    }
}

/* Take one response off the front of c->in: 1 when one was consumed. */
static int __h1c_take(h1c_t* c) {
    if (c->switched) return 0;
    uint8_t* s = c->in;
    uint8_t* e = c->in + c->in_len;
    const uint8_t* head_end = NULL;
    for (uint8_t* q = s; q + 4 <= e; q++)
        if (q[0] == '\r' && q[1] == '\n' && q[2] == '\r' && q[3] == '\n') { head_end = q; break; }
    if (head_end == NULL) {
        if (c->in_len > 16384) __builtin_trap();         /* a head nobody can finish */
        return 0;
    }

    h1c_resp_t rs;
    memset(&rs, 0, sizeof rs);

    /* Status line. */
    const uint8_t* eol = memchr(s, '\n', (size_t)(head_end + 2 - s));
    if (eol == NULL || eol - s < 13 || eol[-1] != '\r' || memcmp(s, "HTTP/1.1 ", 9) != 0 ||
        s[12] != ' ' || s[9] < '1' || s[9] > '5' || s[10] < '0' || s[10] > '9' ||
        s[11] < '0' || s[11] > '9')
        __builtin_trap();
    rs.status = (s[9] - '0') * 100 + (s[10] - '0') * 10 + (s[11] - '0');
    if (rs.status < 200 && rs.status != 101) {
        /* Interim: only 100, only once, only to the request waiting for it
         * (RFC 9110 §15.2), and it carries no body. */
        if (rs.status != 100 || c->answered == c->queued) __builtin_trap();
        h1c_req_t* waiting = &c->reqs[c->answered];
        if (!waiting->expect || waiting->continued || c->closing) __builtin_trap();
        waiting->continued = 1;
        const size_t used = (size_t)(head_end + 4 - s);
        memmove(c->in, c->in + used, c->in_len - used);
        c->in_len -= used;
        return 1;
    }

    /* Fields: "name: value", no bare CR or LF, no obs-fold. */
    const uint8_t* line = eol + 1;
    while (line < head_end + 2) {
        const uint8_t* le = memchr(line, '\n', (size_t)(head_end + 4 - line));
        if (le == NULL || le[-1] != '\r') __builtin_trap();
        const size_t len = (size_t)(le - 1 - line);
        if (len == 0) break;
        const uint8_t* colon = memchr(line, ':', len);
        if (colon == NULL || colon == line || line[0] == ' ' || line[0] == '\t') __builtin_trap();
        for (const uint8_t* q = line; q < line + len; q++)
            if (*q == '\r' || *q == '\n' || *q == '\0') __builtin_trap();
        for (const uint8_t* q = line; q < colon; q++)
            if (*q <= ' ' || *q >= 0x7f) __builtin_trap();

        const size_t nlen = (size_t)(colon - line);
        const uint8_t* v = colon + 1;
        while (v < line + len && (*v == ' ' || *v == '\t')) v++;
        const size_t vlen = (size_t)(line + len - v);
        char value[200];
        if (vlen >= sizeof value) { line = le + 1; continue; }
        memcpy(value, v, vlen);
        value[vlen] = '\0';

#define H1C_IS(name) (nlen == sizeof(name) - 1 && strncasecmp((const char*)line, name, nlen) == 0)
        if (H1C_IS("Content-Length")) {
            char* endp = NULL;
            const unsigned long long n = strtoull(value, &endp, 10);
            if (vlen == 0 || *endp != '\0' || (rs.has_clen && rs.clen != n)) __builtin_trap();
            rs.has_clen = 1;
            rs.clen = n;
        } else if (H1C_IS("Transfer-Encoding")) {
            if (strcasecmp(value, "chunked") != 0) __builtin_trap();
            rs.chunked = 1;
        } else if (H1C_IS("Content-Encoding")) {
            if (strcasecmp(value, "gzip") != 0) __builtin_trap();
            rs.gzip = 1;
        } else if (H1C_IS("Content-Range")) {
            snprintf(rs.crange, sizeof rs.crange, "%s", value);
            rs.has_crange = 1;
        } else if (H1C_IS("Content-Type")) {
            snprintf(rs.ctype, sizeof rs.ctype, "%s", value);
        } else if (H1C_IS("ETag")) {
            snprintf(rs.etag, sizeof rs.etag, "%s", value);
            rs.has_etag = 1;
        } else if (H1C_IS("Last-Modified")) {
            snprintf(rs.lastmod, sizeof rs.lastmod, "%s", value);
            rs.has_lastmod = 1;
        } else if (H1C_IS("Connection")) {
            if (strcasecmp(value, "close") == 0) rs.conn_close = 1;
            if (strcasecmp(value, "upgrade") == 0) rs.conn_upgrade = 1;
        } else if (H1C_IS("Upgrade")) {
            if (strcasecmp(value, "websocket") == 0) rs.upgrade_ws = 1;
        } else if (H1C_IS("Sec-WebSocket-Accept")) {
            snprintf(rs.ws_accept, sizeof rs.ws_accept, "%s", value);
        } else if (H1C_IS("Sec-WebSocket-Version")) {
            snprintf(rs.ws_version, sizeof rs.ws_version, "%s", value);
        } else if (H1C_IS("Sec-WebSocket-Extensions")) {
            rs.has_ws_ext = 1;
        }
#undef H1C_IS
        line = le + 1;
    }

    /* Which request this answers decides whether a body follows. */
    if (c->answered == c->queued) __builtin_trap();       /* an answer to nothing */
    const h1c_req_t* r = &c->reqs[c->answered];
    const uint8_t* body = head_end + 4;
    uint8_t* decoded = NULL;
    size_t decoded_len = 0, decoded_cap = 0;
    const uint8_t* next = body;

    if (r->head || rs.status == 304 || rs.status == 204 || rs.status == 101) {
        next = body;
    } else if (rs.chunked) {
        const uint8_t* q = body;
        for (;;) {
            const uint8_t* le = memchr(q, '\n', (size_t)(e - q));
            if (le == NULL) { free(decoded); return 0; }
            if (le == q || le[-1] != '\r') __builtin_trap();
            char* endp = NULL;
            const unsigned long long n = strtoull((const char*)q, &endp, 16);
            if (endp == (char*)q || (*endp != '\r' && *endp != ';')) __builtin_trap();
            q = le + 1;
            if (n == 0) {
                /* Trailer section, then the empty line. */
                for (;;) {
                    const uint8_t* te = memchr(q, '\n', (size_t)(e - q));
                    if (te == NULL) { free(decoded); return 0; }
                    if (te == q || te[-1] != '\r') __builtin_trap();
                    const int empty = te == q + 1;
                    q = te + 1;
                    if (empty) break;
                }
                break;
            }
            if ((unsigned long long)(e - q) < n + 2) { free(decoded); return 0; }
            __h1c_append(&decoded, &decoded_len, &decoded_cap, q, (size_t)n);
            q += n;
            if (q[0] != '\r' || q[1] != '\n') __builtin_trap();
            q += 2;
        }
        next = q;
    } else if (rs.has_clen) {
        if ((unsigned long long)(e - body) < rs.clen) return 0;
        next = body + rs.clen;
    } else {
        __builtin_trap();              /* a keep-alive answer with no length */
    }

    rs.body = decoded != NULL ? decoded : (uint8_t*)body;
    rs.body_len = decoded != NULL ? decoded_len : (size_t)(next - body);
    if (rs.chunked && decoded == NULL) rs.body_len = 0;

    if (c->closing) __builtin_trap();                     /* bytes after the last answer */
    __h1c_check(c, r, &rs);
    free(decoded);

    c->answered++;
    if (r->close || rs.conn_close) c->closing = 1;

    const size_t used = (size_t)(next - s);
    memmove(c->in, c->in + used, c->in_len - used);
    c->in_len -= used;
    return 1;
}

static int __h1c_pump(h1c_t* c, int fd, size_t want) {
    uint8_t buf[4096];
    int got = 0;
    while (want > 0) {
        const ssize_t n = recv(fd, buf, want < sizeof buf ? want : sizeof buf, 0);
        if (n == 0) { c->eof = 1; break; }
        if (n < 0) break;
        got = 1;
        want -= (size_t)n;
        if (c->raw || c->switched) {                      /* nothing to hold it to */
            if (getenv("FUZZ_TRACE") != NULL)
                fprintf(stderr, "server sent %zd bytes:\n%.*s\n", n, (int)n, (const char*)buf);
            continue;
        }
        __h1c_append(&c->in, &c->in_len, &c->in_cap, buf, (size_t)n);
        while (__h1c_take(c)) {}
    }
    return got;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3) return 0;
    __h1c_root_init();

    const uint8_t flags = data[0];
    __h1c_static = (flags & 1) != 0;
    __h1c_cache = (flags & 2) != 0;
    http_gzip_cache_clear();
    http_policy_init();

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0) return 0;
    const int small = 4096;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);

    h1c_t* c = calloc(1, sizeof *c);
    char* buffer = malloc(16384);
    if (c == NULL || buffer == NULL) { free(c); free(buffer); close(sv[0]); close(sv[1]); return 0; }
    c->raw = (flags >> 2) % 8 == 0;
    c->depth = 1 + (flags >> 5) % 4;

    const ipaddr_t loopback = ipaddr_from_v4(0x0100007F);
    connection_t* connection = connection_s_alloc(&__fuzz_listener, sv[0], &loopback, 8080,
                                                  &loopback, 40000, buffer, 16384);
    if (connection == NULL) { free(c); free(buffer); close(sv[0]); close(sv[1]); return 0; }
    connection_server_ctx_t* ctx = connection->ctx;
    ctx->server = &__fuzz_server;
    int alive = set_http(connection);
    __h1c_armed = MPXIN | MPXRDHUP;           /* what accept() arms a connection for */

    const uint8_t* p = data + 2;
    const uint8_t* end = data + size;
    if (c->raw) {
        __h1c_append(&c->out, &c->out_len, &c->out_cap, p, (size_t)(end - p));
        p = end;
    }

    uint64_t rng = (uint64_t)data[1] * 0x9E3779B97F4A7C15ULL + 1;
    for (size_t steps = 0; alive && steps < 20000; steps++) {
        if (!c->raw)
            while (c->queued - c->answered < c->depth && __h1c_generate(c, &p, end)) {}
        if (c->out_pos == c->out_len && c->answered == c->queued &&
            (p >= end || c->closing || c->switched)) break;
        if (c->eof) break;

        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
        const size_t amount = 1 + (size_t)((rng >> 8) % 700);
        switch (rng % 5) {
        case 0: {
            const size_t left = c->out_len - c->out_pos;
            const size_t n = left < amount ? left : amount;
            if (n == 0) break;
            const ssize_t w = send(sv[1], c->out + c->out_pos, n, MSG_NOSIGNAL);
            if (w > 0) c->out_pos += (size_t)w;
            break;
        }
        case 1: alive = __h1c_event(connection, MPXIN); break;
        case 2: alive = __h1c_event(connection, MPXOUT); break;
        case 3: (void)__h1c_pump(c, sv[1], amount * 8); break;
        case 4: (void)__fuzz_worker(); break;
        }
    }

    /* Drain: the rest of the requests in, everything the server has out. */
    for (int idle = 0; idle < 4 && !c->eof;) {
        int moved = 0;
        if (c->out_pos < c->out_len) {
            const ssize_t w = send(sv[1], c->out + c->out_pos, c->out_len - c->out_pos, MSG_NOSIGNAL);
            if (w > 0) { c->out_pos += (size_t)w; moved = 1; }
        }
        if (alive) alive = __h1c_event(connection, MPXIN);
        while (__fuzz_worker()) moved = 1;
        if (alive) alive = __h1c_event(connection, MPXOUT);
        if (__h1c_pump(c, sv[1], SIZE_MAX)) moved = 1;
        if (!c->raw && alive && c->answered < c->queued && !c->closing)
            while (c->queued - c->answered < c->depth && __h1c_generate(c, &p, end)) moved = 1;
        idle = moved ? 0 : idle + 1;
    }

    if (!c->raw) {
        /* The server stopped: every request it was sent must have been
         * answered, unless someone asked to close. A half-sent answer is one
         * the client waits on for ever. */
        const int complete = c->out_pos == c->out_len;
        if (complete && !c->closing && c->answered < c->queued) __builtin_trap();
        if (alive && c->in_len != 0) __builtin_trap();
        if (!alive && !c->closing && c->answered < c->queued && complete) __builtin_trap();
    }

    /* Nothing may still hold the connection when it goes. */
    while (__fuzz_worker()) {}
    connection_s_free_local(connection);
    for (size_t i = 0; i < H1C_FILES; i++) free(c->repr[i]);
    free(c->out);
    free(c->in);
    free(c);
    free(buffer);
    close(sv[0]);
    close(sv[1]);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_TEXT

#include "cstr.h"
#include "escape.h"
#include "strtemplate.h"
#include "validation.h"

/* The helpers that stand between what a form sent and where it ends up: HTML
 * and log escaping, form cleaning, the validators, and the {N} templates of
 * redirects and static routes. Each has a property that holds for every input,
 * and the checks here are written against the documentation in the headers,
 * not the code:
 *
 *   html_escape      -- no raw < > " ' left, every & starts one of the five
 *                       entities, and unescaping gives the input back (line
 *                       breaks as <br>\n for the multi-line form, CRLF as one);
 *   log_escape       -- what reaches the journal is valid UTF-8 with no C0,
 *                       DEL or C1 control character in it;
 *   cstr_clean       -- never longer, idempotent, and each flag's promise
 *                       kept (valid UTF-8, no controls, no line breaks, one
 *                       space per run, lower case, no whitespace at the ends);
 *   validators       -- UTF-8 and phone numbers against a reference, and an
 *                       accepted address or link carries nothing that could
 *                       break the header or the attribute it is put into;
 *   strtemplate      -- the expansion equals a reference expansion.
 *
 * The first byte picks the helper, the rest is the value. */

/* Strict UTF-8 (RFC 3629): no overlongs, no surrogates, nothing past U+10FFFF.
 * Decodes one code point at s[i..n); 0 when there is none. */
static size_t __text_utf8_next(const uint8_t* s, size_t n, size_t i, uint32_t* cp) {
    const uint8_t c = s[i];
    if (c < 0x80) { *cp = c; return 1; }
    size_t len;
    uint32_t v;
    if (c >= 0xC2 && c <= 0xDF) { len = 2; v = c & 0x1F; }
    else if (c >= 0xE0 && c <= 0xEF) { len = 3; v = c & 0x0F; }
    else if (c >= 0xF0 && c <= 0xF4) { len = 4; v = c & 0x07; }
    else return 0;
    if (i + len > n) return 0;
    for (size_t k = 1; k < len; k++) {
        if ((s[i + k] & 0xC0) != 0x80) return 0;
        v = v << 6 | (s[i + k] & 0x3F);
    }
    if (len == 3 && (v < 0x800 || (v >= 0xD800 && v <= 0xDFFF))) return 0;
    if (len == 4 && (v < 0x10000 || v > 0x10FFFF)) return 0;
    *cp = v;
    return len;
}

static int __text_utf8_valid(const char* str) {
    const uint8_t* s = (const uint8_t*)str;
    const size_t n = strlen(str);
    uint32_t cp;
    for (size_t i = 0; i < n;) {
        const size_t len = __text_utf8_next(s, n, i, &cp);
        if (len == 0) return 0;
        i += len;
    }
    return 1;
}

/* cstr.c's set, spelled out there for the same reason it is here. */
static int __text_space(uint32_t cp) {
    return cp == 0x20 || (cp >= 0x09 && cp <= 0x0D) || (cp >= 0x2000 && cp <= 0x200A) ||
           cp == 0x85 || cp == 0xA0 || cp == 0x1680 || cp == 0x2028 || cp == 0x2029 ||
           cp == 0x202F || cp == 0x205F || cp == 0x3000;
}

static void __text_html(const char* in) {
    for (int multiline = 0; multiline <= 1; multiline++) {
        char* out = multiline ? html_escape_multiline(in) : html_escape(in);
        if (out == NULL) return;

        /* Unescape while checking that nothing raw is left. */
        const size_t n = strlen(in);
        char* back = malloc(n + 1);
        if (back == NULL) { free(out); return; }
        size_t k = 0;
        for (const char* p = out; *p;) {
            static const struct { const char* entity; char c; } entities[] = {
                { "&amp;", '&' }, { "&lt;", '<' }, { "&gt;", '>' }, { "&quot;", '"' }, { "&#39;", '\'' },
            };
            if (*p == '<' && multiline && strncmp(p, "<br>\n", 5) == 0) {
                if (k == n + 1) __builtin_trap();
                back[k++] = '\n';
                p += 5;
                continue;
            }
            if (*p == '<' || *p == '>' || *p == '"' || *p == '\'') __builtin_trap();
            if (multiline && (*p == '\r' || *p == '\n')) __builtin_trap();
            if (*p == '&') {
                size_t e = 0;
                while (e < 5 && strncmp(p, entities[e].entity, strlen(entities[e].entity)) != 0) e++;
                if (e == 5) __builtin_trap();                  /* a bare & */
                if (k == n + 1) __builtin_trap();
                back[k++] = entities[e].c;
                p += strlen(entities[e].entity);
                continue;
            }
            if (k == n + 1) __builtin_trap();
            back[k++] = *p++;
        }
        back[k] = '\0';

        /* What the input becomes once its breaks are normalised. */
        char* want = malloc(n + 1);
        if (want == NULL) { free(out); free(back); return; }
        size_t w = 0;
        for (size_t i = 0; i < n; i++) {
            if (multiline && (in[i] == '\r' || in[i] == '\n')) {
                if (in[i] == '\r' && in[i + 1] == '\n') i++;
                want[w++] = '\n';
            } else {
                want[w++] = in[i];
            }
        }
        want[w] = '\0';
        if (strcmp(back, want) != 0) __builtin_trap();

        free(want);
        free(back);
        free(out);
    }
}

static void __text_log(const char* in) {
    char* out = log_escape(in);
    if (out == NULL) return;

    /* RFC 3629 validity, and no C0, DEL or C1: a lone 0x9B, or U+009B in two
     * bytes, is CSI to a terminal reading the journal. */
    const uint8_t* s = (const uint8_t*)out;
    const size_t n = strlen(out);
    uint32_t cp;
    for (size_t i = 0; i < n;) {
        const size_t len = __text_utf8_next(s, n, i, &cp);
        if (len == 0) __builtin_trap();
        if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) __builtin_trap();
        i += len;
    }
    free(out);
}

static void __text_clean(const char* in, int flags) {
    char* once = cstr_clean_copy(in, flags);
    if (once == NULL) return;
    char* twice = cstr_clean_copy(once, flags);
    if (twice == NULL) { free(once); return; }

    if (strlen(once) > strlen(in)) __builtin_trap();
    if (strcmp(once, twice) != 0) __builtin_trap();              /* idempotent */

    if ((flags & CSTR_CLEAN_UTF8) && !__text_utf8_valid(once)) __builtin_trap();
    for (const char* p = once; *p; p++) {
        const unsigned char c = (unsigned char)*p;
        if ((flags & CSTR_CLEAN_CONTROL) && ((c < 0x20 && c != '\t' && c != '\r' && c != '\n') || c == 0x7F))
            __builtin_trap();
        if ((flags & CSTR_CLEAN_NEWLINES) && (c == '\r' || c == '\n')) __builtin_trap();
        if ((flags & CSTR_CLEAN_LOWER) && c >= 'A' && c <= 'Z') __builtin_trap();
    }

    /* The whitespace promises are about code points, so only where the
     * string can be read as such. */
    if (__text_utf8_valid(once)) {
        const uint8_t* s = (const uint8_t*)once;
        const size_t n = strlen(once);
        uint32_t cp = 0, prev = 0;
        int first = 1, prev_space = 0;
        for (size_t i = 0; i < n;) {
            const size_t len = __text_utf8_next(s, n, i, &cp);
            const int space = __text_space(cp);
            if ((flags & CSTR_CLEAN_TRIM) && first && space) __builtin_trap();
            if ((flags & CSTR_CLEAN_COLLAPSE) && space && (cp != 0x20 || prev_space)) __builtin_trap();
            first = 0;
            prev_space = space;
            prev = cp;
            i += len;
        }
        if ((flags & CSTR_CLEAN_TRIM) && n > 0 && __text_space(prev)) __builtin_trap();
    }

    free(twice);
    free(once);
}

static void __text_validators(const char* in) {
    if (validate_utf8(in) != __text_utf8_valid(in)) __builtin_trap();

    /* Phone: the rule as validation.h states it. */
    const char* p = in;
    if (*p == '+') p++;
    size_t digits = 0;
    int ok = *in != '\0';
    for (; *p; p++) {
        if (*p >= '0' && *p <= '9') digits++;
        else if (strchr(" ()-.", *p) == NULL) ok = 0;
    }
    ok = ok && digits >= 7 && digits <= 15;
    if (validate_phone(in) != ok) __builtin_trap();

    /* Length in characters, for strings that have characters. */
    if (__text_utf8_valid(in)) {
        size_t chars = 0;
        for (const unsigned char* q = (const unsigned char*)in; *q; q++)
            if ((*q & 0xC0) != 0x80) chars++;
        if (validate_length(in, 2, 10) != (chars >= 2 && chars <= 10)) __builtin_trap();
    }

    /* An accepted address goes between < > in a header: nothing in it may end
     * the field or the brackets -- no controls, spaces, brackets, quotes,
     * commas or a second @ (RFC 5322 atext, dots and one @). */
    if (validate_email(in)) {
        size_t at = 0;
        for (const unsigned char* q = (const unsigned char*)in; *q; q++) {
            if (*q == '@') { at++; continue; }
            if (*q <= 0x20 || *q >= 0x7F || strchr("<>\"(),:;[\\]", *q) != NULL) __builtin_trap();
        }
        if (at != 1 || strlen(in) > 254) __builtin_trap();
    }

    /* An accepted link is http(s), printable ASCII, with no user info. */
    if (validate_url(in)) {
        if (strncmp(in, "http://", 7) != 0 && strncmp(in, "https://", 8) != 0) __builtin_trap();
        for (const unsigned char* q = (const unsigned char*)in; *q; q++)
            if (*q <= 0x20 || *q >= 0x7F) __builtin_trap();
    }

    if (validate_no_control(in)) {
        for (const unsigned char* q = (const unsigned char*)in; *q; q++)
            if ((*q < 0x20 && *q != '\t' && *q != '\r' && *q != '\n') || *q == 0x7F) __builtin_trap();
    }
}

/* strtemplate.h: {N} with one or two digits is group N; "{}" and braces around
 * anything else are text; three digits or more fail the whole template. */
static void __text_template(const char* source, const char* subject, const uint8_t* groups, size_t ng) {
    strtemplate_t* tpl = strtemplate_create(source);

    /* The reference parse, and the reference expansion. */
    int vector[200];
    const size_t slen = strlen(subject);
    for (int g = 0; g < 100; g++) {
        const uint8_t a = (size_t)g * 2 + 1 < ng ? groups[g * 2] : 0xff;
        const uint8_t b = (size_t)g * 2 + 1 < ng ? groups[g * 2 + 1] : 0xff;
        if (a == 0xff || slen == 0) { vector[g * 2] = vector[g * 2 + 1] = -1; continue; }
        size_t x = a % (slen + 1), y = b % (slen + 1);
        if (x > y) { const size_t t = x; x = y; y = t; }
        vector[g * 2] = (int)x;
        vector[g * 2 + 1] = (int)y;
    }

    size_t cap = strlen(source) * 1 + 1;
    for (const char* q = source; *q; q++) if (*q == '{') cap += slen;
    char* want = malloc(cap + 1);
    if (want == NULL) { strtemplate_free(tpl); return; }
    size_t w = 0;
    int valid = source[0] != '\0';
    for (size_t i = 0; source[i];) {
        if (source[i] == '{') {
            size_t j = i + 1;
            while (source[j] >= '0' && source[j] <= '9') j++;
            if (source[j] == '}' && j > i + 1) {
                if (j - i - 1 > 2) { valid = 0; break; }
                const int g = (source[i + 1] - '0') * (j - i - 1 == 2 ? 10 : 1) +
                              (j - i - 1 == 2 ? source[i + 2] - '0' : 0);
                if (vector[g * 2] >= 0) {
                    memcpy(want + w, subject + vector[g * 2], (size_t)(vector[g * 2 + 1] - vector[g * 2]));
                    w += (size_t)(vector[g * 2 + 1] - vector[g * 2]);
                }
                i = j + 1;
                continue;
            }
        }
        want[w++] = source[i++];
    }
    want[w] = '\0';

    if ((tpl != NULL) != valid) __builtin_trap();
    if (tpl != NULL) {
        char* got = strtemplate_expand(tpl, subject, vector);
        if (got != NULL && strcmp(got, want) != 0) __builtin_trap();
        free(got);
    }
    free(want);
    strtemplate_free(tpl);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;

    /* The value as the helpers see it: a C string, cut at the first NUL. */
    char* value = malloc(size);
    if (value == NULL) return 0;
    memcpy(value, data + 2, size - 2);
    value[size - 2] = '\0';

    switch (data[0] % 5) {
    case 0: __text_html(value); break;
    case 1: __text_log(value); break;
    case 2: __text_clean(value, data[1] & 0x3F); break;
    case 3: __text_validators(value); break;
    case 4: {
        /* Template, subject and group offsets, split where the input says. */
        const size_t vlen = strlen(value);
        const size_t cut = vlen > 0 ? data[1] % (vlen + 1) : 0;
        char* source = strndup(value, cut);
        const char* rest = value + cut;
        const size_t half = strlen(rest) / 2;
        char* subject = strndup(rest, half);
        if (source != NULL && subject != NULL)
            __text_template(source, subject, (const uint8_t*)rest + half, strlen(rest) - half);
        free(source);
        free(subject);
        break;
    }
    }

    free(value);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_MAIL_MESSAGE

#include <openssl/evp.h>

#include "mailattachment.h"
#include "mailmessage.h"

/* A letter as mail_message_build() writes it, read back the way a mail server
 * and a mail client would. The input supplies every value an application may
 * pass in -- sender address and name, recipient, subject, HTML body, up to two
 * attachments with name, type, Content-ID and bytes -- and the letter must:
 *
 *   - carry exactly the header fields the builder writes, each once: a value
 *     that smuggles a CR or LF shows up as a field nobody wrote (or, in the
 *     addresses, as an SMTP command -- mail.c prints them into MAIL FROM and
 *     RCPT TO), so an address the builder cannot put safely between < > must
 *     be refused by the setter;
 *   - give back, decoded, the sender name, the subject, the body and every
 *     attachment byte for byte;
 *   - keep every line within RFC 5322's 998 characters;
 *   - end in exactly one "\r\n.\r\n", with no line consisting of a lone dot
 *     anywhere before it (RFC 5321 §4.5.2). */

typedef struct {
    const uint8_t* p;
    const uint8_t* end;
} mm_in_t;

/* A length-prefixed field: one byte of length, then that many bytes. */
static char* __mm_field(mm_in_t* in, size_t max) {
    size_t len = in->p < in->end ? *in->p++ : 0;
    if (len > max) len = max;
    if (len > (size_t)(in->end - in->p)) len = (size_t)(in->end - in->p);
    char* s = malloc(len + 1);
    if (s == NULL) abort();
    memcpy(s, in->p, len);
    s[len] = '\0';
    in->p += len;
    return s;
}

/* What can stand between < > in a header and after MAIL FROM: in SMTP. */
static int __mm_addr_safe(const char* a) {
    if (*a == '\0' || strchr(a, '@') == NULL) return 0;
    for (const unsigned char* q = (const unsigned char*)a; *q; q++)
        if (*q <= 0x20 || *q == 0x7F || *q == '<' || *q == '>') return 0;
    return 1;
}

static char* __mm_b64(const char* s) {
    const size_t n = strlen(s);
    char* out = malloc(4 * ((n + 2) / 3) + 1);
    if (out == NULL) abort();
    EVP_EncodeBlock((unsigned char*)out, (const unsigned char*)s, (int)n);
    return out;
}

/* Base64 lines, CRLF between them, back into bytes. -1 when malformed. */
static long __mm_unb64(const char* text, size_t len, uint8_t** out) {
    char* joined = malloc(len + 1);
    if (joined == NULL) abort();
    size_t j = 0;
    for (size_t i = 0; i < len; i++)
        if (text[i] != '\r' && text[i] != '\n') joined[j++] = text[i];
    joined[j] = '\0';
    if (j % 4 != 0) { free(joined); return -1; }
    *out = malloc(j / 4 * 3 + 1);
    if (*out == NULL) abort();
    const int n = EVP_DecodeBlock(*out, (const unsigned char*)joined, (int)j);
    long pad = 0;
    if (j > 0 && joined[j - 1] == '=') pad++;
    if (j > 1 && joined[j - 2] == '=') pad++;
    free(joined);
    return n < 0 ? -1 : n - pad;
}

/* Header fields of a block ending at the empty line; folded lines belong to
 * the field above. Each name must be in `allowed`, at most once. Returns a
 * pointer past the empty line, NULL (trap) otherwise. `values` receives the
 * unfolded value per allowed name. */
static const char* __mm_fields(const char* s, const char* end, const char* const* allowed,
                               size_t n_allowed, char** values) {
    for (size_t i = 0; i < n_allowed; i++) values[i] = NULL;
    size_t current = n_allowed;
    for (;;) {
        const char* eol = s;
        while (eol + 1 < end && !(eol[0] == '\r' && eol[1] == '\n')) {
            if (*eol == '\r' || *eol == '\n') __builtin_trap();       /* bare CR/LF */
            eol++;
        }
        if (eol + 1 >= end) __builtin_trap();
        if (eol == s) return eol + 2;                                   /* empty line */
        if (*s == ' ' || *s == '\t') {                                  /* folded */
            if (current == n_allowed) __builtin_trap();
            const size_t old = strlen(values[current]);
            char* grown = realloc(values[current], old + (size_t)(eol - s) + 1);
            if (grown == NULL) abort();
            memcpy(grown + old, s, (size_t)(eol - s));
            grown[old + (size_t)(eol - s)] = '\0';
            values[current] = grown;
        } else {
            const char* colon = memchr(s, ':', (size_t)(eol - s));
            if (colon == NULL || colon + 1 >= eol || colon[1] != ' ') __builtin_trap();
            current = n_allowed;
            for (size_t i = 0; i < n_allowed; i++)
                if (strlen(allowed[i]) == (size_t)(colon - s) &&
                    strncasecmp(allowed[i], s, (size_t)(colon - s)) == 0) current = i;
            if (current == n_allowed) __builtin_trap();                 /* a field nobody wrote */
            if (values[current] != NULL) __builtin_trap();              /* twice */
            values[current] = strndup(colon + 2, (size_t)(eol - colon - 2));
            if (values[current] == NULL) abort();
        }
        s = eol + 2;
    }
}

static void __mm_free_values(char** values, size_t n) {
    for (size_t i = 0; i < n; i++) free(values[i]);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    mm_in_t in = { data, data + size };

    char* from = __mm_field(&in, 80);
    char* from_name = __mm_field(&in, 255);
    char* to = __mm_field(&in, 80);
    char* subject = __mm_field(&in, 255);
    char* body = __mm_field(&in, 255);

    mail_attachment_t att[2];
    char *names[2] = { NULL, NULL }, *types[2] = { NULL, NULL }, *cids[2] = { NULL, NULL };
    uint8_t* bytes[2] = { NULL, NULL };
    size_t count = in.p < in.end ? *in.p++ % 3 : 0;
    for (size_t i = 0; i < count; i++) {
        const uint8_t shape = in.p < in.end ? *in.p++ : 0;
        names[i] = __mm_field(&in, 120);
        types[i] = shape & 1 ? __mm_field(&in, 60) : NULL;
        cids[i] = shape & 2 ? __mm_field(&in, 40) : NULL;
        char* raw = __mm_field(&in, 255);
        const size_t n = strlen(raw);
        bytes[i] = (uint8_t*)raw;
        att[i] = (mail_attachment_t){ names[i], types[i], cids[i], bytes[i], n };
    }

    mail_message_t* m = mail_message_create();
    if (m == NULL) abort();

    const int from_ok = mail_message_set_from(m, from, from_name);
    const int to_ok = mail_message_set_to(m, to);
    /* An address the header or the SMTP command cannot hold is refused here. */
    if (from_ok && !__mm_addr_safe(from)) __builtin_trap();
    if (to_ok && !__mm_addr_safe(to)) __builtin_trap();

    if (from_ok && to_ok && mail_message_set_subject(m, subject)) {
        mail_message_set_body(m, body);
        mail_message_set_attachments(m, count > 0 ? att : NULL, count);

        if (mail_message_build(m, (time_t)1700000000)) {
            const char* d = m->data;
            const size_t len = m->data_size;

            /* The terminator, once, and every line within 998. */
            if (len < 5 || memcmp(d + len - 5, "\r\n.\r\n", 5) != 0) __builtin_trap();
            for (size_t i = 0, line = 0; i + 1 < len; i++) {
                if (d[i] == '\r' && d[i + 1] == '\n') {
                    if (line == 1 && d[i - 1] == '.' && i + 2 < len) __builtin_trap();
                    line = 0;
                    i++;
                    continue;
                }
                if (++line > 998) __builtin_trap();
            }

            static const char* const top[] = {
                "From", "To", "Subject", "Date", "Message-Id", "MIME-Version",
                "Content-Type", "Content-Transfer-Encoding",
            };
            char* v[8];
            const char* bodypart = __mm_fields(d, d + len, top, 8, v);
            for (size_t i = 0; i < 7; i++) if (v[i] == NULL) __builtin_trap();

            char* nb = __mm_b64(from_name);
            char* sb = __mm_b64(subject);
            char want[1024];
            snprintf(want, sizeof want, "=?UTF-8?B?%s?= <%s>", nb, from);
            if (strcmp(v[0], want) != 0) __builtin_trap();
            snprintf(want, sizeof want, "<%s>", to);
            if (strcmp(v[1], want) != 0) __builtin_trap();
            snprintf(want, sizeof want, "=?UTF-8?B?%s?=", sb);
            if (strcmp(v[2], want) != 0) __builtin_trap();
            free(nb);
            free(sb);

            const char* body_end = d + len - 5;
            if (count == 0) {
                uint8_t* dec = NULL;
                const long n = __mm_unb64(bodypart, (size_t)(body_end - bodypart), &dec);
                if (n != (long)strlen(body) || memcmp(dec, body, (size_t)n) != 0) __builtin_trap();
                free(dec);
            } else {
                const char* b = strstr(v[6], "boundary=\"");
                if (b == NULL) __builtin_trap();
                b += 10;
                const char* be = strchr(b, '"');
                if (be == NULL) __builtin_trap();
                char delim[96];
                snprintf(delim, sizeof delim, "\r\n--%.*s", (int)(be - b), b);

                /* The first part: the HTML body. Then one per attachment. */
                const char* s = bodypart;
                if (strncmp(s, delim + 2, strlen(delim) - 2) != 0) __builtin_trap();
                s += strlen(delim) - 2;
                for (size_t part = 0; part <= count; part++) {
                    if (s[0] != '\r' || s[1] != '\n') __builtin_trap();
                    static const char* const fields[] = {
                        "Content-Type", "Content-Transfer-Encoding", "Content-Disposition", "Content-ID",
                    };
                    char* pv[4];
                    const char* content = __mm_fields(s + 2, body_end, fields, 4, pv);
                    const char* next = strstr(content, delim);
                    if (next == NULL || next > body_end) __builtin_trap();
                    uint8_t* dec = NULL;
                    const long n = __mm_unb64(content, (size_t)(next - content), &dec);
                    const uint8_t* want_bytes = part == 0 ? (const uint8_t*)body : bytes[part - 1];
                    const size_t want_len = part == 0 ? strlen(body) : att[part - 1].size;
                    if (n != (long)want_len || memcmp(dec, want_bytes, want_len) != 0) __builtin_trap();
                    free(dec);
                    __mm_free_values(pv, 4);
                    s = next + strlen(delim);
                }
                if (strncmp(s, "--\r\n", 4) != 0) __builtin_trap();
            }
            __mm_free_values(v, 8);
        }
    }

    mail_message_free(m);
    for (size_t i = 0; i < 2; i++) { free(names[i]); free(types[i]); free(cids[i]); free(bytes[i]); }
    free(from); free(from_name); free(to); free(subject); free(body);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_QUIC_CONN

#include "quic_stand.h"
#include "quicmemory.h"

/* A whole QUIC connection -- the server's quicconn_t with its real TLS 1.3
 * handshake, loss recovery, congestion control, streams and connection ids --
 * against the test client, over the emulated path of tests/quic/quic_stand.h.
 * The unit tests script that stand one scenario at a time; here the input is
 * the script: the path's delay, loss in each direction, duplication,
 * reordering and bottleneck, then a sequence of events -- time passing, the
 * client opening, writing, resetting and stopping streams, pinging, changing
 * address, updating keys, challenging the path, closing; the server answering;
 * bursts of loss and blackouts.
 *
 * Every byte either side reads is checked against the pattern the other side
 * wrote, and a finished stream must have delivered exactly what was sent. The
 * stand must never spin without its clock moving. At the end the path goes
 * dark, and a connection that is still there after its idle timeout is one
 * that will never go; once everything is freed the QUIC memory budget must be
 * back where it started. */

#define QC_STREAMS 8

static uint8_t __qc_client_byte(size_t k, uint64_t i) { return (uint8_t)(i * 7 + k * 13 + 1); }
static uint8_t __qc_server_byte(size_t k, uint64_t i) { return (uint8_t)(i * 31 + (i >> 8) + k); }

typedef struct {
    int opened, fin_sent, reset;
    uint64_t sent;                  /* client -> server */
    uint64_t server_got;            /* read by the server, checked */
    int responded;
    uint64_t response_len;          /* server -> client, when responded */
    uint64_t client_got;            /* read by the client, checked */
} qc_stream_t;

/* The stand's own guard, but as a finding: events that keep coming while the
 * clock stands still are a spin in the code under test. */
static void __qc_run(stand_t* s, uint64_t horizon_us) {
    const uint64_t limit = __now_us + horizon_us;
    uint64_t last = __now_us;
    unsigned still = 0;
    for (;;) {
        if (s->client_failed) return;
        if (!__step(s, limit)) return;
        if (__now_us == last) {
            if (++still > 200000) __builtin_trap();
        } else {
            last = __now_us;
            still = 0;
        }
    }
}

static void __qc_client_read(stand_t* s, qc_stream_t* st) {
    for (size_t k = 0; k < QC_STREAMS; k++) {
        if (!st[k].opened) continue;
        uint8_t buf[4096];
        for (;;) {
            const size_t ready = quicclient_stream_readable(&s->client, 4 * k);
            if (ready == 0) break;
            const size_t n = quicclient_stream_read(&s->client, 4 * k, buf,
                                                    ready < sizeof buf ? ready : sizeof buf);
            if (n == 0) break;
            for (size_t i = 0; i < n; i++)
                if (buf[i] != __qc_server_byte(k, st[k].client_got + i)) __builtin_trap();
            st[k].client_got += n;
            if (st[k].responded && st[k].client_got > st[k].response_len) __builtin_trap();
        }
        /* The FIN means everything that was written has arrived. */
        if (quicclient_stream_fin(&s->client, 4 * k) && st[k].responded &&
            st[k].client_got != st[k].response_len) __builtin_trap();
    }
    (void)quicclient_flush(&s->client);
}

static void __qc_serve(stand_t* s, qc_stream_t* st, size_t k, uint64_t len, int fin) {
    if (s->conn == NULL || !st[k].opened) return;
    quicstream_t* qs = quicconn_stream_find(s->conn, 4 * k);
    if (qs == NULL) return;

    connection_s_lock(&s->conn->conn, LOCK_SITE_QUIC_SEND);
    uint8_t buf[512];
    size_t taken = 0;
    for (;;) {
        const size_t n = quicstream_read(qs, buf, sizeof buf);
        if (n == 0) break;
        for (size_t i = 0; i < n; i++)
            if (buf[i] != __qc_client_byte(k, st[k].server_got + i)) __builtin_trap();
        st[k].server_got += n;
        taken += n;
    }
    if (st[k].server_got > st[k].sent) __builtin_trap();
    if (taken > 0) quicconn_consumed(s->conn, taken);

    int wrote = 0;
    if (!st[k].responded && quicstream_can_send(4 * k) &&
        qs->send_state == QUIC_SEND_READY) {
        uint8_t* body = malloc(len + 1);
        if (body != NULL) {
            for (uint64_t i = 0; i < len; i++) body[i] = __qc_server_byte(k, i);
            if (quicstream_write(qs, body, len)) {
                if (fin) {
                    quicstream_finish(qs);
                    st[k].responded = 1;
                    st[k].response_len = len;
                }
                wrote = 1;
            }
            free(body);
        }
    }
    connection_s_unlock(&s->conn->conn);
    if (wrote) quicconn_want_write(&s->conn->conn);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 8) return 0;

    const size_t budget_before = quicmemory_current();

    stand_t* s = __stand_create_version(data[0] | 1, data[1] & 1 ? QUIC_VERSION_2 : QUIC_VERSION_1);
    if (s == NULL) return 0;

    s->trace = getenv("FUZZ_TRACE") != NULL;
    s->delay_us = 1000 + (uint64_t)(data[2] % 50) * 1000;
    s->loss_to_server_pct = data[3] % 4 == 0 ? data[3] % 30 : 0;
    s->loss_to_client_pct = data[4] % 4 == 0 ? data[4] % 30 : 0;
    s->dup_pct = data[5] % 8 == 0 ? data[5] % 20 : 0;
    s->reorder_pct = data[6] % 8 == 0 ? data[6] % 30 : 0;
    if (data[7] % 8 == 0) {
        s->bandwidth_bps = 1000000 * (1 + data[7] % 20);
        s->queue_pkts = 5 + data[7] % 30;
    }

    qc_stream_t st[QC_STREAMS];
    memset(st, 0, sizeof st);

    if (!__start(s)) { __stand_free(s); return 0; }

    const uint8_t* p = data + 8;
    const uint8_t* end = data + size;
    int closed = 0;
    while (p < end && !s->client_failed && !closed) {
        const uint8_t op = *p++;
        const uint8_t arg = p < end ? *p++ : 0;
        const size_t k = arg % QC_STREAMS;

        switch (op % 13) {
        case 0:
            __qc_run(s, 1000 + (uint64_t)arg * 2000);
            break;
        case 1: {                                   /* the client writes */
            if (!s->client.handshake_complete || st[k].fin_sent || st[k].reset) break;
            const size_t n = (size_t)arg * 37 % 4000;
            uint8_t* buf = malloc(n + 1);
            if (buf == NULL) break;
            for (size_t i = 0; i < n; i++) buf[i] = __qc_client_byte(k, st[k].sent + i);
            const int fin = (arg & 0x80) != 0;
            if (quicclient_stream_write(&s->client, 4 * k, buf, n, fin)) {
                st[k].opened = 1;
                st[k].sent += n;
                if (fin) st[k].fin_sent = 1;
            }
            free(buf);
            (void)quicclient_flush(&s->client);
            break;
        }
        case 2:                                     /* the server answers */
            __qc_serve(s, st, k, (uint64_t)arg * 131 % 70000, (arg & 1) == 0);
            break;
        case 3:
            __qc_client_read(s, st);
            break;
        case 4:
            if (st[k].opened && !st[k].reset && quicclient_reset_stream(&s->client, 4 * k, arg)) {
                st[k].reset = 1;
                st[k].responded = 0;        /* whatever was answered may not all arrive */
            }
            break;
        case 5:
            if (st[k].opened && quicclient_stop_sending(&s->client, 4 * k, arg))
                st[k].responded = 0;        /* the server stops; the FIN may never come */
            break;
        case 6: (void)quicclient_ping(&s->client); break;
        case 7:
            if (s->client.handshake_complete && quicclient_rebind(&s->client)) {
                /* The stand moves the client's address the way a NAT would. */
                struct sockaddr_in* in = (struct sockaddr_in*)&s->client_path.remote;
                in->sin_port = htons((uint16_t)(ntohs(in->sin_port) + 1));
            }
            break;
        case 8: if (s->client.handshake_complete) (void)quicclient_key_update(&s->client); break;
        case 9: if (s->client.handshake_complete) (void)quicclient_path_challenge(&s->client); break;
        case 10:
            if (arg & 1) s->drop_next_to_server = arg % 5;
            else s->drop_next_to_client = arg % 5;
            break;
        case 11:
            s->blackhole_to_server = (arg & 1) != 0;
            s->blackhole_to_client = (arg & 2) != 0;
            __qc_run(s, 1000 + (uint64_t)(arg >> 2) * 5000);
            s->blackhole_to_server = s->blackhole_to_client = 0;
            break;
        case 12:
            if (arg % 4 == 0) {
                (void)quicclient_close(&s->client, arg, arg & 1);
                closed = 1;
            }
            break;
        }
        (void)quicclient_flush(&s->client);
        __qc_run(s, 2000);
    }

    /* Quiet path, then everything readable is read and checked. */
    __qc_run(s, 3000000);
    __qc_client_read(s, st);

    /* Then the path goes dark: past the idle timeout nothing may be left. */
    s->blackhole_to_server = s->blackhole_to_client = 1;
    __qc_run(s, 400000000);
    if (s->conn != NULL) __builtin_trap();

    __stand_free(s);

    if (quicmemory_current() != budget_before) __builtin_trap();
    return 0;
}

#elif FUZZ_TARGET == FUZZ_H2_SESSION

/* The HTTP/2 connection itself: SETTINGS exchange, the stream table, flow
 * control, the token buckets that bound how fast a peer may open and abort
 * streams. The frame target next door reads one frame at a time and forgets
 * it; everything interesting here is what the previous frame left behind.
 *
 * This is the layer the named HTTP/2 denial-of-service families live in --
 * Rapid Reset opens and cancels streams faster than the server retires them,
 * a CONTINUATION flood never ends a header block -- and none of them is a
 * malformed frame. Each one is a sequence of correct frames, which is why a
 * target that validates frames in isolation cannot reach them and why this one
 * feeds a stream of bytes rather than a message.
 *
 * The session is built the way tests/unit/test_h2session.c builds it: the wire
 * parser, the stream table and the HPACK contexts are the real ones, and only
 * the event loop is missing. fd -1 means every write fails harmlessly, which
 * is what lets the whole thing run with no socket.
 *
 * Fed in chunks of a size the input picks, because a session that only ever
 * sees whole frames is not the one a network delivers: a frame header split
 * across two reads is ordinary, and the parser's resumption is state like any
 * other.
 *
 * Run this one with detect_leaks=0. A dispatched response is owned in turn by
 * the stream, the publish queue, the worker's write pass and the response
 * pool, and the teardown below imitates as much of that as it can reach --
 * ctx.parser so the session is findable, one guarded write pass to drain the
 * queue, the pool emptied, the pending-handler flags cleared. It is still not
 * the event loop, and what remains is reported as leaked. That is a limit of
 * this fixture and not a finding about the session: it cannot be read either
 * way, which is exactly why the option is off rather than the report ignored.
 * ASan and UBSan stay on, and between them they are what found the null
 * memcpy in h2_on_headers that this target's first run turned up. */

static uint64_t __fuzz_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static h2session_t* __fuzz_h2_session_create(connection_t* connection) {
    h2session_t* s = calloc(1, sizeof *s);
    if (s == NULL) return NULL;

    s->connection = connection;
    s->decoder = hpack_decoder_create(4096);
    s->encoder = hpack_encoder_create(4096);
    s->publish_queue = cqueue_create();
    s->read_cap = 16384;
    s->read_buf = malloc(s->read_cap);
    s->peer_settings_seen = 1;
    s->peer_initial_window = H2_DEFAULT_WINDOW;
    s->peer_max_frame_size = H2_MAX_FRAME_SIZE_DEFAULT;
    s->stream_recv_learned = H2_DEFAULT_WINDOW;
    s->recv.size = s->recv.avail = H2_DEFAULT_WINDOW;
    s->abort_tokens = s->ctrl_tokens = 200000;
    s->abort_epoch_ms = s->ctrl_epoch_ms = s->last_activity_ms = __fuzz_now_ms();

    h2frame_parser_init(&s->frame, 0, H2_MAX_FRAME_SIZE_DEFAULT);

    if (s->decoder == NULL || s->encoder == NULL ||
        s->publish_queue == NULL || s->read_buf == NULL) {
        h2_session_free(s);
        return NULL;
    }

    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;

    const size_t chunk = (size_t)data[0] + 1;   /* 1..256 bytes per read */

    connection_t connection;
    memset(&connection, 0, sizeof connection);
    connection.fd = -1;
    connection.ip = ipaddr_from_v4(0x0100007F);
    connection.port = 8080;

    /* A context with a vhost list, not the bare connection the unit test next
     * door uses. That test never gets as far as a header block; this target
     * does, and h2_build_request() hands the :authority to the same
     * httpparser_select_server() the h1.1 path uses, which reads the context
     * without checking it. Leaving it NULL crashes on the first valid request
     * -- in the fixture, not in the code under test. */
    connection_server_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.listener = &__fuzz_listener;
    connection.ctx = (connection_ctx_t*)&ctx;

    h2session_t* s = __fuzz_h2_session_create(&connection);
    if (s == NULL) return 0;

    /* The session has to be reachable from the connection, not merely to hold
     * a pointer back to it: h2_session_of() reads it here, and the write path
     * finds it the same way. Without this the drain below is a no-op and every
     * response the session publishes is stranded. */
    ctx.parser = s;

    const uint8_t* p = data + 1;
    size_t left = size - 1;

    while (left > 0) {
        const size_t n = left < chunk ? left : chunk;

        /* A false return is the session asking to be closed, which is the one
         * thing the event loop would do that this target must imitate:
         * feeding a connection the server has given up on tests nothing. */
        if (!h2_session_feed(s, p, n)) break;

        p += n;
        left -= n;
    }

    /* Drain the way the event loop drains, before the session goes.
     *
     * A request that dispatches produces a response, and in the server that
     * response is taken off the session by the read path
     * (httpserverhandlers.c:78) and freed once it has been written. Nothing
     * here writes anything, so without this the responses simply accumulate --
     * twelve megabytes of them in ninety seconds, reported as a leak on every
     * input that completes a request. That is the fixture standing in for the
     * loop, not a leak in the session. */
    /* One write pass, the way the worker does it. It drains the publish queue
     * -- which is where a dispatched response waits, owned by nobody the
     * teardown can reach until it has been through here -- and then writes to
     * fd -1, which fails and is meant to. */
    (void)h2_server_guard_write(&connection);

    httpresponse_t* parked;
    while ((parked = h2_server_take_response(&connection)) != NULL)
        httpresponse_free(parked);

    /* No handler ever reports back in here, so a stream that dispatched is
     * still marked as having one in flight, and a stream in that state keeps
     * what it was given rather than leave a queued item pointing at freed
     * memory (h2stream.c:88). Clearing the flag is what the post-handler hook
     * does in the server. */
    for (h2stream_t* st = s->streams; st != NULL; st = st->next)
        atomic_store_explicit(&st->handler_pending, 0, memory_order_release);

    h2_session_free(s);

    /* Whatever else the session parked on the context belongs to this
     * iteration: the connection it was cached for is going away with it. */
    if (ctx.request_cache != NULL)
        httprequest_free(ctx.request_cache);
    if (ctx.response_cache != NULL)
        httpresponse_free(ctx.response_cache);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_H3_PRIORITY

/* The Priority Field Value (RFC 9218 §4), which reaches this parser two ways
 * and is attacker-chosen both times: as a `priority` request header field, and
 * as the tail of a PRIORITY_UPDATE frame behind a varint element id.
 *
 * Worth a target of its own because of what the parser is: a hand-written walk
 * over a structured-fields dictionary with quoted strings, backslash escapes
 * and parameters -- indices advanced in half a dozen places, on bytes nobody
 * has checked. The unit tests cover what its author thought of; this covers
 * what a peer thinks of.
 *
 * And because a mistake here is not merely a crash: a malformed value on the
 * frame path is H3_FRAME_ERROR, which ends the connection, so an accepted value
 * that should be refused (or the reverse) is a protocol bug the transport
 * cannot catch. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    h3priority_t field;
    const int field_ok = h3priority_parse(data, size, &field);

    /* The one invariant the callers rely on: what comes back is inside the
     * range they will hand to the scheduler. The transport clamps urgency, so
     * an out-of-range value here would be silently absorbed rather than
     * reported -- exactly the kind of thing a fuzzer should turn into a crash. */
    if (field_ok && (field.urgency > H3_PRIORITY_URGENCY_MAX ||
                     field.incremental > 1)) __builtin_trap();

    /* Defaults must survive a refusal too: h3conn keeps the struct it passed
     * in, so a parser that half-fills it on the way to returning 0 would leave
     * a stream prioritised by garbage. */
    if (!field_ok && (field.urgency != H3_PRIORITY_URGENCY_DEFAULT ||
                      field.incremental != 0)) __builtin_trap();

    /* The frame path: a varint element id, then the same value. Split here the
     * way __priority_update splits it, so the target walks the same boundary --
     * including the length underflow a truncated varint would produce. */
    uint64_t element = 0;
    const size_t n = varint_read(data, size, &element);
    if (n > 0 && n <= size) {
        h3priority_t frame;
        const int frame_ok = h3priority_parse(data + n, size - n, &frame);

        if (frame_ok && frame.urgency > H3_PRIORITY_URGENCY_MAX) __builtin_trap();

        /* Merging is what §7 does with a frame that carries only one member. */
        h3priority_merge(&field, &frame);

        if (field.urgency > H3_PRIORITY_URGENCY_MAX) __builtin_trap();
    }

    return 0;
}

#elif FUZZ_TARGET == FUZZ_COOKIE

/* The Cookie header as the peer wrote it. It arrives on requests that have
 * proved nothing, the header buffer is its only size limit, and the parser
 * walks it with index arithmetic of its own over ';' and '=' -- including the
 * branch that trims leading spaces off a key, which moves one index while
 * another stands still. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    cookieparser_t parser;
    cookieparser_init(&parser);

    (void)cookieparser_parse(&parser, (const char*)data, size);

    /* Freed whether the parse succeeded or not: a failure partway leaves the
     * pairs it had already built on the list. */
    http_cookie_free(parser.cookie);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_URLENCODED

/* application/x-www-form-urlencoded, which is how the feedback form of the
 * site this framework runs arrives. The scan walks the buffer recording where
 * each field begins and ends, while the values are pulled out of the payload
 * fd afterwards with pread at those offsets -- so the interesting failures are
 * the ones where the two stop agreeing about the end of a field. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const int fd = __fuzz_payload_fd(data, size);
    if (fd < 0) return 0;

    /* parse() takes a non-const buffer. Whether it writes to it or not, the
     * fuzzer's own memory is not ours to hand over. */
    char* buffer = malloc(size > 0 ? size : 1);
    if (buffer == NULL) {
        close(fd);
        return 0;
    }
    memcpy(buffer, data, size);

    urlencodedparser_t parser;
    urlencodedparser_init(&parser, fd, size);

    (void)urlencodedparser_parse(&parser, buffer, size);

    urlencodedparser_clear(&parser);
    free(buffer);
    close(fd);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_MULTIPART

/* Parses `data` delivered in reads of `fixed` bytes, or -- with fixed 0 and a
 * seed -- of sizes 1..64 from a small PRNG, or whole with both 0. Returns a
 * digest of the result and of every part the parser produced. */
static uint64_t __fuzz_multipart_run(int fd, const char* boundary,
                                     const uint8_t* data, size_t size,
                                     size_t fixed, uint64_t seed) {
    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);

    multipart_res_e result = MP_RES_PARTIAL;
    uint64_t rng = seed * 0x9E3779B97F4A7C15ULL + 1;
    for (size_t off = 0; off < size && result == MP_RES_PARTIAL;) {
        size_t n = size - off;
        if (fixed != 0) n = fixed;
        else if (seed != 0) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            n = 1 + (size_t)(rng % 64);
        }
        if (n > size - off) n = size - off;

        char* chunk = malloc(n);
        if (chunk == NULL) { multipartparser_clear(&parser); return 0; }
        memcpy(chunk, data + off, n);
        result = multipartparser_parse(&parser, chunk, n);
        free(chunk);
        off += n;
    }

    uint64_t h = __fuzz_fnv(1469598103934665603ULL, &result, sizeof result);
    for (const http_payloadpart_t* part = multipartparser_part(&parser);
         part != NULL; part = part->next) {
        h = __fuzz_fnv(h, &part->offset, sizeof part->offset);
        h = __fuzz_fnv(h, &part->size, sizeof part->size);
        h = __fuzz_fnv_headers(h, part->field);
        h = __fuzz_fnv_headers(h, part->header);
        if (part->offset > size || part->size > size - part->offset) __builtin_trap();
    }

    multipartparser_clear(&parser);
    return h;
}

/* multipart/form-data, where two separate things the peer controls meet: the
 * body, and the boundary that delimits it. The boundary comes from
 * Content-Type and init() only ever measures it with strlen(), deriving two
 * separator lengths by adding 4 and 6 to it -- so an empty boundary is part of
 * the input space rather than an impossible case, and it is worth reaching.
 *
 * The first byte picks the boundary length and the bytes after it are the
 * boundary, so the fuzzer can move that split around instead of being handed a
 * constant one. */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    size_t blen = 0;

    if (size > 0) {
        blen = data[0];
        if (blen > size - 1) blen = size - 1;
    }

    /* On the heap, sized to the boundary and its terminator and nothing more.
     * A fixed array would be the obvious thing and the wrong one: the parser
     * indexes the boundary with arithmetic derived from its length, and a read
     * past the end lands inside a roomy array without a word from the
     * sanitizer. Here the allocation ends where the string does, which is also
     * how the real thing looks -- the boundary points into the Content-Type
     * header, not into a buffer with room to spare. */
    char* boundary = malloc(blen + 1);
    if (boundary == NULL) return 0;

    for (size_t i = 0; i < blen; i++) {
        const char ch = (char)data[1 + i];
        /* strlen() has to see the whole boundary, so an embedded NUL would
           silently shorten it instead of testing the length chosen here. */
        boundary[i] = ch == '\0' ? '.' : ch;
    }
    boundary[blen] = '\0';

    if (size > 0) {
        data += 1 + blen;
        size -= 1 + blen;
    }

    const int fd = __fuzz_payload_fd(data, size);
    if (fd < 0) {
        free(boundary);
        return 0;
    }

    /* Three deliveries of the same body -- whole, byte by byte, and in steps
     * the input chooses -- must produce the same result and the same parts.
     * Each read gets its own exact-size buffer that is freed after the call,
     * the way httprequest.c reuses one: a part that kept a pointer into an
     * earlier read shows up as a use-after-free, not as a quiet mismatch. */
    const uint64_t whole = __fuzz_multipart_run(fd, boundary, data, size, 0, 0);
    const uint64_t bytes = __fuzz_multipart_run(fd, boundary, data, size, 1, 0);
    const uint64_t steps = __fuzz_multipart_run(fd, boundary, data, size, 0, blen + 1);
    if (whole != bytes || whole != steps) __builtin_trap();

    free(boundary);
    close(fd);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_REQUEST_SEQUENCE

/* One keep-alive connection, a byte stream of pipelined requests, and the
 * same stream delivered three ways: in a single read, one byte per read, and
 * in reads of 1..256 bytes the input chooses. A network picks the boundaries,
 * not the client, so every observable result must be the same for all three:
 * how many requests completed, what each one was -- method, version, target,
 * header and trailer fields, the body bytes, the keep-alive decision -- and the
 * status the stream ended on.
 *
 * Each completed request is also held to what the parser promises on its own:
 * at most one Host and one Content-Length, no Transfer-Encoding (requests with
 * it are refused, RFC 9112 §6.3 leaves that choice to the server), and a body
 * exactly as long as Content-Length said. A body byte or a field that leaked
 * from one request into the next breaks one of these, or the comparison. */
typedef struct {
    uint64_t digest;
    size_t completed;
    int final_status;
} fuzz_request_result_t;

static size_t __fuzz_count_field(const http_header_t* header, const char* name) {
    size_t count = 0;
    const size_t len = strlen(name);
    for (; header != NULL; header = header->next)
        if (header->key_length == len && strncasecmp(header->key, name, len) == 0)
            count++;
    return count;
}

static uint64_t __fuzz_request_digest(uint64_t h, httprequest_t* request,
                                      const connection_t* connection) {
    const http_header_t* cl = request->get_header(request, "Content-Length");
    if (__fuzz_count_field(request->header_, "Content-Length") > 1 ||
        __fuzz_count_field(request->header_, "Transfer-Encoding") != 0 ||
        __fuzz_count_field(request->header_, "Host") > 1)
        __builtin_trap();
    if (request->version == HTTP1_VER_1_1 &&
        __fuzz_count_field(request->header_, "Host") != 1)
        __builtin_trap();

    size_t expected = 0;
    if (cl != NULL)
        for (size_t i = 0; i < cl->value_length; i++) {
            if (cl->value[i] < '0' || cl->value[i] > '9') __builtin_trap();
            if (expected > (SIZE_MAX - 9) / 10) __builtin_trap();
            expected = expected * 10 + (size_t)(cl->value[i] - '0');
        }

    const file_t* body = &request->payload_.file;
    const size_t body_size = body->fd >= 0 ? body->size : 0;
    if (body_size != expected) __builtin_trap();

    h = __fuzz_fnv(h, &request->method, sizeof request->method);
    h = __fuzz_fnv(h, &request->version, sizeof request->version);
    const unsigned char keepalive = connection->keepalive;
    h = __fuzz_fnv(h, &keepalive, 1);
    if (request->uri != NULL) h = __fuzz_fnv(h, request->uri, request->uri_length);
    h = __fuzz_fnv(h, "\0", 1);
    if (request->path != NULL) h = __fuzz_fnv(h, request->path, request->path_length);
    h = __fuzz_fnv(h, "\0", 1);
    h = __fuzz_fnv_headers(h, request->header_);
    h = __fuzz_fnv_headers(h, request->trailer_);

    char chunk[4096];
    for (size_t off = 0; off < body_size;) {
        const size_t want = body_size - off < sizeof chunk ? body_size - off : sizeof chunk;
        const ssize_t n = pread(body->fd, chunk, want, (off_t)off);
        if (n <= 0) __builtin_trap();
        h = __fuzz_fnv(h, chunk, (size_t)n);
        off += (size_t)n;
    }
    return __fuzz_fnv(h, "\xff", 1);
}

/* chunk 0: one read of the whole input; seed 0: reads of `chunk` bytes;
 * otherwise reads of 1..256 bytes drawn from a PRNG seeded with `seed`. */
static fuzz_request_result_t __fuzz_request_sequence_run(
    const uint8_t* data, size_t size, size_t chunk, uint64_t seed) {
    fuzz_request_result_t result = { .digest = 1469598103934665603ULL,
                                     .completed = 0,
                                     .final_status = HTTP1PARSER_CONTINUE };
    const size_t cap = chunk == 0 ? size : seed != 0 ? 256 : chunk;
    char* buffer = malloc(cap + 1);
    if (buffer == NULL) return result;

    connection_server_ctx_t ctx;
    connection_t connection;
    memset(&ctx, 0, sizeof ctx);
    memset(&connection, 0, sizeof connection);
    ctx.listener = &__fuzz_listener;
    connection.buffer = buffer;
    connection.buffer_size = cap;
    connection.ip = ipaddr_from_v4(0x0100007F);
    connection.port = 8080;
    connection.fd = -1;
    connection.keepalive = 1;
    connection.ctx = (connection_ctx_t*)&ctx;

    httprequestparser_t* parser = httpparser_create(&connection);
    if (parser == NULL) { free(buffer); return result; }

    uint64_t rng = seed * 0x9E3779B97F4A7C15ULL + 1;
    for (size_t off = 0; off < size;) {
        size_t n = cap;
        if (chunk != 0 && seed != 0) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            n = 1 + (size_t)(rng % 256);
        }
        if (n > size - off) n = size - off;
        memcpy(buffer, data + off, n);
        buffer[n] = 0;
        httpparser_set_bytes_readed(parser, n);
        parser->pos_start = 0;
        parser->pos = 0;

        /* A read can contain several requests. Bound the number of completions
         * to its byte count so even a parser regression cannot spin forever. */
        for (size_t complete = 0; complete <= n; complete++) {
            const int status = httpparser_run(parser);
            result.final_status = status;
            if (status == HTTP1PARSER_HANDLE_AND_CONTINUE ||
                status == HTTP1PARSER_COMPLETE) {
                if (parser->pos > n || parser->request == NULL) __builtin_trap();
                result.digest = __fuzz_request_digest(result.digest, parser->request,
                                                      &connection);
                result.completed++;
                if (ctx.request_retire != NULL)
                    ctx.request_retire(&ctx, parser->request);
                else
                    httprequest_free(parser->request);

                if (status == HTTP1PARSER_HANDLE_AND_CONTINUE) {
                    httpparser_prepare_continue(parser);
                    if (parser->pos_start >= n) __builtin_trap();
                    continue;
                }

                parser->request = NULL;
                httpparser_reset(parser);
            }
            break;
        }
        if (result.final_status != HTTP1PARSER_CONTINUE &&
            result.final_status != HTTP1PARSER_COMPLETE &&
            result.final_status != HTTP1PARSER_HANDLE_AND_CONTINUE)
            break;
        off += n;
    }

    httpparser_free(parser);
    if (ctx.request_cache != NULL) httprequest_free(ctx.request_cache);
    free(buffer);
    return result;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    const size_t input_len = size - 1 > 65536 ? 65536 : size - 1;
    const fuzz_request_result_t whole =
        __fuzz_request_sequence_run(data + 1, input_len, 0, 0);
    const fuzz_request_result_t bytes =
        __fuzz_request_sequence_run(data + 1, input_len, 1, 0);
    const fuzz_request_result_t split =
        __fuzz_request_sequence_run(data + 1, input_len, 1, (uint64_t)data[0] + 1);
    if (whole.completed != bytes.completed || whole.completed != split.completed ||
        whole.digest != bytes.digest || whole.digest != split.digest ||
        whole.final_status != bytes.final_status ||
        whole.final_status != split.final_status)
        __builtin_trap();
    return 0;
}

#elif FUZZ_TARGET == FUZZ_HTTP_RESPONSE

#include <zlib.h>
#include "connection_c.h"
#include "httpresponseparser.h"

/* The HTTP/1.1 client reading a server's response (httpclienthandlers.c
 * __read): status line, fields, and a body framed by Content-Length or by
 * chunked transfer coding, possibly gzip-encoded -- the path every outgoing
 * HTTP request of the framework takes, fed by a server we do not control.
 *
 * Raw mode: the response as the input spells it, delivered in one read, one
 * byte per read and in reads of 1..256 bytes. Same final status, status code,
 * fields and body bytes in all three.
 *
 * Generated mode: a well-formed response -- Content-Length or chunked with
 * chunk sizes, extensions and trailers the input picks, identity or gzip, to a
 * GET or a HEAD -- after which the server may keep talking (a stray CRLF, the
 * start of another response). Expected: COMPLETE, and a body that is exactly
 * the bytes that were framed -- no more, no less, none for HEAD. */

static connection_client_ctx_t __resp_ctx;

typedef struct {
    int status;
    int code;
    uint64_t digest;
    size_t body_len;
} resp_result_t;

static resp_result_t __resp_run(const uint8_t* data, size_t size, int head,
                                size_t chunk, uint64_t seed, uint8_t* body_out, size_t body_cap) {
    resp_result_t r = { .status = HTTP1PARSER_CONTINUE, .digest = 1469598103934665603ULL };
    const size_t cap = chunk == 0 ? (size ? size : 1) : seed != 0 ? 256 : chunk;
    char* buffer = malloc(cap + 1);
    connection_t* conn = calloc(1, sizeof *conn);
    if (buffer == NULL || conn == NULL) { free(buffer); free(conn); return r; }
    conn->buffer = buffer;
    conn->buffer_size = cap;
    conn->ctx = (connection_ctx_t*)&__resp_ctx;

    httpresponse_t* response = httpresponse_create(conn);
    httprequest_t* request = httprequest_create(conn);
    if (response == NULL || request == NULL) {
        if (response) httpresponse_free(response);
        if (request) httprequest_free(request);
        free(buffer); free(conn);
        return r;
    }
    request->method = head ? ROUTE_HEAD : ROUTE_GET;
    __resp_ctx.response = response;
    __resp_ctx.request = request;
    httpresponseparser_t* parser = response->parser;
    httpresponseparser_set_connection(parser, conn);
    httpresponseparser_set_buffer(parser, conn->buffer);

    uint64_t rng = seed * 0x9E3779B97F4A7C15ULL + 1;
    for (size_t off = 0; off < size;) {
        size_t n = cap;
        if (chunk != 0 && seed != 0) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            n = 1 + (size_t)(rng % 256);
        }
        if (n > size - off) n = size - off;
        memcpy(buffer, data + off, n);
        buffer[n] = 0;
        off += n;
        httpresponseparser_set_bytes_readed(parser, (ssize_t)n);
        r.status = httpresponseparser_run(parser);
        if (r.status != HTTP1PARSER_CONTINUE) break;
    }

    r.code = response->status_code;
    r.digest = __fuzz_fnv_headers(r.digest, response->header_);
    const file_t* body = &response->payload_.file;
    if (body->fd >= 0) {
        uint8_t tmp[4096];
        for (off_t o = 0;;) {
            const ssize_t n = pread(body->fd, tmp, sizeof tmp, o);
            if (n <= 0) break;
            r.digest = __fuzz_fnv(r.digest, tmp, (size_t)n);
            if (body_out != NULL && r.body_len + (size_t)n <= body_cap)
                memcpy(body_out + r.body_len, tmp, (size_t)n);
            r.body_len += (size_t)n;
            o += n;
        }
    }

    __resp_ctx.response = NULL;
    __resp_ctx.request = NULL;
    httprequest_free(request);
    httpresponse_free(response);
    free(conn);
    free(buffer);
    return r;
}

static int __resp_put(uint8_t* out, size_t cap, size_t* len, const void* p, size_t n) {
    if (n > cap - *len) return 0;
    memcpy(out + *len, p, n);
    *len += n;
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;
    const int head = (data[0] & 2) != 0;

    if (!(data[0] & 1)) {
        const uint64_t seed = (uint64_t)(data[0] >> 2) + 1;
        const resp_result_t whole = __resp_run(data + 1, size - 1, head, 0, 0, NULL, 0);
        const resp_result_t bytes = __resp_run(data + 1, size - 1, head, 1, 0, NULL, 0);
        const resp_result_t split = __resp_run(data + 1, size - 1, head, 1, seed, NULL, 0);
        if (whole.status != bytes.status || whole.status != split.status ||
            whole.code != bytes.code || whole.code != split.code ||
            whole.digest != bytes.digest || whole.digest != split.digest ||
            whole.body_len != bytes.body_len || whole.body_len != split.body_len)
            __builtin_trap();
        return 0;
    }

    /* Generated: [mode][framing][chunk seed][tail] then the body. */
    const int chunked = data[1] & 1, gzipped = (data[1] & 2) != 0;
    const int extensions = (data[1] & 4) != 0, trailers = (data[1] & 8) != 0;
    const int tail = data[3] % 3;
    const uint8_t* body = data + 4;
    const size_t body_len = size - 4 > 3000 ? 3000 : size - 4;

    /* What goes on the wire as the representation: the body, or its gzip. */
    static uint8_t packed[8192];
    const uint8_t* rep = body;
    size_t rep_len = body_len;
    if (gzipped) {
        z_stream z;
        memset(&z, 0, sizeof z);
        if (deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16, 8,
                         Z_DEFAULT_STRATEGY) != Z_OK) return 0;
        z.next_in = (Bytef*)body;
        z.avail_in = (uInt)body_len;
        z.next_out = packed;
        z.avail_out = sizeof packed;
        const int st = deflate(&z, Z_FINISH);
        rep_len = sizeof packed - z.avail_out;
        deflateEnd(&z);
        if (st != Z_STREAM_END) return 0;
        rep = packed;
    }

    static uint8_t wire[16384];
    size_t len = 0;
    char line[128];
    int ok = __resp_put(wire, sizeof wire, &len, "HTTP/1.1 200 OK\r\nServer: fuzz\r\n", 31);
    if (gzipped) ok = ok && __resp_put(wire, sizeof wire, &len, "Content-Encoding: gzip\r\n", 24);
    if (chunked) {
        ok = ok && __resp_put(wire, sizeof wire, &len, "Transfer-Encoding: chunked\r\n\r\n", 30);
        if (!head) {
            uint64_t rng = (uint64_t)data[2] * 0x9E3779B97F4A7C15ULL + 1;
            for (size_t off = 0; off < rep_len && ok;) {
                rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                size_t n = 1 + (size_t)(rng % 300);
                if (n > rep_len - off) n = rep_len - off;
                const int w = snprintf(line, sizeof line, "%zx%s\r\n", n, extensions ? ";ext=1" : "");
                ok = __resp_put(wire, sizeof wire, &len, line, (size_t)w) &&
                     __resp_put(wire, sizeof wire, &len, rep + off, n) &&
                     __resp_put(wire, sizeof wire, &len, "\r\n", 2);
                off += n;
            }
            ok = ok && __resp_put(wire, sizeof wire, &len, "0\r\n", 3);
            if (trailers) ok = ok && __resp_put(wire, sizeof wire, &len, "X-Trailer: t\r\n", 14);
            ok = ok && __resp_put(wire, sizeof wire, &len, "\r\n", 2);
        }
    } else {
        const int w = snprintf(line, sizeof line, "Content-Length: %zu\r\n\r\n", rep_len);
        ok = ok && __resp_put(wire, sizeof wire, &len, line, (size_t)w);
        if (!head) ok = ok && __resp_put(wire, sizeof wire, &len, rep, rep_len);
    }
    /* What a server may put after a complete response on a keep-alive
     * connection: nothing, a stray CRLF, or the start of another response. */
    if (tail == 1) ok = ok && __resp_put(wire, sizeof wire, &len, "\r\n", 2);
    if (tail == 2) ok = ok && __resp_put(wire, sizeof wire, &len, "HTTP/1.1 204 No", 15);
    if (!ok) return 0;

    static uint8_t got[4096];
    const resp_result_t runs[3] = {
        __resp_run(wire, len, head, 0, 0, got, sizeof got),
        __resp_run(wire, len, head, 1, 0, NULL, 0),
        __resp_run(wire, len, head, 1, (uint64_t)data[2] + 1, NULL, 0),
    };
    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "chunked %d gzip %d head %d tail %d: status %d/%d/%d body %zu/%zu/%zu want %zu\n",
                chunked, gzipped, head, tail, runs[0].status, runs[1].status, runs[2].status,
                runs[0].body_len, runs[1].body_len, runs[2].body_len, head ? 0 : body_len);
    for (int i = 0; i < 3; i++) {
        if (runs[i].status != HTTP1RESPONSEPARSER_COMPLETE || runs[i].code != 200) __builtin_trap();
        if (runs[i].body_len != (head ? 0 : body_len)) __builtin_trap();
    }
    if (!head && memcmp(got, body, body_len) != 0) __builtin_trap();
    return 0;
}

#elif FUZZ_TARGET == FUZZ_SMTP_RESPONSE

#include <ctype.h>
#include "connection_c.h"
#include "smtpresponse.h"
#include "smtpresponseparser.h"

/* The SMTP client reading a server reply (smtpclienthandlers.c), and what it
 * learns from an EHLO reply: whether the server offers STARTTLS -- which
 * decides whether the password goes out encrypted -- which AUTH mechanisms,
 * and the SIZE limit.
 *
 * Raw mode: the reply as the input spells it, in one read, one byte per read
 * and in reads of 1..64 bytes; the same status, message, extensions, AUTH
 * mechanisms and size in all three.
 *
 * Generated mode: a reply of 1..8 lines, all with one code, each carrying a
 * keyword from a list that includes the look-alikes -- "STARTTLSX",
 * "X-STARTTLS", "sTaRtTlS", "SIZE=10", "AUTH=PLAIN", "AUTH PLAINX" -- and the
 * capabilities are checked against a model of RFC 5321 §4.1.1.1, RFC 3207,
 * RFC 4954 and RFC 1870: a keyword counts, case-insensitively, when it is the
 * whole first word of a line of a 250 reply; nothing else counts. */

static connection_client_ctx_t __smtp_ctx;

typedef struct {
    int status, parser_status;
    unsigned ext, auth;
    size_t size;
    char message[SMTPRESPONSE_MESSAGE_SIZE];
} smtp_result_t;

static smtp_result_t __smtp_run(const uint8_t* data, size_t size, size_t chunk, uint64_t seed) {
    smtp_result_t r;
    memset(&r, 0, sizeof r);
    r.parser_status = SMTPRESPONSEPARSER_CONTINUE;
    connection_t* conn = calloc(1, sizeof *conn);
    if (conn == NULL) return r;
    smtpresponse_t* response = smtpresponse_create(conn);
    if (response == NULL) { free(conn); return r; }
    __smtp_ctx.response = response;
    conn->ctx = (connection_ctx_t*)&__smtp_ctx;
    smtpresponseparser_t* parser = response->parser;
    smtpresponseparser_set_connection(parser, conn);

    uint64_t rng = seed * 0x9E3779B97F4A7C15ULL + 1;
    for (size_t off = 0; off < size;) {
        size_t n = chunk == 0 ? size : chunk;
        if (chunk != 0 && seed != 0) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            n = 1 + (size_t)(rng % 64);
        }
        if (n > size - off) n = size - off;
        char* buffer = malloc(n);               /* exact size: ASan sees any overread */
        if (buffer == NULL) break;
        memcpy(buffer, data + off, n);
        off += n;
        smtpresponseparser_set_buffer(parser, buffer);
        smtpresponseparser_set_bytes_readed(parser, (int)n);
        r.parser_status = smtpresponseparser_run(parser);
        free(buffer);
        if (r.parser_status != SMTPRESPONSEPARSER_CONTINUE) break;
    }
    r.status = response->status;
    r.ext = response->extensions;
    r.auth = response->auth_mechanisms;
    r.size = response->size_limit;
    memcpy(r.message, response->message, sizeof r.message);

    __smtp_ctx.response = NULL;
    response->base.free(response);
    free(conn);
    return r;
}

static int __smtp_same(const smtp_result_t* a, const smtp_result_t* b) {
    return a->status == b->status && a->parser_status == b->parser_status &&
           a->ext == b->ext && a->auth == b->auth && a->size == b->size &&
           memcmp(a->message, b->message, sizeof a->message) == 0;
}

/* The model: the first word of the line, compared case-insensitively. */
static int __smtp_word_is(const char* text, const char* keyword) {
    const size_t n = strlen(keyword);
    for (size_t i = 0; i < n; i++)
        if (toupper((unsigned char)text[i]) != keyword[i]) return 0;
    return text[n] == '\0' || text[n] == ' ' || text[n] == '=';
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;

    if (!(data[0] & 1)) {
        const uint64_t seed = (uint64_t)(data[0] >> 1) + 1;
        const smtp_result_t whole = __smtp_run(data + 1, size - 1, 0, 0);
        const smtp_result_t bytes = __smtp_run(data + 1, size - 1, 1, 0);
        const smtp_result_t split = __smtp_run(data + 1, size - 1, 1, seed);
        if (!__smtp_same(&whole, &bytes) || !__smtp_same(&whole, &split)) __builtin_trap();
        return 0;
    }

    static const char* const words[] = {
        "STARTTLS", "starttls", "StartTLS", "STARTTLSX", "X-STARTTLS", "PIPELINING",
        "PIPELININGX", "SIZE 35882577", "SIZE", "SIZE=10", "SIZE  42", "SIZEX 5",
        "AUTH PLAIN LOGIN", "AUTH=PLAIN", "AUTH LOGIN", "AUTH PLAINX", "AUTH CRAM-MD5",
        "auth plain", "8BITMIME", "HELP", "mx.example.com greets you", "ENHANCEDSTATUSCODES",
    };
    const size_t nwords = sizeof words / sizeof words[0];
    static const int codes[] = { 250, 250, 250, 220, 550, 421 };
    const int code = codes[(data[0] >> 1) % 6];
    const size_t lines = (size_t)(data[1] % 8) + 1;

    char wire[1024];
    size_t len = 0;
    unsigned ext = 0, auth = 0;
    size_t size_limit = 0;
    for (size_t i = 0; i < lines; i++) {
        const char* w = words[(2 + i < size ? data[2 + i] : i) % nwords];
        const int n = snprintf(wire + len, sizeof wire - len, "%03d%c%s\r\n", code,
                               i + 1 == lines ? ' ' : '-', w);
        if (n < 0 || (size_t)n >= sizeof wire - len) return 0;
        len += (size_t)n;

        if (code != 250) continue;
        if (__smtp_word_is(w, "STARTTLS")) ext |= SMTPRESPONSE_EXT_STARTTLS;
        if (__smtp_word_is(w, "PIPELINING")) ext |= SMTPRESPONSE_EXT_PIPELINING;
        if (__smtp_word_is(w, "SIZE")) {
            ext |= SMTPRESPONSE_EXT_SIZE;
            const char* p = w + 4;
            while (*p == ' ') p++;
            if (isdigit((unsigned char)*p)) size_limit = (size_t)strtoull(p, NULL, 10);
        }
        if (__smtp_word_is(w, "AUTH")) {
            ext |= SMTPRESPONSE_EXT_AUTH;
            char args[64];
            snprintf(args, sizeof args, "%s", w + 4);
            for (char* tok = strtok(args, " ="); tok != NULL; tok = strtok(NULL, " =")) {
                if (__smtp_word_is(tok, "PLAIN")) auth |= SMTPRESPONSE_AUTH_PLAIN;
                if (__smtp_word_is(tok, "LOGIN")) auth |= SMTPRESPONSE_AUTH_LOGIN;
            }
        }
    }

    const smtp_result_t runs[3] = {
        __smtp_run((const uint8_t*)wire, len, 0, 0), __smtp_run((const uint8_t*)wire, len, 1, 0),
        __smtp_run((const uint8_t*)wire, len, 1, (uint64_t)data[1] + 1),
    };
    for (int i = 0; i < 3; i++) {
        if (runs[i].parser_status != SMTPRESPONSEPARSER_COMPLETE || runs[i].status != code)
            __builtin_trap();
        if (runs[i].ext != ext || runs[i].auth != auth || runs[i].size != size_limit)
            __builtin_trap();
    }
    return 0;
}

#elif FUZZ_TARGET == FUZZ_JWT

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "jwt.h"

/* JSON Web Tokens as the framework verifies them, with an HS256 key. The
 * property that matters above all others: a token is accepted only with the
 * right signature. It is checked here without the library -- HMAC-SHA256 of
 * the signing input computed with OpenSSL, the signature decoded by a strict
 * base64url decoder of our own -- for every token jwt_decode accepts (an
 * expired one included: its signature was checked before its expiry).
 *
 * Raw mode: the input is the token. Almost none will be valid, and any that
 * is accepted without a matching HMAC is a forgery.
 *
 * Generated mode: a payload built from the input is encoded and must decode
 * to the same claims; then the token is attacked the ways tokens are
 * attacked -- one character of the header or payload changed, one character
 * of the signature changed, the algorithm renamed to "none" or to HS512 with a
 * genuine HS512 signature, the expiry moved into the past -- and each must be
 * refused, the last one as EXPIRED. */

static const char __jwt_secret[] = "fuzz-secret-0123456789abcdef-0123";

static int __jwt_b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

/* Strict base64url without padding; returns decoded length or -1. */
static int __jwt_b64url_decode(const char* s, size_t len, uint8_t* out, size_t cap) {
    if (len % 4 == 1) return -1;
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        const int v = __jwt_b64val(s[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o == cap) return -1;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return (int)o;
}

static void __jwt_b64url_encode(const uint8_t* in, size_t len, char* out) {
    static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        const uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < len ? (uint32_t)in[i + 1] << 8 : 0) |
                           (i + 2 < len ? in[i + 2] : 0);
        out[o++] = a[v >> 18 & 63];
        out[o++] = a[v >> 12 & 63];
        if (i + 1 < len) out[o++] = a[v >> 6 & 63];
        if (i + 2 < len) out[o++] = a[v & 63];
    }
    out[o] = '\0';
}

/* The independent check: is `token` signed with our secret, and does its
 * header name HS256? */
static int __jwt_genuinely_signed(const char* token) {
    const char* d1 = strchr(token, '.');
    const char* d2 = d1 != NULL ? strchr(d1 + 1, '.') : NULL;
    if (d2 == NULL) return 0;
    uint8_t want[EVP_MAX_MD_SIZE];
    unsigned int want_len = 0;
    if (HMAC(EVP_sha256(), __jwt_secret, (int)strlen(__jwt_secret),
             (const unsigned char*)token, (size_t)(d2 - token), want, &want_len) == NULL)
        return 0;
    uint8_t got[128];
    const int got_len = __jwt_b64url_decode(d2 + 1, strlen(d2 + 1), got, sizeof got);
    if (got_len != (int)want_len || memcmp(got, want, want_len) != 0) return 0;
    /* And spelled the one canonical way: re-encoding gives the segment back. */
    char again[256];
    __jwt_b64url_encode(got, (size_t)got_len, again);
    return strcmp(again, d2 + 1) == 0;
}

static void __jwt_check_decode(const char* token, const jwt_key_t* key) {
    jwt_t r = jwt_decode(token, key);
    if ((r.error == JWT_OK || r.error == JWT_ERROR_EXPIRED) && !__jwt_genuinely_signed(token))
        __builtin_trap();                     /* accepted without our signature */
    if (r.error == JWT_OK && jwt_verify(token, key) != JWT_OK) __builtin_trap();
    jwt_free(&r);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    jwt_key_t* key = jwt_key_hs256(__jwt_secret, strlen(__jwt_secret));
    if (key == NULL) return 0;

    if (!(data[0] & 1)) {
        char* token = malloc(size);
        if (token != NULL) {
            for (size_t i = 1; i < size; i++) token[i - 1] = data[i] ? (char)data[i] : '.';
            token[size - 1] = '\0';
            __jwt_check_decode(token, key);
            free(token);
        }
        jwt_key_free(key);
        return 0;
    }

    /* Claims: a subject and a number from the input, and an expiry either in
     * the future or in the past. */
    const int expired = (data[0] & 2) != 0;
    json_doc_t* payload = json_root_create_object();
    char sub[64];
    const size_t sub_len = size - 2 < sizeof sub - 1 ? size - 2 : sizeof sub - 1;
    for (size_t i = 0; i < sub_len; i++) sub[i] = (char)(data[2 + i] % 94 + 33);
    sub[sub_len] = '\0';
    json_object_set(json_root(payload), "sub", json_create_string(sub));
    json_object_set(json_root(payload), "n", json_create_number(data[1]));
    json_object_set(json_root(payload), "exp",
                    json_create_number((long double)(time(NULL) + (expired ? -100 : 3600))));
    char* token = jwt_encode(payload, key);
    json_free(payload);
    if (token == NULL) { jwt_key_free(key); return 0; }

    /* The genuine token. */
    jwt_t r = jwt_decode(token, key);
    if (r.error != (expired ? JWT_ERROR_EXPIRED : JWT_OK)) __builtin_trap();
    if (!expired) {
        const json_token_t* got = json_object_get(json_root(r.payload), "sub");
        if (got == NULL || !json_is_string(got) || strcmp(json_string(got), sub) != 0)
            __builtin_trap();
    }
    jwt_free(&r);
    __jwt_check_decode(token, key);

    const size_t len = strlen(token);
    const char* d1 = strchr(token, '.');
    const char* d2 = strchr(d1 + 1, '.');

    /* One character changed. In the signing input any change must fail; in the
     * signature, all but the last character (whose low bits base64url does not
     * use, so a change there may decode to the same bytes). */
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const size_t at = data[1] * 131u % len;
    if (token[at] != '.' && at != len - 1) {
        char* bad = strdup(token);
        if (bad != NULL) {
            const char* was = strchr(alphabet, bad[at]);
            const size_t idx = was != NULL ? (size_t)(was - alphabet) : 0;
            bad[at] = alphabet[(idx + 1 + data[1] % 62) % 64];
            jwt_t t = jwt_decode(bad, key);
            if (t.error == JWT_OK || t.error == JWT_ERROR_EXPIRED) __builtin_trap();
            jwt_free(&t);
            __jwt_check_decode(bad, key);
            free(bad);
        }
    }

    /* The algorithm changed: to "none" with no signature, and to HS512 with a
     * correct HS512 signature under the same secret (RFC 8725 §2.1, §3.1). */
    const char* payload_b64 = d1 + 1;
    const size_t payload_b64_len = (size_t)(d2 - payload_b64);
    for (int variant = 0; variant < 2; variant++) {
        const char* header = variant == 0 ? "{\"alg\":\"none\",\"typ\":\"JWT\"}"
                                          : "{\"alg\":\"HS512\",\"typ\":\"JWT\"}";
        char forged[2048];
        __jwt_b64url_encode((const uint8_t*)header, strlen(header), forged);
        size_t n = strlen(forged);
        forged[n++] = '.';
        if (n + payload_b64_len + 200 > sizeof forged) break;
        memcpy(forged + n, payload_b64, payload_b64_len);
        n += payload_b64_len;
        forged[n++] = '.';
        forged[n] = '\0';
        if (variant == 1) {
            uint8_t mac[EVP_MAX_MD_SIZE];
            unsigned int mac_len = 0;
            HMAC(EVP_sha512(), __jwt_secret, (int)strlen(__jwt_secret),
                 (const unsigned char*)forged, n - 1, mac, &mac_len);
            __jwt_b64url_encode(mac, mac_len, forged + n);
        }
        jwt_t t = jwt_decode(forged, key);
        if (t.error == JWT_OK || t.error == JWT_ERROR_EXPIRED) __builtin_trap();
        jwt_free(&t);
    }

    free(token);
    jwt_key_free(key);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_REQUEST

/* The HTTP/1.1 request as it comes off the socket: request line, headers, and
 * whatever the Content-Length or Transfer-Encoding claims about the body. It is
 * the first code in the process to look at a connection's bytes, it runs before
 * a route is chosen or a handler exists, and every request to an h1.1 server
 * goes through it. Of the parsers here it is the one with the largest state
 * machine and the only one that needs a connection to talk to at all.
 *
 * The mock objects below follow tests/unit/test_httprequestparser_dumb_fuzzing.c,
 * which already had to build them. That test walks 100 buffers of bytes from a
 * seeded PRNG; this target is the same setup with coverage feedback behind it,
 * so a header the random one would need a lucky draw to spell gets assembled
 * from the branches it already reached.
 *
 * Two departures from that test. The domain is literal rather than left half
 * built: the pcre branch of domain_matches() would be handed a NULL pattern,
 * and the empty server list the test uses to avoid that also skips the
 * matching entirely, leaving the branch that adopts a vhost unreached. And the
 * context is per-iteration rather than file-static, because the parser caches a
 * recycled request on it -- shared between runs that is a leak, and a fuzzer
 * that reports one on every input reports nothing. */

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    connection_server_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.listener = &__fuzz_listener;

    connection_t* conn = calloc(1, sizeof *conn);
    if (conn == NULL) return 0;

    /* The parser reads from connection->buffer and writes back into it, so it
     * gets a copy sized to the input: a buffer with room to spare would hide
     * exactly the overruns this is here to find. */
    conn->buffer = malloc(size + 1);
    if (conn->buffer == NULL) {
        free(conn);
        return 0;
    }
    memcpy(conn->buffer, data, size);
    conn->buffer[size] = '\0';
    conn->buffer_size = size;

    conn->ip = ipaddr_from_v4(0x0100007F);
    conn->port = 8080;
    conn->ssl = NULL;
    conn->keepalive = 0;
    conn->ctx = (connection_ctx_t*)&ctx;

    httprequestparser_t* parser = httpparser_create(conn);
    if (parser != NULL) {
        httpparser_set_bytes_readed(parser, size);
        (void)httpparser_run(parser);
        httpparser_free(parser);
    }

    /* Whatever the parser left on the context is ours now: the connection it
     * belonged to is going away with this iteration. */
    if (ctx.request_cache != NULL)
        httprequest_free(ctx.request_cache);

    free(conn->buffer);
    free(conn);

    return 0;
}

#else
#error "FUZZ_TARGET is not set to a known target"
#endif
