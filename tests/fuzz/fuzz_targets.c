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
    FUZZ_TARGET == FUZZ_H3_REQUEST || FUZZ_TARGET == FUZZ_H3_RESPONSE
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
    FUZZ_TARGET == FUZZ_MAIL_MESSAGE || FUZZ_TARGET == FUZZ_H3_RESPONSE || \
    FUZZ_TARGET == FUZZ_VIEW || FUZZ_TARGET == FUZZ_WS_CONNECTION

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

#if FUZZ_TARGET == FUZZ_H1_CONNECTION || FUZZ_TARGET == FUZZ_H2_CONNECTION || \
    FUZZ_TARGET == FUZZ_WS_CONNECTION

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

/* Legacy fd entry points use a real seekable memfd; the incoming entry points
 * use an owned body store. Both must produce the same fields and offsets. */
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

#if FUZZ_TARGET == FUZZ_DB_QUERY || FUZZ_TARGET == FUZZ_DB_MODEL

#include "array.h"
#include "database.h"
#include "dbquery.h"
#include "dbresult.h"
#include "json.h"
#include "model.h"
#include "mparams.h"
#include "sqlite.h"
#include "str.h"

/* The database targets run on SQLite ":memory:" (dbid sqlite.test): the
 * configuration is built here, the way tests/db/test_config.json declares it,
 * rather than read from a file. */

static appconfig_t* __db_config;

static void __db_init(void) {
    if (__db_config != NULL) return;

    __db_config = calloc(1, sizeof *__db_config);
    if (__db_config == NULL) abort();
    __db_config->env.main.log.enabled = false;
    __db_config->env.main.tmp = "/tmp";
    __db_config->env.main.workers = 1;
    __db_config->env.main.threads = 1;
    __db_config->databases = array_create();

    json_doc_t* doc = json_parse("[{\"host_id\":\"test\",\"path\":\":memory:\"}]");
    db_t* db = doc != NULL ? sqlite_load("sqlite", json_root(doc)) : NULL;
    if (db == NULL || __db_config->databases == NULL) abort();
    json_free(doc);
    array_push_back(__db_config->databases, array_create_pointer(db, array_nocopy, db_free));
}

__attribute__((weak)) appconfig_t* appconfig(void) {
    __db_init();
    return __db_config;
}

__attribute__((weak)) env_t* env(void) {
    __db_init();
    return &__db_config->env;
}

__attribute__((weak)) void appconfig_set(appconfig_t* config) {
    (void)config;
}

#define DQ_DBID "sqlite.test"

typedef struct {
    const uint8_t* p;
    const uint8_t* end;
} dq_in_t;

static uint8_t __dq_byte(dq_in_t* in) {
    return in->p < in->end ? *in->p++ : 0;
}

typedef struct {
    char* data;
    size_t len;
    size_t cap;
} dq_buf_t;

static void __dq_put(dq_buf_t* b, const void* p, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->len + n + 1) cap *= 2;
        char* grown = realloc(b->data, cap);
        if (grown == NULL) abort();
        b->data = grown;
        b->cap = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void __dq_puts(dq_buf_t* b, const char* s) {
    __dq_put(b, s, strlen(s));
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
    const size_t size = http_payload_size(&r->payload_);
    char chunk[4096];
    for (size_t off = 0; off < size;) {
        size_t count = size - off;
        if (count > sizeof(chunk)) count = sizeof(chunk);
        if (!http_payload_read(&r->payload_, off, chunk, count)) __builtin_trap();
        h = __fuzz_fnv(h, chunk, count);
        off += count;
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

    size_t pos = 1, offered = 1;
    while (offered < size) {
        offered += size - offered < step ? size - offered : step;
        size_t consumed = 0;

        if (qpack_decoder_read_encoder(d, data + pos, offered - pos, &consumed) != QPACK_OK)
            break;

        /* The reader retains no partial instruction. Offer its unread tail
         * again together with the next chunk, just as h3session does. */
        if (consumed > offered - pos) __builtin_trap();
        pos += consumed;
    }

    qpack_decoder_free(d);

    pos = offered = 1;
    while (offered < size) {
        offered += size - offered < step ? size - offered : step;
        size_t consumed = 0;

        if (qpack_encoder_read_decoder(data + pos, offered - pos, &consumed) != QPACK_OK)
            break;

        if (consumed > offered - pos) __builtin_trap();
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
    size_t len = websocketsrequest_payload_size(request->protocol);
    char chunk[4096];
    for (size_t offset = 0; offset < len;) {
        size_t count = len - offset;
        if (count > sizeof(chunk)) count = sizeof(chunk);
        if (!websocketsrequest_payload_read(request->protocol, offset, chunk, count)) __builtin_trap();
        h = __fuzz_fnv(h, chunk, count);
        offset += count;
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

#include "httpcontext.h"
#include "route.h"
#include "wscontext.h"

#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
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
 * than the default 64 KiB window, so a response has to wait for credit, and
 * /h/... by a handler, which goes through the handler queue and reports back
 * with h2_server_response_ready. With the first input byte odd the queue is
 * run by a real worker thread, concurrently with the event-loop calls, the way
 * the server runs it: a handler then finishes whenever the thread gets to it,
 * in the middle of a read pass or a write pass. Such a run does not replay
 * exactly, and is not meant to -- it is the publish queue and the locks that
 * are under test, and ASan reports what they get wrong. */

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
/* The handler behind /h/...: a body of the path's length, so the answer
 * differs per request. */
static void __h2c_handler(void* arg) {
    httpctx_t* ctx = arg;
    char body[512];
    const size_t n = ctx->request->path_length < sizeof body ? ctx->request->path_length : sizeof body;
    memset(body, 'h', n);
    ctx->response->send_datan(ctx->response, body, n);
}

static atomic_int __h2c_stop;

static void* __h2c_worker_thread(void* arg) {
    (void)arg;
    while (!atomic_load(&__h2c_stop))
        if (!__fuzz_worker()) sched_yield();
    return NULL;
}

static void __h2c_root_init(void) {
    if (__h2c_root[0] != '\0') return;
    route_t* handled = route_create("^/h/(.*)$");
    if (handled == NULL || !route_set_http_handler(handled, "GET", __h2c_handler, NULL)) abort();
    __fuzz_server.http.route = handled;
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

    const int threaded = data[0] & 1;
    pthread_t worker;
    atomic_store(&__h2c_stop, 0);
    if (threaded && pthread_create(&worker, NULL, __h2c_worker_thread, NULL) != 0) abort();

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
            /* Handlers queued since the last write have run by now -- or, with
             * the worker thread, whenever it got to them. */
            if (!threaded) while (__fuzz_worker()) {}
            alive = h2_server_guard_write(connection);
            break;
        case 3: (void)__h2c_pump(c, sv[1], amount * 8); break;
        }
    }

    /* The worker stops before the drain, which is then the same either way:
     * what it left in the queue runs here. */
    if (threaded) {
        atomic_store(&__h2c_stop, 1);
        pthread_join(worker, NULL);
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

/* F-01, RFC 9112 §9.6: a request the parser refused is answered, and the
 * connection ends with that answer -- the parser cannot say where the broken
 * request stops, so nothing after it may be read as a request. Held to on the
 * server's own state rather than on the wire, where a refused WebSocket
 * handshake is a 400 too, and raw input has no requests to match answers to:
 * the answer to a refusal is the one response the connection holds without a
 * request (__post_parse_refusal passes none, and the queued path carries
 * that NULL through). It must not keep the connection, and once it exists the
 * server must not read again. */
static int __h1c_refused;

static void __h1c_refusal(connection_t* connection) {
    if (connection->read != http_server_guard_read) return;  /* switched protocols */
    const connection_server_ctx_t* ctx = connection->ctx;
    const httpresponse_t* response = ctx->response;
    if (response == NULL || ctx->request != NULL) return;
    if (response->keepalive) __builtin_trap();
    __h1c_refused = 1;
}

static int __h1c_event(connection_t* connection, int event) {
    if (!(__h1c_armed & event)) return 1;                 /* epoll would not call */
    /* multiplexingepoll.c: a connection marked destroyed -- the write path's
     * way of saying "close after this response" -- is closed on its next
     * event, whatever the event is. */
    const connection_server_ctx_t* ctx = connection->ctx;
    if (atomic_load(&ctx->destroyed)) return 0;
    if (__h1c_armed & MPXONESHOT) __h1c_armed = 0;
    __h1c_refusal(connection);                            /* a worker may have posted it */
    if (event == MPXIN && __h1c_refused) __builtin_trap();
    const int alive = event == MPXIN ? http_server_guard_read(connection)
                                     : http_server_guard_write(connection);
    if (alive) __h1c_refusal(connection);
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

    /* F-01, RFC 9112 §9.6: an answer to a request the parser refused ends the
     * connection. Every request generated here frames, so the only 400 one may
     * get is a refused WebSocket handshake -- a handler's answer to a request
     * that was read whole, which may keep the connection. Anything else with
     * 400 or 413 is the parser's, and must say "Connection: close". */
    if ((rs.status == 400 || rs.status == 413) && !rs.conn_close &&
        !(r->upgrade && r->ws_status == 400))
        __builtin_trap();
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
    __h1c_refused = 0;

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

    /* The server refused a request, or the last answer is whole on the wire and
     * closes (the request asked, or the server said so): either way the
     * connection must be marked for closing by now. F-01 -- a 4xx on a parse
     * error used to be sent as keep-alive, and the connection stayed open to
     * read on whatever the broken request left behind; and a "Connection:
     * close" on a request whose body came in after the previous answer was
     * written used to be answered as keep-alive (__write had set
     * connection->keepalive from that answer, over the parser's verdict). */
    if ((__h1c_refused || (c->closing && c->out_pos == c->out_len && !c->switched)) &&
        alive && !atomic_load(&ctx->destroyed))
        __builtin_trap();

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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <openssl/evp.h>
#include "base64.h"
#include "cstr.h"
#include "escape.h"
#include "helpers.h"
#include "idn_utils.h"
#include "ipaddr.h"
#include "queryparser.h"
#include "sha1.h"
#include "sha256.h"
#include "typecheck.h"
#include "utf8.h"
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
 * The first byte picks the helper, the rest is the value. A first byte of
 * 0xE0 and up picks one of the helpers added later (idn, ipaddr, base64, ...),
 * described where they are defined. */

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

/* ---- Stage 22 and on: helpers picked by a first byte of 0xE0 or more ----
 *
 * Kept out of the `% 5` above so the existing corpus keeps its meaning. */

/* idn: the ASCII fast path copies whatever it is given; a name that needs
 * conversion goes through libidn2 and comes out ASCII, labels of at most 63
 * and the whole within 253 -- or NULL. */
static void __text_idn(const char* value) {
    int wide = 0;
    for (const unsigned char* p = (const unsigned char*)value; *p; p++)
        if (*p > 127) wide = 1;
    if (idn_needs_conversion(value) != wide) __builtin_trap();

    char* ascii = idn_to_ascii(value);
    if (!wide) {
        if (ascii == NULL || strcmp(ascii, value) != 0) __builtin_trap();
    } else if (ascii != NULL) {
        size_t label = 0;
        for (const unsigned char* p = (const unsigned char*)ascii; *p; p++) {
            if (*p > 127) __builtin_trap();
            label = *p == '.' ? 0 : label + 1;
            if (label > 63) __builtin_trap();
        }
        if (strlen(ascii) > 254 || (strlen(ascii) == 254 && ascii[253] != '.')) __builtin_trap();
        char* again = idn_to_ascii(ascii);
        if (again == NULL || strcmp(again, ascii) != 0) __builtin_trap();
        free(again);
    }
    free(ascii);
}

/* ipaddr: against a parser written here from RFC 791 dotted quads (no leading
 * zeros, as glibc) and RFC 4291 §2.2 text (1-4 hex digits a group, one "::"
 * standing for at least one group, an IPv4 tail in place of the last two).
 * The differences ipaddr.h documents, and only those: "[v6]" is accepted, and
 * brackets around anything else are refused. */
static int __ref_v4(const char* s, uint8_t out[4]) {
    for (int part = 0; part < 4; part++) {
        if (*s < '0' || *s > '9') return 0;
        if (*s == '0' && s[1] >= '0' && s[1] <= '9') return 0;
        unsigned v = 0;
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (unsigned)(*s++ - '0');
            if (v > 255) return 0;
        }
        out[part] = (uint8_t)v;
        if (part < 3 && *s++ != '.') return 0;
    }
    return *s == '\0';
}

static int __ref_hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int __ref_v6(const char* s, uint8_t out[16]) {
    uint16_t head[8], tail[8];
    int nh = 0, nt = 0, gap = 0;
    const char* p = s;
    if (p[0] == ':') {
        if (p[1] != ':') return 0;
        gap = 1;
        p += 2;
    }
    while (*p != '\0') {
        const char* start = p;
        unsigned v = 0;
        int digits = 0;
        while (__ref_hex(*p) >= 0) {
            v = v << 4 | (unsigned)__ref_hex(*p++);
            if (++digits > 4) return 0;
        }
        if (*p == '.') {
            uint8_t v4[4];
            if ((gap ? nh + nt : nh) + 2 > 8 || !__ref_v4(start, v4)) return 0;
            uint16_t* g = gap ? tail : head;
            int* n = gap ? &nt : &nh;
            g[(*n)++] = (uint16_t)(v4[0] << 8 | v4[1]);
            g[(*n)++] = (uint16_t)(v4[2] << 8 | v4[3]);
            p = start + strlen(start);
            break;
        }
        if (digits == 0 || nh + nt == 8) return 0;
        if (gap) tail[nt++] = (uint16_t)v;
        else head[nh++] = (uint16_t)v;
        if (*p == '\0') break;
        if (*p++ != ':') return 0;
        if (*p == ':') {
            if (gap) return 0;
            gap = 1;
            p++;
        } else if (*p == '\0') return 0;
    }
    if (gap ? nh + nt > 7 : nh + nt != 8) return 0;
    memset(out, 0, 16);
    for (int i = 0; i < nh; i++) { out[2 * i] = (uint8_t)(head[i] >> 8); out[2 * i + 1] = (uint8_t)head[i]; }
    for (int i = 0; i < nt; i++) {
        const int at = 8 - nt + i;
        out[2 * at] = (uint8_t)(tail[i] >> 8);
        out[2 * at + 1] = (uint8_t)tail[i];
    }
    return 1;
}

static void __text_ipaddr(const char* value, uint16_t port) {
    uint8_t v4[4], v6[16];
    int family = 0;
    const size_t n = strlen(value);
    if (n >= 2 && value[0] == '[' && value[n - 1] == ']') {
        char* inner = strndup(value + 1, n - 2);
        if (inner == NULL) abort();
        if (__ref_v6(inner, v6)) family = AF_INET6;
        free(inner);
    } else if (__ref_v4(value, v4)) family = AF_INET;
    else if (__ref_v6(value, v6)) family = AF_INET6;

    ipaddr_t addr;
    const int ok = ipaddr_parse(&addr, value);
    if (ok != (family != 0)) __builtin_trap();
    if (!ok) {
        if (ipaddr_is_set(&addr)) __builtin_trap();
        return;
    }
    if (addr.family != family) __builtin_trap();
    if (family == AF_INET && memcmp(&addr.u.v4, v4, 4) != 0) __builtin_trap();
    if (family == AF_INET6 && memcmp(&addr.u.v6, v6, 16) != 0) __builtin_trap();

    /* Text and back, and the authority form. */
    char text[IPADDR_STRLEN], authority[IPADDR_AUTHORITY_STRLEN], want[IPADDR_AUTHORITY_STRLEN];
    ipaddr_t again;
    if (!ipaddr_parse(&again, ipaddr_text(&addr, text, sizeof text)) || !ipaddr_equal(&again, &addr)) __builtin_trap();
    snprintf(want, sizeof want, family == AF_INET6 ? "[%s]:%u" : "%s:%u", text, port);
    if (strcmp(ipaddr_authority(&addr, port, authority, sizeof authority), want) != 0) __builtin_trap();
}

/* base64: encode then decode gives the bytes back; the encoding is the
 * standard alphabet, padded, 4*ceil(n/3) long, and the _nl form breaks it
 * into lines of exactly `wrap` characters when wrap is a whole number of
 * groups. Decoding is lenient by contract (Apache's ap_base64decode): CR and
 * LF are skipped, the first character outside the alphabet ends the input,
 * and the result must be what a decoder written here makes of that. */
static size_t __ref_unb64(const char* s, uint8_t* out) {
    uint8_t six[4];
    size_t n = 0, have = 0;
    for (; *s; s++) {
        if (*s == '\r' || *s == '\n') continue;
        const char* at = strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", *s);
        if (at == NULL) break;
        six[have++] = (uint8_t)(at - "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        if (have == 4) {
            out[n++] = (uint8_t)(six[0] << 2 | six[1] >> 4);
            out[n++] = (uint8_t)(six[1] << 4 | six[2] >> 2);
            out[n++] = (uint8_t)(six[2] << 6 | six[3]);
            have = 0;
        }
    }
    if (have > 1) out[n++] = (uint8_t)(six[0] << 2 | six[1] >> 4);
    if (have > 2) out[n++] = (uint8_t)(six[1] << 4 | six[2] >> 2);
    return n;
}

static void __text_base64(const uint8_t* raw, size_t n, const char* value, uint8_t wrap) {
    char* enc = malloc((size_t)base64_encode_len((int)n));
    if (enc == NULL) abort();
    const int elen = base64_encode(enc, (const char*)raw, (int)n);
    if (elen != (int)(4 * ((n + 2) / 3)) || strlen(enc) != (size_t)elen) __builtin_trap();
    for (int i = 0; i < elen; i++) {
        const int pad = enc[i] == '=';
        if (pad ? i < elen - 2 || (i == elen - 2 && enc[elen - 1] != '=') : strchr("+/", enc[i]) == NULL && !isalnum((unsigned char)enc[i])) __builtin_trap();
    }
    uint8_t* dec = malloc((size_t)base64_decode_len(enc));
    if (dec == NULL) abort();
    if (base64_decode((char*)dec, enc) != (int)n || memcmp(dec, raw, n) != 0) __builtin_trap();
    free(dec);

    if (wrap > 0) {
        char* nl = malloc((size_t)base64_encode_nl_len((int)n, wrap));
        if (nl == NULL) abort();
        const int nlen = base64_encode_nl(nl, (const char*)raw, (int)n, wrap);
        if (nlen < elen || nlen + 1 > base64_encode_nl_len((int)n, wrap)) __builtin_trap();
        if (wrap % 4 == 0) {
            const char* line = nl;
            for (;;) {
                const char* eol = strstr(line, "\r\n");
                if (eol == NULL) { if (strlen(line) > wrap) __builtin_trap(); break; }
                if (eol - line != wrap) __builtin_trap();
                line = eol + 2;
            }
        }
        dec = malloc((size_t)base64_decode_len(nl));
        if (dec == NULL) abort();
        if (base64_decode((char*)dec, nl) != (int)n || memcmp(dec, raw, n) != 0) __builtin_trap();
        free(dec);
        free(nl);
    }
    free(enc);

    /* Whatever the input says, decoded leniently into a buffer of exactly the
     * size base64_decode_len asks for. */
    const int cap = base64_decode_len(value);
    uint8_t* got = malloc((size_t)cap);
    uint8_t* want = malloc(strlen(value) + 1);
    if (got == NULL || want == NULL) abort();
    const size_t want_n = __ref_unb64(value, want);
    const int got_n = base64_decode((char*)got, value);
    if (got_n < 0 || (size_t)got_n != want_n || got_n > cap || memcmp(got, want, want_n) != 0) __builtin_trap();
    free(got);
    free(want);

    /* base64url, as the h2c Upgrade header brings it. */
    const int ucap = base64url_decode_len(value);
    uint8_t* ugot = malloc((size_t)(ucap > 0 ? ucap : 1));
    if (ugot == NULL) abort();
    const int ugot_n = base64url_decode((char*)ugot, value);
    if (ugot_n < 0 || ugot_n > ucap) __builtin_trap();
    free(ugot);
}

/* url: any bytes encode to the unreserved set, '+' and %XX, and decode back;
 * decoding anything agrees with a decoder written here (%XX with two hex
 * digits is a byte, any other '%' stays, '+' is a space) and is never longer
 * than its input. */
static size_t __ref_urldecode(const uint8_t* s, size_t n, uint8_t* out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '%' && i + 2 < n && __ref_hex((char)s[i + 1]) >= 0 && __ref_hex((char)s[i + 2]) >= 0) {
            out[o++] = (uint8_t)(__ref_hex((char)s[i + 1]) << 4 | __ref_hex((char)s[i + 2]));
            i += 2;
        } else out[o++] = s[i] == '+' ? ' ' : s[i];
    }
    return o;
}

static void __text_url(const uint8_t* raw, size_t n) {
    size_t elen = 0;
    char* enc = urlencodel((const char*)raw, n, &elen);
    if (enc == NULL || strlen(enc) != elen) __builtin_trap();
    for (size_t i = 0; i < elen; i++)
        if (!isalnum((unsigned char)enc[i]) && strchr("-_.~+%", enc[i]) == NULL) __builtin_trap();
    size_t dlen = 0;
    char* dec = urldecodel(enc, elen, &dlen);
    if (dec == NULL || dlen != n || memcmp(dec, raw, n) != 0) __builtin_trap();
    free(dec);
    free(enc);

    uint8_t* want = malloc(n + 1);
    if (want == NULL) abort();
    const size_t want_n = __ref_urldecode(raw, n, want);
    dec = urldecodel((const char*)raw, n, &dlen);
    if (dec == NULL || dlen != want_n || dlen > n || memcmp(dec, want, want_n) != 0 || dec[dlen] != '\0') __builtin_trap();
    free(dec);
    free(want);
}

/* hex: bytes_to_hex and back; hex_to_bytes takes an even number of hex
 * digits that fit the buffer, and nothing else. */
static void __text_hex(const uint8_t* raw, size_t n, const char* value, uint8_t arg) {
    char* hex = malloc(2 * n + 1);
    uint8_t* back = malloc(n + 1);
    if (hex == NULL || back == NULL) abort();
    bytes_to_hex(raw, n, hex);
    if (strlen(hex) != 2 * n) __builtin_trap();
    for (size_t i = 0; i < 2 * n; i++) if (!strchr("0123456789abcdef", hex[i])) __builtin_trap();
    if (!hex_to_bytes(hex, back, n) || memcmp(back, raw, n) != 0) __builtin_trap();
    free(hex);
    free(back);

    const size_t len = strlen(value);
    const size_t cap = arg % 64;
    int valid = len % 2 == 0 && len / 2 <= cap;
    for (size_t i = 0; valid && i < len; i++) if (__ref_hex(value[i]) < 0) valid = 0;
    uint8_t* out = malloc(cap + 1);
    if (out == NULL) abort();
    if (hex_to_bytes(value, out, cap) != valid) __builtin_trap();
    for (size_t i = 0; valid && i < len / 2; i++)
        if (out[i] != (uint8_t)(__ref_hex(value[2 * i]) << 4 | __ref_hex(value[2 * i + 1]))) __builtin_trap();
    free(out);
}

/* is_path_traversal: a path climbs out when one of its '/'-separated
 * segments is exactly "..". A backslash is a character of a Linux file
 * name, not a separator. */
static void __text_traversal(const uint8_t* raw, size_t n) {
    int want = 0;
    size_t start = 0;
    for (size_t i = 0; i <= n; i++)
        if (i == n || raw[i] == '/') {
            if (i - start == 2 && raw[start] == '.' && raw[start + 1] == '.') want = 1;
            start = i + 1;
        }
    char* copy = malloc(n + 1);
    if (copy == NULL) abort();
    memcpy(copy, raw, n);
    if (is_path_traversal(copy, n) != want) __builtin_trap();
    free(copy);
}

static void __text_compare(const uint8_t* raw, size_t n, uint8_t arg) {
    const size_t cut = n ? arg % (n + 1) : 0;
    const size_t la = cut, lb = n - cut, m = la < lb ? la : lb;
    if (secure_compare_bytes(raw, raw + cut, m) != (memcmp(raw, raw + cut, m) == 0)) __builtin_trap();
    char* a = strndup((const char*)raw, la);
    char* b = strndup((const char*)raw + cut, lb);
    if (a == NULL || b == NULL) abort();
    if (secure_compare(a, b) != (strcmp(a, b) == 0)) __builtin_trap();
    if (!secure_compare(a, a)) __builtin_trap();
    free(a);
    free(b);
}

/* http_format_date: IMF-fixdate (RFC 9110 §5.6.7) in English whatever the
 * locale, for every year that has four digits, and 0 for any other year or a
 * buffer it does not fit. */
static void __text_date(const uint8_t* raw, size_t n, uint8_t arg) {
    int64_t t = 0;
    for (size_t i = 0; i < 8 && i < n; i++) t = (int64_t)((uint64_t)t << 8 | raw[i]);
    if (n > 8 && raw[8] & 1) t %= 400LL * 366 * 86400;          /* mostly sane years */
    static const char* const days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const char* const months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const size_t size = 1 + arg % 40;
    char buf[64];
    memset(buf, 'x', sizeof buf);
    const size_t got = http_format_date((time_t)t, buf, size);
    if (got >= size || (got > 0 && buf[got] != '\0') || buf[size] != 'x') __builtin_trap();

    struct tm tm;
    const time_t tt = (time_t)t;
    if (gmtime_r(&tt, &tm) == NULL) { if (got != 0) __builtin_trap(); return; }
    if (tm.tm_year + 1900 < 0 || tm.tm_year + 1900 > 9999) { if (got != 0) __builtin_trap(); return; }
    char want[40];
    const int wn = snprintf(want, sizeof want, "%s, %02d %s %04d %02d:%02d:%02d GMT", days[tm.tm_wday], tm.tm_mday,
                            months[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
    if ((size_t)wn + 1 > size) { if (got != 0) __builtin_trap(); return; }
    if (got != (size_t)wn || strcmp(buf, want) != 0) __builtin_trap();
}

/* typecheck: each is_* against the strto* it is named after, read with errno:
 * the whole string taken (is_int also allows trailing blanks, as it always
 * has), no ERANGE, the value in range and finite; and an unsigned type takes
 * no minus sign, before or after the blanks strtoul skips. */
static int __ref_blank_tail(const char* e) {
    while (*e) if (!isspace((unsigned char)*e++)) return 0;
    return 1;
}

static void __text_typecheck(const char* v) {
    char* e;
    const int empty = *v == '\0';
    const char* nb = v;
    while (isspace((unsigned char)*nb)) nb++;

    errno = 0; long l = strtol(v, &e, 10);
    const int want_int = !empty && e != v && errno != ERANGE && l >= INT_MIN && l <= INT_MAX && __ref_blank_tail(e);
    const int want_long = !empty && e != v && errno != ERANGE && *e == '\0';
    errno = 0; unsigned long ul = strtoul(v, &e, 10);
    const int want_ulong = !empty && *nb != '-' && e != v && errno != ERANGE && *e == '\0';
    const int want_uint = want_ulong && ul <= UINT_MAX;
    errno = 0; float f = strtof(v, &e);
    const int want_float = !empty && e != v && *e == '\0' && errno != ERANGE && isfinite(f);
    errno = 0; double d = strtod(v, &e);
    const int want_double = !empty && e != v && *e == '\0' && errno != ERANGE && isfinite(d);
    errno = 0; long double ld = strtold(v, &e);
    const int want_ldouble = !empty && e != v && *e == '\0' && errno != ERANGE && isfinite(ld);

    if (is_int(v) != want_int || is_long(v) != want_long || is_ulong(v) != want_ulong ||
        is_uint(v) != want_uint || is_float(v) != want_float || is_double(v) != want_double ||
        is_long_double(v) != want_ldouble) __builtin_trap();
}

/* utf8: utf8_decode agrees with the strict RFC 3629 decoder above at every
 * position, and utf8_strlen counts a broken byte as one character. */
static void __text_utf8(const char* value) {
    const size_t n = strlen(value);
    size_t count = 0;
    for (size_t i = 0; i < n; count++) {
        uint32_t want_cp = 0, got_cp = 0;
        const size_t want = __text_utf8_next((const uint8_t*)value, n, i, &want_cp);
        const size_t got = utf8_decode((const unsigned char*)value + i, &got_cp);
        if (got != want || (got && got_cp != want_cp)) __builtin_trap();
        i += want ? want : 1;
    }
    if (utf8_strlen(value) != count) __builtin_trap();
}

/* queryparser: as its header says -- pairs split on '&', the key to the first
 * '=', a key without one gets "", '#' ends it, both halves %-decoded (and, as
 * C strings, ending at a decoded NUL); and parsing what query_stringify makes
 * of the result gives the same list. */
static query_t* __text_qparse(const char* s, size_t n) {
    query_t* first = NULL;
    query_t* last = NULL;
    if (queryparser_parse(s, n, 0, NULL, NULL, &first, &last) != QUERYPARSER_OK) __builtin_trap();
    return first;
}

static void __text_query(const uint8_t* raw, size_t n) {
    query_t* list = __text_qparse((const char*)raw, n);

    /* The reference, pair by pair. */
    const query_t* q = list;
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i < n && raw[i] != '&' && raw[i] != '#') continue;
        size_t eq = start;
        while (eq < i && raw[eq] != '=') eq++;
        uint8_t* key = malloc(i - start + 1);
        uint8_t* val = malloc(i - start + 1);
        if (key == NULL || val == NULL) abort();
        key[__ref_urldecode(raw + start, eq - start, key)] = 0;
        const size_t vn = eq < i ? __ref_urldecode(raw + eq + 1, i - eq - 1, val) : 0;
        val[vn] = 0;
        if (q == NULL || strcmp(q->key, (char*)key) != 0 || strcmp(q->value, (char*)val) != 0) __builtin_trap();
        free(key);
        free(val);
        q = q->next;
        start = i + 1;
        if (i < n && raw[i] == '#') break;
    }
    if (q != NULL) __builtin_trap();

    char* text = query_stringify(list);
    if (text == NULL) __builtin_trap();
    query_t* again = __text_qparse(text, strlen(text));
    const query_t* a = list;
    const query_t* b = again;
    for (; a != NULL && b != NULL; a = a->next, b = b->next)
        if (strcmp(a->key, b->key) != 0 || strcmp(a->value, b->value) != 0) __builtin_trap();
    if (a != NULL || b != NULL) __builtin_trap();
    free(text);
    queries_free(again);
    queries_free(list);
}

/* sha1 / sha256: against OpenSSL, sha256_hex against hex of the digest. */
static void __text_sha(const uint8_t* raw, size_t n) {
    unsigned char got[32], want[32];
    unsigned int wn = 0;
    sha1(raw, n, got);
    if (EVP_Digest(raw, n, want, &wn, EVP_sha1(), NULL) != 1 || wn != 20) abort();
    if (memcmp(got, want, 20) != 0) __builtin_trap();
    sha256(raw, n, got);
    if (EVP_Digest(raw, n, want, &wn, EVP_sha256(), NULL) != 1 || wn != 32) abort();
    if (memcmp(got, want, 32) != 0) __builtin_trap();
    char hex[SHA256_HEX_SIZE], want_hex[SHA256_HEX_SIZE];
    sha256_hex(raw, n, hex);
    for (int i = 0; i < 32; i++) snprintf(want_hex + 2 * i, 3, "%02x", want[i]);
    if (strcmp(hex, want_hex) != 0) __builtin_trap();
}

static void __text_extra(uint8_t which, uint8_t arg, const char* value, const uint8_t* raw, size_t n) {
    switch (which) {
    case 0: __text_idn(value); break;
    case 1: __text_ipaddr(value, (uint16_t)(arg * 257)); break;
    case 2: __text_base64(raw, n, value, arg % 100); break;
    case 3: __text_url(raw, n); break;
    case 4: __text_hex(raw, n, value, arg); break;
    case 5: __text_traversal(raw, n); break;
    case 6: __text_compare(raw, n, arg); break;
    case 7: __text_date(raw, n, arg); break;
    case 8: __text_typecheck(value); break;
    case 9: __text_utf8(value); break;
    case 10: __text_query(raw, n); break;
    case 11: __text_sha(raw, n); break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;

    /* The value as the helpers see it: a C string, cut at the first NUL. */
    char* value = malloc(size);
    if (value == NULL) return 0;
    memcpy(value, data + 2, size - 2);
    value[size - 2] = '\0';

    if (data[0] >= 0xE0) {
        __text_extra(data[0] & 0x1F, data[1], value, data + 2, size - 2);
        free(value);
        return 0;
    }

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

#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "dkim.h"
#include "dkimcanonparser.h"
#include "dkimheaderparser.h"
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
 *     anywhere before it (RFC 5321 §4.5.2);
 *   - carry one DKIM-Signature, above MIME-Version, that verifies (below), and
 *     be the same letter, signature included, when built twice from the same
 *     values at the same time. */

typedef struct {
    const uint8_t* p;
    const uint8_t* end;
    int wide;
} mm_in_t;

/* Legacy inputs use one byte of length. A leading 0xff selects three-byte
 * little-endian lengths, so large-profile inputs can reach large fields.
 * Binary fields retain their length even when they contain NUL bytes. */
static char* __mm_field(mm_in_t* in, size_t max, size_t* length) {
    size_t len = 0;
    for (unsigned i = 0; i < (in->wide ? 3u : 1u) && in->p < in->end; i++)
        len |= (size_t)*in->p++ << (8 * i);
    if (len > max) len = max;
    if (len > (size_t)(in->end - in->p)) len = (size_t)(in->end - in->p);
    char* s = malloc(len + 1);
    if (s == NULL) abort();
    memcpy(s, in->p, len);
    s[len] = '\0';
    in->p += len;
    if (length != NULL) *length = len;
    return s;
}

/* What can stand between < > in a header and after MAIL FROM: in SMTP. */
static int __mm_addr_safe(const char* a) {
    if (*a == '\0' || strchr(a, '@') == NULL) return 0;
    for (const unsigned char* q = (const unsigned char*)a; *q; q++)
        if (*q <= 0x20 || *q == 0x7F || *q == '<' || *q == '>') return 0;
    return 1;
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

/* Decode adjacent RFC 2047 words independently of the builder's choice of
 * folding positions. Whitespace between words is not part of the value.
 * Return the suffix (the framed address for From, nothing for Subject). */
static const char* __mm_words(const char* s, const char* want) {
    size_t left = strlen(want);
    for (;;) {
        if (strncmp(s, "=?UTF-8?B?", 10) != 0) __builtin_trap();
        const char* end = strstr(s + 10, "?=");
        if (end == NULL || end + 2 - s > 75) __builtin_trap();
        const size_t len = (size_t)(end - s - 10);
        if (len % 4 != 0) __builtin_trap();
        unsigned char decoded[64];
        int n = EVP_DecodeBlock(decoded, (const unsigned char*)s + 10, (int)len);
        if (n < 0) __builtin_trap();
        if (len > 0 && end[-1] == '=') n--;
        if (len > 1 && end[-2] == '=') n--;
        if (n < 0 || (size_t)n > left || memcmp(decoded, want, (size_t)n) != 0) __builtin_trap();
        want += n;
        left -= (size_t)n;
        const char* next = end + 2;
        while (*next == ' ' || *next == '\t') next++;
        if (next != end + 2 && strncmp(next, "=?UTF-8?B?", 10) == 0) {
            s = next;
            continue;
        }
        if (left != 0) __builtin_trap();
        return end + 2;
    }
}

/* Header fields of a block ending at the empty line; folded lines belong to
 * the field above. Each name must be in `allowed`, at most once. Returns a
 * pointer past the empty line, NULL (trap) otherwise. `values` receives the
 * unfolded value per allowed name. */
static const char* __mm_fields(const char* s, const char* end, const char* const* allowed,
                               size_t n_allowed, char** values) {
    size_t lengths[16] = { 0 }, capacities[16] = { 0 };
    if (n_allowed > 16) __builtin_trap();
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
            const size_t old = lengths[current];
            const size_t len = old + (size_t)(eol - s);
            if (len + 1 > capacities[current]) {
                size_t cap = capacities[current];
                while (cap < len + 1) cap *= 2;
                char* grown = realloc(values[current], cap);
                if (grown == NULL) abort();
                values[current] = grown;
                capacities[current] = cap;
            }
            memcpy(values[current] + old, s, (size_t)(eol - s));
            values[current][len] = '\0';
            lengths[current] = len;
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
            lengths[current] = (size_t)(eol - colon - 2);
            capacities[current] = lengths[current] + 1;
        }
        s = eol + 2;
    }
}

static void __mm_free_values(char** values, size_t n) {
    for (size_t i = 0; i < n; i++) free(values[i]);
}

/* ---- DKIM ----
 *
 * The fixture signs every letter: a key, a selector and mail.host in the
 * configuration, as a site that sends mail has them. The key is RSA-2048,
 * made once per process the way test_dkim.c makes it, and the PEM stays in
 * memory.
 *
 * The signature is checked by a verifier written here from RFC 6376, not from
 * dkim.c: it reads the DKIM-Signature field off the letter as a receiving
 * server would, canonicalizes the fields named in h= and the body with the
 * relaxed algorithms (§3.4.2, §3.4.4), and checks bh= and b= with OpenSSL.
 * What it must not do is reuse what the signer kept -- the unit test that
 * rebuilds the signed bytes from the signer's own state agrees with the signer
 * by construction. */

static char* __mm_dkim_pem;
static EVP_PKEY* __mm_dkim_pub;

static void __mm_dkim_init(void) {
    if (__mm_dkim_pub != NULL) return;

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) abort();
    EVP_PKEY_CTX_free(ctx);

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL || PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) abort();
    BUF_MEM* mem = NULL;
    BIO_get_mem_ptr(bio, &mem);
    __mm_dkim_pem = strndup(mem->data, mem->length);
    if (__mm_dkim_pem == NULL) abort();
    BIO_free(bio);

    __mm_dkim_pub = pkey;

    env_t* e = env();
    e->mail.dkim_private = __mm_dkim_pem;
    e->mail.dkim_selector = "sel";
    e->mail.host = "example.com";
}

typedef struct {
    char* data;
    size_t len;
    size_t cap;
} mm_buf_t;

static void __mm_put(mm_buf_t* b, const void* p, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->len + n + 1) cap *= 2;
        char* grown = realloc(b->data, cap);
        if (grown == NULL) abort();
        b->data = grown;
        b->cap = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static int __mm_wsp(char c) {
    return c == ' ' || c == '\t';
}

/* §3.4.2: the value unfolded, every WSP run one SP, none at either end. */
static void __mm_canon_value(mm_buf_t* out, const char* v, size_t n) {
    int space = 0, any = 0;
    for (size_t i = 0; i < n; i++) {
        if (v[i] == '\r' && i + 1 < n && v[i + 1] == '\n') { i++; continue; }
        if (__mm_wsp(v[i])) { space = 1; continue; }
        if (space && any) __mm_put(out, " ", 1);
        space = 0;
        any = 1;
        __mm_put(out, v + i, 1);
    }
}

/* §3.4.4: WSP runs to one SP, none at the end of a line, no empty lines at
 * the end, and a CRLF after the last line unless the body is empty. */
static void __mm_canon_body(mm_buf_t* out, const char* b, size_t n) {
    size_t empty = 0;
    for (size_t i = 0; i < n;) {
        size_t eol = i;
        while (eol < n && !(b[eol] == '\r' && eol + 1 < n && b[eol + 1] == '\n')) eol++;
        mm_buf_t line = { 0 };
        int space = 0;
        for (size_t k = i; k < eol; k++) {
            if (__mm_wsp(b[k])) { space = 1; continue; }
            if (space) __mm_put(&line, " ", 1);
            space = 0;
            __mm_put(&line, b + k, 1);
        }
        if (line.len == 0) empty++;
        else {
            for (; empty > 0; empty--) __mm_put(out, "\r\n", 2);
            __mm_put(out, line.data, line.len);
            __mm_put(out, "\r\n", 2);
        }
        free(line.data);
        i = eol + 2;
    }
}

/* One field of a header block: its raw bytes, name included, folds kept. */
typedef struct {
    const char* p;
    size_t n;
    size_t name;
    int used;
} mm_field_t;

static size_t __mm_split_fields(const char* h, size_t n, mm_field_t* f, size_t max) {
    size_t count = 0;
    for (size_t i = 0; i < n;) {
        size_t eol = i;
        while (eol + 1 < n && !(h[eol] == '\r' && h[eol + 1] == '\n')) eol++;
        if (eol + 1 >= n) eol = n;
        if ((h[i] == ' ' || h[i] == '\t') && count > 0) {
            f[count - 1].n = eol - (size_t)(f[count - 1].p - h);
        } else {
            if (count == max) break;
            const char* colon = memchr(h + i, ':', eol - i);
            f[count++] = (mm_field_t){ h + i, eol - i, colon ? (size_t)(colon - (h + i)) : eol - i, 0 };
        }
        i = eol + 2;
    }
    return count;
}

/* Field name without trailing WSP, compared case-insensitively. */
static int __mm_field_is(const mm_field_t* f, const char* name, size_t len) {
    size_t n = f->name;
    while (n > 0 && __mm_wsp(f->p[n - 1])) n--;
    return n == len && strncasecmp(f->p, name, len) == 0;
}

static void __mm_canon_field(mm_buf_t* out, const mm_field_t* f, int b_empty) {
    size_t n = f->name;
    while (n > 0 && __mm_wsp(f->p[n - 1])) n--;
    for (size_t i = 0; i < n; i++) {
        const char c = (char)tolower((unsigned char)f->p[i]);
        __mm_put(out, &c, 1);
    }
    __mm_put(out, ":", 1);

    const char* v = f->p + f->name + 1;
    const size_t vn = f->n - f->name - 1;
    if (!b_empty) { __mm_canon_value(out, v, vn); return; }

    /* The DKIM-Signature field itself, with the value of b= removed (§3.5,
     * "b=" with nothing after it) and everything else as it stands. */
    mm_buf_t without = { 0 };
    for (size_t i = 0; i < vn;) {
        size_t end = i;
        while (end < vn && v[end] != ';') end++;
        size_t t = i;
        while (t < end && (__mm_wsp(v[t]) || v[t] == '\r' || v[t] == '\n')) t++;
        size_t eq = t;
        while (eq < end && v[eq] != '=') eq++;
        size_t name_end = eq;
        while (name_end > t && (__mm_wsp(v[name_end - 1]) || v[name_end - 1] == '\r' || v[name_end - 1] == '\n')) name_end--;
        if (eq < end && name_end - t == 1 && v[t] == 'b') __mm_put(&without, v + i, eq + 1 - i);
        else __mm_put(&without, v + i, end - i);
        if (end < vn) __mm_put(&without, ";", 1);
        i = end + 1;
    }
    __mm_canon_value(out, without.data ? without.data : "", without.len);
    free(without.data);
}

/* The value of tag `name` with every FWS removed, NULL when absent. */
static char* __mm_dkim_tag(const char* v, size_t n, const char* name) {
    for (size_t i = 0; i < n;) {
        size_t end = i;
        while (end < n && v[end] != ';') end++;
        mm_buf_t tag = { 0 };
        for (size_t k = i; k < end; k++)
            if (!__mm_wsp(v[k]) && v[k] != '\r' && v[k] != '\n') __mm_put(&tag, v + k, 1);
        const size_t len = strlen(name);
        if (tag.data != NULL && strncmp(tag.data, name, len) == 0 && tag.data[len] == '=') {
            char* value = strdup(tag.data + len + 1);
            free(tag.data);
            if (value == NULL) abort();
            return value;
        }
        free(tag.data);
        i = end + 1;
    }
    return NULL;
}

static char* __mm_b64(const unsigned char* p, size_t n) {
    char* out = malloc(4 * ((n + 2) / 3) + 1);
    if (out == NULL) abort();
    EVP_EncodeBlock((unsigned char*)out, p, (int)n);
    return out;
}

/* Verifies the one DKIM-Signature of a letter whose header block is h[0..hn)
 * (fields separated by CRLF, no empty line) and whose body is b[0..bn). Traps
 * on anything a receiving server would reject; From must be signed in a letter
 * the builder made (§5.4), not in a raw one that may have none. */
static void __mm_dkim_verify(const char* h, size_t hn, const char* b, size_t bn, int require_from) {
    mm_field_t fields[64];
    const size_t count = __mm_split_fields(h, hn, fields, 64);

    const mm_field_t* sig = NULL;
    for (size_t i = 0; i < count; i++)
        if (__mm_field_is(&fields[i], "DKIM-Signature", 14)) {
            if (sig != NULL) __builtin_trap();                            /* once */
            sig = &fields[i];
        }
    if (sig == NULL || sig->name == sig->n) __builtin_trap();
    const char* sv = sig->p + sig->name + 1;
    const size_t sn = sig->n - sig->name - 1;

    char* v = __mm_dkim_tag(sv, sn, "v");
    char* a = __mm_dkim_tag(sv, sn, "a");
    char* c = __mm_dkim_tag(sv, sn, "c");
    char* d = __mm_dkim_tag(sv, sn, "d");
    char* s = __mm_dkim_tag(sv, sn, "s");
    char* hl = __mm_dkim_tag(sv, sn, "h");
    char* bh = __mm_dkim_tag(sv, sn, "bh");
    char* bb = __mm_dkim_tag(sv, sn, "b");
    char* l = __mm_dkim_tag(sv, sn, "l");
    if (!v || !a || !c || !d || !s || !hl || !bh || !bb) __builtin_trap();
    if (strcmp(v, "1") || strcmp(a, "rsa-sha1") || strcmp(c, "relaxed/relaxed") ||
        strcmp(d, env()->mail.host) || strcmp(s, env()->mail.dkim_selector)) __builtin_trap();

    /* Body: l= must cover all of it, or what follows could be anything. */
    mm_buf_t body = { 0 };
    __mm_canon_body(&body, b, bn);
    if (l != NULL && (strspn(l, "0123456789") != strlen(l) || strtoull(l, NULL, 10) != body.len)) __builtin_trap();
    unsigned char digest[20];
    SHA1((const unsigned char*)(body.data ? body.data : ""), body.len, digest);
    char* want_bh = __mm_b64(digest, sizeof digest);
    if (strcmp(want_bh, bh) != 0) __builtin_trap();

    /* Headers: each name in h=, the last unused instance of it (§5.4.2), then
     * the signature field with b= emptied and no CRLF. From is mandatory. */
    mm_buf_t signed_data = { 0 };
    int from = 0;
    for (char* save = NULL, *name = strtok_r(hl, ":", &save); name; name = strtok_r(NULL, ":", &save)) {
        if (strcasecmp(name, "from") == 0) from = 1;
        for (size_t i = count; i-- > 0;)
            if (!fields[i].used && &fields[i] != sig && fields[i].name < fields[i].n && __mm_field_is(&fields[i], name, strlen(name))) {
                fields[i].used = 1;
                __mm_canon_field(&signed_data, &fields[i], 0);
                __mm_put(&signed_data, "\r\n", 2);
                break;
            }
    }
    if (require_from && !from) __builtin_trap();
    __mm_canon_field(&signed_data, sig, 1);

    unsigned char raw[512];
    const size_t bl = strlen(bb);
    if (bl % 4 != 0 || bl / 4 * 3 > sizeof raw) __builtin_trap();
    int rn = EVP_DecodeBlock(raw, (const unsigned char*)bb, (int)bl);
    if (rn < 0) __builtin_trap();
    if (bl > 0 && bb[bl - 1] == '=') rn--;
    if (bl > 1 && bb[bl - 2] == '=') rn--;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) abort();
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha1(), NULL, __mm_dkim_pub) != 1 ||
        EVP_DigestVerifyUpdate(ctx, signed_data.data, signed_data.len) != 1 ||
        EVP_DigestVerifyFinal(ctx, raw, (size_t)rn) != 1) __builtin_trap();
    EVP_MD_CTX_free(ctx);

    free(signed_data.data); free(body.data); free(want_bh);
    free(v); free(a); free(c); free(d); free(s); free(hl); free(bh); free(bb); free(l);
}

/* Mode 0xfe: the input is a raw letter -- header fields, an empty line, a
 * body -- signed through the dkim.c API directly, the way any application may
 * call it, and then verified as above. A field dkim_header_add accepts must be
 * one a letter can carry: a name of RFC 5322 ftext, a value with no NUL and no
 * CR or LF other than a fold (CRLF followed by WSP). Anything else must be
 * refused, or the signature covers a field that is not the one on the wire;
 * and no ';' in the name, which h= cannot carry.
 *
 * The body is normalised the way it would reach a verifier over SMTP: C-string
 * (dkim_create_sign takes one), lone CR and LF made CRLF. Both canonicalizers
 * are also run on their own: relaxed canonicalization is idempotent, and on a
 * value or a body a letter can carry it equals the one written above. The
 * byte after 0xfe picks the signing domain and selector, IDN included. */

static int __mm_ftext_name(const char* n, size_t len) {
    if (len == 0) return 0;
    for (size_t i = 0; i < len; i++)
        if ((unsigned char)n[i] < 33 || (unsigned char)n[i] > 126 || n[i] == ':' || n[i] == ';') return 0;
    return 1;
}

static int __mm_folded_value(const char* v, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (v[i] == '\0') return 0;
        if (v[i] == '\r' || v[i] == '\n') {
            if (!(v[i] == '\r' && i + 2 < len && v[i + 1] == '\n' && __mm_wsp(v[i + 2]))) return 0;
            i++;
        }
    }
    return 1;
}

static char* __mm_canon_run(int header, const char* p, size_t n, size_t* out_n) {
    char* out;
    if (header) {
        dkimheaderparser_t* parser = dkimheaderparser_alloc();
        if (parser == NULL) abort();
        dkimheaderparser_init(parser);
        dkimheaderparser_set_buffer(parser, p, n);
        if (!dkimheaderparser_run(parser)) __builtin_trap();
        out = dkimheaderparser_get_content(parser);
        *out_n = dkimheaderparser_get_content_length(parser);
        dkimheaderparser_free(parser);
    } else {
        dkimcanonparser_t* parser = dkimcanonparser_alloc();
        if (parser == NULL) abort();
        dkimcanonparser_init(parser);
        dkimcanonparser_set_buffer(parser, p, n);
        if (!dkimcanonparser_run(parser)) __builtin_trap();
        out = dkimcanonparser_get_content(parser);
        dkimcanonparser_free(parser);
        if (out != NULL) *out_n = strlen(out);
    }
    if (out == NULL) abort();
    return out;
}

static void __mm_canon_check(int header, const char* p, size_t n, int on_the_wire) {
    size_t once_n, twice_n;
    char* once = __mm_canon_run(header, p, n, &once_n);
    char* twice = __mm_canon_run(header, once, once_n, &twice_n);
    if (once_n != twice_n || memcmp(once, twice, once_n) != 0) __builtin_trap();
    if (on_the_wire) {
        mm_buf_t want = { 0 };
        if (header) __mm_canon_value(&want, p, n);
        else __mm_canon_body(&want, p, n);
        if (once_n != want.len || memcmp(once, want.data ? want.data : "", once_n) != 0) __builtin_trap();
        free(want.data);
    }
    free(once);
    free(twice);
}

static void __mm_dkim_raw(const uint8_t* data, size_t size) {
    static const char* const domains[] = { "example.com", "xn--e1afmkfd.xn--p1ai", "\xd0\xbf\xd1\x80\xd0\xb8\xd0\xbc\xd0\xb5\xd1\x80.\xd1\x80\xd1\x84" };
    static const char* const selectors[] = { "sel", "s-2026.mail", "\xd0\xba\xd0\xbb\xd1\x8e\xd1\x87" };
    if (size < 1) return;
    char* const host = env()->mail.host;
    char* const selector = env()->mail.dkim_selector;
    env()->mail.host = (char*)domains[data[0] % 3];
    env()->mail.dkim_selector = (char*)selectors[data[0] / 3 % 3];
    data++; size--;

    const char* text = (const char*)data;
    size_t hn = size;
    const char* body_raw = "";
    size_t body_raw_n = 0;
    for (size_t i = 0; i + 3 < size; i++)
        if (memcmp(text + i, "\r\n\r\n", 4) == 0) {
            hn = i + 2;
            body_raw = text + i + 4;
            body_raw_n = size - i - 4;
            break;
        }

    mm_field_t fields[32];
    const size_t count = __mm_split_fields(text, hn, fields, 32);

    dkim_t* dkim = dkim_create();
    if (dkim == NULL) abort();
    dkim_set_private_key(dkim, env()->mail.dkim_private);
    dkim_set_domain(dkim, env()->mail.host);
    dkim_set_selector(dkim, env()->mail.dkim_selector);
    dkim_set_timestamp(dkim, 1700000000);

    mm_buf_t letter = { 0 };
    size_t accepted = 0;
    for (size_t i = 0; i < count; i++) {
        const mm_field_t* f = &fields[i];
        if (f->name == f->n) continue;                                    /* no colon */
        if (__mm_field_is(f, "DKIM-Signature", 14)) continue;             /* the one we add */
        const char* value = f->p + f->name + 1;
        const size_t vn = f->n - f->name - 1;
        const int ok = dkim_header_add(dkim, f->p, f->name, value, vn);
        const int valid = __mm_ftext_name(f->p, f->name) && __mm_folded_value(value, vn) && vn > 0 && value[0] != '\0';
        if (ok && !valid) __builtin_trap();
        __mm_canon_check(1, value, vn, valid);
        if (!ok) continue;
        accepted++;
        __mm_put(&letter, f->p, f->n);
        __mm_put(&letter, "\r\n", 2);
    }

    /* The body as SMTP carries it. */
    mm_buf_t body = { 0 };
    for (size_t i = 0; i < body_raw_n && body_raw[i] != '\0'; i++) {
        if (body_raw[i] == '\r' && i + 1 < body_raw_n && body_raw[i + 1] == '\n') { __mm_put(&body, "\r\n", 2); i++; }
        else if (body_raw[i] == '\r' || body_raw[i] == '\n') __mm_put(&body, "\r\n", 2);
        else __mm_put(&body, body_raw + i, 1);
    }
    const char* b = body.data ? body.data : "";
    __mm_canon_check(0, b, body.len, 1);

    if (accepted > 0) {
        char* sign = dkim_create_sign(dkim, b);
        if (sign == NULL) __builtin_trap();
        __mm_put(&letter, "DKIM-Signature: ", 16);
        __mm_put(&letter, sign, strlen(sign));
        const size_t headers = letter.len;
        __mm_dkim_verify(letter.data, headers, b, body.len, 0);
        free(sign);
    }

    dkim_free(dkim);
    free(letter.data);
    free(body.data);
    env()->mail.host = host;
    env()->mail.dkim_selector = selector;
}


int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    __mm_dkim_init();
    if (data[0] == 0xfe) {
        __mm_dkim_raw(data + 1, size - 1);
        return 0;
    }
    mm_in_t in = { .p = data, .end = data + size, .wide = data[0] == 0xff };
    if (in.wide) in.p++;

    char* from = __mm_field(&in, 80, NULL);
    char* from_name = __mm_field(&in, SIZE_MAX, NULL);
    char* to = __mm_field(&in, 80, NULL);
    char* subject = __mm_field(&in, SIZE_MAX, NULL);
    char* body = __mm_field(&in, SIZE_MAX, NULL);

    mail_attachment_t att[2];
    char *names[2] = { NULL, NULL }, *types[2] = { NULL, NULL }, *cids[2] = { NULL, NULL };
    uint8_t* bytes[2] = { NULL, NULL };
    size_t count = in.p < in.end ? *in.p++ % 3 : 0;
    for (size_t i = 0; i < count; i++) {
        const uint8_t shape = in.p < in.end ? *in.p++ : 0;
        names[i] = __mm_field(&in, 120, NULL);
        types[i] = shape & 1 ? __mm_field(&in, 60, NULL) : NULL;
        cids[i] = shape & 2 ? __mm_field(&in, 40, NULL) : NULL;
        size_t n = 0;
        char* raw = __mm_field(&in, SIZE_MAX, &n);
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

        /* A letter the setters took and the builder's own preconditions allow
         * is built -- signature included: a DKIM failure is a letter that is
         * never sent, and must not pass here as a refusal. */
        int buildable = body[0] != '\0' && subject[0] != '\0';
        for (size_t i = 0; i < count; i++) {
            if (names[i][0] == '\0' || att[i].size == 0) buildable = 0;
            if (cids[i] != NULL && cids[i][0] != '\0' && !mailattachment_cid_valid(cids[i])) buildable = 0;
            for (const unsigned char* t = (const unsigned char*)(types[i] ? types[i] : ""); *t; t++)
                if (*t < 0x20 || *t == 0x7F) buildable = 0;
        }

        const int built = mail_message_build(m, (time_t)1700000000);
        if (buildable && !built) __builtin_trap();
        if (built) {
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
                "Content-Type", "Content-Transfer-Encoding", "DKIM-Signature",
            };
            char* v[9];
            const char* bodypart = __mm_fields(d, d + len, top, 9, v);
            for (size_t i = 0; i < 7; i++) if (v[i] == NULL) __builtin_trap();
            if (v[8] == NULL) __builtin_trap();

            /* Signed, above MIME-Version, and verifiable by a stranger. The
             * body a receiver hashes ends before the terminator's dot. */
            const char* sig_at = strstr(d, "\r\nDKIM-Signature: ");
            const char* mime_at = strstr(d, "\r\nMIME-Version: ");
            if (sig_at == NULL || mime_at == NULL || sig_at > mime_at) __builtin_trap();
            __mm_dkim_verify(d, (size_t)(bodypart - d) - 2, bodypart, (size_t)(d + len - 3 - bodypart), 1);

            char want[128];
            snprintf(want, sizeof want, " <%s>", from);
            if (strcmp(__mm_words(v[0], from_name), want) != 0) __builtin_trap();
            snprintf(want, sizeof want, "<%s>", to);
            if (strcmp(v[1], want) != 0) __builtin_trap();
            if (*__mm_words(v[2], subject) != '\0') __builtin_trap();

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
            __mm_free_values(v, 9);

            /* The same values at the same time make the same letter. With
             * attachments the multipart boundary is random, so only then is
             * the letter allowed to differ. */
            if (count == 0) {
                mail_message_t* again = mail_message_create();
                if (again == NULL) abort();
                if (!mail_message_set_from(again, from, from_name) || !mail_message_set_to(again, to) ||
                    !mail_message_set_subject(again, subject)) __builtin_trap();
                mail_message_set_body(again, body);
                if (!mail_message_build(again, (time_t)1700000000)) __builtin_trap();
                if (again->data_size != len || memcmp(again->data, d, len) != 0) __builtin_trap();
                mail_message_free(again);
            }
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
 * bursts of loss and blackouts, damaged datagrams, the process stalling while
 * its clock runs on, and a path MTU that PMTU probes run into and that can drop
 * under a size already raised to.
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

/* The congestion window's count against what loss detection holds. The count
 * is raised and lowered in several places -- sent, acknowledged, lost,
 * discarded with its keys -- and every one of them must agree with the list
 * the packets actually sit on. And only what RFC 9002 §2 calls in flight
 * belongs in it: ack-eliciting packets, or Initials, padded to 1200 bytes. An
 * ACK-only packet counted here is one the peer will never acknowledge. */
static void __qc_check(const stand_t* s) {
    /* The client is correct, so the server has no cause to close with an
     * error, whatever the path did: a datagram lost, duplicated, late or
     * damaged is dropped or recovered from, never a protocol violation. A
     * damaged header once was one -- the reserved bits were read before the
     * packet was authenticated. */
    if (s->client.close_received && s->client.close_error != QUIC_NO_ERROR) __builtin_trap();

    if (s->conn == NULL) return;

    /* A live connection always has a deadline -- at the least its idle
     * timeout. One without any would be woken by nothing but the peer, and a
     * peer that has gone never wakes it: it would stay in the table for good. */
    if (s->conn->state != QUICCONN_DEAD && quicconn_next_timeout(s->conn) == 0) __builtin_trap();

    uint64_t sum = 0;
    for (int level = 0; level < QUIC_ENC_COUNT; level++) {
        for (const quicsent_t* p = s->conn->loss.space[level].sent; p != NULL; p = p->next) {
            if (!p->in_flight) continue;
            if (!p->ack_eliciting && level != QUIC_ENC_INITIAL) __builtin_trap();
            sum += p->size;
        }
    }
    if (s->conn->cc.bytes_in_flight != sum) __builtin_trap();
}

/* The stand's own guard, but as a finding: events that keep coming while the
 * clock stands still are a spin in the code under test. */
static void __qc_run(stand_t* s, uint64_t horizon_us) {
    const uint64_t limit = __now_us + horizon_us;
    uint64_t last = __now_us;
    unsigned still = 0;
    for (;;) {
        if (s->client_failed) return;
        const int stepped = __step(s, limit);
        __qc_check(s);
        if (!stepped) return;
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
        /* FIN can precede missing data after loss or reordering. Compare the
         * final length only once every byte before FIN has been read. */
        if (quicclient_stream_complete(&s->client, 4 * k) && st[k].responded &&
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

        switch (op % 15) {
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
        case 6:
            /* The ping's argument, unused otherwise, sets the path MTU: a
             * probe over it is lost for its size, and a raised size it drops
             * under is a black hole the server has to find its way out of.
             * Never under the base (1350), which is all QUIC promises. */
            if (arg & 0x80) s->mtu = arg == 0xff ? 0 : 1360 + (arg & 0x7f);
            (void)quicclient_ping(&s->client);
            break;
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
        case 13:                                    /* damage in transit */
            s->corrupt_at = (uint32_t)arg * 97 + (uint32_t)(p - data);
            if (arg & 1) s->corrupt_next_to_server = 1 + arg % 3;
            else s->corrupt_next_to_client = 1 + arg % 3;
            break;
        case 14:
            /* A stall: the clock jumps and every timer and datagram that fell
             * due meanwhile is handled late, all at once. */
            __now_us += 1000 + (uint64_t)arg * 20000;
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
 * LeakSanitizer is on. It was off for a long time, with every dispatched
 * request reported as leaked: the fixture's context lacked is_http2, so the
 * dispatcher built an HTTP/1.1 response that no stream owned. With the flag
 * set, as h2_server_set_http2 sets it, a response belongs to its stream and
 * goes with it through the pool, and the teardown below -- one write pass to
 * drain the publish queue, the pending-handler flags cleared, the session
 * freed -- releases everything. ASan and UBSan found the null memcpy in
 * h2_on_headers on this target's first run. */

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
    /* What h2_server_set_http2 sets: without it a dispatched request got an
     * HTTP/1.1 response, taken from the connection's cache and never bound to
     * its stream, and nothing the teardown can reach owned it. */
    ctx.is_http2 = 1;
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

    /* The response pool goes with the session (h2_session_free). Emptying it
     * here is no option: on an empty pool h2_server_take_response makes a new
     * response, and a loop waiting for NULL never ends. */

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
    int legacy_ok = urlencodedparser_parse(&parser, buffer, size);

    http_payload_t payload = {.file = file_alloc()};
    body_store_init(&payload.incoming, SIZE_MAX, BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_MODE_AUTO);
    if (body_store_prepare(&payload.incoming, size, "/tmp") &&
        body_store_append(&payload.incoming, data, size, "/tmp")) {
        urlencodedparser_t incoming;
        urlencodedparser_init_payload(&incoming, &payload);
        int incoming_ok = urlencodedparser_parse(&incoming, buffer, size);
        if (legacy_ok != incoming_ok) __builtin_trap();
        const http_payloadfield_t* a = parser.field;
        const http_payloadfield_t* b = incoming.field;
        while (a && b) {
            if (a->key_length != b->key_length || a->value_length != b->value_length ||
                (a->key == NULL) != (b->key == NULL) ||
                (a->value == NULL) != (b->value == NULL) ||
                (a->key_length && memcmp(a->key, b->key, a->key_length)) ||
                (a->value_length && memcmp(a->value, b->value, a->value_length))) __builtin_trap();
            a = a->next;
            b = b->next;
        }
        if (a || b) __builtin_trap();
        urlencodedparser_clear(&incoming);
    }
    body_store_reset(&payload.incoming);
    urlencodedparser_clear(&parser);
    free(buffer);
    close(fd);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_MULTIPART

/* Parses `data` delivered in reads of `fixed` bytes, or -- with fixed 0 and a
 * seed -- of sizes 1..64 from a small PRNG, or whole with both 0. Returns a
 * digest of the result and of every part the parser produced. */
static uint64_t __fuzz_multipart_run(int fd, const http_payload_t* payload, const char* boundary,
                                     const uint8_t* data, size_t size,
                                     size_t fixed, uint64_t seed) {
    multipartparser_t parser;
    if (payload) multipartparser_init_payload(&parser, payload, boundary);
    else multipartparser_init(&parser, fd, boundary);

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
    const uint64_t whole = __fuzz_multipart_run(fd, NULL, boundary, data, size, 0, 0);
    const uint64_t bytes = __fuzz_multipart_run(fd, NULL, boundary, data, size, 1, 0);
    const uint64_t steps = __fuzz_multipart_run(fd, NULL, boundary, data, size, 0, blen + 1);
    if (whole != bytes || whole != steps) __builtin_trap();
    http_payload_t payload = {.file = file_alloc()};
    body_store_init(&payload.incoming, SIZE_MAX, BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_MODE_AUTO);
    if (body_store_prepare(&payload.incoming, size, "/tmp") &&
        body_store_append(&payload.incoming, data, size, "/tmp")) {
        const uint64_t memory = __fuzz_multipart_run(-1, &payload, boundary, data, size, 0, 0);
        const uint64_t memory_steps = __fuzz_multipart_run(-1, &payload, boundary, data, size, 0, blen + 1);
        if (whole != memory || whole != memory_steps) __builtin_trap();
    }
    body_store_reset(&payload.incoming);


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
    const body_store_t* incoming = &request->payload_.incoming;
    const int stored = incoming->state != BODY_STORE_EMPTY;
    const size_t body_size = stored ? incoming->size : (body->fd >= 0 ? body->size : 0);
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
        const ssize_t n = stored
            ? (body_store_read(incoming, off, chunk, want) ? (ssize_t)want : -1)
            : pread(body->fd, chunk, want, (off_t)off);
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
        if (runs[i].digest != runs[0].digest) __builtin_trap();
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

#elif FUZZ_TARGET == FUZZ_RATELIMITER

#include <arpa/inet.h>
#include "ipaddr.h"
#include "map.h"
#include "ratelimiter.h"

/* The token bucket in front of the contact form, against a model of its own
 * written from ratelimiter.h and nothing else: one integer count per client
 * key, refilled from the last refill by refill_rate per whole elapsed second
 * (what is left over below one token is dropped with the refill, as the code
 * does), capped at max_tokens, taken whole or not at all; a sweep at most once
 * per cleanup_interval_s that forgets every client idle for longer than that.
 * A NULL address and a zero refill_rate are always allowed.
 *
 * The key is computed here from the address bytes as ipaddr.h describes it --
 * the whole IPv4 address under ffff:ffff::/32, the first 64 bits of an IPv6
 * one -- not by calling ipaddr_client_key. That includes the overlap the
 * header documents: an IPv6 source in ffff:ffff::/32 shares a key with an IPv4
 * one, which is harmless only because such a source cannot exist.
 *
 * The clock is the target's (ratelimiter_set_time_source) and the input moves
 * it: not at all, a little, a lot, or backwards -- a backward step must grant
 * nothing and forget nobody.
 *
 * Input: four bytes of configuration, then records of
 *   [op] [clock argument] [address] [tokens]
 * op bits 0-1: clock step (none, +arg ms, +arg*2^32 ns, -arg ms), bit 2:
 * address is literal text (length byte, then bytes) instead of an index into
 * the table below. The tokens byte is the request, with 254 meaning max_tokens
 * and 255 one more than that.
 *
 * After every call: the verdict is the model's, the map holds exactly the
 * model's clients, and each bucket holds the model's count. */

#define RL_MAX_CLIENTS 64

typedef struct {
    uint64_t key;
    uint32_t tokens;
    uint64_t last_refill;
    uint64_t last_access;
} rl_model_bucket_t;

typedef struct {
    ratelimiter_config_t config;
    rl_model_bucket_t buckets[RL_MAX_CLIENTS];
    size_t count;
    uint64_t last_cleanup;
} rl_model_t;

static uint64_t __rl_now;

static uint64_t __rl_clock(void) {
    return __rl_now;
}

static uint64_t __rl_elapsed(uint64_t now, uint64_t then) {
    return now > then ? now - then : 0;
}

static uint64_t __rl_key(const ipaddr_t* ip) {
    if (ip->family == AF_INET)
        return 0xffffffff00000000ULL | ntohl(ip->u.v4.s_addr);

    uint64_t key = 0;
    for (int i = 0; i < 8; i++)
        key = key << 8 | ip->u.v6.s6_addr[i];
    return key;
}

static int __rl_model_allow(rl_model_t* m, const ipaddr_t* ip, uint32_t tokens, uint64_t now) {
    const uint64_t interval = (uint64_t)m->config.cleanup_interval_s * 1000000000ULL;

    if (__rl_elapsed(now, m->last_cleanup) >= interval) {
        m->last_cleanup = now;
        size_t kept = 0;
        for (size_t i = 0; i < m->count; i++)
            if (__rl_elapsed(now, m->buckets[i].last_access) <= interval)
                m->buckets[kept++] = m->buckets[i];
        m->count = kept;
    }

    if (m->config.refill_rate == 0 || ip == NULL) return 1;

    const uint64_t key = __rl_key(ip);
    rl_model_bucket_t* b = NULL;
    for (size_t i = 0; i < m->count; i++)
        if (m->buckets[i].key == key) b = &m->buckets[i];
    if (b == NULL) {
        if (m->count == RL_MAX_CLIENTS) __builtin_trap();  /* the input cannot name more */
        b = &m->buckets[m->count++];
        *b = (rl_model_bucket_t){ key, m->config.max_tokens, now, now };
    }

    /* Whole tokens, in 128 bits so that no pause is long enough to wrap. */
    const unsigned __int128 add =
        (unsigned __int128)__rl_elapsed(now, b->last_refill) * m->config.refill_rate / 1000000000ULL;
    if (add > 0) {
        const unsigned __int128 sum = (unsigned __int128)b->tokens + add;
        b->tokens = sum > m->config.max_tokens ? m->config.max_tokens : (uint32_t)sum;
        b->last_refill = now;
    }
    b->last_access = now;

    if (b->tokens < tokens) return 0;
    b->tokens -= tokens;
    return 1;
}

static const char* const __rl_addresses[] = {
    "192.0.2.1", "192.0.2.2", "10.0.0.1", "0.0.0.0", "255.255.255.255",
    "2001:db8::1", "2001:db8::ffff:1", "[2001:db8::2]", "2001:db8:0:1::1",
    "::1", "::", "::ffff:192.0.2.1", "fe80::1", "ffff:ffff:c000:201::1",
    "not an address", "",
};

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;

    rl_model_t* m = calloc(1, sizeof *m);
    if (m == NULL) return 0;

    /* Small burst so that it runs out; a rate from one token a second to one
     * large enough that elapsed*rate overflows 64 bits after a pause; an
     * interval from "every call sweeps" to the longest there is. */
    m->config.max_tokens = data[0];
    m->config.refill_rate = ((uint32_t)data[1] | (uint32_t)(data[2] & 0x7f) << 8) << (data[2] & 0x80 ? 16 : 0);
    m->config.time_window_ns = 1000000000ULL;
    m->config.cleanup_interval_s = data[3] == 255 ? UINT32_MAX : data[3];
    data += 4; size -= 4;

    __rl_now = 1ULL << 40;
    m->last_cleanup = __rl_now;
    ratelimiter_set_time_source(__rl_clock);

    ratelimiter_t* limiter = ratelimiter_init(&m->config);
    if (limiter == NULL) __builtin_trap();

    size_t pos = 0;
    for (int record = 0; record < 4096 && pos + 3 <= size; record++) {
        const uint8_t op = data[pos++];
        const uint64_t arg = data[pos++];

        switch (op & 3) {
        case 1: __rl_now += arg * 1000000ULL; break;
        case 2: __rl_now += arg << 32; break;
        case 3: __rl_now = __rl_now > arg * 1000000ULL ? __rl_now - arg * 1000000ULL : 0; break;
        }
        if (__rl_now > 1ULL << 62) __rl_now = 1ULL << 62;

        char text[64];
        if (op & 4) {
            size_t len = data[pos++] % sizeof text;
            if (len > size - pos) len = size - pos;
            memcpy(text, data + pos, len);
            text[len] = '\0';
            pos += len;
        } else {
            const size_t n = sizeof __rl_addresses / sizeof __rl_addresses[0];
            snprintf(text, sizeof text, "%s", __rl_addresses[data[pos++] % n]);
        }
        if (pos >= size) break;

        uint32_t tokens = data[pos++];
        if (tokens == 254) tokens = m->config.max_tokens;
        else if (tokens == 255) tokens = m->config.max_tokens + 1;

        ipaddr_t ip;
        const int parsed = ipaddr_parse(&ip, text);
        const ipaddr_t* arg_ip = parsed ? &ip : NULL;

        const int expected = __rl_model_allow(m, arg_ip, tokens, __rl_now);
        const int got = ratelimiter_allow(limiter, arg_ip, tokens);
        if (got != expected) __builtin_trap();

        if (map_size(limiter->buckets) != m->count) __builtin_trap();
        for (size_t i = 0; i < m->count; i++) {
            const ratelimiter_bucket_t* b = map_find(limiter->buckets, (void*)(uintptr_t)m->buckets[i].key);
            if (b == NULL || b->tokens != m->buckets[i].tokens) __builtin_trap();
            if (b->tokens > m->config.max_tokens) __builtin_trap();
        }
    }

    ratelimiter_free(limiter);
    ratelimiter_set_time_source(NULL);
    free(m);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_DB_QUERY

/* The query layer that user data reaches on its way to the database: the
 * template builder (parse_sql_parameters), the bound execution of dbquery,
 * the result cursor, and the dbinsert/dbselect/dbupdate/dbdelete compilers --
 * on SQLite ":memory:", which needs no server. The first byte picks the mode:
 *
 *   0 builder -- a template generated from the input out of SQL words, string
 *     literals, quoted identifiers, both kinds of comment, and :v @w :list__l
 *     parameters with whatever follows them (a quote, a comment, a cast). The
 *     builder, run with a processor that writes <name> and {name}, must give
 *     exactly the template with those substitutions -- nothing inside a literal
 *     or a comment, nothing lost at the end -- or refuse an unknown name, two
 *     names run together, or a list that is empty. Backslash before a quote is
 *     left out of the generator: the scanner treats it as an escape, which is
 *     MySQL's reading and not SQLite's or PostgreSQL's (ruled, not tested);
 *   1 values -- a value (any bytes, NUL included), a list and an identifier
 *     go through dbquery and come back byte for byte; the identifier is quoted,
 *     never spliced (one column, named as given up to its first NUL -- the
 *     escaper works on C strings); an unknown name is refused;
 *   2 results -- a VALUES table of the input's shape, NULLs included, walked
 *     with every cursor call and arbitrary (negative too) indices against a
 *     model of the cursor: nothing outside the table, NULL for SQL NULL;
 *   3 compilers -- a table and two columns named from the input (quotes,
 *     separators, any UTF-8; not the expression forms dbselect passes through
 *     raw by contract), a row inserted, selected, updated, deleted.
 *
 * Throughout: a result that is not ok carries an error, one that is ok does
 * not, and LeakSanitizer sees everything freed. */

static void __dq_check(dbresult_t* r) {
    if (r == NULL) return;
    if (dbresult_ok(r) && dbresult_error(r) != NULL) __builtin_trap();
    if (!dbresult_ok(r) && dbresult_error(r) == NULL) __builtin_trap();
}

/* ---- 0: builder ---- */

static int __dq_marker(void* connection, char type, const char* name, mfield_t* field, str_t* sql, void* user_data) {
    (void)connection; (void)field; (void)user_data;
    str_appendc(sql, type == ':' ? '<' : '{');
    str_append(sql, name, strlen(name));
    str_appendc(sql, type == ':' ? '>' : '}');
    return 1;
}

/* Bytes of a literal, identifier or comment: anything but a backslash (see
 * above) and the terminator, which the caller doubles or avoids. */
static void __dq_content(dq_in_t* in, dq_buf_t* t, char quote, int comment) {
    const size_t n = __dq_byte(in) % 12;
    char prev = 0;
    for (size_t i = 0; i < n; i++) {
        char c = (char)__dq_byte(in);
        if (c == '\\') c = 'b';
        if (comment == 1 && prev == '*' && c == '/') c = '|';
        if (comment == 2 && (c == '\n' || c == '\r')) c = ' ';
        if (quote != 0 && c == quote) __dq_put(t, &c, 1);
        __dq_put(t, &c, 1);
        prev = c;
    }
}

static void __dq_builder(dq_in_t* in) {
    static const char* const words[] = {
        "SELECT", " ", ",", "(", ")", "1", "x", "AS", "=", "\n", "\t", ";", "*", ": ", "@ ", "x::int", "::",
    };
    static const char* const after[] = { " ", ",", ")", "::int", "'q'", "\"i\"", "--c\n", "/*c*/", "\n", "=1" };

    const size_t list_n = __dq_byte(in) % 4;
    array_t* list = array_create();
    for (size_t i = 0; i < list_n; i++) array_push_back(list, array_create_int((int)i));
    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(v, 1), mparam_int(w, 2), mparam_array(l, list));

    dq_buf_t t = { 0 }, e = { 0 };
    int refused = 0;
    const size_t pieces = __dq_byte(in) % 48 + 1;
    for (size_t k = 0; k < pieces && in->p < in->end; k++) {
        const uint8_t op = __dq_byte(in);
        const size_t start = t.len;
        switch (op % 9) {
        case 0:
            __dq_puts(&t, words[__dq_byte(in) % (sizeof words / sizeof words[0])]);
            break;
        case 1:
            __dq_puts(&t, "'"); __dq_content(in, &t, '\'', 0); __dq_puts(&t, "'");
            break;
        case 2:
            __dq_puts(&t, "\""); __dq_content(in, &t, '"', 0); __dq_puts(&t, "\"");
            break;
        case 3:
            __dq_puts(&t, "/*"); __dq_content(in, &t, 0, 1);
            if (t.data[t.len - 1] == '*') __dq_puts(&t, " ");
            __dq_puts(&t, "*/");
            break;
        case 4:
            __dq_puts(&t, "--"); __dq_content(in, &t, 0, 2); __dq_puts(&t, "\n");
            break;
        case 5:
        case 6: {
            const char type = op % 9 == 5 ? ':' : '@';
            const uint8_t which = __dq_byte(in) % 3;
            const char* name = which == 0 ? "v" : which == 1 ? "w" : "list__l";
            __dq_put(&t, &type, 1);
            __dq_puts(&t, name);
            if (which == 2) {
                if (list_n == 0) refused = 1;
                for (size_t i = 0; i < list_n; i++) {
                    if (i > 0) __dq_puts(&e, ",");
                    __dq_puts(&e, type == ':' ? "<l>" : "{l}");
                }
            } else {
                __dq_puts(&e, type == ':' ? "<" : "{");
                __dq_puts(&e, name);
                __dq_puts(&e, type == ':' ? ">" : "}");
            }
            const size_t mark = t.len;
            __dq_puts(&t, after[__dq_byte(in) % (sizeof after / sizeof after[0])]);
            __dq_put(&e, t.data + mark, t.len - mark);
            continue;
        }
        case 7:
            __dq_puts(&t, ":zz ");
            refused = 1;
            break;
        case 8:
            __dq_puts(&t, ":v:w ");
            refused = 1;
            break;
        }
        __dq_put(&e, t.data + start, t.len - start);
    }

    str_t* built = parse_sql_parameters(NULL, t.data ? t.data : "", t.len, params, __dq_marker, NULL);
    if (refused) {
        if (built != NULL) __builtin_trap();
    } else {
        if (built == NULL) __builtin_trap();
        if (str_size(built) != e.len || memcmp(str_get(built), e.data ? e.data : "", e.len) != 0) __builtin_trap();
    }

    str_free(built);
    array_free(params);
    free(t.data);
    free(e.data);
}

/* ---- 1: values ---- */

static void __dq_values(dq_in_t* in) {
    uint8_t bytes[256];
    const size_t n = __dq_byte(in);
    size_t len = 0;
    while (len < n && in->p < in->end) bytes[len++] = *in->p++;

    /* The value, as a text field that keeps its NUL bytes. */
    mfield_t* v = field_create_text("v", "");
    if (v == NULL) abort();
    str_assign(v->value._string, (const char*)bytes, len);
    array_t* params = array_create();
    array_push_back(params, array_create_pointer(v, NULL, model_param_free));
    dbresult_t* r = dbquery(DQ_DBID, "SELECT :v AS v", params);
    __dq_check(r);
    if (!dbresult_ok(r)) __builtin_trap();
    db_table_cell_t* cell = dbresult_field(r, "v");
    if (cell == NULL || cell->value == NULL || cell->length != len || memcmp(cell->value, bytes, len) != 0) __builtin_trap();
    dbresult_free(r);

    /* Through a table and back. */
    r = dbquery(DQ_DBID, "INSERT INTO fz (t) VALUES (:v) RETURNING t", params);
    __dq_check(r);
    cell = dbresult_ok(r) ? dbresult_field(r, "t") : NULL;
    if (cell == NULL || cell->length != len || memcmp(cell->value, bytes, len) != 0) __builtin_trap();
    dbresult_free(r);
    r = dbquery(DQ_DBID, "DELETE FROM fz", NULL);
    if (!dbresult_ok(r)) __builtin_trap();
    dbresult_free(r);

    /* An identifier: quoted, whatever it holds. */
    mfield_t* w = field_create_text("w", "");
    if (w == NULL) abort();
    str_assign(w->value._string, (const char*)bytes, len);
    array_push_back(params, array_create_pointer(w, NULL, model_param_free));
    r = dbquery(DQ_DBID, "SELECT 1 AS @w", params);
    __dq_check(r);
    if (dbresult_ok(r)) {
        const size_t name_len = strnlen((const char*)bytes, len);
        const char* name = dbresult_col_name(r, 0);
        if (dbresult_query_cols(r) != 1 || name == NULL || strlen(name) != name_len ||
            memcmp(name, bytes, name_len) != 0) __builtin_trap();
    }
    dbresult_free(r);

    /* A list: exactly as many values as elements, in order. Strings are C
     * strings in an array_t, so these stop at NUL. */
    const size_t count = __dq_byte(in) % 5 + 1;
    array_t* list = array_create();
    for (size_t i = 0; i < count; i++) {
        if (i % 2 == 0) array_push_back(list, array_create_int((int)(int8_t)__dq_byte(in)));
        else array_push_back(list, array_create_stringn((const char*)bytes + i % (len + 1), strnlen((const char*)bytes + i % (len + 1), len - i % (len + 1))));
    }
    array_push_back(params, array_create_pointer(mparam_array(l, list), NULL, model_param_free));
    r = dbquery(DQ_DBID, "SELECT :list__l", params);
    __dq_check(r);
    if (!dbresult_ok(r) || dbresult_query_cols(r) != (int)count) __builtin_trap();
    for (size_t i = 0; i < count; i++) {
        cell = dbresult_cell(r, 0, (int)i);
        char want[32];
        const char* w_value = want;
        size_t w_len;
        if (i % 2 == 0) w_len = (size_t)snprintf(want, sizeof want, "%d", array_get_int(list, i));
        else { w_value = array_get_string(list, i); w_len = strlen(w_value); }
        if (cell == NULL || cell->value == NULL || cell->length != w_len || memcmp(cell->value, w_value, w_len) != 0) __builtin_trap();
    }
    dbresult_free(r);

    r = dbquery(DQ_DBID, "SELECT :nope", params);
    if (r != NULL) __builtin_trap();

    array_free(params);
}

/* ---- 2: results ---- */

static void __dq_results(dq_in_t* in) {
    const int rows = __dq_byte(in) % 6;
    const int cols = __dq_byte(in) % 5 + 1;
    int values[5][5];
    int nulls[5][5];

    dq_buf_t sql = { 0 };
    __dq_puts(&sql, "SELECT * FROM (VALUES ");
    for (int r = 0; r < (rows ? rows : 1); r++) {
        __dq_puts(&sql, r ? ",(" : "(");
        for (int c = 0; c < cols; c++) {
            const uint8_t b = __dq_byte(in);
            nulls[r][c] = b % 5 == 0;
            values[r][c] = (int8_t)b;
            char num[16];
            snprintf(num, sizeof num, "%s%d", c ? "," : "", values[r][c]);
            __dq_puts(&sql, nulls[r][c] ? (c ? ",NULL" : "NULL") : num);
        }
        __dq_puts(&sql, ")");
    }
    __dq_puts(&sql, rows ? ")" : ") WHERE 0");

    dbresult_t* r = dbquery(DQ_DBID, sql.data, NULL);
    free(sql.data);
    __dq_check(r);
    if (!dbresult_ok(r) || dbresult_query_rows(r) != rows || dbresult_query_cols(r) != cols) __builtin_trap();

    int cur_row = 0, cur_col = 0;
    for (int step = 0; step < 64 && in->p < in->end; step++) {
        const uint8_t op = __dq_byte(in);
        const int a = (int8_t)__dq_byte(in);
        const int b = (int8_t)__dq_byte(in);
        int got, want;
        const db_table_cell_t* cell = NULL;
        int at_row = -1, at_col = -1;
        switch (op % 8) {
        case 0:
            want = cur_row + 1 < rows;
            if (dbresult_row_next(r) != want) __builtin_trap();
            if (want) cur_row++;
            continue;
        case 1:
            want = cur_col + 1 < cols;
            if (dbresult_col_next(r) != want) __builtin_trap();
            if (want) cur_col++;
            continue;
        case 2:
            want = a >= 0 && a < rows;
            if ((got = dbresult_row_set(r, a)) != want) __builtin_trap();
            if (want) cur_row = a;
            continue;
        case 3:
            want = a >= 0 && a < cols;
            if ((got = dbresult_col_set(r, a)) != want) __builtin_trap();
            if (want) cur_col = a;
            continue;
        case 4:
            cell = dbresult_field(r, NULL);
            at_row = cur_row; at_col = cur_col;
            break;
        case 5: {
            char name[16];
            snprintf(name, sizeof name, "column%d", (a & 7) + 1);
            cell = dbresult_field(r, name);
            at_row = cur_row; at_col = (a & 7) < cols ? (a & 7) : -1;
            break;
        }
        case 6:
            cell = dbresult_cell(r, a, b);
            at_row = a; at_col = b;
            break;
        case 7:
            dbresult_row_first(r);
            dbresult_col_first(r);
            cur_row = cur_col = 0;
            if (dbresult_query_next(r) != NULL) __builtin_trap();
            continue;
        }
        const int inside = at_row >= 0 && at_row < rows && at_col >= 0 && at_col < cols;
        if (!inside) {
            if (cell != NULL) __builtin_trap();
            continue;
        }
        if (cell == NULL) __builtin_trap();
        if (nulls[at_row][at_col]) {
            if (cell->value != NULL) __builtin_trap();
        } else {
            char want_text[16];
            snprintf(want_text, sizeof want_text, "%d", values[at_row][at_col]);
            if (cell->value == NULL || strcmp(cell->value, want_text) != 0) __builtin_trap();
        }
    }

    dbresult_free(r);
}

/* ---- 3: compilers ---- */

/* A name from the input: never empty, no NUL, and starting with a letter
 * with none of + / | : * - ( ' in it, so that dbselect does not take it for
 * the expression it would pass through raw. */
static void __dq_name(dq_in_t* in, char* out, size_t cap, const char* prefix) {
    size_t n = strlen(prefix);
    memcpy(out, prefix, n);
    const size_t len = __dq_byte(in) % 16;
    for (size_t i = 0; i < len && n + 1 < cap; i++) {
        const char c = (char)__dq_byte(in);
        if (c == '\0' || strchr("+/|:*-('", c) != NULL) continue;
        out[n++] = c;
    }
    out[n] = '\0';
}

static void __dq_text(dq_in_t* in, char* out, size_t cap) {
    size_t n = 0;
    const size_t len = __dq_byte(in) % 24;
    for (size_t i = 0; i < len && n + 1 < cap; i++) {
        const char c = (char)__dq_byte(in);
        if (c != '\0') out[n++] = c;
    }
    out[n] = '\0';
}

static dbresult_t* __dq_select(const char* table, const char* a, const char* b, const char* key) {
    array_t* columns = array_create();
    array_push_back(columns, array_create_string(a));
    array_push_back(columns, array_create_string(b));
    array_t* where = array_create();
    array_push_back(where, array_create_pointer(field_create_text(a, key), NULL, model_param_free));
    dbresult_t* r = dbselect(DQ_DBID, table, columns, where);
    array_free(columns);
    array_free(where);
    __dq_check(r);
    return r;
}

static void __dq_compilers(dq_in_t* in) {
    char table[32], a[32], b[32], v1[32], v2[32], v3[32];
    __dq_name(in, table, sizeof table, "t");
    __dq_name(in, a, sizeof a, "a");
    __dq_name(in, b, sizeof b, "b");
    __dq_text(in, v1, sizeof v1);
    __dq_text(in, v2, sizeof v2);
    __dq_text(in, v3, sizeof v3);
    if (strcasecmp(a, b) == 0) return;

    array_t* ids = array_create();
    mparams_fill_array(ids, mparam_text(t, table), mparam_text(a, a), mparam_text(b, b));
    dbresult_t* r = dbquery(DQ_DBID, "DROP TABLE IF EXISTS @t", ids);
    __dq_check(r);
    dbresult_free(r);
    r = dbquery(DQ_DBID, "CREATE TABLE @t (@a TEXT, @b TEXT)", ids);
    __dq_check(r);
    if (!dbresult_ok(r)) __builtin_trap();
    dbresult_free(r);

    array_t* row = array_create();
    array_push_back(row, array_create_pointer(field_create_text(a, v1), NULL, model_param_free));
    array_push_back(row, array_create_pointer(field_create_text(b, v2), NULL, model_param_free));
    r = dbinsert(DQ_DBID, table, row);
    array_free(row);
    __dq_check(r);
    if (!dbresult_ok(r)) __builtin_trap();
    dbresult_free(r);

    r = __dq_select(table, a, b, v1);
    if (!dbresult_ok(r) || dbresult_query_rows(r) != 1 ||
        strcmp(dbresult_cell(r, 0, 0)->value, v1) != 0 || strcmp(dbresult_cell(r, 0, 1)->value, v2) != 0) __builtin_trap();
    dbresult_free(r);

    array_t* set = array_create();
    array_push_back(set, array_create_pointer(field_create_text(b, v3), NULL, model_param_free));
    array_t* where = array_create();
    array_push_back(where, array_create_pointer(field_create_text(a, v1), NULL, model_param_free));
    r = dbupdate(DQ_DBID, table, set, where);
    array_free(set);
    __dq_check(r);
    if (!dbresult_ok(r)) __builtin_trap();
    dbresult_free(r);

    r = __dq_select(table, a, b, v1);
    if (!dbresult_ok(r) || dbresult_query_rows(r) != 1 || strcmp(dbresult_cell(r, 0, 1)->value, v3) != 0) __builtin_trap();
    dbresult_free(r);

    r = dbdelete(DQ_DBID, table, where);
    array_free(where);
    __dq_check(r);
    if (!dbresult_ok(r)) __builtin_trap();
    dbresult_free(r);

    r = __dq_select(table, a, b, v1);
    if (!dbresult_ok(r) || dbresult_query_rows(r) != 0) __builtin_trap();
    dbresult_free(r);

    r = dbquery(DQ_DBID, "DROP TABLE @t", ids);
    if (!dbresult_ok(r)) __builtin_trap();
    dbresult_free(r);
    array_free(ids);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static int ready;
    if (!ready) {
        dbresult_t* r = dbquery(DQ_DBID, "CREATE TABLE IF NOT EXISTS fz (t)", NULL);
        if (!dbresult_ok(r)) abort();
        dbresult_free(r);
        ready = 1;
    }
    if (size < 1) return 0;

    dq_in_t in = { data + 1, data + size };
    switch (data[0] % 4) {
    case 0: __dq_builder(&in); break;
    case 1: __dq_values(&in); break;
    case 2: __dq_results(&in); break;
    case 3: __dq_compilers(&in); break;
    }

    return 0;
}

#elif FUZZ_TARGET == FUZZ_DB_MODEL

#include <math.h>

/* The model layer the feedback form writes through (app/models/feedback.c
 * uses model_create), on SQLite ":memory:". A schema of its own here, shaped
 * like the feedback one -- auto-increment key, text, integer, real, an enum,
 * a timestamp the database fills in -- and a script of operations from the
 * input, checked against a table the target keeps:
 *
 *   create   -- the row reads back byte for byte, key assigned, created_at set;
 *   read     -- a live row reads back as last written, a deleted one is
 *               MODEL_ERR_NOTFOUND;
 *   update   -- only the fields that were set change; nothing set is refused
 *               without reaching the database;
 *   delete   -- the row is gone;
 *   stringify -- valid JSON with the same values (a name that is not UTF-8
 *               only has to come out as valid JSON).
 *
 * Mode 1: enum values are accepted exactly when listed (or empty, which is
 * unset), the same way twice,
 * and a setter of the wrong type fails without touching the field. */

enum { FM_ID, FM_NAME, FM_QTY, FM_PRICE, FM_STATE, FM_CREATED, FM_COUNT };

static const char* const __fm_states[] = { "new", "done", "spam" };

static const mcolumn_t __fm_columns[FM_COUNT] = {
    [FM_ID]      = { .name = "id",         .type = MODEL_INT, .is_primary = 1, .auto_increment = 1 },
    [FM_NAME]    = { .name = "name",       .type = MODEL_TEXT },
    [FM_QTY]     = { .name = "qty",        .type = MODEL_INT },
    [FM_PRICE]   = { .name = "price",      .type = MODEL_DOUBLE },
    [FM_STATE]   = { .name = "state",      .type = MODEL_ENUM, .enum_values = __fm_states, .enum_count = 3 },
    [FM_CREATED] = { .name = "created_at", .type = MODEL_TIMESTAMPTZ, .has_default = 1 },
};

static const int __fm_primary[] = { FM_ID };

static const mschema_t __fm_schema = {
    .table = "fm",
    .columns = __fm_columns,
    .columns_count = FM_COUNT,
    .primary_keys = __fm_primary,
    .primary_keys_count = 1,
};

typedef struct {
    model_t record;
} fm_t;

static void* __fm_instance(void) {
    fm_t* m = calloc(1, sizeof *m);
    if (m == NULL || !model_init(&m->record, &__fm_schema)) abort();
    return m;
}

typedef struct {
    int id;
    int live;
    char name[40];
    int qty;
    double price;
    const char* state;
} fm_row_t;

static fm_t* __fm_read(int id) {
    array_t* params = array_create();
    mparams_fill_array(params, mparam_int(id, id));
    fm_t* m = model_one(DQ_DBID, __fm_instance, "SELECT * FROM fm WHERE id = :id", params);
    array_free(params);
    return m;
}

static void __fm_expect(fm_t* m, const fm_row_t* row) {
    if (m == NULL) __builtin_trap();
    str_t* name = model_text(model_field(m, FM_NAME));
    if (name == NULL || str_size(name) != strlen(row->name) || memcmp(str_get(name), row->name, str_size(name)) != 0) __builtin_trap();
    if (model_int(model_field(m, FM_ID)) != row->id) __builtin_trap();
    if (model_int(model_field(m, FM_QTY)) != row->qty) __builtin_trap();
    if (model_double(model_field(m, FM_PRICE)) != row->price) __builtin_trap();
    str_t* state = model_enum(model_field(m, FM_STATE));
    if (state == NULL || strcmp(str_get(state), row->state) != 0) __builtin_trap();
    if (model_field(m, FM_CREATED)->is_null) __builtin_trap();
}

/* Strict UTF-8 (RFC 3629): no overlongs, no surrogates, nothing past U+10FFFF. */
static int __fm_utf8(const char* text) {
    const unsigned char* s = (const unsigned char*)text;
    while (*s) {
        size_t len;
        uint32_t v;
        if (*s < 0x80) { s++; continue; }
        if (*s >= 0xC2 && *s <= 0xDF) { len = 2; v = *s & 0x1F; }
        else if (*s >= 0xE0 && *s <= 0xEF) { len = 3; v = *s & 0x0F; }
        else if (*s >= 0xF0 && *s <= 0xF4) { len = 4; v = *s & 0x07; }
        else return 0;
        for (size_t k = 1; k < len; k++) {
            if ((s[k] & 0xC0) != 0x80) return 0;
            v = v << 6 | (s[k] & 0x3F);
        }
        if (len == 3 && (v < 0x800 || (v >= 0xD800 && v <= 0xDFFF))) return 0;
        if (len == 4 && (v < 0x10000 || v > 0x10FFFF)) return 0;
        s += len;
    }
    return 1;
}

static void __fm_text(dq_in_t* in, char* out, size_t cap) {
    size_t n = 0;
    const size_t len = __dq_byte(in) % cap;
    for (size_t i = 0; i < len && n + 1 < cap; i++) {
        const char c = (char)__dq_byte(in);
        if (c != '\0') out[n++] = c;
    }
    out[n] = '\0';
}

static double __fm_price(dq_in_t* in, uint8_t how) {
    if (how & 0x80) {
        uint64_t bits = 0;
        for (int i = 0; i < 8; i++) bits = bits << 8 | __dq_byte(in);
        double d;
        memcpy(&d, &bits, sizeof d);
        if (isfinite(d)) return d;
    }
    return (int16_t)(__dq_byte(in) | __dq_byte(in) << 8) / 100.0;
}

static void __fm_set(fm_t* m, fm_row_t* row, dq_in_t* in, uint8_t mask) {
    if (mask & 1) {
        __fm_text(in, row->name, sizeof row->name);
        if (!model_set_text(model_field(m, FM_NAME), row->name)) __builtin_trap();
    }
    if (mask & 2) {
        row->qty = (int32_t)(__dq_byte(in) | __dq_byte(in) << 8 | __dq_byte(in) << 16 | (uint32_t)__dq_byte(in) << 24);
        if (!model_set_int(model_field(m, FM_QTY), row->qty)) __builtin_trap();
    }
    if (mask & 4) {
        row->price = __fm_price(in, mask);
        if (!model_set_double(model_field(m, FM_PRICE), row->price)) __builtin_trap();
    }
    if (mask & 8) {
        row->state = __fm_states[__dq_byte(in) % 3];
        if (!model_set_enum(model_field(m, FM_STATE), row->state)) __builtin_trap();
    }
}

static void __fm_script(dq_in_t* in) {
    dbresult_t* r = dbquery(DQ_DBID, "DELETE FROM fm", NULL);
    if (!dbresult_ok(r)) __builtin_trap();
    dbresult_free(r);

    fm_row_t rows[6];
    int count = 0;

    for (int step = 0; step < 12 && in->p < in->end; step++) {
        const uint8_t op = __dq_byte(in);
        fm_row_t* row = count > 0 ? &rows[__dq_byte(in) % count] : NULL;

        switch (op % 5) {
        case 0: {
            if (count == 6) break;
            fm_row_t* fresh = &rows[count];
            *fresh = (fm_row_t){ .live = 1, .name = "", .state = "new" };
            fm_t* m = __fm_instance();
            /* Every field set on create: a column left unset is written as
             * its zero value, which is not what this test is about. */
            __fm_set(m, fresh, in, (uint8_t)(op | 0x0f));
            if (!model_create(DQ_DBID, m)) __builtin_trap();
            fresh->id = model_int(model_field(m, FM_ID));
            if (fresh->id <= 0) __builtin_trap();
            model_free(m);
            count++;
            __fm_expect(m = __fm_read(fresh->id), fresh);
            model_free(m);
            break;
        }
        case 1: {
            if (row == NULL) break;
            fm_t* m = __fm_read(row->id);
            if (row->live) __fm_expect(m, row);
            else if (m != NULL || model_last_status() != MODEL_ERR_NOTFOUND) __builtin_trap();
            model_free(m);
            break;
        }
        case 2: {
            if (row == NULL || !row->live) break;
            fm_t* m = __fm_read(row->id);
            const uint8_t mask = __dq_byte(in);
            __fm_set(m, row, in, mask);
            const int ok = model_update(DQ_DBID, m);
            if ((mask & 0x0f) != 0 && !ok) __builtin_trap();
            if ((mask & 0x0f) == 0 && (ok || model_last_status() == MODEL_ERR_DB)) __builtin_trap();
            model_free(m);
            __fm_expect(m = __fm_read(row->id), row);
            model_free(m);
            break;
        }
        case 3: {
            if (row == NULL || !row->live) break;
            fm_t* m = __fm_read(row->id);
            if (!model_delete(DQ_DBID, m)) __builtin_trap();
            model_free(m);
            row->live = 0;
            if ((m = __fm_read(row->id)) != NULL || model_last_status() != MODEL_ERR_NOTFOUND) __builtin_trap();
            break;
        }
        case 4: {
            if (row == NULL || !row->live) break;
            fm_t* m = __fm_read(row->id);
            char* text = model_stringify(m, NULL);
            json_doc_t* doc = text != NULL ? json_parse(text) : NULL;
            json_token_t* root = doc != NULL ? json_root(doc) : NULL;
            if (root == NULL || !json_is_object(root)) __builtin_trap();
            json_token_t* name = json_object_get(root, "name");
            json_token_t* qty = json_object_get(root, "qty");
            json_token_t* price = json_object_get(root, "price");
            json_token_t* state = json_object_get(root, "state");
            int ok_int = 0, ok_double = 0;
            /* JSON carries UTF-8: a name that is not comes out with U+FFFD in
             * place of what cannot be carried, so only a valid one must match. */
            if (name == NULL || !json_is_string(name)) __builtin_trap();
            if (__fm_utf8(row->name) && strcmp(json_string(name), row->name) != 0) __builtin_trap();
            if (qty == NULL || json_int(qty, &ok_int) != row->qty || !ok_int) __builtin_trap();
            if (price == NULL || json_double(price, &ok_double) != row->price || !ok_double) __builtin_trap();
            if (state == NULL || !json_is_string(state) || strcmp(json_string(state), row->state) != 0) __builtin_trap();
            json_free(doc);
            free(text);
            model_free(m);
            break;
        }
        }
    }
}

static void __fm_types(dq_in_t* in) {
    fm_t* m = __fm_instance();
    char value[16];
    __fm_text(in, value, sizeof value);

    /* The empty value is "unset" and always taken: it is what a NULL or
     * empty column reads back as (model_set_enum_from_str, size 0). */
    int listed = value[0] == '\0';
    for (int i = 0; i < 3; i++)
        if (strcmp(value, __fm_states[i]) == 0) listed = 1;

    mfield_t* state = model_field(m, FM_STATE);
    const int first = model_set_enum(state, value);
    const int second = model_set_enum(state, value);
    if (first != listed || second != listed) __builtin_trap();
    if (listed && strcmp(str_get(model_enum(state)), value) != 0) __builtin_trap();

    /* The wrong setter for the type fails and leaves the field as it was. */
    mfield_t* name = model_field(m, FM_NAME);
    model_set_text(name, value);
    mfield_t* qty = model_field(m, FM_QTY);
    model_set_int(qty, 7);
    if (model_set_int(name, 5) || model_set_double(name, 1.5) || model_set_enum(name, "new")) __builtin_trap();
    if (model_set_text(qty, "x") || model_set_double(qty, 2.5) || model_set_enum(qty, "new")) __builtin_trap();
    if (model_set_int(state, 1) || model_set_text(state, "x")) __builtin_trap();
    if (strcmp(str_get(model_text(name)), value) != 0 || model_int(qty) != 7) __builtin_trap();

    model_free(m);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static int ready;
    if (!ready) {
        dbresult_t* r = dbquery(DQ_DBID,
            "CREATE TABLE IF NOT EXISTS fm (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, qty INTEGER, "
            "price REAL, state TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)", NULL);
        if (!dbresult_ok(r)) abort();
        dbresult_free(r);
        ready = 1;
    }
    if (size < 1) return 0;

    dq_in_t in = { data + 1, data + size };
    if (data[0] % 2 == 0) __fm_script(&in);
    else __fm_types(&in);

    return 0;
}

#elif FUZZ_TARGET == FUZZ_QUIC_PMTUD

#include "quicpmtud.h"

/* DPLPMTUD (RFC 8899) as quicconn.c drives it, on a path the input controls:
 * the path's MTU, which may change, whether a probe is lost for another
 * reason, the clock, and the events -- a probe sent when one is due, the ACK
 * of the probe or of any other packet, the probe timer, a black hole. The
 * state machine needs no connection: quicconn.c only feeds it these calls.
 *
 * After every step: base <= current <= ceiling; a probe in flight is above
 * the size in use and within the ceiling, with a finite deadline no earlier
 * than when it was sent; the size rises only by the ACK of that probe, to
 * the size probed, which the path carried; no more than QUICPMTUD_MAX_PROBES
 * attempts at a size; an ACK, a timeout or a black hole repeated at once with
 * the same arguments changes nothing.
 *
 * At the end the path stops losing and changing, and the search must finish
 * in a bounded number of probes -- no probe repeated forever without its
 * deadline moving. */

typedef struct {
    quicpmtud_t p;
    uint64_t now;
    size_t path;
    uint64_t pn;
    uint64_t sent_at;
} pm_state_t;

static void __pm_check(const pm_state_t* s) {
    const quicpmtud_t* p = &s->p;
    if (p->current < p->base || p->current > p->ceiling) __builtin_trap();
    if (p->attempts > QUICPMTUD_MAX_PROBES) __builtin_trap();
    if (p->outstanding) {
        if (p->candidate <= p->current || p->candidate > p->ceiling) __builtin_trap();
        const uint64_t d = quicpmtud_deadline(p);
        if (d == 0 || d < s->sent_at) __builtin_trap();
    } else if (quicpmtud_deadline(p) != 0) __builtin_trap();
}

/* The event repeated at once must be a no-op. */
#define PM_TWICE(state, call) do { \
    call; \
    quicpmtud_t __snapshot = (state)->p; \
    call; \
    if (memcmp(&__snapshot, &(state)->p, sizeof __snapshot) != 0) __builtin_trap(); \
} while (0)

static void __pm_send(pm_state_t* s, uint64_t pto) {
    if (!quicpmtud_should_probe(&s->p, s->now)) return;
    const size_t target = quicpmtud_candidate(&s->p);
    if (target <= s->p.current) return;                  /* what quicconn skips */
    s->sent_at = s->now;
    quicpmtud_on_probe_sent(&s->p, ++s->pn, s->now, pto);
}

/* The ACK of the probe, if the path carried it. */
static void __pm_deliver(pm_state_t* s, uint64_t pto, int lost) {
    if (!s->p.outstanding) return;
    const size_t probed = s->p.candidate;
    const size_t before = s->p.current;
    if (lost || probed > s->path) return;
    const uint64_t pn = s->p.probe_pn;
    int raised = 0;
    PM_TWICE(s, raised |= quicpmtud_on_ack(&s->p, pn, s->now, pto));
    if (!raised || s->p.current != probed || s->p.current <= before) __builtin_trap();
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;

    pm_state_t s = { 0 };
    const size_t base = 1200 + data[0] % 200;
    const size_t ceiling = 1200 + (size_t)(data[1] | data[2] << 8) % 400;
    quicpmtud_init(&s.p, base, ceiling);
    s.path = 1200 + (size_t)data[3] * 2;
    s.now = 1000000;
    __pm_check(&s);

    for (size_t i = 4; i + 1 < size && i < 4 + 2 * 512; i += 2) {
        const uint8_t op = data[i];
        const uint8_t arg = data[i + 1];
        const uint64_t pto = 1000 + (uint64_t)arg * 100;

        switch (op % 7) {
        case 0: s.now += (uint64_t)arg * 1000; break;
        case 1: __pm_send(&s, pto); break;
        case 2: __pm_deliver(&s, pto, arg & 1); break;
        case 3: {
            /* The ACK of some other packet. */
            const quicpmtud_t before = s.p;
            if (quicpmtud_on_ack(&s.p, s.pn + 1 + arg, s.now, pto)) __builtin_trap();
            if (memcmp(&before, &s.p, sizeof before) != 0) __builtin_trap();
            break;
        }
        case 4: {
            const size_t before = s.p.current;
            int flags = 0;
            PM_TWICE(&s, flags |= quicpmtud_on_timeout(&s.p, s.now));
            if (s.p.current != before) __builtin_trap();
            (void)flags;
            break;
        }
        case 5: {
            const size_t before = s.p.current;
            int taken = 0;
            PM_TWICE(&s, taken |= quicpmtud_on_blackhole(&s.p, s.now, pto));
            if (taken && (before == s.p.base || s.p.current != s.p.base || s.p.ceiling >= before)) __builtin_trap();
            if (!taken && s.p.current != before) __builtin_trap();
            break;
        }
        case 6:
            s.path = 1200 + (size_t)arg * 2;
            break;
        }
        __pm_check(&s);
    }

    /* Settle: a clean, stable path; the search has to end. */
    const uint64_t pto = 10000;
    for (int step = 0;; step++) {
        if (step > 16 * QUICPMTUD_MAX_PROBES + 16) __builtin_trap();
        if (s.p.outstanding) {
            if (s.p.candidate <= s.path) __pm_deliver(&s, pto, 0);
            else {
                /* The timer fires at the deadline, or now if the clock has
                 * already passed it. */
                const uint64_t deadline = quicpmtud_deadline(&s.p);
                if (deadline > s.now) s.now = deadline;
                if (!(quicpmtud_on_timeout(&s.p, s.now) & QUICPMTUD_PROBE_LOST)) __builtin_trap();
            }
        } else if (s.p.current >= s.p.ceiling) {
            break;
        } else if (quicpmtud_should_probe(&s.p, s.now)) {
            __pm_send(&s, pto);
            if (!s.p.outstanding) break;                  /* nothing larger to try */
        } else {
            if (s.p.next_probe_us <= s.now) __builtin_trap();
            s.now = s.p.next_probe_us;
        }
        __pm_check(&s);
    }

    return 0;
}

#elif FUZZ_TARGET == FUZZ_SESSION_CRYPTO

#include <ctype.h>
#include <openssl/evp.h>
#include "aes256gcm.h"

/* The session cookie's cryptography (framework/session/aes256gcm.c): what a
 * cookie from the network is decrypted with before any session data is read.
 * The first byte picks the mode:
 *
 *   0 round trip -- any C string (empty, not UTF-8, long) under any key comes
 *     back from decrypt(encrypt(x)) unchanged; the sealed form is plain base64
 *     of nonce, ciphertext and tag; the wrong key, one character changed, a
 *     cut or a tail added give NULL or the same plaintext -- never another, and
 *     never a part of it (GCM authenticates the whole);
 *   1 forgery -- arbitrary bytes, as a cookie would bring them, never decrypt;
 *   2 hex key -- aes256gcm_key_from_hex takes exactly 64 hex digits, agrees
 *     with a parser written here, and leaves the key alone when it refuses;
 *   3 passphrase -- the derived key is SHA-256 of the passphrase (OpenSSL). */

static int __sc_b64(const char* s, size_t n) {
    if (n % 4 != 0) return 0;
    for (size_t i = 0; i < n; i++) {
        const char c = s[i];
        const int pad_ok = c == '=' && i >= n - 2 && (i == n - 1 || s[n - 1] == '=');
        if (!(isalnum((unsigned char)c) || c == '+' || c == '/' || pad_ok)) return 0;
    }
    return 1;
}

static void __sc_expect(const char* got, const char* want) {
    if (got != NULL && strcmp(got, want) != 0) __builtin_trap();
}

static void __sc_roundtrip(const uint8_t* data, size_t size) {
    if (size < AES256GCM_KEY_SIZE + 2) return;
    unsigned char key[AES256GCM_KEY_SIZE];
    memcpy(key, data, sizeof key);
    const uint8_t at = data[AES256GCM_KEY_SIZE];
    const uint8_t how = data[AES256GCM_KEY_SIZE + 1];
    data += AES256GCM_KEY_SIZE + 2; size -= AES256GCM_KEY_SIZE + 2;

    char* plain = strndup((const char*)data, size);
    if (plain == NULL) abort();
    const size_t len = strlen(plain);

    char* sealed = aes256gcm_encrypt(plain, key);
    if (sealed == NULL) __builtin_trap();
    const size_t n = strlen(sealed);
    if (n != 4 * ((12 + len + 16 + 2) / 3) || !__sc_b64(sealed, n)) __builtin_trap();

    char* opened = aes256gcm_decrypt(sealed, key);
    if (opened == NULL || strcmp(opened, plain) != 0) __builtin_trap();
    free(opened);

    unsigned char other[AES256GCM_KEY_SIZE];
    memcpy(other, key, sizeof other);
    other[at % AES256GCM_KEY_SIZE] ^= (uint8_t)(1u << (how % 8));
    if ((opened = aes256gcm_decrypt(sealed, other)) != NULL) __builtin_trap();

    /* One character changed, cut, or a tail added. */
    char* copy = malloc(n + 8);
    if (copy == NULL) abort();
    memcpy(copy, sealed, n + 1);
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=!\r\n";
    switch (how % 3) {
    case 0: copy[at % n] = alphabet[how % (sizeof alphabet - 1)]; break;
    case 1: copy[at % n] = '\0'; break;
    case 2: memcpy(copy + n, "QUJD", 5); break;
    }
    opened = aes256gcm_decrypt(copy, key);
    __sc_expect(opened, plain);
    free(opened);

    free(copy);
    free(sealed);
    free(plain);
}

static void __sc_forgery(const uint8_t* data, size_t size) {
    static const unsigned char key[AES256GCM_KEY_SIZE] = { 7 };
    char* cookie = strndup((const char*)data, size);
    if (cookie == NULL) abort();
    char* opened = aes256gcm_decrypt(cookie, key);
    if (opened != NULL) __builtin_trap();
    free(cookie);
}

static int __sc_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void __sc_hex(const uint8_t* data, size_t size) {
    /* Exactly the string, so a read past its end is ASan's. */
    char* hex = strndup((const char*)data, size);
    if (hex == NULL) abort();
    const size_t n = strlen(hex);

    unsigned char want[AES256GCM_KEY_SIZE];
    int valid = n == 64;
    for (size_t i = 0; valid && i < AES256GCM_KEY_SIZE; i++) {
        const int hi = __sc_nibble(hex[2 * i]), lo = __sc_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) valid = 0;
        else want[i] = (unsigned char)(hi << 4 | lo);
    }

    unsigned char key[AES256GCM_KEY_SIZE];
    memset(key, 0xa5, sizeof key);
    const int ok = aes256gcm_key_from_hex(hex, key);
    if (ok != valid) __builtin_trap();
    for (size_t i = 0; i < AES256GCM_KEY_SIZE; i++)
        if (key[i] != (valid ? want[i] : 0xa5)) __builtin_trap();
    free(hex);
}

static void __sc_passphrase(const uint8_t* data, size_t size) {
    char* pass = strndup((const char*)data, size);
    if (pass == NULL) abort();
    unsigned char key[AES256GCM_KEY_SIZE], want[32];
    unsigned int want_len = 0;
    aes256gcm_key_from_passphrase(pass, key);
    if (EVP_Digest(pass, strlen(pass), want, &want_len, EVP_sha256(), NULL) != 1 || want_len != 32) abort();
    if (memcmp(key, want, 32) != 0) __builtin_trap();
    free(pass);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    switch (data[0] % 4) {
    case 0: __sc_roundtrip(data + 1, size - 1); break;
    case 1: __sc_forgery(data + 1, size - 1); break;
    case 2: __sc_hex(data + 1, size - 1); break;
    case 3: __sc_passphrase(data + 1, size - 1); break;
    }
    return 0;
}

#elif FUZZ_TARGET == FUZZ_MISC_CONTAINERS

#include <math.h>
#include <stdio.h>
#include "arena.h"
#include "array.h"
#include "bufo.h"
#include "hashmap.h"
#include "map.h"
#include "str.h"

/* The containers of misc/ that every other target leans on without looking at
 * them: arena, array, map (red-black tree), hashmap, str, bufo. Each one runs
 * next to a model written here from its header -- a plain list, a byte buffer
 * -- and after every operation the container must agree with the model: what
 * was inserted is found with the same value until it is erased, the count is
 * the number of inserts that took minus the erases that did, an iteration
 * yields each key exactly once (the map in strict order, forwards and back),
 * growth and rehash lose and duplicate nothing, and appends leave exactly the
 * concatenation. Everything is freed at the end, so a leak is LeakSanitizer's.
 *
 * Input: one byte of configuration (hashmap capacity, load factor and hash,
 * str initial capacity), then records of
 *   [selector] [length] [length bytes of argument]
 * selector % 6 picks the container, selector / 6 the operation. */

#define MC_MAX_RECORDS 2048
#define MC_KEY_MAX 8
#define MC_BUFO_LIMIT (10 * 1024 * 1024)

static uint32_t __mc_u32(const uint8_t* a, size_t n, size_t at) {
    uint32_t v = 0;
    for (size_t i = 0; i < 4; i++)
        v = v << 8 | (at + i < n ? a[at + i] : 0);
    return v;
}

static uint16_t __mc_u16(const uint8_t* a, size_t n, size_t at) {
    return (uint16_t)(__mc_u32(a, n, at) >> 16);
}

static void* __mc_xmalloc(size_t n) {
    void* p = malloc(n ? n : 1);
    if (p == NULL) abort();
    return p;
}

/* ---- keyed containers: one model for map and hashmap ---- */

typedef struct {
    char* keys[MC_MAX_RECORDS];
    intptr_t values[MC_MAX_RECORDS];
    size_t count;
} mc_keyed_t;

static char* __mc_key(const uint8_t* a, size_t n) {
    return strndup((const char*)a, n < MC_KEY_MAX ? n : MC_KEY_MAX);
}

static ssize_t __mc_keyed_find(const mc_keyed_t* m, const char* key) {
    for (size_t i = 0; i < m->count; i++)
        if (strcmp(m->keys[i], key) == 0) return (ssize_t)i;
    return -1;
}

static void __mc_keyed_put(mc_keyed_t* m, const char* key, intptr_t value) {
    const ssize_t at = __mc_keyed_find(m, key);
    if (at >= 0) { m->values[at] = value; return; }
    if (m->count == MC_MAX_RECORDS) abort();
    m->keys[m->count] = strdup(key);
    if (m->keys[m->count] == NULL) abort();
    m->values[m->count++] = value;
}

static void __mc_keyed_erase(mc_keyed_t* m, const char* key) {
    const ssize_t at = __mc_keyed_find(m, key);
    if (at < 0) return;
    free(m->keys[at]);
    m->keys[at] = m->keys[--m->count];
    m->values[at] = m->values[m->count];
}

static void __mc_keyed_clear(mc_keyed_t* m) {
    for (size_t i = 0; i < m->count; i++) free(m->keys[i]);
    m->count = 0;
}

/* ---- map: string keys copied and freed by the map, boxed values it frees ---- */

static intptr_t __mc_unbox(void* v) {
    return v == NULL ? 0 : *(intptr_t*)v;
}

static void* __mc_box(intptr_t v) {
    intptr_t* p = __mc_xmalloc(sizeof *p);
    *p = v;
    return p;
}

/* Red-black invariants: the root and nil are black, a red node has black
 * children, every path has the same black count, parents point back, and an
 * in-order walk is strictly increasing. Returns the black height. */
static int __mc_rb_check(map_t* map, map_node_t* node, map_node_t* parent, size_t* count) {
    if (node == map->nil) return 1;
    if (node->parent != parent) __builtin_trap();
    if (node->color == MAP_RED &&
        (node->left->color != MAP_BLACK || node->right->color != MAP_BLACK)) __builtin_trap();
    if (node->left != map->nil && strcmp(node->left->key, node->key) >= 0) __builtin_trap();
    if (node->right != map->nil && strcmp(node->right->key, node->key) <= 0) __builtin_trap();
    const int l = __mc_rb_check(map, node->left, node, count);
    const int r = __mc_rb_check(map, node->right, node, count);
    if (l != r) __builtin_trap();
    (*count)++;
    return l + (node->color == MAP_BLACK);
}

static void __mc_map_verify(map_t* map, const mc_keyed_t* m) {
    if (map_size(map) != m->count || map_empty(map) != (m->count == 0)) __builtin_trap();
    if (map->nil->color != MAP_BLACK || map->root->color != MAP_BLACK) __builtin_trap();
    size_t count = 0;
    __mc_rb_check(map, map->root, map->nil, &count);
    if (count != m->count) __builtin_trap();
}

static void __mc_map_walk(map_t* map, const mc_keyed_t* m, int backwards) {
    map_iterator_t it = backwards ? map_prev(map_end(map)) : map_begin(map);
    const char* last = NULL;
    size_t seen = 0;
    for (; map_iterator_valid(it); it = backwards ? map_prev(it) : map_next(it)) {
        const char* key = map_iterator_key(it);
        if (last != NULL && (backwards ? strcmp(key, last) >= 0 : strcmp(key, last) <= 0)) __builtin_trap();
        const ssize_t at = __mc_keyed_find(m, key);
        if (at < 0 || m->values[at] != __mc_unbox(map_iterator_value(it))) __builtin_trap();
        last = key;
        if (++seen > m->count) __builtin_trap();
    }
    if (seen != m->count) __builtin_trap();
}

static void __mc_map(map_t* map, mc_keyed_t* m, unsigned op, const uint8_t* a, size_t n, intptr_t id) {
    char* key = __mc_key(a, n);
    if (key == NULL) abort();
    const ssize_t at = __mc_keyed_find(m, key);

    switch (op % 9) {
    case 0: {
        void* box = __mc_box(id);
        const int r = map_insert(map, key, box);
        if (r != (at < 0 ? 1 : 0)) __builtin_trap();
        if (r == 1) __mc_keyed_put(m, key, id);
        else free(box); /* refused: the value is still the caller's */
        break;
    }
    case 1:
        if (map_insert_or_assign(map, key, __mc_box(id)) != (at < 0 ? 1 : 2)) __builtin_trap();
        __mc_keyed_put(m, key, id);
        break;
    case 2:
        if (__mc_unbox(map_find(map, key)) != (at < 0 ? 0 : m->values[at])) __builtin_trap();
        break;
    case 3:
        if (map_erase(map, key) != (at >= 0)) __builtin_trap();
        __mc_keyed_erase(m, key);
        break;
    case 4:
        if (map_contains(map, key) != (at >= 0)) __builtin_trap();
        break;
    case 5: __mc_map_walk(map, m, 0); break;
    case 6: __mc_map_walk(map, m, 1); break;
    case 7: __mc_map_verify(map, m); break;
    case 8:
        map_clear(map);
        __mc_keyed_clear(m);
        break;
    }
    free(key);
    __mc_map_verify(map, m);
}

/* ---- hashmap: string keys copied and freed, plain integer values ---- */

/* The length alone: every key of one length collides, so chains get long. */
static uint64_t __mc_weak_hash(const void* key) {
    return strlen(key);
}

static void __mc_hashmap_verify(hashmap_t* h, const mc_keyed_t* m) {
    if (hashmap_size(h) != m->count || hashmap_empty(h) != (m->count == 0)) __builtin_trap();
    size_t in_buckets = 0;
    for (size_t i = 0; i < h->capacity; i++)
        for (hashmap_entry_t* e = h->buckets[i]; e != NULL; e = e->next) {
            if (e->hash != h->hash(e->key) || e->hash % h->capacity != i) __builtin_trap();
            if (++in_buckets > m->count) __builtin_trap();
        }
    if (in_buckets != m->count) __builtin_trap();
}

static void __mc_hashmap_walk(hashmap_t* h, const mc_keyed_t* m) {
    uint8_t seen[MC_MAX_RECORDS] = {0};
    size_t count = 0;
    hashmap_foreach(h, it) {
        const ssize_t at = __mc_keyed_find(m, hashmap_iterator_key(it));
        if (at < 0 || seen[at]++ || m->values[at] != (intptr_t)hashmap_iterator_value(it)) __builtin_trap();
        count++;
    }
    if (count != m->count) __builtin_trap();
    if (hashmap_iterator_valid(hashmap_end(h))) __builtin_trap();
}

static void __mc_hashmap(hashmap_t* h, mc_keyed_t* m, unsigned op, const uint8_t* a, size_t n, intptr_t id) {
    char* key = __mc_key(a, n);
    if (key == NULL) abort();
    const ssize_t at = __mc_keyed_find(m, key);

    switch (op % 9) {
    case 0: {
        const int r = hashmap_insert(h, key, (void*)id);
        if (r != (at < 0 ? 1 : 0)) __builtin_trap();
        if (r == 1) __mc_keyed_put(m, key, id);
        break;
    }
    case 1:
        if (hashmap_insert_or_assign(h, key, (void*)id) != (at < 0 ? 1 : 2)) __builtin_trap();
        __mc_keyed_put(m, key, id);
        break;
    case 2:
        if ((intptr_t)hashmap_find(h, key) != (at < 0 ? 0 : m->values[at])) __builtin_trap();
        break;
    case 3:
        if (hashmap_erase(h, key) != (at >= 0)) __builtin_trap();
        __mc_keyed_erase(m, key);
        break;
    case 4:
        if (hashmap_contains(h, key) != (at >= 0)) __builtin_trap();
        break;
    case 5: __mc_hashmap_walk(h, m); break;
    case 6: {
        const size_t want = __mc_u16(a, n, 0) % 512;
        const int r = hashmap_rehash(h, want);
        if (r != (want == 0 || want < m->count ? -1 : 0)) __builtin_trap();
        if (r == 0 && h->capacity != want) __builtin_trap();
        break;
    }
    case 7: {
        const size_t want = __mc_u16(a, n, 0);
        if (hashmap_reserve(h, want) != 0) __builtin_trap();
        if (h->capacity < 16 || (double)want > (double)h->capacity * (double)h->load_factor) __builtin_trap();
        break;
    }
    case 8:
        hashmap_clear(h);
        __mc_keyed_clear(m);
        break;
    }
    free(key);
    __mc_hashmap_verify(h, m);
}

/* ---- array: typed values, the model keeps what each one must read back as ---- */

typedef enum { MC_INT, MC_DOUBLE, MC_LDOUBLE, MC_STRING, MC_OWNED, MC_BORROWED, MC_UNCOPYABLE } mc_kind_t;

typedef struct {
    mc_kind_t kind;
    int i;
    double d;
    long double ld;
    char* bytes;     /* MC_STRING: what the element must hold; pointers: the blob */
    size_t length;   /* MC_STRING: the length the array records */
    size_t blob;     /* pointers: blob size */
} mc_value_t;

typedef struct {
    mc_value_t items[MC_MAX_RECORDS];
    size_t count;
} mc_array_t;

static const char __mc_borrowed[] = "borrowed";

typedef struct { size_t size; uint8_t bytes[]; } mc_blob_t;

static void* __mc_blob_copy(void* p) {
    const mc_blob_t* b = p;
    mc_blob_t* c = __mc_xmalloc(sizeof *c + b->size);
    memcpy(c, b, sizeof *c + b->size);
    return c;
}

/* The value for the array, and the model's record of it. */
static avalue_t __mc_value(const uint8_t* a, size_t n, mc_value_t* v) {
    memset(v, 0, sizeof *v);
    const uint8_t kind = n > 0 ? a[0] : 0;
    if (n > 0) { a++; n--; }
    switch (kind % 7) {
    case 0:
        v->kind = MC_INT;
        v->i = (int)__mc_u32(a, n, 0);
        return array_create_int(v->i);
    case 1: {
        v->kind = MC_DOUBLE;
        uint8_t raw[8] = {0};
        memcpy(raw, a, n < 8 ? n : 8);
        memcpy(&v->d, raw, 8);
        return array_create_double(v->d);
    }
    case 2:
        v->kind = MC_LDOUBLE;
        v->ld = (long double)(int)__mc_u32(a, n, 0) / 7.0L;
        return array_create_ldouble(v->ld);
    case 3: {
        /* array_create_stringn copies up to the first NUL and pads with zeros
         * to the length it was given, which it keeps. */
        v->kind = MC_STRING;
        v->length = n;
        v->bytes = __mc_xmalloc(n + 1);
        const size_t text = strnlen((const char*)a, n);
        memcpy(v->bytes, a, text);
        memset(v->bytes + text, 0, n + 1 - text);
        return array_create_stringn((const char*)a, n);
    }
    case 4: case 6: {
        mc_blob_t* b = __mc_xmalloc(sizeof *b + n);
        b->size = n;
        memcpy(b->bytes, a, n);
        v->kind = kind % 7 == 4 ? MC_OWNED : MC_UNCOPYABLE;
        v->bytes = (char*)b;
        return array_create_pointer(b, v->kind == MC_OWNED ? __mc_blob_copy : NULL, free);
    }
    default:
        v->kind = MC_BORROWED;
        v->bytes = (char*)__mc_borrowed;
        return array_create_pointer((void*)__mc_borrowed, NULL, NULL);
    }
}

static void __mc_value_forget(mc_value_t* v) {
    /* The array owns the blob of an owned pointer; the model only points. */
    if (v->kind == MC_STRING) free(v->bytes);
    v->bytes = NULL;
}

static int __mc_same_double(double a, double b) {
    return memcmp(&a, &b, sizeof a) == 0;
}

static int __mc_same_ldouble(long double a, long double b) {
    return a == b || (isnan(a) && isnan(b));
}

static void __mc_element_check(array_t* arr, size_t at, const mc_value_t* v, int deep_copy) {
    const avalue_t* e = &arr->elements[at];
    switch (v->kind) {
    case MC_INT:
        if (e->type != ARRAY_INT || array_get_int(arr, at) != v->i) __builtin_trap();
        if (*(int*)array_get(arr, at) != v->i) __builtin_trap();
        break;
    case MC_DOUBLE:
        if (e->type != ARRAY_DOUBLE || !__mc_same_double(array_get_double(arr, at), v->d)) __builtin_trap();
        break;
    case MC_LDOUBLE:
        if (e->type != ARRAY_LONGDOUBLE || !__mc_same_ldouble(array_get_ldouble(arr, at), v->ld)) __builtin_trap();
        break;
    case MC_STRING:
        if (e->type != ARRAY_STRING || e->_length != v->length) __builtin_trap();
        if (memcmp(array_get_string(arr, at), v->bytes, v->length + 1) != 0) __builtin_trap();
        if (array_get(arr, at) != (void*)array_get_string(arr, at)) __builtin_trap();
        break;
    case MC_OWNED: case MC_UNCOPYABLE: case MC_BORROWED: {
        if (e->type != ARRAY_POINTER) __builtin_trap();
        void* p = array_get_pointer(arr, at);
        if (v->kind == MC_BORROWED || !deep_copy) {
            if (p != v->bytes) __builtin_trap();
        } else {
            const mc_blob_t* want = (const mc_blob_t*)v->bytes;
            if (p == v->bytes || memcmp(p, want, sizeof *want + want->size) != 0) __builtin_trap();
        }
        break;
    }
    }
    /* A getter of the wrong type reads nothing. */
    if (v->kind != MC_INT && array_get_int(arr, at) != 0) __builtin_trap();
    if (v->kind != MC_STRING && array_get_string(arr, at) != NULL) __builtin_trap();
    if (v->kind < MC_OWNED && array_get_pointer(arr, at) != NULL) __builtin_trap();
}

static void __mc_array_verify(array_t* arr, const mc_array_t* m) {
    if (array_size(arr) != m->count || arr->size > arr->capacity) __builtin_trap();
    for (size_t i = 0; i < m->count; i++) __mc_element_check(arr, i, &m->items[i], 0);
}

static void __mc_array_to_string(array_t* arr, const mc_array_t* m, size_t at) {
    str_t* s = array_item_to_string(arr, at);
    if (at >= m->count) { if (s != NULL) __builtin_trap(); return; }
    const mc_value_t* v = &m->items[at];
    char want[1024];
    int len = -1;
    switch (v->kind) {
    case MC_INT: len = snprintf(want, sizeof want, "%d", v->i); break;
    case MC_DOUBLE: len = snprintf(want, sizeof want, "%.12f", v->d); break;
    case MC_LDOUBLE: len = snprintf(want, sizeof want, "%.17Lg", v->ld); break;
    case MC_STRING: len = (int)strlen(v->bytes); break;
    default: break;
    }
    if (len < 0) { if (s != NULL) __builtin_trap(); return; }
    if (s == NULL || str_size(s) != (size_t)len) __builtin_trap();
    if (v->kind != MC_STRING && memcmp(str_get(s), want, (size_t)len) != 0) __builtin_trap();
    if (v->kind == MC_STRING && memcmp(str_get(s), v->bytes, (size_t)len) != 0) __builtin_trap();
    str_free(s);
}

static void __mc_array(array_t* arr, mc_array_t* m, unsigned op, const uint8_t* a, size_t n) {
    const size_t index = n > 0 ? a[0] % (m->count + 2) : 0; /* one past the end, and further */
    const uint8_t* rest = n > 0 ? a + 1 : a;
    const size_t rest_n = n > 0 ? n - 1 : 0;

    switch (op % 10) {
    case 0: case 1: case 2: {
        if (m->count == MC_MAX_RECORDS) break;
        mc_value_t v;
        const avalue_t value = __mc_value(rest, rest_n, &v);
        const size_t at = op % 10 == 0 ? m->count : op % 10 == 1 ? 0 : index;
        if (op % 10 == 0) array_push_back(arr, value);
        else if (op % 10 == 1) array_push_front(arr, value);
        else array_insert(arr, at, value);
        if (at > m->count) { __mc_value_forget(&v); break; } /* refused, and freed */
        memmove(&m->items[at + 1], &m->items[at], (m->count - at) * sizeof m->items[0]);
        m->items[at] = v;
        m->count++;
        break;
    }
    case 3: {
        mc_value_t v;
        array_update(arr, index, __mc_value(rest, rest_n, &v));
        if (index >= m->count) { __mc_value_forget(&v); break; } /* refused */
        __mc_value_forget(&m->items[index]);
        m->items[index] = v;
        break;
    }
    case 4:
        array_delete(arr, index);
        if (index >= m->count) break;
        __mc_value_forget(&m->items[index]);
        memmove(&m->items[index], &m->items[index + 1], (m->count - index - 1) * sizeof m->items[0]);
        m->count--;
        break;
    case 5:
        if (index < m->count) __mc_element_check(arr, index, &m->items[index], 0);
        else if (array_get(arr, index) != NULL || array_get_string(arr, index) != NULL) __builtin_trap();
        break;
    case 6: __mc_array_to_string(arr, m, index); break;
    case 7: {
        array_t* copy = array_copy(arr);
        int copyable = 1;
        for (size_t i = 0; i < m->count; i++)
            if (m->items[i].kind == MC_UNCOPYABLE) copyable = 0;
        if ((copy != NULL) != copyable) __builtin_trap();
        if (copy == NULL) break;
        if (array_size(copy) != m->count) __builtin_trap();
        for (size_t i = 0; i < m->count; i++) __mc_element_check(copy, i, &m->items[i], 1);
        array_free(copy);
        break;
    }
    case 8:
        array_clear(arr);
        for (size_t i = 0; i < m->count; i++) __mc_value_forget(&m->items[i]);
        m->count = 0;
        break;
    case 9: break;
    }
    __mc_array_verify(arr, m);
}

/* ---- str: bytes, NUL included, against a plain buffer ---- */

typedef struct {
    char* bytes;
    size_t size;
} mc_bytes_t;

static void __mc_bytes_splice(mc_bytes_t* b, size_t pos, const void* p, size_t n) {
    char* grown = realloc(b->bytes, b->size + n + 1);
    if (grown == NULL) abort();
    b->bytes = grown;
    memmove(b->bytes + pos + n, b->bytes + pos, b->size - pos);
    memcpy(b->bytes + pos, p, n);
    b->size += n;
}

static void __mc_str_verify(str_t* s, const mc_bytes_t* b) {
    if (str_size(s) != b->size) __builtin_trap();
    const char* got = str_get(s);
    if (memcmp(got, b->bytes, b->size) != 0 || got[b->size] != '\0') __builtin_trap();
    if (s->is_dynamic ? s->capacity <= s->size : s->size >= STR_SSO_SIZE) __builtin_trap();
    if (str_last(s) != (b->size ? b->bytes[b->size - 1] : '\0')) __builtin_trap();
}

static int __mc_sign(int v) {
    return (v > 0) - (v < 0);
}

static void __mc_str(str_t** s, mc_bytes_t* b, unsigned op, const uint8_t* a, size_t n) {
    const int w = (op / 12) & 1;
    str_t* str = s[w];
    mc_bytes_t* m = &b[w];
    const size_t pos = n > 0 ? a[0] % (m->size + 2) : 0;
    const uint8_t* rest = n > 0 ? a + 1 : a;
    const size_t rest_n = n > 0 ? n - 1 : 0;

    switch (op % 12) {
    case 0:
        if (!str_append(str, (const char*)a, n)) __builtin_trap();
        __mc_bytes_splice(m, m->size, a, n);
        break;
    case 1:
        if (!str_prepend(str, (const char*)a, n)) __builtin_trap();
        __mc_bytes_splice(m, 0, a, n);
        break;
    case 2:
        if (str_insert(str, (const char*)rest, rest_n, pos) != (pos <= m->size)) __builtin_trap();
        if (pos <= m->size) __mc_bytes_splice(m, pos, rest, rest_n);
        break;
    case 3: {
        const char c = rest_n ? (char)rest[0] : 'x';
        if (!str_appendc(str, c)) __builtin_trap();
        __mc_bytes_splice(m, m->size, &c, 1);
        break;
    }
    case 4: {
        const char c = rest_n ? (char)rest[0] : 'x';
        if (str_insertc(str, c, pos) != (pos <= m->size)) __builtin_trap();
        if (pos <= m->size) __mc_bytes_splice(m, pos, &c, 1);
        break;
    }
    case 5:
        if (!str_assign(str, (const char*)a, n)) __builtin_trap();
        m->size = 0;
        __mc_bytes_splice(m, 0, a, n);
        break;
    case 6:
        if (!str_reserve(str, __mc_u16(a, n, 0) % 8192)) __builtin_trap();
        break;
    case 7:
        if (str_pop(str) != (m->size > 0)) __builtin_trap();
        if (m->size > 0) m->size--;
        break;
    case 8: {
        char* copy = str_copy(str);
        if (copy == NULL || memcmp(copy, m->bytes, m->size) != 0 || copy[m->size] != '\0') __builtin_trap();
        free(copy);
        /* Compared as C strings: up to the first NUL of each. */
        char* x = strndup(b[0].bytes, b[0].size);
        char* y = strndup(b[1].bytes, b[1].size);
        if (x == NULL || y == NULL) abort();
        if (__mc_sign(str_cmp(s[0], s[1])) != __mc_sign(strcmp(x, y))) __builtin_trap();
        free(x); free(y);
        break;
    }
    case 9:
        if (rest_n & 1) str_clear(str);
        else if (!str_reset(str)) __builtin_trap();
        m->size = 0;
        break;
    case 10: {
        /* Into the other one; this one is left empty. */
        if (!str_move(str, s[!w])) __builtin_trap();
        mc_bytes_t* other = &b[!w];
        other->size = 0;
        __mc_bytes_splice(other, 0, m->bytes, m->size);
        m->size = 0;
        __mc_str_verify(s[!w], other);
        break;
    }
    case 11: {
        const int len = (int)(rest_n < 4096 ? rest_n : 4096);
        if (!str_appendf(str, "%.*s|%d", len, (const char*)rest, len)) __builtin_trap();
        const size_t text = strnlen((const char*)rest, (size_t)len);
        char tail[16];
        const int t = snprintf(tail, sizeof tail, "|%d", len);
        __mc_bytes_splice(m, m->size, rest, text);
        __mc_bytes_splice(m, m->size, tail, (size_t)t);
        break;
    }
    }
    __mc_str_verify(str, m);
}

/* ---- bufo: a fixed window of bytes, with the bytes it has not written unknown ---- */

typedef struct {
    uint8_t* bytes;
    uint8_t* known;
    size_t capacity, size, pos;
    size_t known_end; /* nothing at or past it was ever written */
    int has_data;
} mc_bufo_t;

static void __mc_bufo_resize(mc_bufo_t* m, size_t capacity) {
    uint8_t* b = realloc(m->bytes, capacity ? capacity : 1);
    uint8_t* k = realloc(m->known, capacity ? capacity : 1);
    if (b == NULL || k == NULL) abort();
    if (capacity > m->capacity) memset(k + m->capacity, 0, capacity - m->capacity);
    if (m->known_end > capacity) m->known_end = capacity;
    m->bytes = b;
    m->known = k;
    m->capacity = capacity;
}

static void __mc_bufo_verify(bufo_t* buf, const mc_bufo_t* m) {
    if (buf->capacity != m->capacity || buf->size != m->size || buf->pos != m->pos) __builtin_trap();
    if ((buf->data != NULL) != m->has_data || bufo_size(buf) != m->size) __builtin_trap();
    if (bufo_data(buf) != (m->has_data ? buf->data + m->pos : NULL)) __builtin_trap();
    const size_t end = m->size < m->known_end ? m->size : m->known_end;
    for (size_t i = 0; i < end; i++)
        if (m->known[i] && (uint8_t)buf->data[i] != m->bytes[i]) __builtin_trap();
}

static void __mc_bufo(bufo_t* buf, mc_bufo_t* m, unsigned op, const uint8_t* a, size_t n) {
    /* Capacities up to 16 MiB, so the 10 MiB ceiling is crossed; mostly small. */
    const uint32_t raw = __mc_u32(a, n, 0);
    const size_t big = raw & 0xFFFFFF;
    const size_t amount = n > 0 && (a[0] & 0x80) ? big : big % 8192;

    switch (op % 10) {
    case 0: {
        const int r = bufo_alloc(buf, amount);
        const int want = m->has_data ? 1 : amount <= MC_BUFO_LIMIT;
        if (r != want) __builtin_trap();
        if (r && !m->has_data) { m->has_data = 1; __mc_bufo_resize(m, amount); }
        break;
    }
    case 1: {
        const int r = bufo_ensure_capacity(buf, amount);
        if (amount <= m->capacity) { if (r != 1) __builtin_trap(); break; }
        if (amount > MC_BUFO_LIMIT) { if (r != 0) __builtin_trap(); break; }
        if (r != 1) __builtin_trap();
        size_t cap = m->capacity == 0 ? 4096 : m->capacity;
        while (cap < amount) cap *= 2;
        if (cap > MC_BUFO_LIMIT) cap = MC_BUFO_LIMIT;
        m->has_data = 1;
        __mc_bufo_resize(m, cap);
        break;
    }
    case 2: {
        const ssize_t r = bufo_append(buf, (const char*)a, n);
        ssize_t want;
        if (n == 0) want = 0;
        else if (!m->has_data) want = -1;
        else if (m->pos >= m->capacity) want = 0;
        else want = (ssize_t)(n < m->capacity - m->pos ? n : m->capacity - m->pos);
        if (r != want) __builtin_trap();
        if (want > 0) {
            memcpy(m->bytes + m->pos, a, (size_t)want);
            memset(m->known + m->pos, 1, (size_t)want);
            m->pos += (size_t)want;
            if (m->pos > m->known_end) m->known_end = m->pos;
            if (m->pos > m->size) m->size = m->pos;
        }
        break;
    }
    case 3: {
        const size_t r = bufo_move_front_pos(buf, amount);
        size_t want = 0;
        if (m->pos < m->size) {
            want = m->pos + amount >= m->size ? m->size - m->pos : amount;
            m->pos += want;
        }
        if (r != want) __builtin_trap();
        break;
    }
    case 4: bufo_reset_pos(buf); m->pos = 0; break;
    case 5: bufo_reset_size(buf); m->size = 0; break;
    case 6:
        bufo_set_size(buf, amount);
        m->size = amount > m->capacity ? m->capacity : amount;
        break;
    case 7: {
        const size_t want = m->pos >= m->size ? 0 : (amount < m->size - m->pos ? amount : m->size - m->pos);
        if (bufo_chunk_size(buf, amount) != want) __builtin_trap();
        break;
    }
    case 8: bufo_flush(buf); m->size = m->pos = 0; break;
    case 9:
        bufo_clear(buf);
        m->size = m->pos = 0;
        m->has_data = 0;
        __mc_bufo_resize(m, 0);
        break;
    }
    __mc_bufo_verify(buf, m);
}

/* ---- arena: every live allocation keeps its bytes until the reset ---- */

typedef struct {
    uint8_t* p;
    size_t size;
    uint8_t fill;
} mc_alloc_t;

typedef struct {
    mc_alloc_t live[MC_MAX_RECORDS];
    size_t count;
} mc_arena_t;

/* Past this an allocation is not filled or checked byte by byte. */
#define MC_ARENA_FILL_MAX 65536

static size_t __mc_arena_held(const arena_block_t* b, int* blocks) {
    size_t held = 0;
    for (; b != NULL; b = b->next) { held += b->capacity; (*blocks)++; }
    return held;
}

static void __mc_arena_verify(arena_t* arena, const mc_arena_t* m, int bytes) {
    int blocks = 0;
    const size_t held = __mc_arena_held(arena->head, &blocks) + __mc_arena_held(arena->spare, &blocks);
    if (held != arena->total_bytes) __builtin_trap();
    for (const arena_block_t* b = arena->head; b != NULL; b = b->next)
        if (b->used > b->capacity) __builtin_trap();
    if (!bytes) return;
    for (size_t i = 0; i < m->count; i++) {
        const mc_alloc_t* x = &m->live[i];
        const size_t n = x->size < MC_ARENA_FILL_MAX ? x->size : 0;
        for (size_t j = 0; j < n; j++)
            if (x->p[j] != (uint8_t)(x->fill + j)) __builtin_trap();
    }
}

/* The block of the chain that holds [p, p + size), or a trap. */
static void __mc_arena_contains(arena_t* arena, const uint8_t* p, size_t size) {
    for (const arena_block_t* b = arena->head; b != NULL; b = b->next)
        if (p >= b->data && p <= b->data + b->capacity && size <= (size_t)(b->data + b->capacity - p))
            return;
    __builtin_trap();
}

static void __mc_arena_record(arena_t* arena, mc_arena_t* m, uint8_t* p, size_t size, uint8_t fill) {
    if (((uintptr_t)p & (2 * sizeof(void*) - 1)) != 0) __builtin_trap();
    __mc_arena_contains(arena, p, size ? size : 1);
    /* Nothing live overlaps it. */
    for (size_t i = 0; i < m->count; i++) {
        const mc_alloc_t* x = &m->live[i];
        if (p < x->p + (x->size ? x->size : 1) && x->p < p + (size ? size : 1)) __builtin_trap();
    }
    if (m->count < MC_MAX_RECORDS) m->live[m->count++] = (mc_alloc_t){ p, size, fill };
}

static void __mc_arena(arena_t* arena, mc_arena_t* m, unsigned op, const uint8_t* a, size_t n) {
    switch (op % 5) {
    case 0: {
        /* Small, larger than a block, or so large that the block header
         * would wrap the allocation size around. */
        const uint32_t raw = __mc_u32(a, n, 0);
        size_t size;
        switch (n > 0 ? a[0] >> 6 : 0) {
        case 0: case 1: size = raw % 512; break;
        case 2: size = raw % (1u << 20); break;
        default: size = SIZE_MAX - (raw % 256); break;
        }
        uint8_t* p = arena_alloc(arena, size);
        if (size > PTRDIFF_MAX) { if (p != NULL) __builtin_trap(); break; }
        if (p == NULL) __builtin_trap();
        const uint8_t fill = (uint8_t)raw;
        if (size < MC_ARENA_FILL_MAX)
            for (size_t j = 0; j < size; j++) p[j] = (uint8_t)(fill + j);
        __mc_arena_record(arena, m, p, size < MC_ARENA_FILL_MAX ? size : 0, fill);
        break;
    }
    case 1: {
        char* p = arena_strndup(arena, (const char*)a, n);
        if (p == NULL || memcmp(p, a, n) != 0 || p[n] != '\0') __builtin_trap();
        /* Recorded as a pattern: rewrite it so. */
        for (size_t j = 0; j <= n; j++) p[j] = (char)(uint8_t)(n + j);
        __mc_arena_record(arena, m, (uint8_t*)p, n + 1, (uint8_t)n);
        break;
    }
    case 2: {
        const size_t held = arena->total_bytes;
        arena_reset(arena);
        if (arena->head != NULL || arena->total_bytes != held) __builtin_trap();
        m->count = 0;
        break;
    }
    case 3:
        arena_free(arena);
        if (arena->head != NULL || arena->spare != NULL || arena->total_bytes != 0) __builtin_trap();
        m->count = 0;
        break;
    case 4: __mc_arena_verify(arena, m, 1); break;
    }
    __mc_arena_verify(arena, m, 0);
}

static mc_keyed_t __mc_map_model, __mc_hash_model;
static mc_array_t __mc_array_model;
static mc_arena_t __mc_arena_model;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    const uint8_t config = data[0];
    data++; size--;

    map_t* map = map_create_ex(map_compare_string, map_copy_string, free, NULL, free);
    static const float factors[4] = { 0.0f, 0.25f, 0.75f, 1.0f };
    hashmap_t* hash = hashmap_create_ex((config & 0x80) ? __mc_weak_hash : hashmap_hash_string,
                                        hashmap_equals_string, config & 7, factors[(config >> 3) & 3],
                                        map_copy_string, free, NULL, NULL);
    array_t* arr = array_create();
    str_t* strs[2] = { str_create_empty((config >> 5) & 1 ? 0 : 100), str_create_empty(0) };
    bufo_t* buf = bufo_create();
    arena_t arena;
    arena_init(&arena);
    if (map == NULL || hash == NULL || arr == NULL || strs[0] == NULL || strs[1] == NULL || buf == NULL) abort();

    mc_keyed_t* mm = &__mc_map_model;
    mc_keyed_t* hm = &__mc_hash_model;
    mc_array_t* am = &__mc_array_model;
    mc_arena_t* rm = &__mc_arena_model;
    mc_bytes_t sm[2] = { { NULL, 0 }, { NULL, 0 } };
    mc_bufo_t bm = { 0 };
    mm->count = hm->count = am->count = rm->count = 0;
    __mc_bytes_splice(&sm[0], 0, "", 0);
    __mc_bytes_splice(&sm[1], 0, "", 0);

    size_t records = 0;
    intptr_t id = 0;
    while (size >= 2 && records++ < MC_MAX_RECORDS) {
        const uint8_t sel = data[0];
        size_t n = data[1];
        data += 2; size -= 2;
        if (n > size) n = size;
        const uint8_t* arg = data;
        data += n; size -= n;
        const unsigned op = sel / 6;
        id++;

        switch (sel % 6) {
        case 0: __mc_arena(&arena, rm, op, arg, n); break;
        case 1: __mc_array(arr, am, op, arg, n); break;
        case 2: __mc_map(map, mm, op, arg, n, id); break;
        case 3: __mc_hashmap(hash, hm, op, arg, n, id); break;
        case 4: __mc_str(strs, sm, op, arg, n); break;
        case 5: __mc_bufo(buf, &bm, op, arg, n); break;
        }
    }

    __mc_map_walk(map, mm, 0);
    __mc_map_walk(map, mm, 1);
    __mc_hashmap_walk(hash, hm);
    __mc_arena_verify(&arena, rm, 1);

    map_free(map);
    hashmap_free(hash);
    array_free(arr);
    str_free(strs[0]);
    str_free(strs[1]);
    bufo_free(buf);
    arena_free(&arena);

    __mc_keyed_clear(mm);
    __mc_keyed_clear(hm);
    for (size_t i = 0; i < am->count; i++) __mc_value_forget(&am->items[i]);
    free(sm[0].bytes);
    free(sm[1].bytes);
    free(bm.bytes);
    free(bm.known);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_GZIP

#include <zlib.h>
#include "gzip.h"

/* misc/gzip.c, driven the way its callers drive it: the response filter
 * (http_gzip_filter.c) hands one input buffer at a time to gzip_deflate and
 * calls again while the output buffer came back full and the stream has not
 * ended; the HTTP client parsers (httpteparser.c, httpresponseparser.c) give
 * each received chunk to gzip_inflate_init and call gzip_inflate while the
 * output buffer came back full. The chunk and buffer sizes come from the
 * input, down to one byte.
 *
 * The first byte picks the mode:
 *   0 round trip at level 0-9 -- the stream decodes (zlib's own inflate, and
 *     gzip_inflate chunk by chunk) to the input exactly, with no error on the
 *     way and every input byte consumed before the next buffer;
 *   1 arbitrary bytes into gzip_inflate -- the result does not depend on the
 *     chunking: the same output, error and end as one zlib call on the whole;
 *   2 a valid stream cut short, followed by another stream or garbage, or with
 *     one byte changed -- cut short gives a prefix and no end, followed gives
 *     the whole and an end with the tail left alone, changed gives an error or
 *     the original. */

#define GZ_OUT_LIMIT (4u << 20)

static uint32_t __gz_mix(uint32_t x) {
    x = (x + 1) * 2654435761u;
    return x ^ x >> 15;
}

typedef struct {
    uint32_t state;
    uint8_t shape;
} gz_sizes_t;

/* Chunk sizes: one byte, a few, or the callers' GZIP_BUFFER, from a small
 * generator the input seeds. */
static size_t __gz_next(gz_sizes_t* g) {
    g->state = g->state * 1103515245u + 12345u;
    const uint32_t r = g->state >> 8;
    switch (g->shape % 4) {
    case 0: return 1 + r % 3;
    case 1: return 1 + r % 64;
    case 2: return 1 + r % 4096;
    default: return GZIP_BUFFER;
    }
}

typedef struct {
    uint8_t* bytes;
    size_t size, capacity;
} gz_buf_t;

static void __gz_put(gz_buf_t* b, const void* p, size_t n) {
    if (n == 0) return;
    if (b->size + n > b->capacity) {
        size_t cap = b->capacity ? b->capacity : 256;
        while (cap < b->size + n) cap *= 2;
        uint8_t* grown = realloc(b->bytes, cap);
        if (grown == NULL) abort();
        b->bytes = grown;
        b->capacity = cap;
    }
    memcpy(b->bytes + b->size, p, n);
    b->size += n;
}

/* The response filter's loop, over the whole input. */
static void __gz_deflate(const uint8_t* data, size_t size, int level, gz_sizes_t* in, gz_sizes_t* out, gz_buf_t* z) {
    gzip_t gz;
    gzip_init(&gz);
    if (!gzip_deflate_init_level(&gz, level)) abort();
    char* buffer = malloc(GZIP_BUFFER + 6);
    if (buffer == NULL) abort();

    size_t at = 0;
    do {
        size_t chunk = __gz_next(in);
        if (chunk > size - at) chunk = size - at;
        const int last = at + chunk == size;
        gzip_set_in(&gz, (const char*)data + at, chunk);
        for (;;) {
            /* zlib.h: more than six bytes of room for a sync flush, or the
             * flush marker repeats forever. The callers give GZIP_BUFFER. */
            const size_t cap = 6 + __gz_next(out);
            const size_t n = gzip_deflate(&gz, buffer, cap, last);
            if (gzip_deflate_has_error(&gz) || n > cap) __builtin_trap();
            __gz_put(z, buffer, n);
            if (!(gzip_want_continue(&gz) && !gzip_is_end(&gz))) break;
        }
        if (gz.stream.avail_in != 0) __builtin_trap();
        at += chunk;
        if (last && !gzip_is_end(&gz)) __builtin_trap();
    } while (at < size);

    if (!gzip_free(&gz)) __builtin_trap();
    free(buffer);
}

typedef struct {
    int error, end;
} gz_result_t;

/* The client parsers' loop, one received chunk at a time; after an error or
 * the end nothing more is fed, as they stop. */
static gz_result_t __gz_inflate(const uint8_t* data, size_t size, gz_sizes_t* in, gz_sizes_t* out, gz_buf_t* plain) {
    gz_result_t r = { 0, 0 };
    gzip_t gz;
    gzip_init(&gz);
    char* buffer = malloc(GZIP_BUFFER);
    if (buffer == NULL) abort();

    size_t at = 0;
    while (at < size && !r.error && !r.end && plain->size < GZ_OUT_LIMIT) {
        size_t chunk = __gz_next(in);
        if (chunk > size - at) chunk = size - at;
        if (!gzip_inflate_init(&gz, (const char*)data + at, chunk)) abort();
        do {
            const size_t cap = __gz_next(out);
            const size_t n = gzip_inflate(&gz, buffer, cap);
            if (n > cap) __builtin_trap();
            /* Kept even from the call that fails, for the comparison with
             * the reference; the callers drop the lot on an error. */
            __gz_put(plain, buffer, n);
            if (gzip_inflate_has_error(&gz)) { r.error = 1; break; }
        } while (gzip_want_continue(&gz) && plain->size < GZ_OUT_LIMIT);
        r.end = gzip_is_end(&gz);
        at += chunk;
    }

    gzip_free(&gz);
    free(buffer);
    return r;
}

/* The reference: one zlib inflate over everything, as far as it goes. */
static gz_result_t __gz_reference(const uint8_t* data, size_t size, gz_buf_t* plain) {
    gz_result_t r = { 0, 0 };
    z_stream s;
    memset(&s, 0, sizeof s);
    if (inflateInit2(&s, MAX_WBITS + 16) != Z_OK) abort();
    s.next_in = (Bytef*)data;
    s.avail_in = (uInt)size;
    uint8_t buffer[16384];
    for (;;) {
        s.next_out = buffer;
        s.avail_out = sizeof buffer;
        const int z = inflate(&s, Z_NO_FLUSH);
        __gz_put(plain, buffer, sizeof buffer - s.avail_out);
        if (z == Z_STREAM_END) { r.end = 1; break; }
        if (z == Z_NEED_DICT || z == Z_DATA_ERROR || z == Z_MEM_ERROR || z == Z_STREAM_ERROR) { r.error = 1; break; }
        if (s.avail_out != 0 || plain->size >= GZ_OUT_LIMIT) break;
    }
    inflateEnd(&s);
    return r;
}

static void __gz_compress(const uint8_t* data, size_t size, gz_buf_t* z) {
    z_stream s;
    memset(&s, 0, sizeof s);
    if (deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) abort();
    const uLong bound = deflateBound(&s, size);
    uint8_t* out = malloc(bound);
    if (out == NULL) abort();
    s.next_in = (Bytef*)data;
    s.avail_in = (uInt)size;
    s.next_out = out;
    s.avail_out = (uInt)bound;
    if (deflate(&s, Z_FINISH) != Z_STREAM_END) abort();
    __gz_put(z, out, bound - s.avail_out);
    deflateEnd(&s);
    free(out);
}

static int __gz_equal(const gz_buf_t* a, const uint8_t* b, size_t n) {
    return a->size == n && (n == 0 || memcmp(a->bytes, b, n) == 0);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 5) return 0;
    const uint8_t mode = data[0], level = data[1];
    gz_sizes_t in = { __gz_mix(data[2]), data[2] }, out = { data[3] * 2654435761u, data[3] >> 2 };
    const uint8_t extra = data[4];
    data += 5; size -= 5;

    gz_buf_t z = { 0 }, plain = { 0 }, ref = { 0 };

    switch (mode % 3) {
    case 0: {
        __gz_deflate(data, size, level % 10, &in, &out, &z);
        const gz_result_t want = __gz_reference(z.bytes, z.size, &ref);
        if (!want.end || want.error || !__gz_equal(&ref, data, size)) __builtin_trap();
        const gz_result_t got = __gz_inflate(z.bytes, z.size, &in, &out, &plain);
        if (!got.end || got.error || !__gz_equal(&plain, data, size)) __builtin_trap();
        break;
    }
    case 1: {
        const gz_result_t want = __gz_reference(data, size, &ref);
        const gz_result_t got = __gz_inflate(data, size, &in, &out, &plain);
        if (plain.size < GZ_OUT_LIMIT && ref.size < GZ_OUT_LIMIT) {
            if (got.end != want.end || got.error != want.error) __builtin_trap();
            if (!__gz_equal(&plain, ref.bytes, ref.size)) __builtin_trap();
        }
        break;
    }
    case 2: {
        /* The payload is what follows the first `extra` bytes of input. */
        const size_t split = size ? extra % (size + 1) : 0;
        const uint8_t* tail = data;
        const size_t tail_n = split;
        const uint8_t* body = data + split;
        const size_t body_n = size - split;
        __gz_compress(body, body_n, &z);
        const size_t cut = z.size ? __gz_mix(level) % z.size : 0;

        switch (level % 3) {
        case 0: { /* cut short */
            const gz_result_t got = __gz_inflate(z.bytes, cut, &in, &out, &plain);
            if (got.end || got.error) __builtin_trap();
            if (plain.size > body_n || (plain.size && memcmp(plain.bytes, body, plain.size) != 0)) __builtin_trap();
            break;
        }
        case 1: { /* followed by more */
            __gz_put(&z, tail, tail_n);
            const gz_result_t got = __gz_inflate(z.bytes, z.size, &in, &out, &plain);
            if (!got.end || got.error || !__gz_equal(&plain, body, body_n)) __builtin_trap();
            break;
        }
        default: { /* one byte changed */
            z.bytes[cut] ^= (uint8_t)(extra | 1);
            const gz_result_t got = __gz_inflate(z.bytes, z.size, &in, &out, &plain);
            if (got.end && !__gz_equal(&plain, body, body_n)) __builtin_trap();
            break;
        }
        }
        break;
    }
    }

    free(z.bytes);
    free(plain.bytes);
    free(ref.bytes);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_H3_RESPONSE

#include <zlib.h>
#include "h3conn.h"
#include "h3frame.h"
#include "h3response.h"
#include "quicmemory.h"
#include "quicsendbuf.h"
#include "varint.h"

/* The serving half of an HTTP/3 request stream: a response a handler built,
 * through the h3 filter chain (not_modified, range, data, gzip) into
 * h3response.c, h3_write_filter.c and h3data.c, onto the QUIC stream -- what
 * h1_connection does for HTTP/1.1.
 *
 * The connection is the bare one of test_h3dispatch.c: a quicconn_t whose ctx
 * resolves to an h3conn, with no handshake. Nothing on the response path looks
 * past the stream list, quicstream_write/finish and the write-ahead budget, so
 * a TLS handshake would add time and nothing under test; the transport under
 * the stream is quic_conn's. Between write turns the "network" takes what the
 * stream queued the way the packetiser does (quicsendbuf_next, mark_sent, ack),
 * as much per turn as the input says, which is what frees the budget.
 *
 * The client reads the stream: HEADERS decoded by QPACK, DATA frames joined,
 * an optional trailing HEADERS, then FIN and nothing after it. It checks
 *   - :status first and alone among pseudo-fields, the status the handler set
 *     (or 304 when the validator matched), names in lower case, no
 *     connection-specific field, every field the handler added with its value;
 *   - Content-Length, when there is one, equals the DATA payload;
 *   - no DATA for HEAD, 204 or 304; otherwise the body, or with Content-Encoding:
 *     gzip a stream that inflates to it -- and gzip only when the request
 *     accepted it;
 *   - the trailers the handler added, minus what §4.1 drops, after the body;
 *   - after everything is freed the QUIC memory budget is where it started.
 *
 * Input: [flags] [status] [network] [body size, 2 bytes] [fields] [trailers],
 * then the bytes the body repeats. Fields and trailers are a count and then
 * name/value pairs of a length byte and bytes each. */

#define H3P_WINDOW (64u * 1024 * 1024)
#define H3P_FIELDS 8
#define H3P_TURNS 4096

typedef struct {
    char name[32];
    size_t name_len;
    char value[64];
    size_t value_len;
} h3p_field_t;

typedef struct {
    uint8_t* bytes;
    size_t len, cap;
} h3p_buf_t;

static void __h3p_put(h3p_buf_t* b, const void* p, size_t n) {
    if (n == 0) return;
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n) cap *= 2;
        uint8_t* grown = realloc(b->bytes, cap);
        if (grown == NULL) abort();
        b->bytes = grown;
        b->cap = cap;
    }
    memcpy(b->bytes + b->len, p, n);
    b->len += n;
}

static int __h3p_ieq(const char* a, size_t al, const char* b, size_t bl) {
    return al == bl && strncasecmp(a, b, al) == 0;
}

/* Fields no HTTP/3 message may carry (RFC 9114 §4.2), which the server drops. */
static int __h3p_connection_specific(const char* n, size_t l) {
    return __h3p_ieq(n, l, "connection", 10) || __h3p_ieq(n, l, "keep-alive", 10) ||
           __h3p_ieq(n, l, "proxy-connection", 16) || __h3p_ieq(n, l, "transfer-encoding", 17) ||
           __h3p_ieq(n, l, "upgrade", 7) || __h3p_ieq(n, l, "te", 2);
}

/* Fields the chain itself decides; a handler's copy of one is not compared. */
static int __h3p_chain_owned(const char* n, size_t l) {
    return __h3p_connection_specific(n, l) ||
           __h3p_ieq(n, l, "content-length", 14) || __h3p_ieq(n, l, "content-encoding", 16) ||
           __h3p_ieq(n, l, "content-type", 12) || __h3p_ieq(n, l, "vary", 4) ||
           __h3p_ieq(n, l, "etag", 4) || __h3p_ieq(n, l, "last-modified", 13) ||
           __h3p_ieq(n, l, "content-range", 13) || __h3p_ieq(n, l, "accept-ranges", 13) ||
           __h3p_ieq(n, l, "cache-control", 13) || __h3p_ieq(n, l, "date", 4) ||
           __h3p_ieq(n, l, "server", 6);
}

static size_t __h3p_fields(const uint8_t** data, size_t* size, h3p_field_t* out, size_t max) {
    if (*size < 1) return 0;
    size_t n = (*data)[0] % (max + 1);
    (*data)++; (*size)--;
    size_t count = 0;
    for (size_t i = 0; i < n && *size >= 2; i++) {
        h3p_field_t* f = &out[count];
        /* A token of a name, never empty; a value of any byte but CR, LF and
         * NUL. The other controls are left in: the response drops a field
         * that holds one, and the checks below expect exactly that. */
        size_t nl = 1 + (*data)[0] % (sizeof f->name - 1);
        size_t vl = (*data)[1] % sizeof f->value;
        (*data) += 2; (*size) -= 2;
        if (nl > *size) nl = *size;
        if (nl == 0) break;
        static const char token[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!#$%&'*+^`|~";
        for (size_t j = 0; j < nl; j++) f->name[j] = token[(*data)[j] % (sizeof token - 1)];
        f->name_len = nl;
        /* What the chain decides itself -- framing, encoding, validators --
         * is not the handler's to set here: renamed out of the way. */
        if (__h3p_chain_owned(f->name, nl) && !__h3p_connection_specific(f->name, nl)) f->name[0] = 'x';
        (*data) += nl; (*size) -= nl;
        if (vl > *size) vl = *size;
        for (size_t j = 0; j < vl; j++) {
            const uint8_t c = (*data)[j];
            f->value[j] = (char)(c == '\r' || c == '\n' || c == 0 ? ' ' : c);
        }
        /* A field value has no leading or trailing whitespace (RFC 9110 §5.5). */
        while (vl > 0 && (f->value[vl - 1] == ' ' || f->value[vl - 1] == '\t')) vl--;
        size_t lead = 0;
        while (lead < vl && (f->value[lead] == ' ' || f->value[lead] == '\t')) lead++;
        memmove(f->value, f->value + lead, vl - lead);
        f->value_len = vl - lead;
        (*data) += vl; (*size) -= vl;
        count++;
    }
    return count;
}

static const qpack_header_t* __h3p_find(const qpack_header_t* f, size_t n, const char* name) {
    for (size_t i = 0; i < n; i++)
        if (__h3p_ieq(f[i].name, f[i].name_len, name, strlen(name))) return &f[i];
    return NULL;
}

static void __h3p_check_section(const qpack_header_t* f, size_t n, int is_trailer) {
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < f[i].name_len; j++)
            if (f[i].name[j] >= 'A' && f[i].name[j] <= 'Z') __builtin_trap();
        if (f[i].name_len > 0 && f[i].name[0] == ':' && (is_trailer || i != 0)) __builtin_trap();
        if (__h3p_connection_specific(f[i].name, f[i].name_len)) __builtin_trap();
        if (is_trailer && __h3p_ieq(f[i].name, f[i].name_len, "content-length", 14)) __builtin_trap();
        /* The handler's fields with a control byte are dropped, not sent
         * (__h3p_value_kept): that one is missing from the expected fields
         * proves nothing unless none arrives. HTAB only inside a value. */
        for (size_t j = 0; j < f[i].name_len; j++) {
            const unsigned char c = (unsigned char)f[i].name[j];
            if (c <= 0x20 || c >= 0x7f) __builtin_trap();
        }
        for (size_t j = 0; j < f[i].value_len; j++) {
            const unsigned char c = (unsigned char)f[i].value[j];
            if (c == 0x7f || (c < 0x20 && c != '\t')) __builtin_trap();
        }
    }
}

/* Every field the handler added and the chain leaves alone, with its value.
 * Several copies of one name: each value must be there. */
/* Whether the response keeps a field with this value: one holding a C0
 * control other than HTAB, or DEL, is dropped where the handler adds it
 * (httpresponse.c, h2_field_response_value_valid). */
static int __h3p_value_kept(const h3p_field_t* w) {
    for (size_t i = 0; i < w->value_len; i++) {
        const unsigned char c = (unsigned char)w->value[i];
        if (c == 0x7f || (c < 0x20 && c != '\t')) return 0;
    }
    return 1;
}

static void __h3p_expect_fields(const qpack_header_t* f, size_t n, const h3p_field_t* want, size_t count) {
    for (size_t k = 0; k < count; k++) {
        const h3p_field_t* w = &want[k];
        if (__h3p_chain_owned(w->name, w->name_len) || w->name[0] == ':') continue;
        if (!__h3p_value_kept(w)) continue;
        int found = 0;
        for (size_t i = 0; i < n && !found; i++)
            found = __h3p_ieq(f[i].name, f[i].name_len, w->name, w->name_len) &&
                    f[i].value_len == w->value_len && memcmp(f[i].value, w->value, w->value_len) == 0;
        if (!found) __builtin_trap();
    }
}

static int __h3p_inflate(const uint8_t* z, size_t zn, h3p_buf_t* out) {
    z_stream s;
    memset(&s, 0, sizeof s);
    if (inflateInit2(&s, MAX_WBITS + 16) != Z_OK) abort();
    s.next_in = (Bytef*)z;
    s.avail_in = (uInt)zn;
    uint8_t buf[16384];
    int r;
    do {
        s.next_out = buf;
        s.avail_out = sizeof buf;
        r = inflate(&s, Z_NO_FLUSH);
        __h3p_put(out, buf, sizeof buf - s.avail_out);
    } while (r == Z_OK && (s.avail_in > 0 || s.avail_out == 0));
    inflateEnd(&s);
    return r == Z_STREAM_END && s.avail_in == 0;
}

typedef struct {
    quicconn_t* qc;
    connection_server_ctx_t ctx;
    h3conn_t* c;
    quicstream_t* qs;
} h3p_stand_t;

static void __h3p_request(h3p_stand_t* s, int method, int gzip, int conditional) {
    static const char* methods[] = { "GET", "HEAD", "POST", "GET" };
    qpack_header_t fields[6] = {
        { (char*)":method", 7, (char*)methods[method], strlen(methods[method]), 0 },
        { (char*)":path", 5, (char*)"/", 1, 0 },
        { (char*)":scheme", 7, (char*)"https", 5, 0 },
        { (char*)":authority", 10, (char*)"localhost", 9, 0 },
    };
    size_t n = 4;
    if (gzip) fields[n++] = (qpack_header_t){ (char*)"accept-encoding", 15, (char*)"gzip, br", 8, 0 };
    if (conditional) fields[n++] = (qpack_header_t){ (char*)"if-none-match", 13, (char*)"\"v1\"", 4, 0 };

    uint8_t block[512], frame[600];
    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    if (enc == NULL) abort();
    const size_t blen = qpack_encode_block(enc, fields, n, block, sizeof block);
    qpack_encoder_free(enc);
    const size_t flen = h3frame_write(frame, sizeof frame, H3_FRAME_HEADERS, block, blen);
    if (blen == 0 || flen == 0) abort();
    quicstream_on_data(s->qs, 0, frame, flen, 1);
    h3conn_stream_read(s->c, NULL, s->qs);
}

/* What the network takes from the stream in one turn, then acknowledges. */
static void __h3p_drain(quicstream_t* qs, size_t quota, size_t mtu, h3p_buf_t* wire, int* fin) {
    while (quota > 0) {
        uint64_t off = 0;
        const uint8_t* p = NULL;
        size_t n = 0;
        int f = 0;
        if (!quicsendbuf_next(&qs->send, mtu < quota ? mtu : quota, &off, &p, &n, &f)) break;
        if (off != wire->len) __builtin_trap();        /* nothing lost, so in order */
        if (*fin && n > 0) __builtin_trap();            /* bytes after FIN */
        __h3p_put(wire, p, n);
        if (f) *fin = 1;
        quicsendbuf_mark_sent(&qs->send, off, n, f);
        quicsendbuf_ack(&qs->send, off, n, f);
        quota = quota > n ? quota - n : 0;
        if (n == 0 && !f) break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 5) return 0;
    const uint8_t flags = data[0], status_sel = data[1], net = data[2];
    /* Up to 256 KiB: past the connection's write-ahead budget, so a response
     * takes several turns, and no further, so a run stays fast. */
    const size_t body_len = ((size_t)data[3] << 8 | data[4]) * ((flags & 0x80) ? 17 : 1) % (1u << 18);
    data += 5; size -= 5;

    h3p_field_t fields[H3P_FIELDS], trailers[H3P_FIELDS];
    const size_t nfields = __h3p_fields(&data, &size, fields, H3P_FIELDS);
    const size_t ntrailers = (flags & 8) ? __h3p_fields(&data, &size, trailers, H3P_FIELDS) : 0;

    static const int statuses[8] = { 200, 200, 201, 404, 500, 299, 204, 410 };
    const int method = flags & 3;
    const int accept_gzip = (flags >> 2) & 1;
    const int conditional = (flags >> 4) & 1;   /* handler sets ETag "v1", request If-None-Match */
    const int status = statuses[status_sel % 8];

    char* body = malloc(body_len ? body_len : 1);
    if (body == NULL) abort();
    for (size_t i = 0; i < body_len; i++)
        body[i] = size ? (char)data[i % size] : (char)('a' + i % 26);

    __fuzz_appconfig_init();
    static env_gzip_str_t html = { (char*)"text/html; charset=utf-8", NULL };
    env()->main.gzip = &html;

    const size_t budget_before = quicmemory_current();

    h3p_stand_t s;
    s.qc = calloc(1, sizeof *s.qc);
    s.c = h3conn_create(NULL, 65536, 0);
    if (s.qc == NULL || s.c == NULL) abort();
    memset(&s.ctx, 0, sizeof s.ctx);
    s.ctx.parser = s.c;
    s.qc->conn.transport = CONN_TRANSPORT_QUIC;
    s.qc->conn.ctx = &s.ctx;
    s.qs = quicstream_create(0, H3P_WINDOW, H3P_WINDOW, H3P_WINDOW);
    if (s.qs == NULL) abort();
    s.qc->streams = s.qs;
    s.qc->stream_count = 1;
    __h3p_request(&s, method, accept_gzip, conditional);

    h3stream_t* st = h3conn_request_of(s.qs);
    if (st == NULL || st->request == NULL) __builtin_trap();   /* a valid request */

    /* The handler. */
    httpresponse_t* r = httpresponse_create_h3(&s.qc->conn);
    if (r == NULL) abort();
    if (accept_gzip) httpresponse_set_accept_encoding(r, "gzip, br", 8);
    if (!h3_server_attach_response(&s.qc->conn, st->request, r)) __builtin_trap();
    r->status_code = status;
    for (size_t i = 0; i < nfields; i++)
        r->add_headern(r, fields[i].name, fields[i].name_len, fields[i].value, fields[i].value_len);
    if (conditional) r->add_header(r, "ETag", "\"v1\"");
    r->send_datan(r, body, body_len);
    for (size_t i = 0; i < ntrailers; i++)
        r->add_trailern(r, trailers[i].name, trailers[i].name_len, trailers[i].value, trailers[i].value_len);
    h3_server_publish_inline(&s.qc->conn, r);

    /* Write turns, the network in between. */
    static const size_t quotas[4] = { SIZE_MAX, 16384, 65536, 1200 };
    const size_t quota = quotas[net % 4];
    const size_t mtu = 1 + (size_t)(net >> 2) * 37;
    h3p_buf_t wire = { 0 };
    int fin = 0;
    int turns = 0;
    while (!st->response_done && turns++ < H3P_TURNS) {
        if (!h3conn_write(s.c, s.qc)) __builtin_trap();
        __h3p_drain(s.qs, quota, mtu, &wire, &fin);
    }
    while (!fin && turns++ < H3P_TURNS) __h3p_drain(s.qs, SIZE_MAX, mtu, &wire, &fin);
    if (!st->response_done || !fin || !s.qs->send.fin) __builtin_trap();
    if (h3conn_write(s.c, s.qc) != 1) __builtin_trap();
    __h3p_drain(s.qs, SIZE_MAX, mtu, &wire, &fin);     /* nothing after FIN */

    /* The client. */
    qpack_decoder_t* dec = qpack_decoder_create(0, 0);
    if (dec == NULL) abort();
    qpack_header_t* head = NULL, * tail = NULL;
    size_t nhead = 0, ntail = 0;
    h3p_buf_t payload = { 0 };
    int sections = 0, data_after_trailers = 0;
    for (size_t off = 0; off < wire.len;) {
        uint64_t type = 0, len = 0;
        size_t a = varint_read(wire.bytes + off, wire.len - off, &type);
        if (a == 0) __builtin_trap();
        size_t b = varint_read(wire.bytes + off + a, wire.len - off - a, &len);
        if (b == 0 || len > wire.len - off - a - b) __builtin_trap();
        const uint8_t* p = wire.bytes + off + a + b;
        off += a + b + (size_t)len;
        if (type == H3_FRAME_HEADERS) {
            if (sections == 2) __builtin_trap();
            qpack_header_t** out = sections == 0 ? &head : &tail;
            size_t* count = sections == 0 ? &nhead : &ntail;
            if (qpack_decode_block(dec, p, (size_t)len, 1u << 20, out, count) != QPACK_OK) __builtin_trap();
            sections++;
        } else if (type == H3_FRAME_DATA) {
            if (sections != 1) data_after_trailers = 1;
            __h3p_put(&payload, p, (size_t)len);
        } else __builtin_trap();                         /* the server sends no other frame here */
    }
    if (sections == 0 || data_after_trailers) __builtin_trap();

    __h3p_check_section(head, nhead, 0);
    if (nhead == 0 || !__h3p_ieq(head[0].name, head[0].name_len, ":status", 7)) __builtin_trap();
    char status_text[8];
    const int not_modified = head[0].value_len == 3 && memcmp(head[0].value, "304", 3) == 0;
    snprintf(status_text, sizeof status_text, "%d", status);
    if (!not_modified && !__h3p_ieq(head[0].value, head[0].value_len, status_text, strlen(status_text))) __builtin_trap();
    if (not_modified && !conditional) __builtin_trap();
    if (conditional && method != 2 && status == 200 && !not_modified) __builtin_trap();
    __h3p_expect_fields(head, nhead, fields, nfields);

    const qpack_header_t* cl = __h3p_find(head, nhead, "content-length");
    if (cl != NULL) {
        char want[24];
        snprintf(want, sizeof want, "%zu", payload.len);
        if (method != 1 && !not_modified && !__h3p_ieq(cl->value, cl->value_len, want, strlen(want))) __builtin_trap();
    }
    const qpack_header_t* ce = __h3p_find(head, nhead, "content-encoding");
    const int gzipped = ce != NULL && __h3p_ieq(ce->value, ce->value_len, "gzip", 4);
    if (gzipped && !accept_gzip) __builtin_trap();
    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "method %d status %.*s gzip %d payload %zu body %zu sections %d turns %d\n",
                method, (int)head[0].value_len, head[0].value, gzipped, payload.len, body_len,
                sections, turns);

    /* RFC 9110 §15.3.5: a 204 ends with its header section, like a 304. */
    if (method == 1 || not_modified || status == 204) {
        if (payload.len != 0) __builtin_trap();
    } else if (gzipped) {
        h3p_buf_t plain = { 0 };
        if (!__h3p_inflate(payload.bytes, payload.len, &plain)) __builtin_trap();
        if (plain.len != body_len || (body_len && memcmp(plain.bytes, body, body_len) != 0)) __builtin_trap();
        free(plain.bytes);
    } else if (payload.len != body_len || (body_len && memcmp(payload.bytes, body, body_len) != 0)) {
        __builtin_trap();
    }

    /* Trailers: what the handler added, minus pseudo-fields, content-length and
     * connection-specific ones. */
    size_t kept = 0;
    for (size_t i = 0; i < ntrailers; i++)
        if (!__h3p_connection_specific(trailers[i].name, trailers[i].name_len) &&
            !__h3p_ieq(trailers[i].name, trailers[i].name_len, "content-length", 14) &&
            __h3p_value_kept(&trailers[i]))
            kept++;
    if (sections == 2) {
        __h3p_check_section(tail, ntail, 1);
        if (ntail != kept) __builtin_trap();
        __h3p_expect_fields(tail, ntail, trailers, ntrailers);
    } else if (kept != 0 && method != 1 && !not_modified) {
        __builtin_trap();
    }

    qpack_headers_free(head, nhead);
    qpack_headers_free(tail, ntail);
    qpack_decoder_free(dec);
    free(payload.bytes);
    free(wire.bytes);

    h3conn_stream_release(s.qs);
    quicstream_free(s.qs);
    h3conn_free(s.c);
    free(s.qc);
    free(body);

    if (quicmemory_current() != budget_before) __builtin_trap();   /* budget leaked */
    return 0;
}

#elif FUZZ_TARGET == FUZZ_VIEW

#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <sys/stat.h>
#include "storagefs.h"
#include "view.h"
#include "viewparser.h"
#include "viewstore.h"

/* The template engine (framework/view): viewparser turns a template file into
 * a tag tree, viewexpr parses and evaluates the expressions in it, render()
 * walks the tree against a JSON document. Templates are the developer's, but
 * the document is built from whatever a request brought, so what matters most
 * is that a value is only ever data.
 *
 * The first byte picks the mode:
 *   raw -- any bytes as the template, against a document of strings, numbers,
 *     booleans, arrays and an object from the input. Parsing twice gives the
 *     same tree; rendering from a fresh store and again from the cache gives
 *     the same bytes; a template the parser refuses renders to NULL; nothing
 *     crashes or leaks.
 *   generated -- a template assembled from text, {{ expressions }}, if /
 *     elseif / else and for loops over arrays and objects, with the output it
 *     must render to computed here: RFC-free, just the engine's own rules --
 *     null propagates through arithmetic, strings compare with strcmp, a
 *     number prints as an integer, truthiness as viewexpr_value_istrue says.
 *     Values carry "{{", "{%", "}}" and any other byte but NUL, and must come
 *     out as themselves.
 *
 * The templates live in a directory made once; a fresh viewstore per input
 * keeps the cache from carrying one input's tree into the next. */

#define VW_STORAGE "fuzz_view"
#define VW_VALUES 4
#define VW_ITEMS 4

static char __vw_root[64];
static storagefs_t* __vw_fs;

static int __vw_init(void) {
    if (__vw_fs != NULL) return 1;
    snprintf(__vw_root, sizeof __vw_root, "/tmp/cwfr_fuzz_view_XXXXXX");
    if (mkdtemp(__vw_root) == NULL) return 0;
    __vw_fs = storage_create_fs(VW_STORAGE, __vw_root);
    if (__vw_fs == NULL) return 0;
    char path[128];
    snprintf(path, sizeof path, "%s/inc.html", __vw_root);
    FILE* f = fopen(path, "w");
    if (f == NULL) return 0;
    fputs("<{{ s0 }}>", f);
    fclose(f);
    appconfig()->storages = (storage_t*)__vw_fs;
    return 1;
}

static void __vw_write(const char* name, const char* data, size_t size) {
    char path[128];
    snprintf(path, sizeof path, "%s/%s", __vw_root, name);
    const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) abort();
    for (size_t off = 0; off < size;) {
        const ssize_t n = write(fd, data + off, size - off);
        if (n <= 0) abort();
        off += (size_t)n;
    }
    close(fd);
}

/* ---- the input, read a byte at a time ---- */

typedef struct {
    const uint8_t* p;
    size_t n;
} vw_in_t;

static uint8_t __vw_byte(vw_in_t* in) {
    if (in->n == 0) return 0;
    in->n--;
    return *in->p++;
}

/* ---- the document ---- */

typedef struct {
    char* s[VW_VALUES];                 /* strings: any byte but NUL */
    long long n[VW_VALUES];
    int b[2];
    char* a[2][VW_ITEMS];               /* arrays of strings */
    size_t a_len[2];
    char* keys[VW_ITEMS];               /* the object o0: keys to strings */
    char* vals[VW_ITEMS];
    size_t o_len;
    json_doc_t* doc;
} vw_doc_t;

static char* __vw_string(vw_in_t* in, size_t max) {
    size_t len = __vw_byte(in) % (max + 1);
    char* s = malloc(len + 1);
    if (s == NULL) abort();
    for (size_t i = 0; i < len; i++) {
        const uint8_t c = __vw_byte(in);
        s[i] = (char)(c ? c : '{');
    }
    s[len] = 0;
    return s;
}

static void __vw_doc_build(vw_doc_t* d, vw_in_t* in) {
    memset(d, 0, sizeof *d);
    d->doc = json_root_create_object();
    if (d->doc == NULL) abort();
    json_token_t* root = json_root(d->doc);
    char name[8];
    for (int i = 0; i < VW_VALUES; i++) {
        d->s[i] = __vw_string(in, 40);
        snprintf(name, sizeof name, "s%d", i);
        json_object_set(root, name, json_create_string(d->s[i]));
        d->n[i] = (long long)(int8_t)__vw_byte(in) * (1 + __vw_byte(in) % 3);
        snprintf(name, sizeof name, "n%d", i);
        json_object_set(root, name, json_create_number((long double)d->n[i]));
    }
    for (int i = 0; i < 2; i++) {
        d->b[i] = __vw_byte(in) & 1;
        snprintf(name, sizeof name, "b%d", i);
        json_object_set(root, name, json_create_bool(d->b[i]));
        json_token_t* arr = json_create_array();
        d->a_len[i] = __vw_byte(in) % (VW_ITEMS + 1);
        for (size_t j = 0; j < d->a_len[i]; j++) {
            d->a[i][j] = __vw_string(in, 12);
            json_array_append(arr, json_create_string(d->a[i][j]));
        }
        snprintf(name, sizeof name, "a%d", i);
        json_object_set(root, name, arr);
    }
    json_token_t* obj = json_create_object();
    const size_t want = __vw_byte(in) % (VW_ITEMS + 1);
    for (size_t j = 0; j < want; j++) {
        char* key = __vw_string(in, 100);
        int dup = 0;
        for (size_t k = 0; k < d->o_len; k++) dup |= strcmp(d->keys[k], key) == 0;
        if (dup) { free(key); continue; }
        d->keys[d->o_len] = key;
        d->vals[d->o_len] = __vw_string(in, 12);
        json_object_set(obj, key, json_create_string(d->vals[d->o_len]));
        d->o_len++;
    }
    json_object_set(root, "o0", obj);
}

static void __vw_doc_free(vw_doc_t* d) {
    for (int i = 0; i < VW_VALUES; i++) free(d->s[i]);
    for (int i = 0; i < 2; i++)
        for (size_t j = 0; j < d->a_len[i]; j++) free(d->a[i][j]);
    for (size_t j = 0; j < d->o_len; j++) { free(d->keys[j]); free(d->vals[j]); }
    json_free(d->doc);
}

/* ---- growable text ---- */

typedef struct {
    char* p;
    size_t len, cap;
} vw_text_t;

static void __vw_put(vw_text_t* t, const char* s, size_t n) {
    if (t->len + n + 1 > t->cap) {
        size_t cap = t->cap ? t->cap : 256;
        while (cap < t->len + n + 1) cap *= 2;
        char* grown = realloc(t->p, cap);
        if (grown == NULL) abort();
        t->p = grown;
        t->cap = cap;
    }
    memcpy(t->p + t->len, s, n);
    t->len += n;
    t->p[t->len] = 0;
}

static void __vw_puts(vw_text_t* t, const char* s) {
    __vw_put(t, s, strlen(s));
}

/* ---- the model's values ---- */

typedef enum { VW_NULL, VW_BOOL, VW_NUM, VW_STR, VW_ARR } vw_type_e;

typedef struct {
    vw_type_e type;
    int b;
    long long n;         /* numbers stay integral and small */
    const char* s;
    size_t arr_len;
} vw_val_t;

static int __vw_true(vw_val_t v) {
    switch (v.type) {
    case VW_BOOL: return v.b;
    case VW_NUM: return v.n != 0;
    case VW_STR: return v.s[0] != 0;
    case VW_ARR: return v.arr_len > 0;
    default: return 0;
    }
}

static void __vw_render_val(vw_text_t* out, vw_val_t v) {
    char buf[32];
    switch (v.type) {
    case VW_STR: __vw_puts(out, v.s); break;
    case VW_NUM: snprintf(buf, sizeof buf, "%lld", v.n); __vw_puts(out, buf); break;
    case VW_BOOL: __vw_puts(out, v.b ? "true" : "false"); break;
    default: break;
    }
}

/* Loop variables in scope, innermost last. */
typedef struct {
    char elem[8], key[8];
    int with_key;        /* without one the default key name is not ours to guess */
    const char* elem_value;
    int key_is_index;
    long long index;
    const char* key_value;
} vw_frame_t;

typedef struct {
    vw_in_t* in;
    vw_doc_t* doc;
    vw_frame_t frames[4];
    int depth;
    int budget;          /* tags left, so templates stay small */
    vw_text_t tpl;
} vw_gen_t;

/* Precedence, lowest first: || && == != < <= > >= + - * / % unary. */
enum { P_OR = 1, P_AND, P_EQ, P_REL, P_ADD, P_MUL, P_UNARY, P_ATOM };

typedef struct {
    vw_text_t text;
    int prec;
    vw_val_t v;
} vw_expr_t;

static void __vw_expr_free(vw_expr_t* e) {
    free(e->text.p);
}

static void __vw_wrap(vw_expr_t* e, int need, int force) {
    if (e->prec >= need && !force) return;
    vw_text_t t = { 0 };
    __vw_puts(&t, "(");
    __vw_put(&t, e->text.p, e->text.len);
    __vw_puts(&t, ")");
    free(e->text.p);
    e->text = t;
    e->prec = P_ATOM;
}

static const char* __vw_space(vw_in_t* in) {
    static const char* spaces[4] = { "", " ", "  ", "\t" };
    return spaces[__vw_byte(in) % 4];
}

static vw_expr_t __vw_leaf(vw_gen_t* g) {
    vw_expr_t e = { { 0 }, P_ATOM, { VW_NULL, 0, 0, NULL, 0 } };
    char buf[48];
    const uint8_t pick = __vw_byte(g->in);
    switch (pick % 10) {
    case 0: case 1: {
        const long long n = __vw_byte(g->in) % 100;
        snprintf(buf, sizeof buf, "%lld", n);
        __vw_puts(&e.text, buf);
        e.v = (vw_val_t){ VW_NUM, 0, n, NULL, 0 };
        break;
    }
    case 2: {
        const int i = __vw_byte(g->in) % VW_VALUES;
        snprintf(buf, sizeof buf, "s%d", i);
        __vw_puts(&e.text, buf);
        e.v = (vw_val_t){ VW_STR, 0, 0, g->doc->s[i], 0 };
        break;
    }
    case 3: {
        const int i = __vw_byte(g->in) % VW_VALUES;
        snprintf(buf, sizeof buf, "n%d", i);
        __vw_puts(&e.text, buf);
        e.v = (vw_val_t){ VW_NUM, 0, g->doc->n[i], NULL, 0 };
        break;
    }
    case 4: {
        const int i = __vw_byte(g->in) % 2;
        snprintf(buf, sizeof buf, "b%d", i);
        __vw_puts(&e.text, buf);
        e.v = (vw_val_t){ VW_BOOL, g->doc->b[i], 0, NULL, 0 };
        break;
    }
    case 5: {
        /* A string literal: quotes, braces and escapes inside it are text. */
        static const char* lits[][2] = {
            { "'abc'", "abc" }, { "\"x}}y\"", "x}}y" }, { "'{% z %}'", "{% z %}" },
            { "'it\\'s'", "it's" }, { "''", "" }, { "\"a\\\\b\"", "a\\b" },
        };
        const int i = __vw_byte(g->in) % 6;
        __vw_puts(&e.text, lits[i][0]);
        e.v = (vw_val_t){ VW_STR, 0, 0, lits[i][1], 0 };
        break;
    }
    case 6: {
        static const char* kw[3] = { "true", "false", "null" };
        const int i = __vw_byte(g->in) % 3;
        __vw_puts(&e.text, kw[i]);
        e.v = i == 2 ? (vw_val_t){ VW_NULL, 0, 0, NULL, 0 } : (vw_val_t){ VW_BOOL, i == 0, 0, NULL, 0 };
        break;
    }
    case 7: {
        /* An element of an array, in range or not. */
        const int i = __vw_byte(g->in) % 2;
        const size_t k = __vw_byte(g->in) % (VW_ITEMS + 1);
        snprintf(buf, sizeof buf, "a%d[%zu]", i, k);
        __vw_puts(&e.text, buf);
        if (k < g->doc->a_len[i]) e.v = (vw_val_t){ VW_STR, 0, 0, g->doc->a[i][k], 0 };
        break;
    }
    case 8:
        if (g->depth > 0) {
            const vw_frame_t* f = &g->frames[__vw_byte(g->in) % g->depth];
            if ((__vw_byte(g->in) & 1) || !f->with_key) {
                __vw_puts(&e.text, f->elem);
                e.v = (vw_val_t){ VW_STR, 0, 0, f->elem_value, 0 };
            } else {
                __vw_puts(&e.text, f->key);
                e.v = f->key_is_index ? (vw_val_t){ VW_NUM, 0, f->index, NULL, 0 }
                                      : (vw_val_t){ VW_STR, 0, 0, f->key_value, 0 };
            }
            break;
        }
        /* fall through */
    default:
        __vw_puts(&e.text, (__vw_byte(g->in) & 1) ? "missing" : "o0.nothing");
        break;
    }
    return e;
}

/* Arithmetic stays integral and within ±2^40, where long double and long long
 * agree exactly: a result that would leave that range is not generated. */
#define VW_LIMIT (1LL << 40)

static vw_expr_t __vw_expr(vw_gen_t* g, int depth) {
    const uint8_t pick = __vw_byte(g->in);
    if (depth <= 0 || pick % 3 == 0) return __vw_leaf(g);

    if (pick % 7 == 1) {
        vw_expr_t a = __vw_expr(g, depth - 1);
        const int neg = __vw_byte(g->in) & 1;
        __vw_wrap(&a, P_UNARY, 0);
        vw_text_t t = { 0 };
        __vw_puts(&t, neg ? "-" : "!");
        __vw_put(&t, a.text.p, a.text.len);
        free(a.text.p);
        a.text = t;
        a.prec = P_UNARY;
        if (!neg) a.v = (vw_val_t){ VW_BOOL, !__vw_true(a.v), 0, NULL, 0 };
        else if (a.v.type == VW_NUM) a.v.n = -a.v.n;
        else a.v = (vw_val_t){ VW_NULL, 0, 0, NULL, 0 };
        return a;
    }

    static const struct { const char* op; int prec; } ops[] = {
        { "||", P_OR }, { "&&", P_AND }, { "==", P_EQ }, { "!=", P_EQ },
        { "<", P_REL }, { "<=", P_REL }, { ">", P_REL }, { ">=", P_REL },
        { "+", P_ADD }, { "-", P_ADD }, { "*", P_MUL }, { "/", P_MUL }, { "%", P_MUL },
    };
    const int k = __vw_byte(g->in) % 13;
    vw_expr_t a = __vw_expr(g, depth - 1);
    vw_expr_t b = __vw_expr(g, depth - 1);
    const int prec = ops[k].prec;
    /* Left-associative: the right operand needs strictly higher precedence.
     * Now and then parentheses that change nothing. */
    const int extra = __vw_byte(g->in);
    __vw_wrap(&a, prec, (extra & 3) == 0);
    __vw_wrap(&b, prec + 1, (extra & 12) == 0);

    vw_val_t r = { VW_NULL, 0, 0, NULL, 0 };
    const vw_val_t x = a.v, y = b.v;
    const int nums = x.type == VW_NUM && y.type == VW_NUM;
    const int strs = x.type == VW_STR && y.type == VW_STR;
    switch (k) {
    case 0: r = (vw_val_t){ VW_BOOL, __vw_true(x) || __vw_true(y), 0, NULL, 0 }; break;
    case 1: r = (vw_val_t){ VW_BOOL, __vw_true(x) && __vw_true(y), 0, NULL, 0 }; break;
    case 2: case 3: {
        int eq = x.type == y.type;
        if (eq && x.type == VW_BOOL) eq = x.b == y.b;
        if (eq && x.type == VW_NUM) eq = x.n == y.n;
        if (eq && x.type == VW_STR) eq = strcmp(x.s, y.s) == 0;
        if (eq && x.type == VW_ARR) eq = 0;      /* never generated as operands */
        r = (vw_val_t){ VW_BOOL, k == 2 ? eq : !eq, 0, NULL, 0 };
        break;
    }
    case 4: case 5: case 6: case 7: {
        int less = 0, equal = 0;
        if (nums) { less = x.n < y.n; equal = x.n == y.n; }
        else if (strs) { const int c = strcmp(x.s, y.s); less = c < 0; equal = c == 0; }
        const int res = !(nums || strs) ? 0 : k == 4 ? less : k == 5 ? less || equal
                      : k == 6 ? !less && !equal : !less;
        r = (vw_val_t){ VW_BOOL, res, 0, NULL, 0 };
        break;
    }
    default: {
        if (!nums) break;
        long long v = 0;
        int ok = 1;
        switch (k) {
        case 8: v = x.n + y.n; break;
        case 9: v = x.n - y.n; break;
        case 10: ok = x.n == 0 || llabs(y.n) <= VW_LIMIT / llabs(x.n); v = ok ? x.n * y.n : 0; break;
        case 11:
            if (y.n == 0) { ok = 2; break; }           /* null */
            ok = x.n % y.n == 0;                        /* whole quotients only */
            v = ok ? x.n / y.n : 0;
            break;
        default:
            if (y.n == 0) { ok = 2; break; }
            v = x.n % y.n;                              /* fmodl on integers: C's remainder */
            break;
        }
        if (ok == 1 && llabs(v) <= VW_LIMIT) r = (vw_val_t){ VW_NUM, 0, v, NULL, 0 };
        else if (ok == 0 || ok == 1) {
            /* Not generated: fall back to the left operand alone. */
            __vw_expr_free(&b);
            return a;
        }
        break;
    }
    }

    vw_expr_t e = { { 0 }, prec, r };
    __vw_put(&e.text, a.text.p, a.text.len);
    __vw_puts(&e.text, " ");
    __vw_puts(&e.text, ops[k].op);
    __vw_puts(&e.text, " ");
    __vw_put(&e.text, b.text.p, b.text.len);
    __vw_expr_free(&a);
    __vw_expr_free(&b);
    return e;
}

static void __vw_block(vw_gen_t* g, vw_text_t* out, int live);

static void __vw_item(vw_gen_t* g, vw_text_t* out, int live) {
    const uint8_t pick = __vw_byte(g->in);
    if (g->budget <= 0) return;
    switch (pick % 6) {
    case 0: case 1: {
        /* Text: no '{' before '{', '%' or '*' -- that would open a tag. */
        static const char alphabet[] = "abcXYZ 019.,;:<>/-_\n}%*#'\"";
        const size_t n = 1 + __vw_byte(g->in) % 12;
        char buf[16];
        for (size_t i = 0; i < n; i++) buf[i] = alphabet[__vw_byte(g->in) % (sizeof alphabet - 1)];
        __vw_put(&g->tpl, buf, n);
        if (live) __vw_put(out, buf, n);
        break;
    }
    case 2: case 3: {
        g->budget--;
        vw_expr_t e = __vw_expr(g, 3);
        __vw_puts(&g->tpl, "{{");
        __vw_puts(&g->tpl, __vw_space(g->in));
        __vw_put(&g->tpl, e.text.p, e.text.len);
        __vw_puts(&g->tpl, __vw_space(g->in));
        __vw_puts(&g->tpl, "}}");
        if (live) __vw_render_val(out, e.v);
        __vw_expr_free(&e);
        break;
    }
    case 4: {
        g->budget--;
        /* if [elseif]* [else] endif: the first true branch renders. */
        int taken = 0;
        const int branches = 1 + __vw_byte(g->in) % 3;
        const int has_else = __vw_byte(g->in) & 1;
        for (int i = 0; i < branches; i++) {
            vw_expr_t c = __vw_expr(g, 2);
            __vw_puts(&g->tpl, i == 0 ? "{% if " : "{% elseif ");
            __vw_put(&g->tpl, c.text.p, c.text.len);
            __vw_puts(&g->tpl, " %}");
            const int now = !taken && __vw_true(c.v);
            __vw_expr_free(&c);
            __vw_block(g, out, live && now);
            taken |= now;
        }
        if (has_else) {
            __vw_puts(&g->tpl, "{% else %}");
            __vw_block(g, out, live && !taken);
        }
        __vw_puts(&g->tpl, "{% endif %}");
        break;
    }
    default: {
        if (g->depth >= 4) break;
        g->budget--;
        vw_frame_t* f = &g->frames[g->depth];
        snprintf(f->elem, sizeof f->elem, "e%d", g->depth);
        snprintf(f->key, sizeof f->key, "k%d", g->depth);
        const int which = __vw_byte(g->in) % 3;     /* a0, a1, o0 */
        const int with_key = __vw_byte(g->in) & 1;
        char head[64];
        if (with_key) snprintf(head, sizeof head, "{%% for %s, %s in %s %%}", f->elem, f->key,
                               which == 2 ? "o0" : which ? "a1" : "a0");
        else snprintf(head, sizeof head, "{%% for %s in %s %%}", f->elem,
                      which == 2 ? "o0" : which ? "a1" : "a0");
        __vw_puts(&g->tpl, head);
        /* The body is generated once and rendered once per element: remember
         * where the input and the template were, and replay. */
        const size_t count = which == 2 ? g->doc->o_len : g->doc->a_len[which];
        const vw_in_t saved_in = *g->in;
        const size_t tpl_mark = g->tpl.len;
        const int saved_budget = g->budget;
        g->depth++;
        for (size_t i = 0; i < (count ? count : 1); i++) {
            *g->in = saved_in;
            g->tpl.len = tpl_mark;
            g->budget = saved_budget;
            f->key_is_index = which != 2;
            f->index = (long long)i;
            if (count) {
                f->elem_value = which == 2 ? g->doc->vals[i] : g->doc->a[which][i];
                f->key_value = which == 2 ? g->doc->keys[i] : NULL;
            } else {
                f->elem_value = "";
                f->key_value = "";
            }
            f->with_key = with_key;
            __vw_block(g, out, live && count > 0);
        }
        g->depth--;
        __vw_puts(&g->tpl, "{% endfor %}");
        break;
    }
    }
}

static void __vw_block(vw_gen_t* g, vw_text_t* out, int live) {
    const int n = __vw_byte(g->in) % 4;
    for (int i = 0; i < n; i++) __vw_item(g, out, live);
}

/* ---- tree comparison ---- */

static int __vw_same_tree(const view_tag_t* a, const view_tag_t* b) {
    for (; a != NULL || b != NULL; a = a->next, b = b->next) {
        if (a == NULL || b == NULL) return 0;
        if (a->type != b->type || a->parent_text_offset != b->parent_text_offset ||
            a->parent_text_size != b->parent_text_size) return 0;
        const size_t an = bufferdata_writed((bufferdata_t*)&a->result_content);
        const size_t bn = bufferdata_writed((bufferdata_t*)&b->result_content);
        if (an != bn) return 0;
        if (an && memcmp(bufferdata_get((bufferdata_t*)&a->result_content),
                         bufferdata_get((bufferdata_t*)&b->result_content), an) != 0) return 0;
        if ((a->expr == NULL) != (b->expr == NULL)) return 0;
        if (!__vw_same_tree(a->child, b->child)) return 0;
    }
    return 1;
}

static view_tag_t* __vw_parse(const char* name, int* ok) {
    viewparser_t* p = viewparser_init(VW_STORAGE, name);
    if (p == NULL) abort();
    *ok = viewparser_run(p);
    view_tag_t* root = *ok ? viewparser_move_root_tag(p) : NULL;
    viewparser_free(p);
    return root;
}

static char* __vw_render(json_doc_t* doc, const char* name) {
    viewstore_t* store = viewstore_create();
    if (store == NULL) abort();
    appconfig()->viewstore = store;
    char* first = render(doc, VW_STORAGE, "/%s", name);
    char* cached = render(doc, VW_STORAGE, "/%s", name);
    if ((first == NULL) != (cached == NULL) || (first && strcmp(first, cached) != 0)) __builtin_trap();
    free(cached);
    appconfig()->viewstore = NULL;
    viewstore_destroy(store);
    return first;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    if (!__vw_init()) abort();
    const uint8_t mode = data[0];
    const size_t split = data[1];
    data += 2; size -= 2;

    if (mode & 1) {
        /* raw: the template first, then the document's bytes */
        const size_t tlen = size < split * 8 ? size : split * 8;
        vw_in_t din = { data + tlen, size - tlen };
        vw_doc_t doc;
        __vw_doc_build(&doc, &din);
        __vw_write("t.html", (const char*)data, tlen);

        int ok1 = 0, ok2 = 0;
        view_tag_t* t1 = __vw_parse("/t.html", &ok1);
        view_tag_t* t2 = __vw_parse("/t.html", &ok2);
        if (ok1 != ok2 || (ok1 && !__vw_same_tree(t1, t2))) __builtin_trap();
        if (t1) t1->free(t1);
        if (t2) t2->free(t2);

        char* a = __vw_render(doc.doc, "t.html");
        char* b = __vw_render(doc.doc, "t.html");
        if ((a == NULL) != (b == NULL) || (a && strcmp(a, b) != 0)) __builtin_trap();
        if ((a != NULL) != ok1) __builtin_trap();     /* refused exactly when the parser refuses */
        free(a);
        free(b);
        __vw_doc_free(&doc);
        return 0;
    }

    /* generated: the document from the first bytes, the template from the rest */
    vw_in_t in = { data, size };
    vw_doc_t doc;
    __vw_doc_build(&doc, &in);
    vw_gen_t g = { &in, &doc, { { { 0 } } }, 0, 24, { 0 } };
    vw_text_t want = { 0 };
    __vw_puts(&want, "");
    __vw_puts(&g.tpl, "");
    const int items = 1 + __vw_byte(&in) % 6;
    for (int i = 0; i < items; i++) __vw_item(&g, &want, 1);
    __vw_write("g.html", g.tpl.p, g.tpl.len);

    char* got = __vw_render(doc.doc, "g.html");
    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "template [%s]\nwant [%s]\ngot  [%s]\n", g.tpl.p, want.p, got ? got : "(null)");
    if (got == NULL || strcmp(got, want.p) != 0) __builtin_trap();
    free(got);

    free(want.p);
    free(g.tpl.p);
    __vw_doc_free(&doc);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_WS_CONNECTION

#include <sys/socket.h>
#include "broadcast.h"
#include "httpserverhandlers.h"
#include "ratelimiter.h"
#include "route.h"
#include "websocketsbroadcast.h"
#include "websocketsprotocolresource.h"
#include "websocketsswitch.h"
#include "wscontext.h"

/* WebSocket after the handshake: two HTTP/1.1 connections upgrade on /ws, one
 * of them or both with the "resource" subprotocol, and then every frame the
 * client sends goes through the server's real path -- websockets_guard_read,
 * the parser, get_resource and the routes, websockets_deferred_handler and a
 * worker, the output order, websockets_guard_write -- on sockets with small
 * buffers, with reads, writes, workers and the clients interleaved as the input
 * says. websocket_sequence stops at the parser and h1_connection at the 101;
 * this is what comes after both.
 *
 * The handlers are an application's: the default protocol echoes, and the
 * resource protocol has GET /echo?q=, POST /echo, GET /sub and /unsub on a
 * broadcast channel, POST /pub to it, and GET /item/{id|[0-9]+}. One rate
 * limiter with a frozen clock is shared by both connections (same address),
 * or there is none.
 *
 * What each client must read after its 101, frame by frame:
 *   - for every message, in the order its last frame was sent: exactly one
 *     reply -- the handler's, "Too Many Requests" for a routed message the
 *     limiter refused, "resource not found" for one no route takes; a PONG
 *     with the PING's payload; nothing for a PONG; the CLOSE echoed, and
 *     after it nothing at all;
 *   - broadcast frames ("B:" + payload) between them, anywhere: exactly the
 *     payloads the other connection published while this one was subscribed,
 *     in publish order, as the handlers' own log records it;
 *   - and across both, as many refusals as routed messages beyond the
 *     limiter's burst -- never fewer, never more.
 * Messages are cut into frames anywhere, pings between the fragments, and
 * the bytes reach the socket in pieces of any size. Everything is freed at the
 * end, so a leak is LeakSanitizer's. */

#define WSC_CONNS 2
#define WSC_EXPECT 128
#define WSC_LOG 256

typedef enum { WSC_REPLY, WSC_PONG, WSC_CLOSE } wsc_kind_e;

typedef struct {
    wsc_kind_e kind;
    int routed;          /* a refusal by the limiter is also a right answer */
    int binary;
    uint8_t* bytes;
    size_t len;
} wsc_expect_t;

typedef struct {
    int fd;                      /* the client's end */
    connection_t* conn;          /* the server's */
    int alive, armed, resource;
    uint8_t* out; size_t out_len, out_pos, out_cap;         /* sent to the server */
    uint8_t* frames; size_t frames_len, frames_cap;         /* held back until the 101 */
    uint8_t* in; size_t in_len, in_cap;                     /* read from the server */
    int switched, closed_by_server, eof;
    wsc_expect_t expect[WSC_EXPECT];
    size_t expect_count, expect_next;
    uint8_t* bcast[WSC_LOG]; size_t bcast_len[WSC_LOG]; size_t bcast_count;
    size_t refused;              /* "Too Many Requests" read */
    int close_sent;
} wsc_t;

static wsc_t __wsc[WSC_CONNS];

typedef enum { WSC_LOG_SUB, WSC_LOG_UNSUB, WSC_LOG_PUB } wsc_log_e;

typedef struct {
    wsc_log_e what;
    int who;
    uint8_t* bytes;
    size_t len;
} wsc_log_t;

static wsc_log_t __wsc_log[WSC_LOG];
static size_t __wsc_log_count;
static size_t __wsc_routed;

static void __wsc_append(uint8_t** buf, size_t* len, size_t* cap, const void* p, size_t n) {
    if (n == 0) return;
    if (*len + n > *cap) {
        size_t c = *cap ? *cap : 1024;
        while (c < *len + n) c *= 2;
        uint8_t* g = realloc(*buf, c);
        if (g == NULL) abort();
        *buf = g;
        *cap = c;
    }
    memcpy(*buf + *len, p, n);
    *len += n;
}

static int __wsc_index(const connection_t* c) {
    for (int i = 0; i < WSC_CONNS; i++)
        if (__wsc[i].conn == c) return i;
    return -1;
}

/* ---- the event loop's side ---- */

static int __wsc_mpx_arm(connection_t* connection, int flags) {
    const int i = __wsc_index(connection);
    if (i >= 0) __wsc[i].armed = flags;
    return 1;
}

static int __wsc_mpx_del(connection_t* connection) {
    const int i = __wsc_index(connection);
    if (i >= 0) __wsc[i].armed = 0;
    return 1;
}

static mpxapi_t __wsc_mpxapi = {
    .control_add = __wsc_mpx_arm,
    .control_mod = __wsc_mpx_arm,
    .control_del = __wsc_mpx_del,
};

static int __wsc_event(wsc_t* w, int event) {
    if (!(w->armed & event)) return 1;
    const connection_server_ctx_t* ctx = w->conn->ctx;
    if (atomic_load(&ctx->destroyed)) return 0;
    if (w->armed & MPXONESHOT) w->armed = 0;
    const int alive = event == MPXIN ? w->conn->read(w->conn) : w->conn->write(w->conn);
    if (getenv("FUZZ_TRACE") != NULL)
        fprintf(stderr, "server %d %s -> %d, armed 0x%x\n", (int)(w - __wsc),
                event == MPXIN ? "read" : "write", alive, w->armed);
    return alive;
}

/* ---- the application ---- */

static void __wsc_http_upgrade(void* arg) {
    switch_to_websockets(arg);
}

/* Read either incoming representation without forcing file materialization. */
static uint8_t* __wsc_payload(websocketsrequest_t* request, size_t* len) {
    *len = websocketsrequest_payload_size(request->protocol);
    if (*len == 0) return NULL;
    uint8_t* p = (uint8_t*)websocketsrequest_payload(request->protocol);
    if (p == NULL) abort();
    return p;
}

static void __wsc_reply(wsctx_t* ctx, const char* prefix, const void* p, size_t n, int binary) {
    const size_t k = strlen(prefix);
    char* buf = malloc(k + n + 1);
    if (buf == NULL) abort();
    memcpy(buf, prefix, k);
    if (n) memcpy(buf + k, p, n);
    if (binary) ctx->response->send_binaryn(ctx->response, buf, k + n);
    else ctx->response->send_textn(ctx->response, buf, k + n);
    free(buf);
}

static void __wsc_log_add(wsc_log_e what, websocketsrequest_t* request, const void* p, size_t n) {
    if (__wsc_log_count == WSC_LOG) abort();
    wsc_log_t* e = &__wsc_log[__wsc_log_count++];
    e->what = what;
    e->who = __wsc_index(request->connection);
    e->bytes = NULL;
    e->len = n;
    if (n) { e->bytes = malloc(n); if (e->bytes == NULL) abort(); memcpy(e->bytes, p, n); }
}

static void __wsc_default(void* arg) {
    wsctx_t* ctx = arg;
    __wsc_routed++;
    size_t n = 0;
    uint8_t* p = __wsc_payload(ctx->request, &n);
    __wsc_reply(ctx, "E:", p, n, ctx->request->type != WEBSOCKETS_TEXT);
    free(p);
}

static void __wsc_echo_get(void* arg) {
    wsctx_t* ctx = arg;
    __wsc_routed++;
    websockets_protocol_resource_t* protocol = (websockets_protocol_resource_t*)ctx->request->protocol;
    int ok = 0;
    const char* q = protocol->get_query(protocol, "q", &ok);
    __wsc_reply(ctx, "E:", ok && q ? q : "", ok && q ? strlen(q) : 0, 0);
}

static void __wsc_echo_post(void* arg) {
    wsctx_t* ctx = arg;
    __wsc_routed++;
    size_t n = 0;
    uint8_t* p = __wsc_payload(ctx->request, &n);
    __wsc_reply(ctx, "E:", p, n, 0);
    free(p);
}

static void __wsc_deliver(response_t* response, const char* payload, size_t size) {
    websocketsresponse_t* r = (websocketsresponse_t*)response;
    char* buf = malloc(size + 2);
    if (buf == NULL) abort();
    memcpy(buf, "B:", 2);
    if (size) memcpy(buf + 2, payload, size);
    r->send_textn(r, buf, size + 2);
    free(buf);
}

static void __wsc_sub(void* arg) {
    wsctx_t* ctx = arg;
    __wsc_routed++;
    websockets_broadcast_add("room", ctx->request, NULL, __wsc_deliver);
    __wsc_log_add(WSC_LOG_SUB, ctx->request, NULL, 0);
    __wsc_reply(ctx, "S", NULL, 0, 0);
}

static void __wsc_unsub(void* arg) {
    wsctx_t* ctx = arg;
    __wsc_routed++;
    websockets_broadcast_remove("room", ctx->request);
    __wsc_log_add(WSC_LOG_UNSUB, ctx->request, NULL, 0);
    __wsc_reply(ctx, "U", NULL, 0, 0);
}

static void __wsc_pub(void* arg) {
    wsctx_t* ctx = arg;
    __wsc_routed++;
    size_t n = 0;
    uint8_t* p = __wsc_payload(ctx->request, &n);
    websockets_broadcast_send_all("room", ctx->request, (const char*)p, n);
    __wsc_log_add(WSC_LOG_PUB, ctx->request, p, n);
    free(p);
    __wsc_reply(ctx, "P", NULL, 0, 0);
}

static void __wsc_item(void* arg) {
    wsctx_t* ctx = arg;
    __wsc_routed++;
    websockets_protocol_resource_t* protocol = (websockets_protocol_resource_t*)ctx->request->protocol;
    int ok = 0;
    const char* id = protocol->get_query(protocol, "id", &ok);
    __wsc_reply(ctx, "I:", ok && id ? id : "", ok && id ? strlen(id) : 0, 0);
}

static uint64_t __wsc_clock(void) {
    return 1000000000ULL;   /* frozen: the burst is all there is */
}

static void __wsc_init(void) {
    static int done;
    if (done) return;
    done = 1;
    __fuzz_listener.api = &__wsc_mpxapi;
    if (!connection_queue_init()) abort();
    ratelimiter_set_time_source(__wsc_clock);

    route_t* upgrade = route_create("/ws");
    if (upgrade == NULL || !route_set_http_handler(upgrade, "GET", __wsc_http_upgrade, NULL)) abort();
    __fuzz_server.http.route = upgrade;

    static const struct { const char* path; const char* method; void (*fn)(void*); } routes[] = {
        { "/echo", "GET", __wsc_echo_get }, { "/echo", "POST", __wsc_echo_post },
        { "/sub", "GET", __wsc_sub }, { "/unsub", "GET", __wsc_unsub },
        { "/pub", "POST", __wsc_pub }, { "/item/{id|[0-9]+}", "GET", __wsc_item },
    };
    route_t* first = NULL, * last = NULL;
    for (size_t i = 0; i < sizeof routes / sizeof routes[0]; i++) {
        route_t* r = i > 0 && strcmp(routes[i].path, routes[i - 1].path) == 0 ? last : NULL;
        if (r == NULL) {
            r = route_create(routes[i].path);
            if (r == NULL) abort();
            if (last) last->next = r; else first = r;
            last = r;
        }
        if (!route_set_websockets_handler(r, routes[i].method, routes[i].fn, NULL)) abort();
    }
    __fuzz_server.websockets.configured = 1;
    __fuzz_server.websockets.default_handler = __wsc_default;
    __fuzz_server.websockets.route = first;
    __fuzz_server.broadcast = broadcast_init();
    if (__fuzz_server.broadcast == NULL) abort();
}

/* ---- the client ---- */

static uint8_t __wsc_byte(const uint8_t** p, const uint8_t* end) {
    return *p < end ? *(*p)++ : 0;
}

/* One masked frame; the mask comes from the input too. */
static void __wsc_frame(wsc_t* w, int fin, int opcode, const uint8_t* payload, size_t len, uint32_t mask) {
    uint8_t h[14];
    size_t n = 0;
    h[n++] = (uint8_t)((fin ? 0x80 : 0) | opcode);
    if (len < 126) h[n++] = (uint8_t)(0x80 | len);
    else if (len < 65536) { h[n++] = 0x80 | 126; h[n++] = (uint8_t)(len >> 8); h[n++] = (uint8_t)len; }
    else { h[n++] = 0x80 | 127; for (int i = 7; i >= 0; i--) h[n++] = (uint8_t)((uint64_t)len >> (8 * i)); }
    const uint8_t m[4] = { (uint8_t)(mask >> 24), (uint8_t)(mask >> 16), (uint8_t)(mask >> 8), (uint8_t)mask };
    memcpy(h + n, m, 4);
    n += 4;
    __wsc_append(&w->frames, &w->frames_len, &w->frames_cap, h, n);
    for (size_t i = 0; i < len; i++) {
        const uint8_t b = payload[i] ^ m[i % 4];
        __wsc_append(&w->frames, &w->frames_len, &w->frames_cap, &b, 1);
    }
}

static void __wsc_expect(wsc_t* w, wsc_kind_e kind, int routed, int binary, const void* p, size_t n) {
    if (w->expect_count == WSC_EXPECT) abort();
    wsc_expect_t* e = &w->expect[w->expect_count++];
    e->kind = kind;
    e->routed = routed;
    e->binary = binary;
    e->len = n;
    e->bytes = malloc(n ? n : 1);
    if (e->bytes == NULL) abort();
    if (n) memcpy(e->bytes, p, n);
}

static void __wsc_expect_reply(wsc_t* w, int routed, int binary, const char* prefix, const void* p, size_t n) {
    uint8_t buf[512];
    const size_t k = strlen(prefix);
    if (k + n > sizeof buf) abort();
    memcpy(buf, prefix, k);
    if (n) memcpy(buf + k, p, n);
    __wsc_expect(w, WSC_REPLY, routed, binary, buf, k + n);
}

static const char __wsc_unreserved[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/* One message from the input: its frames, and what the server must answer. */
static int __wsc_message(wsc_t* w, const uint8_t** p, const uint8_t* end) {
    if (*p >= end || w->close_sent) return 0;
    const uint8_t kind = __wsc_byte(p, end);
    const uint8_t m0 = __wsc_byte(p, end), m1 = __wsc_byte(p, end), m2 = __wsc_byte(p, end);
    const uint32_t mask = (uint32_t)m0 << 24 | (uint32_t)m1 << 16 | (uint32_t)m2 << 8 | (uint8_t)(m0 ^ m1);
    uint8_t msg[320];
    size_t len = 0;
    int binary = 0;

    switch (kind % 8) {
    case 0: {                                           /* ping */
        len = __wsc_byte(p, end) % 126;
        for (size_t i = 0; i < len; i++) msg[i] = __wsc_byte(p, end);
        __wsc_frame(w, 1, 0x9, msg, len, mask);
        __wsc_expect(w, WSC_PONG, 0, 0, msg, len);
        return 1;
    }
    case 1:                                             /* pong: no answer */
        len = __wsc_byte(p, end) % 20;
        for (size_t i = 0; i < len; i++) msg[i] = __wsc_byte(p, end);
        __wsc_frame(w, 1, 0xA, msg, len, mask);
        return 1;
    case 2: {                                           /* close, echoed, the end */
        if ((kind >> 3) & 1) {
            msg[len++] = 0x03; msg[len++] = 0xE8;       /* 1000 */
            const size_t r = __wsc_byte(p, end) % 16;
            for (size_t i = 0; i < r; i++) msg[len++] = (uint8_t)('a' + __wsc_byte(p, end) % 26);
        }
        __wsc_frame(w, 1, 0x8, msg, len, mask);
        __wsc_expect(w, WSC_CLOSE, 0, 0, msg, len);
        w->close_sent = 1;
        return 1;
    }
    default:
        break;
    }

    /* A data message. */
    uint8_t body[256];
    size_t body_len = __wsc_byte(p, end) % 200;
    const uint8_t form = __wsc_byte(p, end);
    if (!w->resource) {
        binary = (form & 1);
        for (size_t i = 0; i < body_len; i++) {
            const uint8_t c = __wsc_byte(p, end);
            body[i] = binary ? c : (uint8_t)(0x20 + c % 95);
        }
        memcpy(msg, body, body_len);
        len = body_len;
        __wsc_expect_reply(w, 1, binary, "E:", body, body_len);
    } else {
        for (size_t i = 0; i < body_len; i++) body[i] = (uint8_t)(0x20 + __wsc_byte(p, end) % 95);
        char head[128];
        int hn = 0;
        switch (form % 8) {
        case 0: {                                       /* GET /echo?q=... */
            char q[96], decoded[64];
            size_t qn = 0, dn = 0;
            const size_t parts = __wsc_byte(p, end) % 12;
            for (size_t i = 0; i < parts && dn < sizeof decoded - 1 && qn < sizeof q - 4; i++) {
                const uint8_t c = __wsc_byte(p, end);
                if (c & 0x80) {
                    const uint8_t b = (uint8_t)(1 + __wsc_byte(p, end) % 255);
                    qn += (size_t)snprintf(q + qn, sizeof q - qn, "%%%02X", b);
                    decoded[dn++] = (char)b;
                } else {
                    q[qn++] = __wsc_unreserved[c % (sizeof __wsc_unreserved - 1)];
                    decoded[dn++] = q[qn - 1];
                }
            }
            q[qn] = 0;
            hn = snprintf(head, sizeof head, "GET /echo?q=%s", q);
            body_len = 0;
            __wsc_expect_reply(w, 1, 0, "E:", decoded, dn);
            break;
        }
        case 1:
            hn = snprintf(head, sizeof head, "POST /echo ");
            __wsc_expect_reply(w, 1, 0, "E:", body, body_len);
            break;
        case 2:
            hn = snprintf(head, sizeof head, "GET /sub");
            body_len = 0;
            __wsc_expect_reply(w, 1, 0, "S", NULL, 0);
            break;
        case 3:
            hn = snprintf(head, sizeof head, "GET /unsub");
            body_len = 0;
            __wsc_expect_reply(w, 1, 0, "U", NULL, 0);
            break;
        case 4:
            hn = snprintf(head, sizeof head, "POST /pub ");
            __wsc_expect_reply(w, 1, 0, "P", NULL, 0);
            break;
        case 5: {
            const unsigned id = __wsc_byte(p, end) * 257u;
            char digits[16];
            snprintf(digits, sizeof digits, "%u", id);
            hn = snprintf(head, sizeof head, "GET /item/%s", digits);
            body_len = 0;
            __wsc_expect_reply(w, 1, 0, "I:", digits, strlen(digits));
            break;
        }
        case 6:                                         /* no route takes it */
            hn = snprintf(head, sizeof head, (form >> 3) & 1 ? "GET /nowhere" : "DELETE /echo");
            body_len = 0;
            __wsc_expect_reply(w, 0, 0, "resource not found", NULL, 0);
            break;
        default:                                        /* a method without that route */
            hn = snprintf(head, sizeof head, "POST /sub ");
            __wsc_expect_reply(w, 0, 0, "resource not found", NULL, 0);
            break;
        }
        memcpy(msg, head, (size_t)hn);
        memcpy(msg + hn, body, body_len);
        len = (size_t)hn + body_len;
    }

    /* Cut into 1..3 frames anywhere, a ping or a pong now and then between. */
    const size_t pieces = 1 + __wsc_byte(p, end) % 3;
    size_t at = 0;
    for (size_t i = 0; i < pieces; i++) {
        size_t to = i + 1 == pieces ? len : at + (len - at) * __wsc_byte(p, end) / 255;
        if (to < at) to = at;
        __wsc_frame(w, i + 1 == pieces, i == 0 ? (binary ? 0x2 : 0x1) : 0x0, msg + at, to - at, mask ^ (uint32_t)i);
        at = to;
        if (i + 1 < pieces && (__wsc_byte(p, end) & 3) == 0) {
            const uint8_t ping[3] = { 'p', (uint8_t)i, (uint8_t)w->expect_count };
            __wsc_frame(w, 1, 0x9, ping, sizeof ping, mask);
            /* The PONG is posted when the PING is read -- ahead of the reply to
             * the message it interrupted, which is only dispatched at its end. */
            wsc_expect_t reply = w->expect[--w->expect_count];
            __wsc_expect(w, WSC_PONG, 0, 0, ping, sizeof ping);
            w->expect[w->expect_count++] = reply;
        }
    }
    return 1;
}

/* What the server wrote: the 101 first, then frames. */
static void __wsc_read(wsc_t* w) {
    uint8_t buf[8192];
    for (;;) {
        const ssize_t n = recv(w->fd, buf, sizeof buf, 0);
        if (n == 0) { w->eof = 1; break; }
        if (n < 0) break;
        __wsc_append(&w->in, &w->in_len, &w->in_cap, buf, (size_t)n);
    }

    size_t off = 0;
    if (!w->switched) {
        const uint8_t* end = w->in_len >= 4 ? memmem(w->in, w->in_len, "\r\n\r\n", 4) : NULL;
        if (end == NULL) return;
        const size_t head = (size_t)(end - w->in) + 4;
        if (head < 12 || memcmp(w->in, "HTTP/1.1 101", 12) != 0) __builtin_trap();
        if (memmem(w->in, head, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n", 51) == NULL) __builtin_trap();
        const int proto = memmem(w->in, head, "Sec-WebSocket-Protocol: resource\r\n", 34) != NULL;
        if (proto != w->resource) __builtin_trap();
        w->switched = 1;
        off = head;
        __wsc_append(&w->out, &w->out_len, &w->out_cap, w->frames, w->frames_len);
    }

    while (w->in_len - off >= 2) {
        const uint8_t* f = w->in + off;
        const size_t avail = w->in_len - off;
        if (f[1] & 0x80) __builtin_trap();                  /* a server never masks */
        size_t hl = 2;
        uint64_t len = f[1] & 0x7F;
        if (len == 126) { if (avail < 4) break; len = (uint64_t)f[2] << 8 | f[3]; hl = 4; }
        else if (len == 127) { if (avail < 10) break; len = 0; for (int i = 0; i < 8; i++) len = len << 8 | f[2 + i]; hl = 10; }
        if (avail < hl || len > avail - hl) break;
        const uint8_t* payload = f + hl;
        const int opcode = f[0] & 0x0F;
        if (!(f[0] & 0x80) || (f[0] & 0x70)) __builtin_trap();   /* whole, no RSV */
        off += hl + (size_t)len;

        if (w->closed_by_server) __builtin_trap();          /* nothing after CLOSE */
        if ((opcode == 0x1 || opcode == 0x2) && len >= 2 && payload[0] == 'B' && payload[1] == ':') {
            if (opcode != 0x1 || w->bcast_count == WSC_LOG) __builtin_trap();
            uint8_t* copy = malloc(len ? len : 1);
            if (copy == NULL) abort();
            memcpy(copy, payload, len);
            w->bcast[w->bcast_count] = copy;
            w->bcast_len[w->bcast_count++] = len;
            continue;
        }
        if (w->expect_next == w->expect_count) __builtin_trap();   /* an answer nobody asked for */
        const wsc_expect_t* e = &w->expect[w->expect_next++];
        switch (e->kind) {
        case WSC_PONG:
            if (opcode != 0xA || len != e->len || memcmp(payload, e->bytes, e->len) != 0) __builtin_trap();
            break;
        case WSC_CLOSE:
            if (opcode != 0x8 || len != e->len || memcmp(payload, e->bytes, e->len) != 0) __builtin_trap();
            w->closed_by_server = 1;
            break;
        default: {
            static const char refused[] = "Too Many Requests";
            if (e->routed && opcode == 0x1 && len == sizeof refused - 1 && memcmp(payload, refused, len) == 0) {
                w->refused++;
                break;
            }
            if (opcode != (e->binary ? 0x2 : 0x1) || len != e->len || memcmp(payload, e->bytes, e->len) != 0) {
                if (getenv("FUZZ_TRACE") != NULL)
                    fprintf(stderr, "conn %d answer %zu: want op %d [%.*s], got op %d [%.*s]\n",
                            (int)(w - __wsc), w->expect_next - 1, e->binary ? 2 : 1, (int)e->len, e->bytes,
                            opcode, (int)len, payload);
                __builtin_trap();
            }
            break;
        }
        }
    }
    memmove(w->in, w->in + off, w->in_len - off);
    w->in_len -= off;
}

static void __wsc_send(wsc_t* w, size_t amount) {
    const size_t left = w->out_len - w->out_pos;
    const size_t n = left < amount ? left : amount;
    if (n == 0) return;
    const ssize_t s = send(w->fd, w->out + w->out_pos, n, MSG_NOSIGNAL);
    if (s > 0) w->out_pos += (size_t)s;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3) return 0;
    __fuzz_appconfig_init();
    __wsc_init();

    const uint8_t flags = data[0];
    const uint64_t seed = data[1];
    const uint8_t* p = data + 2;
    const uint8_t* end = data + size;

    /* The limiter: none, or a burst of 1..7 shared by both connections. */
    ratelimiter_t* limiter = NULL;
    const uint32_t burst = (flags >> 2) & 7;
    if (burst) {
        ratelimiter_config_t cfg = { burst, 1, 1000000000ULL, 3600 };
        limiter = ratelimiter_init(&cfg);
        if (limiter == NULL) abort();
    }
    __fuzz_server.websockets.ratelimiter = limiter;
    __wsc_log_count = 0;
    __wsc_routed = 0;

    char* buffers[WSC_CONNS] = { NULL };
    int client_fds[WSC_CONNS];
    memset(__wsc, 0, sizeof __wsc);
    for (int i = 0; i < WSC_CONNS; i++) {
        wsc_t* w = &__wsc[i];
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0) abort();
        const int small = 4096;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
        setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
        w->fd = sv[1];
        client_fds[i] = sv[0];
        buffers[i] = malloc(16384);
        if (buffers[i] == NULL) abort();
        const ipaddr_t loopback = ipaddr_from_v4(0x0100007F);
        w->conn = connection_s_alloc(&__fuzz_listener, sv[0], &loopback, 8080, &loopback,
                                     (unsigned short)(40000 + i), buffers[i], 16384);
        if (w->conn == NULL) abort();
        connection_server_ctx_t* ctx = w->conn->ctx;
        ctx->server = &__fuzz_server;
        w->alive = set_http(w->conn);
        w->armed = MPXIN | MPXRDHUP;
        w->resource = (flags >> i) & 1;
        char req[256];
        const int n = snprintf(req, sizeof req,
            "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n%s\r\n",
            w->resource ? "Sec-WebSocket-Protocol: resource\r\n" : "");
        __wsc_append(&w->out, &w->out_len, &w->out_cap, req, (size_t)n);
    }

    /* The messages, alternating between the connections as the input says. */
    for (size_t k = 0; k < 64 && p < end; k++) {
        wsc_t* w = &__wsc[__wsc_byte(&p, end) & 1];
        if (!__wsc_message(w, &p, end)) {
            wsc_t* other = &__wsc[w == &__wsc[0]];
            if (!__wsc_message(other, &p, end)) break;
        }
    }

    if (getenv("FUZZ_TRACE") != NULL)
        for (int i = 0; i < WSC_CONNS; i++) {
            fprintf(stderr, "frames %d:", i);
            for (size_t k = 0; k < __wsc[i].frames_len; k++) fprintf(stderr, " %02x", __wsc[i].frames[k]);
            fprintf(stderr, "\n");
        }
    uint64_t rng = seed * 0x9E3779B97F4A7C15ULL + 1;
    for (size_t steps = 0; steps < 20000; steps++) {
        int pending = 0;
        for (int i = 0; i < WSC_CONNS; i++)
            pending |= __wsc[i].alive && (__wsc[i].out_pos < __wsc[i].out_len || !__wsc[i].switched ||
                                          __wsc[i].expect_next < __wsc[i].expect_count);
        if (!pending) break;
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
        wsc_t* w = &__wsc[(rng >> 20) & 1];
        const size_t amount = 1 + (size_t)((rng >> 8) % 700);
        switch (rng % 5) {
        case 0: __wsc_send(w, amount); break;
        case 1: if (w->alive) w->alive = __wsc_event(w, MPXIN); break;
        case 2: if (w->alive) w->alive = __wsc_event(w, MPXOUT); break;
        case 3: __wsc_read(w); break;
        case 4: (void)__fuzz_worker(); break;
        }
    }

    /* Drain: everything in, every worker run, everything out. */
    for (int idle = 0; idle < 6;) {
        int moved = 0;
        for (int i = 0; i < WSC_CONNS; i++) {
            wsc_t* w = &__wsc[i];
            const size_t before = w->out_pos;
            __wsc_send(w, SIZE_MAX);
            if (w->out_pos != before) moved = 1;
            if (w->alive) w->alive = __wsc_event(w, MPXIN);
        }
        while (__fuzz_worker()) moved = 1;
        for (int i = 0; i < WSC_CONNS; i++) {
            wsc_t* w = &__wsc[i];
            if (w->alive) w->alive = __wsc_event(w, MPXOUT);
            const size_t before = w->expect_next + w->bcast_count + w->in_len;
            __wsc_read(w);
            if (w->expect_next + w->bcast_count + w->in_len != before) moved = 1;
        }
        idle = moved ? 0 : idle + 1;
    }

    if (getenv("FUZZ_TRACE") != NULL)
        for (int i = 0; i < WSC_CONNS; i++)
            fprintf(stderr, "conn %d: resource %d switched %d alive %d sent %zu/%zu answers %zu/%zu broadcast %zu refused %zu\n",
                    i, __wsc[i].resource, __wsc[i].switched, __wsc[i].alive, __wsc[i].out_pos, __wsc[i].out_len,
                    __wsc[i].expect_next, __wsc[i].expect_count, __wsc[i].bcast_count, __wsc[i].refused);

    /* Every message answered, in order; broadcast exactly as the log says. */
    size_t refused = 0;
    for (int i = 0; i < WSC_CONNS; i++) {
        wsc_t* w = &__wsc[i];
        if (!w->switched) __builtin_trap();
        if (w->expect_next != w->expect_count) __builtin_trap();
        if (w->close_sent && w->alive) __builtin_trap();     /* a CLOSE ends the connection */
        refused += w->refused;
    }
    size_t routed_sent = 0;
    for (int i = 0; i < WSC_CONNS; i++)
        for (size_t k = 0; k < __wsc[i].expect_count; k++) routed_sent += __wsc[i].expect[k].routed;
    if (__wsc_routed + refused != routed_sent) __builtin_trap();
    const size_t allowed = limiter == NULL ? routed_sent : routed_sent < burst ? routed_sent : burst;
    if (__wsc_routed != allowed) __builtin_trap();

    for (int i = 0; i < WSC_CONNS; i++) {
        wsc_t* w = &__wsc[i];
        int subscribed = 0;
        size_t want = 0;
        for (size_t k = 0; k < __wsc_log_count; k++) {
            const wsc_log_t* e = &__wsc_log[k];
            if (e->who == i && e->what == WSC_LOG_SUB) subscribed = 1;
            else if (e->who == i && e->what == WSC_LOG_UNSUB) subscribed = 0;
            else if (e->who != i && e->what == WSC_LOG_PUB && subscribed) {
                if (want < w->bcast_count) {
                    if (w->bcast_len[want] != e->len + 2 ||
                        (e->len && memcmp(w->bcast[want] + 2, e->bytes, e->len) != 0)) __builtin_trap();
                } else if (!w->close_sent) {
                    __builtin_trap();                        /* a delivery that never came */
                }
                want++;
            }
        }
        if (w->bcast_count > want) __builtin_trap();         /* one nobody published */
    }

    while (__fuzz_worker()) {}
    for (int i = 0; i < WSC_CONNS; i++) {
        wsc_t* w = &__wsc[i];
        /* What connection_close does and the local free does not: the server
         * outlives this input, and so would a subscription of a freed
         * connection. */
        broadcast_clear(w->conn);
        connection_s_free_local(w->conn);
        close(w->fd);
        close(client_fds[i]);
        free(buffers[i]);
        free(w->out);
        free(w->frames);
        free(w->in);
        for (size_t k = 0; k < w->expect_count; k++) free(w->expect[k].bytes);
        for (size_t k = 0; k < w->bcast_count; k++) free(w->bcast[k]);
    }
    for (size_t k = 0; k < __wsc_log_count; k++) free(__wsc_log[k].bytes);
    __fuzz_server.websockets.ratelimiter = NULL;
    ratelimiter_free(limiter);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_QUIC_FRAMES

#include "quic_stand.h"
#include "quicmemory.h"

/* Frames on an established QUIC connection, and the error each wrong one must
 * close it with.
 *
 * quic_conn cannot get here: its input decides what the path does, and a packet
 * it damages simply fails to open. In this target the test client carries bytes
 * the input chose (quicclient_inject) inside a packet it protects properly, so
 * the server opens it and its frame loop reads exactly those bytes -- the same
 * loop, the same keys, and nothing compiled into the server for the purpose.
 *
 * Every packet is built from frames that are correct except, at most, for one
 * deliberate violation, and the target works out by itself what RFC 9000 asks
 * of the server: accept the packet, or close with the code §19 or §12.4 names
 * for that violation. The model behind the verdict keeps what makes a frame
 * right or wrong -- which client streams exist, how far each has reached and
 * where it ends, the connection ids the client has issued -- and starts from the
 * transport parameters the server announced, not from its bookkeeping.
 *
 * One injection may go out before the handshake completes, at the Initial or
 * Handshake level, where §12.4 admits only PADDING, PING, ACK, CRYPTO and the
 * transport CONNECTION_CLOSE; after the handshake every packet is 1-RTT.
 *
 * Checked after every packet, besides the verdict: limits the client lowered
 * stay where they were (MAX_DATA and MAX_STREAM_DATA only ever raise, §19.9,
 * §19.10); the server holds exactly the client ids the model says are active,
 * never more than it allowed (§5.1.1); of its own ids no more are active than
 * the client allowed, every active one routes and every retired one does not
 * (§5.1.2); the last PATH_CHALLENGE of a packet comes back with its own data
 * (§8.2.2). At the end the connection goes, and the QUIC memory budget is back
 * where it started.
 *
 * Where the RFC leaves the choice to the implementation the verdict follows the
 * server's: an ACK of a packet never sent is PROTOCOL_VIOLATION (§13.1, SHOULD),
 * a sequence number reused for another id is PROTOCOL_VIOLATION (§19.15, MAY),
 * CRYPTO past 64 KiB is CRYPTO_BUFFER_EXCEEDED (§7.5), and a stream frame after
 * the stream's reset is ignored rather than checked against its final size
 * (§4.5, SHOULD). */

#define QF_STREAMS 16
#define QF_OK      UINT64_MAX         /* the packet is accepted */
#define QF_DRAIN   (UINT64_MAX - 1)   /* the client closed; the server drains */
#define QF_CID_LEN 8                  /* the client's own ids, like its scid */

typedef struct {
    uint64_t high;       /* one past the highest byte received */
    uint64_t final;
    int has_final, reset;
} qf_stream_t;

typedef struct {
    uint64_t seq;
    quiccid_t cid;
} qf_pcid_t;

typedef struct {
    /* The server's transport parameters, read once after the handshake. */
    uint64_t max_bidi, max_uni, win_bidi, win_uni, max_data, cid_limit;

    uint64_t conn_used;                  /* the connection window spent */
    qf_stream_t bidi[QF_STREAMS], uni[QF_STREAMS];

    /* The client's ids the server must hold: every one at or above the
     * Retire Prior To watermark. */
    qf_pcid_t pcid[QUICCONN_MAX_PEER_CIDS + 1];
    size_t pcid_count;
    uint64_t rpt, next_seq;

    /* What the server may send, as last seen; never allowed to go down. */
    uint64_t send_limit;
    uint64_t stream_send_limit[QF_STREAMS];

    /* The server's own ids the client retired: none may route again. */
    quiccid_t retired[64];
    size_t retired_count;
} qf_model_t;

typedef struct {
    uint8_t b[CLIENT_MAX_INJECT];
    size_t n;
    uint64_t expect;
    int challenge;
    uint8_t challenge_data[8];
} qf_pkt_t;

typedef struct {
    uint8_t b[1400];
    size_t n;
} qf_frame_t;

typedef struct {
    const uint8_t* p;
    const uint8_t* end;
} qf_in_t;

static uint8_t __qf_u8(qf_in_t* in) {
    return in->p < in->end ? *in->p++ : 0;
}

static uint64_t __qf_u16(qf_in_t* in) {
    const uint64_t hi = __qf_u8(in);
    return hi << 8 | __qf_u8(in);
}

static uint64_t __qf_u32(qf_in_t* in) {
    const uint64_t hi = __qf_u16(in);
    return hi << 16 | __qf_u16(in);
}

/* Any value a varint can carry, small ones most often. */
static uint64_t __qf_any(qf_in_t* in) {
    const uint8_t shift = __qf_u8(in);
    return (__qf_u16(in) << (shift % 47)) & QUIC_VARINT_MAX;
}

/* A number in [0, range], small ones most often. */
static uint64_t __qf_upto(qf_in_t* in, uint64_t range) {
    const uint8_t how = __qf_u8(in);
    const uint64_t v = how < 128 ? how : how < 224 ? __qf_u16(in) : __qf_u32(in);
    return range == UINT64_MAX ? v : v % (range + 1);
}

static void __qf_byte(qf_frame_t* f, uint8_t v) {
    if (f->n < sizeof f->b) f->b[f->n] = v;
    f->n++;
}

/* The shortest encoding (RFC 9000 §16); values past 2^62 do not occur here. */
static void __qf_vi(qf_frame_t* f, uint64_t v) {
    if (v < 64) {
        __qf_byte(f, (uint8_t)v);
    } else if (v < 16384) {
        __qf_byte(f, (uint8_t)(0x40 | v >> 8));
        __qf_byte(f, (uint8_t)v);
    } else if (v < (1ULL << 30)) {
        __qf_byte(f, (uint8_t)(0x80 | v >> 24));
        for (int i = 2; i >= 0; i--) __qf_byte(f, (uint8_t)(v >> (i * 8)));
    } else {
        __qf_byte(f, (uint8_t)(0xc0 | v >> 56));
        for (int i = 6; i >= 0; i--) __qf_byte(f, (uint8_t)(v >> (i * 8)));
    }
}

static void __qf_bytes(qf_frame_t* f, uint8_t fill, size_t n) {
    for (size_t i = 0; i < n; i++) __qf_byte(f, (uint8_t)(fill + i * 7));
}

static uint64_t __qf_client_bidi(size_t idx) { return (uint64_t)idx << 2; }
static uint64_t __qf_client_uni(size_t idx) { return (uint64_t)idx << 2 | 2; }

/* A stream the client may use: bidirectional or unidirectional, below the limit
 * the server announced and within what the model tracks. 0 if there is none. */
static int __qf_pick(qf_in_t* in, const qf_model_t* m, int* uni, size_t* idx) {
    const uint8_t b = __qf_u8(in);
    const uint64_t nb = m->max_bidi < QF_STREAMS ? m->max_bidi : QF_STREAMS;
    const uint64_t nu = m->max_uni < QF_STREAMS ? m->max_uni : QF_STREAMS;

    *uni = (b & 1) && nu > 0;
    if (!*uni && nb == 0) *uni = nu > 0;
    if (*uni ? nu == 0 : nb == 0) return 0;

    *idx = (size_t)((b >> 1) % (*uni ? nu : nb));
    return 1;
}

static uint64_t __qf_id(int uni, size_t idx) {
    return uni ? __qf_client_uni(idx) : __qf_client_bidi(idx);
}

/* One past what any client stream of this kind may be numbered, with room for
 * whatever the server granted since: every stream the client has opened, at
 * most QF_STREAMS, may have been released and credited back. */
static uint64_t __qf_beyond(const qf_model_t* m, int uni, uint8_t extra) {
    const uint64_t index = (uni ? m->max_uni : m->max_bidi + QF_STREAMS) + extra % 4;
    return index << 2 | (uni ? 2 : 0);
}

static int __qf_cid_eq(const quiccid_t* a, const quiccid_t* b) {
    return a->len == b->len && memcmp(a->data, b->data, a->len) == 0;
}

static quiccid_t __qf_pcid_of(uint64_t seq, uint8_t salt) {
    quiccid_t cid;
    cid.len = QF_CID_LEN;
    for (size_t i = 0; i < QF_CID_LEN; i++)
        cid.data[i] = (uint8_t)(seq * 131 + i * 7 + 0x40 + salt);
    return cid;
}

static void __qf_new_cid(qf_frame_t* f, uint64_t seq, uint64_t rpt, const quiccid_t* cid) {
    __qf_vi(f, QUIC_FRAME_NEW_CONNECTION_ID);
    __qf_vi(f, seq);
    __qf_vi(f, rpt);
    __qf_byte(f, cid->len);
    for (size_t i = 0; i < cid->len; i++) __qf_byte(f, cid->data[i]);
    __qf_bytes(f, (uint8_t)seq, 16);
}

/* A frame §12.4 forbids in Initial and Handshake packets, well formed. */
static void __qf_forbidden(qf_in_t* in, qf_frame_t* f) {
    static const uint64_t types[] = {
        QUIC_FRAME_RESET_STREAM, QUIC_FRAME_STOP_SENDING, QUIC_FRAME_NEW_TOKEN,
        QUIC_FRAME_STREAM, QUIC_FRAME_MAX_DATA, QUIC_FRAME_MAX_STREAM_DATA,
        QUIC_FRAME_MAX_STREAMS_BIDI, QUIC_FRAME_MAX_STREAMS_UNI, QUIC_FRAME_DATA_BLOCKED,
        QUIC_FRAME_STREAM_DATA_BLOCKED, QUIC_FRAME_STREAMS_BLOCKED_BIDI,
        QUIC_FRAME_STREAMS_BLOCKED_UNI, QUIC_FRAME_NEW_CONNECTION_ID,
        QUIC_FRAME_RETIRE_CONNECTION_ID, QUIC_FRAME_PATH_CHALLENGE,
        QUIC_FRAME_PATH_RESPONSE, QUIC_FRAME_CONNECTION_CLOSE_APP,
        QUIC_FRAME_HANDSHAKE_DONE,
    };
    const uint64_t type = types[__qf_u8(in) % (sizeof types / sizeof types[0])];

    switch (type) {
    case QUIC_FRAME_RESET_STREAM:
        __qf_vi(f, type); __qf_vi(f, 0); __qf_vi(f, 0); __qf_vi(f, 0);
        break;
    case QUIC_FRAME_STOP_SENDING:
    case QUIC_FRAME_MAX_STREAM_DATA:
    case QUIC_FRAME_STREAM_DATA_BLOCKED:
        __qf_vi(f, type); __qf_vi(f, 0); __qf_vi(f, 0);
        break;
    case QUIC_FRAME_NEW_TOKEN:
        __qf_vi(f, type); __qf_vi(f, 1); __qf_byte(f, 0x55);
        break;
    case QUIC_FRAME_STREAM:
        __qf_vi(f, QUIC_FRAME_STREAM | QUIC_STREAM_FLAG_LEN); __qf_vi(f, 0);
        __qf_vi(f, 1); __qf_byte(f, 'x');
        break;
    case QUIC_FRAME_NEW_CONNECTION_ID: {
        const quiccid_t cid = __qf_pcid_of(1, 0);
        __qf_new_cid(f, 1, 0, &cid);
        break;
    }
    case QUIC_FRAME_PATH_CHALLENGE:
    case QUIC_FRAME_PATH_RESPONSE:
        __qf_vi(f, type); __qf_bytes(f, 0x21, 8);
        break;
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        __qf_vi(f, type); __qf_vi(f, 0); __qf_vi(f, 0);
        break;
    case QUIC_FRAME_HANDSHAKE_DONE:
        __qf_vi(f, type);
        break;
    default:   /* MAX_DATA, MAX_STREAMS, DATA_BLOCKED, STREAMS_BLOCKED, RETIRE */
        __qf_vi(f, type); __qf_vi(f, 0);
        break;
    }
}

/* ---- One frame: its bytes, its verdict, and what it does to the model ---- */

static uint64_t __qf_stream(qf_in_t* in, qf_model_t* m, qf_frame_t* f) {
    int uni;
    size_t idx;
    if (!__qf_pick(in, m, &uni, &idx)) return QF_OK;

    qf_stream_t* st = uni ? &m->uni[idx] : &m->bidi[idx];
    const uint64_t win = uni ? m->win_uni : m->win_bidi;

    size_t len = (size_t)(__qf_u8(in) % 48);
    if (__qf_u8(in) >= 240) len = (size_t)(__qf_u16(in) % 900);
    int fin = __qf_u8(in) & 1;
    uint64_t offset;

    if (st->reset) {
        /* §4.5 asks for a check against the final size even here, as a SHOULD;
         * the server ignores whatever arrives once the stream is reset. */
        offset = __qf_upto(in, 1000);
    } else if (st->has_final) {
        if (len > st->final) len = (size_t)st->final;
        offset = fin ? st->final - len : __qf_upto(in, st->final - len);
    } else {
        if (len > win) len = (size_t)win;
        offset = __qf_upto(in, win - len);
        /* A FIN may not end the stream below what has already arrived. */
        if (fin && offset + len < st->high) offset = st->high > len ? st->high - len : 0;

        /* Within the connection window too, or this is a violation of a kind
         * the verdict does not predict: the window may have grown since. */
        const uint64_t end = offset + len;
        if (end > st->high && m->conn_used + (end - st->high) > m->max_data) {
            offset = st->high > len ? st->high - len : 0;
            if (offset + len > st->high) len = (size_t)(st->high - offset);
            fin = 0;
        }
    }

    const int has_off = offset > 0 || (__qf_u8(in) & 1);
    __qf_vi(f, QUIC_FRAME_STREAM | QUIC_STREAM_FLAG_LEN |
               (has_off ? QUIC_STREAM_FLAG_OFF : 0) | (fin ? QUIC_STREAM_FLAG_FIN : 0));
    __qf_vi(f, __qf_id(uni, idx));
    if (has_off) __qf_vi(f, offset);
    __qf_vi(f, len);
    __qf_bytes(f, (uint8_t)offset, len);

    if (!st->reset) {
        const uint64_t end = offset + len;
        if (end > st->high) {
            m->conn_used += end - st->high;
            st->high = end;
        }
        if (fin) {
            st->has_final = 1;
            st->final = end;
        }
    }

    return QF_OK;
}

static uint64_t __qf_stream_bad(qf_in_t* in, qf_model_t* m, qf_frame_t* f) {
    int uni;
    size_t idx;
    const uint8_t sub = __qf_u8(in) % 6;
    uint64_t id, offset = 0, expect;
    size_t len = 1 + __qf_u8(in) % 16;
    int fin = 0;

    const int have = __qf_pick(in, m, &uni, &idx);
    if (!have) { uni = 0; idx = 0; }
    qf_stream_t* st = uni ? &m->uni[idx] : &m->bidi[idx];
    const uint64_t win = uni ? m->win_uni : m->win_bidi;

    switch (sub) {
    case 1:     /* past the stream's window, §4.1 */
        if (have && !st->reset && !st->has_final) {
            id = __qf_id(uni, idx);
            offset = win - len + 1 + __qf_u8(in) % 16;
            expect = QUIC_FLOW_CONTROL_ERROR;
            break;
        }
        /* fall through */
    case 0:     /* a stream the server did not allow, §4.6 */
        id = __qf_beyond(m, uni, __qf_u8(in));
        expect = QUIC_STREAM_LIMIT_ERROR;
        break;
    case 2:     /* one the server would have had to open, §19.8 */
        id = (uint64_t)(__qf_u8(in) % 8) << 2 | 3;
        expect = QUIC_STREAM_STATE_ERROR;
        break;
    case 3:
        id = (uint64_t)(__qf_u8(in) % 8) << 2 | 1;
        expect = QUIC_STREAM_STATE_ERROR;
        break;
    case 4:     /* against a final size, §4.5 */
        if (!have || st->reset) goto limit;
        id = __qf_id(uni, idx);
        if (st->has_final && st->final + len <= win) {
            offset = st->final;                 /* data past the end */
        } else if (st->has_final && st->final > 0) {
            offset = 0;                         /* a different end */
            len = (size_t)(st->final - 1 < 16 ? st->final - 1 : 16);
            fin = 1;
        } else if (!st->has_final && st->high > 0) {
            len = (size_t)(st->high - 1 < 16 ? st->high - 1 : 16);
            offset = st->high - 1 - len;        /* an end below what arrived */
            fin = 1;
        } else {
            goto limit;
        }
        expect = QUIC_FINAL_SIZE_ERROR;
        break;
    default:    /* an offset past 2^62 - 1, §19.8 */
        id = have ? __qf_id(uni, idx) : 0;
        offset = QUIC_VARINT_MAX - len + 1;
        expect = QUIC_FRAME_ENCODING_ERROR;
        break;
    }

    if (0) {
limit:
        id = __qf_beyond(m, uni, __qf_u8(in));
        expect = QUIC_STREAM_LIMIT_ERROR;
    }

    __qf_vi(f, QUIC_FRAME_STREAM | QUIC_STREAM_FLAG_LEN | QUIC_STREAM_FLAG_OFF |
               (fin ? QUIC_STREAM_FLAG_FIN : 0));
    __qf_vi(f, id);
    __qf_vi(f, offset);
    __qf_vi(f, len);
    __qf_bytes(f, 0x33, len);

    return expect;
}

static uint64_t __qf_reset(qf_in_t* in, qf_model_t* m, qf_frame_t* f) {
    int uni;
    size_t idx;
    const uint8_t sub = __qf_u8(in) % 6;
    uint64_t id, final_size = 0, expect = QF_OK;
    const int have = __qf_pick(in, m, &uni, &idx);

    if (!have) { uni = 0; idx = 0; }
    qf_stream_t* st = uni ? &m->uni[idx] : &m->bidi[idx];
    const uint64_t win = uni ? m->win_uni : m->win_bidi;

    if (!have && sub < 3) goto limit;

    switch (sub) {
    case 0:     /* an ordinary reset */
        id = __qf_id(uni, idx);
        if (st->reset) {
            final_size = __qf_upto(in, 1000);
        } else if (st->has_final) {
            final_size = st->final;
        } else {
            uint64_t room = win - st->high;
            const uint64_t conn_room = m->max_data - m->conn_used;
            if (room > conn_room) room = conn_room;
            final_size = st->high + __qf_upto(in, room);
        }
        if (!st->reset) {
            m->conn_used += final_size - st->high;
            st->high = final_size;
            st->final = final_size;
            st->has_final = 1;
            st->reset = 1;
        }
        break;
    case 1:     /* a final size that disagrees, §4.5 */
        if (st->reset) goto limit;
        id = __qf_id(uni, idx);
        if (st->has_final && st->final > 0)
            final_size = st->final - 1 - __qf_upto(in, st->final - 1);
        else if (st->has_final && win > 0)
            final_size = 1 + __qf_upto(in, win - 1 < 16 ? win - 1 : 16);   /* not 0 */
        else if (!st->has_final && st->high > 0)
            final_size = st->high - 1 - __qf_upto(in, st->high - 1);        /* below it */
        else
            goto limit;
        expect = QUIC_FINAL_SIZE_ERROR;
        break;
    case 2:     /* past the window, §4.5 */
        if (st->reset) goto limit;
        id = __qf_id(uni, idx);
        final_size = win + 1 + __qf_u8(in);
        expect = QUIC_FLOW_CONTROL_ERROR;
        break;
    case 3:     /* a stream only the server sends on, §19.4 */
        id = (uint64_t)(__qf_u8(in) % 8) << 2 | 3;
        expect = QUIC_STREAM_STATE_ERROR;
        break;
    case 4:     /* one the server would have had to open, §19.4 */
        id = (uint64_t)(__qf_u8(in) % 8) << 2 | 1;
        expect = QUIC_STREAM_STATE_ERROR;
        break;
    default:
        goto limit;
    }

    if (0) {
limit:
        id = __qf_beyond(m, have ? uni : 0, __qf_u8(in));
        expect = QUIC_STREAM_LIMIT_ERROR;
    }

    __qf_vi(f, QUIC_FRAME_RESET_STREAM);
    __qf_vi(f, id);
    __qf_vi(f, __qf_upto(in, 1000));
    __qf_vi(f, final_size);

    return expect;
}

/* STOP_SENDING, MAX_STREAM_DATA and STREAM_DATA_BLOCKED name a stream and carry
 * one number. The first two are about the server's send side: a client
 * unidirectional stream has none (§19.5, §19.10). STREAM_DATA_BLOCKED is about
 * the client's: a server unidirectional stream is send-only for the server
 * (§19.13). All three answer to the stream limit (§4.6). */
static uint64_t __qf_stream_ctl(qf_in_t* in, qf_model_t* m, qf_frame_t* f, uint64_t type) {
    int uni;
    size_t idx;
    const uint8_t sub = __qf_u8(in) % 4;
    uint64_t id, expect = QF_OK;
    const int have = __qf_pick(in, m, &uni, &idx);
    const int blocked = type == QUIC_FRAME_STREAM_DATA_BLOCKED;

    switch (have ? sub : 3) {
    case 0:
        if (blocked) {
            id = __qf_id(uni, idx);
        } else {
            /* The server's side of a client bidirectional stream. */
            if (m->max_bidi == 0) goto limit;
            id = __qf_client_bidi(idx % (m->max_bidi < QF_STREAMS ? m->max_bidi : QF_STREAMS));
        }
        break;
    case 1:
        if (blocked) {
            id = (uint64_t)(__qf_u8(in) % 8) << 2 | 3;
        } else {
            if (m->max_uni == 0) goto limit;
            id = __qf_client_uni(idx % (m->max_uni < QF_STREAMS ? m->max_uni : QF_STREAMS));
        }
        expect = QUIC_STREAM_STATE_ERROR;
        break;
    case 2:
        if (blocked) goto limit;
        /* A stream only the server could open, and has not. */
        id = (uint64_t)(__qf_u8(in) % 8) << 2 | (__qf_u8(in) & 1 ? 3 : 1);
        expect = QUIC_STREAM_STATE_ERROR;
        break;
    default:
        goto limit;
    }

    if (0) {
limit:
        id = __qf_beyond(m, blocked && have ? uni : 0, __qf_u8(in));
        expect = QUIC_STREAM_LIMIT_ERROR;
    }

    __qf_vi(f, type);
    __qf_vi(f, id);
    __qf_vi(f, __qf_any(in));

    return expect;
}

static size_t __qf_pcid_active(const qf_model_t* m, uint64_t rpt) {
    size_t n = 0;
    for (size_t i = 0; i < m->pcid_count; i++)
        if (m->pcid[i].seq >= rpt) n++;
    return n;
}

static void __qf_pcid_retire(qf_model_t* m, uint64_t rpt) {
    size_t kept = 0;
    for (size_t i = 0; i < m->pcid_count; i++)
        if (m->pcid[i].seq >= rpt) m->pcid[kept++] = m->pcid[i];
    m->pcid_count = kept;
    if (rpt > m->rpt) m->rpt = rpt;
}

static uint64_t __qf_new_cid_frame(qf_in_t* in, qf_model_t* m, qf_frame_t* f) {
    const uint8_t sub = __qf_u8(in) % 8;

    switch (sub) {
    case 0: case 1: case 2: {   /* a new id, retiring as much as it must */
        const uint64_t seq = m->next_seq;
        uint64_t rpt = m->rpt + __qf_upto(in, seq - m->rpt);
        while (__qf_pcid_active(m, rpt) + 1 > m->cid_limit) rpt++;

        const quiccid_t cid = __qf_pcid_of(seq, 0);
        __qf_new_cid(f, seq, rpt, &cid);

        __qf_pcid_retire(m, rpt);
        m->pcid[m->pcid_count].seq = seq;
        m->pcid[m->pcid_count].cid = cid;
        m->pcid_count++;
        m->next_seq++;
        return QF_OK;
    }
    case 3: {   /* one already given: the same id again is a retransmission */
        if (m->pcid_count == 0) return QF_OK;
        const qf_pcid_t* p = &m->pcid[__qf_u8(in) % m->pcid_count];
        const int other = __qf_u8(in) & 1;
        quiccid_t cid = p->cid;
        if (other) cid.data[0] ^= 0xff;
        __qf_new_cid(f, p->seq, m->rpt, &cid);
        /* §19.15: a different id under the same number. */
        return other ? QUIC_PROTOCOL_VIOLATION : QF_OK;
    }
    case 4: {   /* one retired already: retired again, whatever it says */
        if (m->rpt == 0) return QF_OK;
        const uint64_t seq = __qf_upto(in, m->rpt - 1);
        const quiccid_t cid = __qf_pcid_of(seq, 0x80);
        __qf_new_cid(f, seq, 0, &cid);
        return QF_OK;
    }
    case 5: {   /* a new id with nothing retired, §5.1.1 */
        const uint64_t seq = m->next_seq;
        const quiccid_t cid = __qf_pcid_of(seq, 0);
        __qf_new_cid(f, seq, m->rpt, &cid);
        if (__qf_pcid_active(m, m->rpt) + 1 > m->cid_limit)
            return QUIC_CONNECTION_ID_LIMIT_ERROR;
        m->pcid[m->pcid_count].seq = seq;
        m->pcid[m->pcid_count].cid = cid;
        m->pcid_count++;
        m->next_seq++;
        return QF_OK;
    }
    case 6: {   /* Retire Prior To past the frame's own number, §19.15 */
        const uint64_t seq = m->next_seq;
        const quiccid_t cid = __qf_pcid_of(seq, 0);
        __qf_new_cid(f, seq, seq + 1 + __qf_u8(in), &cid);
        return QUIC_FRAME_ENCODING_ERROR;
    }
    default: {  /* a length outside 1..20, §19.15 */
        const uint64_t seq = m->next_seq;
        __qf_vi(f, QUIC_FRAME_NEW_CONNECTION_ID);
        __qf_vi(f, seq);
        __qf_vi(f, m->rpt);
        const uint8_t len = __qf_u8(in) & 1 ? 0 : 21;
        __qf_byte(f, len);
        __qf_bytes(f, 0x10, len + 16u);
        return QUIC_FRAME_ENCODING_ERROR;
    }
    }
}

static uint64_t __qf_retire(qf_in_t* in, qf_model_t* m, qf_frame_t* f, stand_t* s) {
    const quicconn_t* c = s->conn;

    if (__qf_u8(in) % 4 == 0) {
        /* A number the server never gave out, §19.16. */
        __qf_vi(f, QUIC_FRAME_RETIRE_CONNECTION_ID);
        __qf_vi(f, c->next_cid_seq + 1000 + __qf_u8(in));
        return QUIC_PROTOCOL_VIOLATION;
    }

    if (c->next_cid_seq == 0) return QF_OK;
    const uint64_t seq = __qf_upto(in, c->next_cid_seq - 1);

    for (size_t i = 0; i < QUICCONN_MAX_LOCAL_CIDS; i++) {
        const quiccid_entry_t* e = &c->local_cids[i];
        if (!e->active || e->seq != seq) continue;

        /* Not one the client has not been told of, and not the one it is
         * addressing the server by: §19.16 lets the server close for the
         * second, and either way the client would have nothing to reach it
         * with afterwards. */
        if (!e->announced || __qf_cid_eq(&e->cid, &s->client.dcid)) return QF_OK;
        if (m->retired_count < sizeof m->retired / sizeof m->retired[0])
            m->retired[m->retired_count++] = e->cid;
    }

    __qf_vi(f, QUIC_FRAME_RETIRE_CONNECTION_ID);
    __qf_vi(f, seq);
    return QF_OK;
}

static uint64_t __qf_ack(qf_in_t* in, qf_frame_t* f, stand_t* s) {
    const uint64_t np = s->conn->loss.space[QUIC_ENC_APP].next_pn;
    const uint8_t sub = __qf_u8(in) % 4;
    const int ecn = __qf_u8(in) & 1;

    uint64_t largest, first, expect = QF_OK;
    uint64_t gap = 0, range = 0;
    int ranges = 0;

    if (sub == 1) {
        /* A packet the server never sent, §13.1. */
        largest = np + 1000 + __qf_u16(in);
        first = __qf_upto(in, 8);
        expect = QUIC_PROTOCOL_VIOLATION;
    } else if (sub == 2) {
        /* A range that runs below packet number 0, §19.3.1. */
        largest = __qf_u8(in) % 16;
        if (__qf_u8(in) & 1) {
            first = largest + 1 + __qf_u8(in);
        } else {
            first = 0;
            ranges = 1;
            gap = largest + __qf_u8(in);
            range = __qf_u8(in);
        }
        expect = QUIC_FRAME_ENCODING_ERROR;
    } else {
        if (np == 0) return QF_OK;
        largest = __qf_upto(in, np - 1);
        first = __qf_upto(in, largest);
        const uint64_t floor = largest - first;
        /* A second range where one fits: it needs a gap of at least one packet
         * and something below it. */
        if (sub == 3 && floor >= 3) {
            ranges = 1;
            gap = __qf_upto(in, floor - 3);
            range = __qf_upto(in, floor - gap - 2 - 1);
        }
    }

    __qf_vi(f, ecn ? QUIC_FRAME_ACK_ECN : QUIC_FRAME_ACK);
    __qf_vi(f, largest);
    __qf_vi(f, __qf_upto(in, 5000));
    __qf_vi(f, (uint64_t)ranges);
    __qf_vi(f, first);
    if (ranges) {
        __qf_vi(f, gap);
        __qf_vi(f, range);
    }
    if (ecn) {
        __qf_vi(f, __qf_upto(in, 100));
        __qf_vi(f, __qf_upto(in, 100));
        __qf_vi(f, __qf_upto(in, 100));
    }

    return expect;
}

static uint64_t __qf_frame(qf_in_t* in, qf_model_t* m, qf_pkt_t* pk, qf_frame_t* f, stand_t* s) {
    const uint8_t kind = __qf_u8(in);

    switch (kind % 22) {
    case 0:
        __qf_vi(f, QUIC_FRAME_PING);
        return QF_OK;
    case 1: {
        const size_t n = 1 + __qf_u8(in) % 32;
        for (size_t i = 0; i < n; i++) __qf_byte(f, 0);
        return QF_OK;
    }
    case 2: case 3: case 4:
        return __qf_stream(in, m, f);
    case 5:
        return __qf_stream_bad(in, m, f);
    case 6:
        return __qf_reset(in, m, f);
    case 7:
        return __qf_stream_ctl(in, m, f, QUIC_FRAME_STOP_SENDING);
    case 8:
        return __qf_stream_ctl(in, m, f, QUIC_FRAME_MAX_STREAM_DATA);
    case 9:
        return __qf_stream_ctl(in, m, f, QUIC_FRAME_STREAM_DATA_BLOCKED);
    case 10:
        /* Any value: one below the current limit changes nothing (§19.9). */
        __qf_vi(f, __qf_u8(in) & 1 ? QUIC_FRAME_MAX_DATA : QUIC_FRAME_DATA_BLOCKED);
        __qf_vi(f, __qf_any(in));
        return QF_OK;
    case 11: {
        /* MAX_STREAMS and STREAMS_BLOCKED: no more than 2^60, §19.11, §19.14. */
        static const uint64_t types[] = {
            QUIC_FRAME_MAX_STREAMS_BIDI, QUIC_FRAME_MAX_STREAMS_UNI,
            QUIC_FRAME_STREAMS_BLOCKED_BIDI, QUIC_FRAME_STREAMS_BLOCKED_UNI,
        };
        const uint8_t b = __qf_u8(in);
        __qf_vi(f, types[b % 4]);
        if (b & 0x80) {
            __qf_vi(f, (1ULL << 60) + 1 + __qf_u16(in));
            return QUIC_FRAME_ENCODING_ERROR;
        }
        __qf_vi(f, __qf_any(in) % ((1ULL << 60) + 1));
        return QF_OK;
    }
    case 12: case 13:
        return __qf_new_cid_frame(in, m, f);
    case 14:
        return __qf_retire(in, m, f, s);
    case 15: {
        __qf_vi(f, QUIC_FRAME_PATH_CHALLENGE);
        uint8_t data[8];
        for (int i = 0; i < 8; i++) data[i] = __qf_u8(in);
        for (int i = 0; i < 8; i++) __qf_byte(f, data[i]);
        /* Several in one datagram get one answer, to the last of them: the
         * server keeps a single slot on purpose (quicconn.h,
         * path_response_data), and §8.2.2 leaves the peer to ask again. */
        pk->challenge = 1;
        memcpy(pk->challenge_data, data, 8);
        return QF_OK;
    }
    case 16:
        __qf_vi(f, QUIC_FRAME_PATH_RESPONSE);
        for (int i = 0; i < 8; i++) __qf_byte(f, __qf_u8(in));
        return QF_OK;
    case 17:
        return __qf_ack(in, f, s);
    case 18:
        __qf_vi(f, QUIC_FRAME_CRYPTO);
        if (__qf_u8(in) & 1) {
            /* A TLS KeyUpdate: RFC 9001 §6 names the error. */
            __qf_vi(f, 0);
            __qf_vi(f, 5);
            __qf_byte(f, 24); __qf_byte(f, 0); __qf_byte(f, 0); __qf_byte(f, 1);
            __qf_byte(f, __qf_u8(in) & 1);
            return QUIC_CRYPTO_ERROR(10);
        } else {
            const size_t len = 1 + __qf_u8(in) % 32;
            __qf_vi(f, QUICTLS_MAX_CRYPTO_BUFFER - len + 1 + __qf_upto(in, 100000));
            __qf_vi(f, len);
            __qf_bytes(f, 0x16, len);
            return QUIC_CRYPTO_BUFFER_EXCEEDED;
        }
    case 19: {
        /* Server-only frames, §19.7 and §19.20; an empty token, §19.7. */
        const uint8_t b = __qf_u8(in) % 3;
        if (b == 0) {
            __qf_vi(f, QUIC_FRAME_HANDSHAKE_DONE);
            return QUIC_PROTOCOL_VIOLATION;
        }
        __qf_vi(f, QUIC_FRAME_NEW_TOKEN);
        if (b == 1) {
            __qf_vi(f, 0);
            return QUIC_FRAME_ENCODING_ERROR;
        }
        const size_t len = 1 + __qf_u8(in) % 64;
        __qf_vi(f, len);
        __qf_bytes(f, 0x44, len);
        return QUIC_PROTOCOL_VIOLATION;
    }
    case 20: {
        /* A type this server does not know, extensions included: §12.4 makes
         * it FRAME_ENCODING_ERROR. DATAGRAM (0x30, 0x31) is left out, since a
         * server that implemented RFC 9221 would call it something else. */
        uint64_t type = 0x1f + __qf_upto(in, 0x3fffffff);
        if (type == 0x30 || type == 0x31) type = 0x1f;
        __qf_vi(f, type);
        __qf_bytes(f, 0, __qf_u8(in) % 8);
        return QUIC_FRAME_ENCODING_ERROR;
    }
    default: {
        /* The client closes; the server drains and says nothing (§10.2.2). */
        const int app = __qf_u8(in) & 1;
        __qf_vi(f, app ? QUIC_FRAME_CONNECTION_CLOSE_APP : QUIC_FRAME_CONNECTION_CLOSE);
        __qf_vi(f, __qf_any(in));
        if (!app) __qf_vi(f, __qf_upto(in, 0x1e));
        const size_t len = __qf_u8(in) % 16;
        __qf_vi(f, len);
        __qf_bytes(f, 'r', len);
        return QF_DRAIN;
    }
    }
}

/* A packet's worth of frames, stopping at the first one the server must close
 * on: it never reads what follows. */
static void __qf_build(qf_in_t* in, qf_model_t* m, qf_pkt_t* pk, stand_t* s) {
    const size_t frames = 1 + __qf_u8(in) % 6;

    pk->n = 0;
    pk->expect = QF_OK;
    pk->challenge = 0;

    for (size_t i = 0; i < frames && pk->expect == QF_OK && in->p < in->end; i++) {
        qf_frame_t f;
        f.n = 0;
        qf_model_t next = *m;
        qf_pkt_t pk_next = *pk;

        const uint8_t* at = in->p;
        const uint64_t verdict = __qf_frame(in, &next, &pk_next, &f, s);
        if (s->trace) {
            printf("   frame kind %u: expect 0x%llx:", at < in->end ? *at % 22 : 0,
                   (unsigned long long)verdict);
            for (size_t k = 0; k < f.n && k < 40; k++) printf(" %02x", f.b[k]);
            printf("\n");
        }
        if (f.n == 0 || f.n > sizeof f.b || pk->n + f.n > sizeof pk->b) continue;

        memcpy(pk->b + pk->n, f.b, f.n);
        pk->n += f.n;
        pk->expect = verdict;
        pk->challenge = pk_next.challenge;
        memcpy(pk->challenge_data, pk_next.challenge_data, 8);
        if (verdict == QF_OK || verdict == QF_DRAIN) *m = next;
    }
}

/* ---- Observing the server ---- */

static void __qf_run(stand_t* s, uint64_t horizon_us) {
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

static int __qf_routes(stand_t* s, const quiccid_t* cid) {
    quicconn_t* c = quiccidtable_lookup_acquire(s->table, cid);
    if (c == NULL) return 0;
    connection_s_dec(&c->conn);
    return c == s->conn;
}

static void __qf_check(stand_t* s, qf_model_t* m) {
    quicconn_t* c = s->conn;
    if (c == NULL || c->state != QUICCONN_ACTIVE) return;

    /* §19.9, §19.10: a limit only goes up. */
    if (c->send_flow.limit < m->send_limit) __builtin_trap();
    m->send_limit = c->send_flow.limit;

    for (size_t i = 0; i < QF_STREAMS; i++) {
        const quicstream_t* st = quicconn_stream_find(c, __qf_client_bidi(i));
        if (st == NULL) continue;
        if (st->send_flow.limit < m->stream_send_limit[i]) __builtin_trap();
        m->stream_send_limit[i] = st->send_flow.limit;
    }

    /* The client's ids: exactly the model's, within the limit (§5.1.1). */
    if (c->peer_cid_count > m->cid_limit) __builtin_trap();
    if (c->peer_cid_count != m->pcid_count) __builtin_trap();
    for (size_t i = 0; i < c->peer_cid_count; i++) {
        int found = 0;
        for (size_t j = 0; j < m->pcid_count; j++)
            if (m->pcid[j].seq == c->peer_cids[i].seq &&
                __qf_cid_eq(&m->pcid[j].cid, &c->peer_cids[i].cid)) found = 1;
        if (!found) __builtin_trap();
    }

    /* The server's own: no more than the client allowed, the active ones
     * reachable, the retired ones gone from the routing table (§5.1.2). */
    uint64_t want = c->peer_params.active_connection_id_limit;
    if (want < 2) want = 2;
    if (want > QUICCONN_MAX_LOCAL_CIDS) want = QUICCONN_MAX_LOCAL_CIDS;

    size_t active = 0;
    for (size_t i = 0; i < QUICCONN_MAX_LOCAL_CIDS; i++) {
        if (!c->local_cids[i].active) continue;
        active++;
        if (!__qf_routes(s, &c->local_cids[i].cid)) __builtin_trap();
    }
    if (active > want) __builtin_trap();

    for (size_t i = 0; i < m->retired_count; i++)
        if (quiccidtable_lookup_acquire(s->table, &m->retired[i]) != NULL) __builtin_trap();
}

/* The verdict: accepted, drained, or closed with exactly the code expected. */
static int __qf_verdict(stand_t* s, const qf_pkt_t* pk) {
    const quicclient_t* cl = &s->client;

    if (s->trace)
        printf("   verdict: expected 0x%llx, server %s, close %d (0x%llx%s)\n",
               (unsigned long long)pk->expect,
               s->conn == NULL ? "gone" : s->conn->state == QUICCONN_ACTIVE ? "active" : "not active",
               cl->close_received, (unsigned long long)cl->close_error,
               cl->close_is_app ? ", app" : "");
    if (s->trace) fflush(stdout);

    if (pk->expect == QF_OK) {
        if (cl->close_received) __builtin_trap();
        if (s->conn == NULL || s->conn->state != QUICCONN_ACTIVE) __builtin_trap();
        if (pk->challenge &&
            (!cl->path_response_received || !cl->path_response_matched)) __builtin_trap();
        return 1;
    }

    if (pk->expect == QF_DRAIN) {
        if (cl->close_received) __builtin_trap();
        if (s->conn != NULL && s->conn->state != QUICCONN_DRAINING) __builtin_trap();
        return 0;
    }

    if (!cl->close_received || cl->close_is_app || cl->close_error != pk->expect)
        __builtin_trap();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;

    const size_t budget_before = quicmemory_current();

    stand_t* s = __stand_create(0x5eed);
    if (s == NULL) return 0;
    s->trace = getenv("FUZZ_TRACE") != NULL;

    if (!__start(s)) { __stand_free(s); return 0; }

    qf_in_t in = { data + 1, data + size };

    /* Before the handshake: at most one packet, at Initial or Handshake. */
    const uint8_t pre = data[0] % 3;
    uint64_t pre_expect = QF_OK;
    if (pre != 0) {
        const quic_enc_level_e level = pre == 1 ? QUIC_ENC_INITIAL : QUIC_ENC_HANDSHAKE;
        qf_frame_t f;
        f.n = 0;
        const uint8_t b = __qf_u8(&in);
        if (b % 3 == 0) {
            __qf_vi(&f, QUIC_FRAME_PING);
        } else if (b % 3 == 1) {
            for (size_t i = 0, n = 1 + b % 16; i < n; i++) __qf_byte(&f, 0);
        } else {
            __qf_forbidden(&in, &f);
            pre_expect = QUIC_PROTOCOL_VIOLATION;
        }
        if (!quicclient_inject(&s->client, level, f.b, f.n)) __builtin_trap();
    }

    __qf_run(s, 3000000);

    int alive = 0;
    if (pre_expect == QF_OK) {
        if (s->client.inject_queued) __builtin_trap();   /* it never went out */
        if (!__handshake_done(s) || s->client.close_received) __builtin_trap();
        alive = 1;
    } else {
        if (!s->client.close_received || s->client.close_is_app ||
            s->client.close_error != pre_expect) __builtin_trap();
    }

    qf_model_t m;
    memset(&m, 0, sizeof m);

    if (alive) {
        quicconn_t* c = s->conn;
        if (c == NULL) __builtin_trap();

        m.max_bidi = c->local_params.initial_max_streams_bidi;
        m.max_uni = c->local_params.initial_max_streams_uni;
        m.win_bidi = c->local_params.initial_max_stream_data_bidi_remote;
        m.win_uni = c->local_params.initial_max_stream_data_uni;
        m.max_data = c->local_params.initial_max_data;
        m.cid_limit = c->local_params.active_connection_id_limit;
        if (m.cid_limit > QUICCONN_MAX_PEER_CIDS) m.cid_limit = QUICCONN_MAX_PEER_CIDS;

        /* The client's first id, from the handshake; the model issues the rest. */
        for (size_t i = 0; i < c->peer_cid_count; i++) {
            m.pcid[m.pcid_count].seq = c->peer_cids[i].seq;
            m.pcid[m.pcid_count].cid = c->peer_cids[i].cid;
            m.pcid_count++;
            if (c->peer_cids[i].seq >= m.next_seq) m.next_seq = c->peer_cids[i].seq + 1;
        }
        m.rpt = c->peer_retire_prior_to;
        m.send_limit = c->send_flow.limit;
    }

    for (unsigned packets = 0; alive && packets < 64 && in.p < in.end; packets++) {
        qf_pkt_t pk;
        __qf_build(&in, &m, &pk, s);
        if (pk.n == 0) continue;

        if (pk.challenge) {
            memcpy(s->client.path_challenge_data, pk.challenge_data, 8);
            s->client.path_challenge_sent = 1;
            s->client.path_response_received = 0;
            s->client.path_response_matched = 0;
        }

        if (!quicclient_inject(&s->client, QUIC_ENC_APP, pk.b, pk.n)) __builtin_trap();
        (void)quicclient_flush(&s->client);
        if (s->client.inject_queued) __builtin_trap();

        __qf_run(s, 60000);
        if (s->client_failed) break;

        alive = __qf_verdict(s, &pk);
        __qf_check(s, &m);
    }

    /* The path goes dark: past the idle timeout nothing may be left. */
    s->blackhole_to_server = s->blackhole_to_client = 1;
    __qf_run(s, 400000000);
    if (s->conn != NULL) __builtin_trap();

    __stand_free(s);

    if (quicmemory_current() != budget_before) __builtin_trap();
    return 0;
}

#elif FUZZ_TARGET == FUZZ_QUIC_TOKEN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <openssl/evp.h>

#include "quicretry.h"

/* Address validation tokens (RFC 9000 §8.1): the bytes a client sends back in
 * its Initial, read before its address is known to be real.
 *
 * Three kinds of input:
 *
 *   - bytes nobody issued: never accepted, whatever the kind asked for and
 *     whoever presents them;
 *   - a token quic_token_write issued, for an address, kind, original
 *     connection id and moment the input chooses, read back by a peer, at a
 *     time and with a lifetime the input chooses: the status is the one the
 *     rules below give, the connection id comes back for a Retry token, and
 *     any change to the token -- one bit, a byte less, a byte more, another
 *     key -- makes it unreadable;
 *   - a plaintext of the input's choosing, sealed under the server's key the
 *     way quic_token_write seals: what a holder of the key could make, and the
 *     only way past the AEAD to the reader's parsing. It is accepted only if
 *     it is laid out exactly as quic_token_write lays it out.
 *
 * The rules, in the reader's order: not ours or not laid out as issued, BAD; a
 * kind other than the one expected, WRONG_KIND; issued later than now or more
 * than the lifetime ago, EXPIRED; a peer with no address to compare, BAD; an
 * address other than the one issued to, WRONG_ADDR -- the port is not part of
 * it, for either kind (quicretry.h). Whatever the status, the output
 * connection id is written only on success. */

#define QT_NONCE 12
#define QT_TAG   16

typedef struct {
    const uint8_t* p;
    const uint8_t* end;
} qt_in_t;

static uint8_t __qt_u8(qt_in_t* in) {
    return in->p < in->end ? *in->p++ : 0;
}

static uint64_t __qt_u64(qt_in_t* in) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = v << 8 | __qt_u8(in);
    return v;
}

typedef struct {
    struct sockaddr_storage ss;
    socklen_t len;
    uint8_t addr[16];
    size_t addr_len;          /* 0: nothing a token can be bound to */
} qt_peer_t;

static void __qt_peer_v4(qt_peer_t* pr, const uint8_t a[4], uint16_t port) {
    memset(pr, 0, sizeof *pr);
    struct sockaddr_in* sin = (struct sockaddr_in*)&pr->ss;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    memcpy(&sin->sin_addr, a, 4);
    pr->len = sizeof *sin;
    memcpy(pr->addr, a, 4);
    pr->addr_len = 4;
}

static void __qt_peer_v6(qt_peer_t* pr, const uint8_t a[16], uint16_t port) {
    memset(pr, 0, sizeof *pr);
    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&pr->ss;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    memcpy(&sin6->sin6_addr, a, 16);
    pr->len = sizeof *sin6;
    memcpy(pr->addr, a, 16);
    pr->addr_len = 16;
}

static void __qt_peer_read(qt_in_t* in, qt_peer_t* pr) {
    uint8_t a[16];
    const uint8_t how = __qt_u8(in);
    for (size_t i = 0; i < 16; i++) a[i] = __qt_u8(in);
    const uint16_t port = (uint16_t)(__qt_u8(in) << 8 | __qt_u8(in));

    switch (how % 8) {
    case 0: case 1: case 2:
        __qt_peer_v4(pr, a, port);
        break;
    case 3: case 4: case 5:
        __qt_peer_v6(pr, a, port);
        break;
    case 6:
        /* A family with no address a token can carry. */
        memset(pr, 0, sizeof *pr);
        ((struct sockaddr_un*)&pr->ss)->sun_family = AF_UNIX;
        pr->len = sizeof(struct sockaddr_un);
        break;
    default:
        /* An IPv4 or IPv6 family with a length too short to hold it. */
        __qt_peer_v4(pr, a, port);
        if (how & 0x80) __qt_peer_v6(pr, a, port);
        pr->len = (socklen_t)(__qt_u8(in) % pr->len);
        pr->addr_len = 0;
        break;
    }
}

/* The peer that reads the token back: the one it was issued to, or another. */
static void __qt_reader(qt_in_t* in, const qt_peer_t* issued, qt_peer_t* pr) {
    const uint8_t how = __qt_u8(in) % 6;
    uint16_t port = 0;
    if (issued->ss.ss_family == AF_INET)
        port = ntohs(((const struct sockaddr_in*)&issued->ss)->sin_port);
    else if (issued->ss.ss_family == AF_INET6)
        port = ntohs(((const struct sockaddr_in6*)&issued->ss)->sin6_port);

    if (how >= 3 || issued->addr_len == 0) {
        __qt_peer_read(in, pr);
        return;
    }

    uint8_t a[16];
    memcpy(a, issued->addr, issued->addr_len);
    if (how == 1) port = (uint16_t)(port + 1 + __qt_u8(in));     /* another port */
    if (how == 2) a[__qt_u8(in) % issued->addr_len] ^= (uint8_t)(1 << (__qt_u8(in) % 8));

    if (issued->addr_len == 4) __qt_peer_v4(pr, a, port);
    else __qt_peer_v6(pr, a, port);
}

/* The reader's verdict on a plaintext, worked out independently. */
static quic_token_status_e __qt_expect(const uint8_t* plain, size_t p,
                                       quic_token_kind_e want, const qt_peer_t* peer,
                                       uint64_t now, uint64_t lifetime, quiccid_t* odcid) {
    if (p < 10) return QUIC_TOKEN_BAD;

    const uint8_t kind = plain[0];
    if (kind != QUIC_TOKEN_RETRY && kind != QUIC_TOKEN_NEW_TOKEN) return QUIC_TOKEN_BAD;

    uint64_t issued = 0;
    for (size_t i = 1; i <= 8; i++) issued = issued << 8 | plain[i];

    const size_t alen = plain[9];
    if (alen != 4 && alen != 16) return QUIC_TOKEN_BAD;
    if (10 + alen + 1 > p) return QUIC_TOKEN_BAD;

    const uint8_t* addr = plain + 10;
    const size_t olen = plain[10 + alen];
    const size_t at = 10 + alen + 1;
    if (kind == QUIC_TOKEN_NEW_TOKEN ? olen != 0 : olen > QUIC_MAX_CID_LEN) return QUIC_TOKEN_BAD;
    if (at + olen != p) return QUIC_TOKEN_BAD;

    if (kind != want) return QUIC_TOKEN_WRONG_KIND;
    if (now < issued || now - issued > lifetime) return QUIC_TOKEN_EXPIRED;
    if (peer->addr_len == 0) return QUIC_TOKEN_BAD;
    if (peer->addr_len != alen || memcmp(peer->addr, addr, alen) != 0) return QUIC_TOKEN_WRONG_ADDR;

    odcid->len = (uint8_t)olen;
    memcpy(odcid->data, plain + at, olen);
    return QUIC_TOKEN_OK;
}

static void __qt_fill(quiccid_t* c) {
    memset(c, 0xa5, sizeof *c);
}

static int __qt_untouched(const quiccid_t* c) {
    quiccid_t f;
    __qt_fill(&f);
    return memcmp(c, &f, sizeof f) == 0;
}

/* Read `token` and compare with the verdict; the output id only on success. */
static quic_token_status_e __qt_read(const uint8_t* token, size_t n, const uint8_t key[32],
                                     quic_token_kind_e want, const qt_peer_t* peer,
                                     uint64_t now, uint64_t lifetime, quiccid_t* out) {
    /* Exactly `n` bytes of its own, so a read past the token is caught. */
    uint8_t* copy = malloc(n > 0 ? n : 1);
    if (copy == NULL) return QUIC_TOKEN_BAD;
    if (n > 0) memcpy(copy, token, n);

    __qt_fill(out);
    const quic_token_status_e st = quic_token_read(copy, n, key, want,
                                                   (const struct sockaddr*)&peer->ss, peer->len,
                                                   now, lifetime, out);
    free(copy);

    if (st != QUIC_TOKEN_OK && !__qt_untouched(out)) __builtin_trap();
    return st;
}

static uint64_t __qt_now(qt_in_t* in, uint64_t issued, uint64_t lifetime) {
    switch (__qt_u8(in) % 7) {
    case 0: return issued;
    case 1: return issued + lifetime;                 /* the last moment it is good */
    case 2: return issued + lifetime + 1;             /* the first it is not */
    case 3: return issued - 1;                        /* before it was issued */
    case 4: return issued + __qt_u8(in);
    default: return __qt_u64(in);
    }
}

static uint64_t __qt_lifetime(qt_in_t* in) {
    switch (__qt_u8(in) % 4) {
    case 0: return 30ULL * 1000000;
    case 1: return 0;
    case 2: return UINT64_MAX;
    default: return __qt_u64(in);
    }
}

static const uint8_t __qt_key[32] = {
    0x5c, 0x1e, 0x93, 0x07, 0x4a, 0xb2, 0x66, 0xd0, 0x21, 0x8f, 0x3c, 0xe5, 0x70, 0x19, 0xab, 0x44,
    0x02, 0xfe, 0x57, 0x9d, 0xc3, 0x38, 0x6a, 0x81, 0xb4, 0x0d, 0xe9, 0x52, 0x2f, 0x76, 0xca, 0x13,
};

/* Bytes nobody issued. */
static void __qt_garbage(qt_in_t* in) {
    qt_peer_t peer;
    __qt_peer_read(in, &peer);
    const uint64_t now = __qt_u64(in);
    const uint64_t lifetime = __qt_lifetime(in);
    const size_t n = (size_t)(in->end - in->p);
    quiccid_t out;

    for (int k = 0; k < 2; k++)
        if (__qt_read(in->p, n, __qt_key, (quic_token_kind_e)k, &peer, now, lifetime, &out) !=
            QUIC_TOKEN_BAD) __builtin_trap();
}

/* A token issued by quic_token_write, read back, and damaged. */
static void __qt_issued(qt_in_t* in) {
    const quic_token_kind_e kind = (quic_token_kind_e)(__qt_u8(in) & 1);
    qt_peer_t issued_to;
    __qt_peer_read(in, &issued_to);

    quiccid_t odcid;
    memset(&odcid, 0, sizeof odcid);
    odcid.len = (uint8_t)(__qt_u8(in) % (QUIC_MAX_CID_LEN + 1));
    for (size_t i = 0; i < odcid.len; i++) odcid.data[i] = __qt_u8(in);
    const int no_odcid = (__qt_u8(in) % 16) == 0;

    const uint64_t issued = __qt_u64(in);
    const uint8_t cap_how = __qt_u8(in);

    const size_t want_len = QT_NONCE + 1 + 8 + 1 + issued_to.addr_len + 1 +
                            (kind == QUIC_TOKEN_RETRY ? odcid.len : 0) + QT_TAG;
    const int writable = issued_to.addr_len != 0 && !(kind == QUIC_TOKEN_RETRY && no_odcid);
    const size_t cap = cap_how < 32 ? cap_how : QUIC_TOKEN_MAX_LEN;

    /* Exactly `cap` bytes of its own, so a write past it is caught. */
    uint8_t* dst = malloc(cap > 0 ? cap : 1);
    if (dst == NULL) return;
    const size_t n = quic_token_write(dst, cap, __qt_key, kind,
                                      (const struct sockaddr*)&issued_to.ss, issued_to.len,
                                      no_odcid ? NULL : &odcid, issued);

    if (!writable || cap < want_len) {
        if (n != 0) __builtin_trap();
        free(dst);
        return;
    }
    if (n != want_len || n > QUIC_TOKEN_MAX_LEN) __builtin_trap();

    uint8_t token[QUIC_TOKEN_MAX_LEN + 1];
    memcpy(token, dst, n);
    free(dst);

    /* Read back. */
    const quic_token_kind_e want = (quic_token_kind_e)(__qt_u8(in) & 1);
    qt_peer_t reader;
    __qt_reader(in, &issued_to, &reader);
    const uint64_t lifetime = __qt_lifetime(in);
    const uint64_t now = __qt_now(in, issued, lifetime);

    quic_token_status_e expect;
    if (kind != want) expect = QUIC_TOKEN_WRONG_KIND;
    else if (now < issued || now - issued > lifetime) expect = QUIC_TOKEN_EXPIRED;
    else if (reader.addr_len == 0) expect = QUIC_TOKEN_BAD;
    else if (reader.addr_len != issued_to.addr_len ||
             memcmp(reader.addr, issued_to.addr, reader.addr_len) != 0) expect = QUIC_TOKEN_WRONG_ADDR;
    else expect = QUIC_TOKEN_OK;

    quiccid_t out;
    if (__qt_read(token, n, __qt_key, want, &reader, now, lifetime, &out) != expect)
        __builtin_trap();
    if (expect == QUIC_TOKEN_OK) {
        const size_t olen = kind == QUIC_TOKEN_RETRY ? odcid.len : 0;
        if (out.len != olen || memcmp(out.data, odcid.data, olen) != 0) __builtin_trap();
    }

    /* Damaged, it is nobody's: a bit anywhere, a byte less, a byte more, or
     * another server's key. */
    uint8_t bad[QUIC_TOKEN_MAX_LEN + 1];
    memcpy(bad, token, n);
    bad[__qt_u8(in) % n] ^= (uint8_t)(1 << (__qt_u8(in) % 8));
    if (__qt_read(bad, n, __qt_key, want, &reader, now, lifetime, &out) != QUIC_TOKEN_BAD)
        __builtin_trap();

    if (__qt_read(token, __qt_u8(in) % n, __qt_key, want, &reader, now, lifetime, &out) !=
        QUIC_TOKEN_BAD) __builtin_trap();

    memcpy(bad, token, n);
    bad[n] = __qt_u8(in);
    if (__qt_read(bad, n + 1, __qt_key, want, &reader, now, lifetime, &out) != QUIC_TOKEN_BAD)
        __builtin_trap();

    uint8_t other[32];
    memcpy(other, __qt_key, sizeof other);
    other[__qt_u8(in) % 32] ^= (uint8_t)(1 << (__qt_u8(in) % 8));
    if (__qt_read(token, n, other, want, &reader, now, lifetime, &out) != QUIC_TOKEN_BAD)
        __builtin_trap();
}

/* A plaintext sealed under the key, as quic_token_write seals it. */
static void __qt_sealed(qt_in_t* in) {
    const quic_token_kind_e want = (quic_token_kind_e)(__qt_u8(in) & 1);
    qt_peer_t reader;
    __qt_peer_read(in, &reader);
    const uint64_t lifetime = __qt_lifetime(in);
    const uint64_t now = __qt_u64(in);

    uint8_t nonce[QT_NONCE];
    for (size_t i = 0; i < QT_NONCE; i++) nonce[i] = __qt_u8(in);

    uint8_t plain[QUIC_TOKEN_MAX_LEN];
    size_t p = (size_t)(in->end - in->p);
    if (p > QUIC_TOKEN_MAX_LEN - QT_NONCE - QT_TAG) p = QUIC_TOKEN_MAX_LEN - QT_NONCE - QT_TAG;
    memcpy(plain, in->p, p);

    uint8_t token[QUIC_TOKEN_MAX_LEN];
    memcpy(token, nonce, QT_NONCE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return;
    int len = 0, ok = 1;
    size_t n = QT_NONCE;
    ok = ok && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, __qt_key, nonce) == 1;
    ok = ok && EVP_EncryptUpdate(ctx, token + n, &len, plain, (int)p) == 1;
    if (ok) n += (size_t)len;
    ok = ok && EVP_EncryptFinal_ex(ctx, token + n, &len) == 1;
    if (ok) n += (size_t)len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, QT_TAG, token + n) == 1;
    n += QT_TAG;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) __builtin_trap();

    /* An empty plaintext makes a token of nonce and tag alone, which the
     * reader turns away before decrypting: the same verdict either way. */
    quiccid_t odcid, out;
    const quic_token_status_e expect = __qt_expect(plain, p, want, &reader, now, lifetime, &odcid);
    if (__qt_read(token, n, __qt_key, want, &reader, now, lifetime, &out) != expect)
        __builtin_trap();
    if (expect == QUIC_TOKEN_OK &&
        (out.len != odcid.len || memcmp(out.data, odcid.data, odcid.len) != 0)) __builtin_trap();
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    qt_in_t in = { data + 1, data + size };

    switch (data[0] % 3) {
    case 0: __qt_garbage(&in); break;
    case 1: __qt_issued(&in); break;
    default: __qt_sealed(&in); break;
    }
    return 0;
}

#elif FUZZ_TARGET == FUZZ_QUIC_VERSION

#include "appconfig.h"
#include "json.h"
#include "quicendpoint.h"
#include "quicinvariants.h"
#include "quicversion.h"

/* The version-independent header (RFC 8999) and the Version Negotiation the
 * endpoint owes for it (RFC 9000 §6).
 *
 * A datagram of the input's choosing, padded with zeros to a length the input
 * also chooses, so that the 1200-byte line is crossed without the input being
 * that long. quic_invariants_parse, for any version and any length of the ids
 * this endpoint issues, agrees with a parser written here from RFC 8999: form,
 * version, both ids and where the header ends, or the same refusal.
 *
 * quicendpoint_version_negotiation answers exactly when it must: a long header,
 * not itself Version Negotiation, a version the endpoint does not offer, a
 * datagram of at least 1200 bytes (§14.1), and an answer that fits and is
 * smaller than the datagram. The answer parses back as Version Negotiation with
 * the ids swapped (§17.2.1), the first byte's unused bits as given, every
 * version offered and one reserved (§6.3, §15), and never the version the
 * client asked for -- a client discards a list that has it (§6.2).
 *
 * What the endpoint offers is v1, and v2 when http3_version_2 is on (the top
 * bit of the byte of unused bits turns it on). The target knows that from the
 * configuration it sets, not from quicendpoint_versions: that is the list
 * Version Negotiation is built from, so it is checked here rather than trusted. */

/* The configuration quic_policy_init reads, and nothing else. */
static env_t __qv_env;

env_t* env(void) {
    return &__qv_env;
}

static void __qv_version_2(int on) {
    static json_doc_t* docs[2];
    static int current = -1;
    if (on == current) return;
    if (docs[on] == NULL) {
        docs[on] = json_parse(on ? "{\"http3_version_2\": true}" : "{\"http3_version_2\": false}");
        if (docs[on] == NULL) abort();
    }
    __qv_env.custom_store = docs[on];
    if (!quic_policy_init()) abort();
    current = on;
}

static quicinv_status_e __qv_parse(const uint8_t* b, size_t len, size_t lcid,
                                   int* is_long, uint32_t* version,
                                   quiccid_t* dcid, quiccid_t* scid, size_t* header_len) {
    if (len < 1) return QUICINV_TRUNCATED;
    *is_long = (b[0] & 0x80) != 0;
    *version = 0;
    memset(dcid, 0, sizeof *dcid);
    memset(scid, 0, sizeof *scid);

    if (!*is_long) {
        if (1 + lcid > len) return QUICINV_TRUNCATED;
        dcid->len = (uint8_t)lcid;
        memcpy(dcid->data, b + 1, lcid);
        *header_len = 1 + lcid;
        return QUICINV_OK;
    }

    if (len < 5) return QUICINV_TRUNCATED;
    *version = (uint32_t)b[1] << 24 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 8 | b[4];

    size_t off = 5;
    quiccid_t* ids[2] = { dcid, scid };
    for (int i = 0; i < 2; i++) {
        if (off >= len) return QUICINV_TRUNCATED;
        const size_t n = b[off++];
        if (n > QUIC_MAX_CID_LEN) return QUICINV_CID_TOO_LONG;
        if (off + n > len) return QUICINV_TRUNCATED;
        ids[i]->len = (uint8_t)n;
        memcpy(ids[i]->data, b + off, n);
        off += n;
    }
    *header_len = off;
    return QUICINV_OK;
}

static int __qv_cid_eq(const quiccid_t* a, const quiccid_t* b) {
    return a->len == b->len && memcmp(a->data, b->data, a->len) == 0;
}

static uint32_t __qv_be32(const uint8_t* p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 5) return 0;

    const size_t lcid = data[0] % (QUIC_MAX_CID_LEN + 2);   /* one past the cap too */
    const size_t declared = ((size_t)data[1] << 8 | data[2]) % 2049;
    const uint8_t unused = data[3];
    const uint8_t cap_how = data[4];
    const uint8_t* body = data + 5;
    const size_t body_len = size - 5;

    /* Exactly `len` bytes of its own, so a read past the datagram is caught. */
    const size_t len = body_len > declared ? body_len : declared;
    uint8_t* dgram = malloc(len > 0 ? len : 1);
    if (dgram == NULL) return 0;
    memset(dgram, 0, len > 0 ? len : 1);
    memcpy(dgram, body, body_len);

    /* The parser, for whatever id length the endpoint might issue. */
    quicinvariants_t inv;
    const quicinv_status_e st = quic_invariants_parse(dgram, len, lcid, &inv);
    int is_long;
    uint32_t version;
    quiccid_t dcid, scid;
    size_t header_len = 0;
    const quicinv_status_e want = lcid > QUIC_MAX_CID_LEN
        ? QUICINV_CID_TOO_LONG
        : __qv_parse(dgram, len, lcid, &is_long, &version, &dcid, &scid, &header_len);

    if (st != want) __builtin_trap();
    if (st == QUICINV_OK) {
        if (inv.long_header != is_long || inv.version != version) __builtin_trap();
        if (!__qv_cid_eq(&inv.dcid, &dcid) || !__qv_cid_eq(&inv.scid, &scid)) __builtin_trap();
        if (inv.header_len != header_len || inv.first != dgram[0]) __builtin_trap();
    }

    /* The endpoint's answer, for the id length it does issue. */
    if (quic_invariants_parse(dgram, len, QUIC_LOCAL_CID_LEN, &inv) != QUICINV_OK) {
        free(dgram);
        return 0;
    }

    const int v2 = (unused & 0x80) != 0;
    __qv_version_2(v2);
    const uint32_t offered[2] = { QUIC_VERSION_1, QUIC_VERSION_2 };
    const size_t offered_count = v2 ? 2 : 1;
    int speaks = 0;
    for (size_t i = 0; i < offered_count; i++)
        if (offered[i] == inv.version) speaks = 1;

    /* The list the connection layer chooses from (RFC 9368 §2.3) is the same set. */
    const quicversion_t* listed_by[8];
    if (quicendpoint_versions(listed_by, 8) != offered_count) __builtin_trap();
    for (size_t i = 0; i < offered_count; i++) {
        int found = 0;
        for (size_t k = 0; k < offered_count; k++)
            if (listed_by[k]->number == offered[i]) found = 1;
        if (!found) __builtin_trap();
    }

    const size_t need = 7 + inv.dcid.len + inv.scid.len + 4 * (offered_count + 1);
    const size_t cap = cap_how < 128 ? cap_how : 256;
    const int owed = inv.long_header && inv.version != 0 && !speaks &&
                     len >= QUIC_MIN_INITIAL_DATAGRAM;
    const int sent = owed && need <= cap && need < len;

    uint8_t* vn = malloc(cap > 0 ? cap : 1);
    if (vn == NULL) { free(dgram); return 0; }
    const size_t n = quicendpoint_version_negotiation(&inv, len, unused, vn, cap);

    if (!sent) {
        if (n != 0) __builtin_trap();
        free(vn);
        free(dgram);
        return 0;
    }
    if (n != need) __builtin_trap();

    quicinvariants_t back;
    if (quic_invariants_parse(vn, n, QUIC_LOCAL_CID_LEN, &back) != QUICINV_OK) __builtin_trap();
    if (!quic_invariants_is_version_negotiation(&back)) __builtin_trap();
    if ((vn[0] & 0x7f) != (unused & 0x7f)) __builtin_trap();
    if (!__qv_cid_eq(&back.dcid, &inv.scid) || !__qv_cid_eq(&back.scid, &inv.dcid)) __builtin_trap();
    if ((n - back.header_len) % 4 != 0) __builtin_trap();

    size_t reserved = 0, listed = 0;
    for (size_t i = back.header_len; i + 4 <= n; i += 4) {
        const uint32_t v = __qv_be32(vn + i);
        if (v == inv.version) __builtin_trap();
        if ((v & 0x0f0f0f0fu) == 0x0a0a0a0au) { reserved++; continue; }
        int found = 0;
        for (size_t k = 0; k < offered_count; k++)
            if (offered[k] == v) found = 1;
        if (!found) __builtin_trap();
        listed++;
    }
    if (reserved != 1 || listed != offered_count) __builtin_trap();

    free(vn);
    free(dgram);
    return 0;
}

#elif FUZZ_TARGET == FUZZ_H3_SESSION

#include "h3frame.h"
#include "h3priority.h"
#include "h3session.h"
#include "qpack.h"
#include "quicmemory.h"
#include "quictime.h"

/* The HTTP/3 session: the client's unidirectional streams and what the server
 * makes of them (RFC 9114 §6.2, §7.2; RFC 9204 §4.2).
 *
 * The input becomes a script of units -- bytes on one of eight client
 * unidirectional streams, a FIN, a reset, a step of the clock, a request
 * stream's cancellation (the abort budget) or acceptance (priority credit) --
 * and the script is played three times against fresh sessions: each unit
 * whole, one byte at a time, and in pieces of sizes the input picks. The
 * verdict of every unit and the session's state at the end must be the same
 * all three times.
 *
 * In the generated mode (first byte even) the units are built by a model of
 * the session: a control stream whose first frame is SETTINGS, GOAWAY and
 * MAX_PUSH_ID moving the way they may, PRIORITY_UPDATE, CANCEL_PUSH, QPACK
 * encoder and decoder instructions, grease and unknown streams and frames,
 * floods of frames that advance nothing -- correct except for at most one
 * violation, which ends the script. The model predicts each verdict exactly:
 * a second control, encoder or decoder stream or a push stream
 * (H3_STREAM_CREATION_ERROR), a frame before SETTINGS (H3_MISSING_SETTINGS),
 * DATA, HEADERS or an HTTP/2 type on the control stream
 * (H3_FRAME_UNEXPECTED), a critical stream closed (H3_CLOSED_CRITICAL_STREAM),
 * a GOAWAY that raises its id or a MAX_PUSH_ID that lowers it (H3_ID_ERROR),
 * an HTTP/2 or repeated setting (H3_SETTINGS_ERROR), a frame over the size
 * the parser accumulates or a budget spent (H3_EXCESSIVE_LOAD), a table
 * capacity above the advertised one or an insertion that does not fit
 * (QPACK_ENCODER_STREAM_ERROR), an Insert Count Increment for an encoder that
 * inserted nothing (QPACK_DECODER_STREAM_ERROR). Its end state -- the peer's
 * settings, GOAWAY and MAX_PUSH_ID, the budgets, the queued priorities --
 * must be the session's.
 *
 * Where RFC 9114 has two MUSTs for one frame the model follows the server:
 * DATA or an HTTP/2 type as the first control frame is H3_FRAME_UNEXPECTED
 * (§7.2.1, §11.2.1) rather than H3_MISSING_SETTINGS (§6.2.1), and grease or
 * unknown frames may come before SETTINGS (§9).
 *
 * In the raw mode (first byte odd) the bytes are the input's, on streams of
 * any type: nothing is predicted, the three plays must agree.
 *
 * After every unit, in every play: no budget below zero, the control bucket
 * no fuller than its burst. At the end the QUIC memory budget is back where it
 * started. */

#define HS_STREAMS  8
#define HS_UNITS    192
#define HS_POOL     (48 * 1024)
#define HS_RATE     100          /* h3session.c's defaults: no policy is loaded */
#define HS_BURST    200
#define HS_CREDIT0  256
#define HS_CREDIT_PER_REQUEST 4
#define HS_CREDIT_MAX 1024
#define HS_QCAP     4096         /* the dynamic table we advertise */
#define HS_NOT_RUN  UINT64_MAX   /* a unit after the connection closed, or on a dead stream */

enum { HS_BYTES, HS_RESET, HS_TIME, HS_ABORT, HS_EARN };

typedef struct {
    uint8_t  kind;
    uint8_t  stream;
    uint8_t  fin;
    uint32_t off, len;
    uint64_t dt_ms;
    int      expect_action;
    uint64_t expect_error;
} hs_unit_t;

typedef struct {
    hs_unit_t u[HS_UNITS];
    size_t    count;
    uint8_t   pool[HS_POOL];
    size_t    used;
    int       predicted;
} hs_script_t;

typedef struct {
    h3settings_t peer;
    int          peer_seen;
    int          mps, gs;
    uint64_t     mp, gid;
    int64_t      ctrl_tokens, abort_tokens, credit;
    size_t       prio_n;
    h3session_priority_t prio[H3SESSION_PRIORITY_QUEUE];
} hs_state_t;

typedef struct {
    int      action[HS_UNITS];
    uint64_t error[HS_UNITS];
    hs_state_t end;
    uint8_t  bits;
    uint64_t ins, evi;
} hs_trace_t;

typedef struct {
    const uint8_t* p;
    const uint8_t* end;
} hs_in_t;

static uint64_t __hs_now_us;
static uint64_t __hs_clock(void) { return __hs_now_us; }

static uint8_t __hs_u8(hs_in_t* in) {
    return in->p < in->end ? *in->p++ : 0;
}

static uint64_t __hs_u16(hs_in_t* in) {
    const uint64_t hi = __hs_u8(in);
    return hi << 8 | __hs_u8(in);
}

/* ---- Writing units ---- */

static hs_unit_t* __hs_unit(hs_script_t* sc, uint8_t kind, uint8_t stream) {
    if (sc->count >= HS_UNITS) return NULL;
    hs_unit_t* u = &sc->u[sc->count++];
    memset(u, 0, sizeof *u);
    u->kind = kind;
    u->stream = stream;
    u->off = (uint32_t)sc->used;
    return u;
}

static void __hs_put(hs_script_t* sc, hs_unit_t* u, uint8_t b) {
    if (sc->used < HS_POOL) {
        sc->pool[sc->used++] = b;
        u->len++;
    }
}

/* A varint in the width the caller asks for, or the shortest when it cannot. */
static void __hs_vi_w(hs_script_t* sc, hs_unit_t* u, uint64_t v, unsigned width) {
    unsigned need = v < 64 ? 1 : v < 16384 ? 2 : v < (1u << 30) ? 4 : 8;
    unsigned w = width < need ? need : width > 8 ? 8 : width;
    if (w == 3) w = 4;
    if (w > 4 && w < 8) w = 8;
    const uint8_t tag = w == 1 ? 0x00 : w == 2 ? 0x40 : w == 4 ? 0x80 : 0xc0;
    for (int i = (int)w - 1; i >= 0; i--) {
        uint8_t b = (uint8_t)(v >> (i * 8));
        if (i == (int)w - 1) b = (uint8_t)(b | tag);
        __hs_put(sc, u, b);
    }
}

static void __hs_vi(hs_script_t* sc, hs_unit_t* u, uint64_t v) {
    __hs_vi_w(sc, u, v, 1);
}

static size_t __hs_vi_len(uint64_t v) {
    return v < 64 ? 1 : v < 16384 ? 2 : v < (1u << 30) ? 4 : 8;
}

static void __hs_frame(hs_script_t* sc, hs_unit_t* u, uint64_t type,
                       const uint8_t* payload, size_t len) {
    __hs_vi(sc, u, type);
    __hs_vi(sc, u, len);
    for (size_t i = 0; i < len; i++) __hs_put(sc, u, payload[i]);
}

/* An RFC 7541 §5.1 integer with an N-bit prefix under `flags`. */
static void __hs_prefix_int(hs_script_t* sc, hs_unit_t* u, uint8_t flags, unsigned bits, uint64_t v) {
    const uint64_t max = (1u << bits) - 1;
    if (v < max) {
        __hs_put(sc, u, (uint8_t)(flags | v));
        return;
    }
    __hs_put(sc, u, (uint8_t)(flags | max));
    v -= max;
    while (v >= 128) {
        __hs_put(sc, u, (uint8_t)(0x80 | (v & 0x7f)));
        v >>= 7;
    }
    __hs_put(sc, u, (uint8_t)v);
}

static size_t __hs_pvi(uint8_t* b, uint64_t v) {
    if (v < 64) { b[0] = (uint8_t)v; return 1; }
    if (v < 16384) { b[0] = (uint8_t)(0x40 | v >> 8); b[1] = (uint8_t)v; return 2; }
    if (v < (1u << 30)) {
        b[0] = (uint8_t)(0x80 | v >> 24);
        for (int i = 1; i < 4; i++) b[i] = (uint8_t)(v >> ((3 - i) * 8));
        return 4;
    }
    b[0] = (uint8_t)(0xc0 | v >> 56);
    for (int i = 1; i < 8; i++) b[i] = (uint8_t)(v >> ((7 - i) * 8));
    return 8;
}

/* ---- The model ---- */

enum { HS_NONE, HS_CONTROL, HS_ENC, HS_DEC, HS_IGNORED, HS_DEAD };

typedef struct {
    int      kind[HS_STREAMS];
    int      have[4];                /* control, encoder, decoder already open */
    int      settings_seen;
    h3settings_t peer;
    int      gs, mps;
    uint64_t gid, mp;
    uint64_t now_ms;
    int64_t  ctrl_tokens, abort_tokens, credit;
    uint64_t ctrl_epoch, abort_epoch;
    uint64_t qcap;                   /* the capacity the encoder stream set */
    h3session_priority_t prio[H3SESSION_PRIORITY_QUEUE];
    size_t   prio_head, prio_n;
    int      closed;                 /* a connection error was predicted */
} hs_model_t;

static int __hs_spend(int64_t* tokens, uint64_t* epoch, uint64_t now) {
    const uint64_t elapsed = now > *epoch ? now - *epoch : 0;
    *epoch = now;
    *tokens += (int64_t)elapsed * HS_RATE;
    if (*tokens > HS_BURST * 1000) *tokens = HS_BURST * 1000;
    if (*tokens < 1000) return 0;
    *tokens -= 1000;
    return 1;
}

static int __hs_find(const hs_model_t* m, int kind) {
    for (int i = 0; i < HS_STREAMS; i++)
        if (m->kind[i] == kind) return i;
    return -1;
}

static int __hs_free_slot(const hs_model_t* m) {
    return __hs_find(m, HS_NONE);
}

static void __hs_expect(hs_model_t* m, hs_unit_t* u, uint64_t error) {
    if (u == NULL) return;
    if (error == 0) {
        u->expect_action = H3SESSION_OK;
        u->expect_error = 0;
        return;
    }
    u->expect_action = H3SESSION_CONN_ERROR;
    u->expect_error = error;
    m->closed = 1;
}

/* Open a stream: its type, nothing else. */
static void __hs_gen_open(hs_in_t* in, hs_model_t* m, hs_script_t* sc) {
    const int slot = __hs_free_slot(m);
    if (slot < 0) return;
    hs_unit_t* u = __hs_unit(sc, HS_BYTES, (uint8_t)slot);
    if (u == NULL) return;

    const uint8_t b = __hs_u8(in);
    const unsigned width = 1u << (__hs_u8(in) % 4);
    uint64_t type;
    int kind;

    switch (b % 8) {
    case 0: case 1: type = H3_UNI_STREAM_CONTROL; kind = HS_CONTROL; break;
    case 2: type = H3_UNI_STREAM_QPACK_ENCODER; kind = HS_ENC; break;
    case 3: type = H3_UNI_STREAM_QPACK_DECODER; kind = HS_DEC; break;
    case 4: type = 0x21 + 0x1f * (uint64_t)__hs_u16(in); kind = HS_IGNORED; break;   /* grease */
    case 5: type = H3_UNI_STREAM_PUSH; kind = HS_DEAD; break;
    default:
        /* Unknown and not grease. */
        type = 0x04 + __hs_u16(in);
        if (type >= 0x21 && (type - 0x21) % 0x1f == 0) type++;
        kind = HS_DEAD;
        break;
    }

    __hs_vi_w(sc, u, type, width);

    if (type == H3_UNI_STREAM_PUSH) {
        __hs_expect(m, u, H3_STREAM_CREATION_ERROR);
        return;
    }
    if (kind == HS_CONTROL || kind == HS_ENC || kind == HS_DEC) {
        if (m->have[kind]) {
            __hs_expect(m, u, H3_STREAM_CREATION_ERROR);
            return;
        }
        m->have[kind] = 1;
    }
    if (kind == HS_DEAD) {
        /* Unknown: STOP_SENDING, paid for out of the control bucket. */
        if (!__hs_spend(&m->ctrl_tokens, &m->ctrl_epoch, m->now_ms)) {
            __hs_expect(m, u, H3_EXCESSIVE_LOAD);
            return;
        }
        u->expect_action = H3SESSION_STOP_SENDING;
        u->expect_error = H3_STREAM_CREATION_ERROR;
    } else {
        __hs_expect(m, u, 0);
    }
    m->kind[slot] = kind;
}

static void __hs_prio_queue(hs_model_t* m, uint64_t id, const h3priority_t* p) {
    if (m->prio_n == H3SESSION_PRIORITY_QUEUE) {
        m->prio_head = (m->prio_head + 1) % H3SESSION_PRIORITY_QUEUE;
        m->prio_n--;
    }
    h3session_priority_t* e = &m->prio[(m->prio_head + m->prio_n) % H3SESSION_PRIORITY_QUEUE];
    e->stream_id = id;
    e->priority = *p;
    m->prio_n++;
}

/* A setting the server knows, with a value it accepts. */
static void __hs_setting(hs_in_t* in, h3settings_t* peer, uint8_t* pl, size_t* n, uint32_t* seen) {
    uint64_t id, value;
    const uint8_t b = __hs_u8(in);

    switch (b % 7) {
    case 0: id = H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY; value = __hs_u16(in) << (__hs_u8(in) % 24); break;
    case 1: id = H3_SETTINGS_MAX_FIELD_SECTION_SIZE; value = __hs_u16(in) << (__hs_u8(in) % 40); break;
    case 2: id = H3_SETTINGS_QPACK_BLOCKED_STREAMS; value = __hs_u16(in); break;
    case 3: id = H3_SETTINGS_ENABLE_CONNECT_PROTOCOL; value = __hs_u8(in) & 1; break;
    case 4: id = 0x21 + 0x1f * (uint64_t)__hs_u16(in); value = __hs_u16(in); break;   /* grease */
    default:
        /* Unknown, neither an HTTP/2 one nor grease. */
        id = (b & 0x80) ? 0x00 : 0x09 + __hs_u8(in);
        if (id >= 0x21 && (id - 0x21) % 0x1f == 0) id++;
        value = __hs_u16(in);
        break;
    }
    value &= 0x3fffffffffffffffULL;

    unsigned bit = id == H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY ? 1
                 : id == H3_SETTINGS_MAX_FIELD_SECTION_SIZE ? 2
                 : id == H3_SETTINGS_QPACK_BLOCKED_STREAMS ? 4
                 : id == H3_SETTINGS_ENABLE_CONNECT_PROTOCOL ? 8 : 0;
    if (bit & *seen) return;          /* the valid form repeats nothing */
    *seen |= bit;

    *n += __hs_pvi(pl + *n, id);
    *n += __hs_pvi(pl + *n, value);

    if (id == H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY) peer->qpack_max_table_capacity = value;
    if (id == H3_SETTINGS_MAX_FIELD_SECTION_SIZE) peer->max_field_section_size = value;
    if (id == H3_SETTINGS_QPACK_BLOCKED_STREAMS) peer->qpack_blocked_streams = value;
    if (id == H3_SETTINGS_ENABLE_CONNECT_PROTOCOL) peer->enable_connect_protocol = (int)value;
}

/* One frame on the control stream. */
static void __hs_gen_control(hs_in_t* in, hs_model_t* m, hs_script_t* sc) {
    const int slot = __hs_find(m, HS_CONTROL);
    if (slot < 0) { __hs_gen_open(in, m, sc); return; }
    hs_unit_t* u = __hs_unit(sc, HS_BYTES, (uint8_t)slot);
    if (u == NULL) return;

    uint8_t pl[256];
    size_t n = 0;
    const uint8_t kind = __hs_u8(in) % 14;
    uint64_t error = 0;

    switch (kind) {
    case 0: case 1: {   /* SETTINGS */
        h3settings_t peer;
        h3settings_defaults(&peer);
        uint32_t seen = 0;
        const size_t count = __hs_u8(in) % 6;
        for (size_t i = 0; i < count; i++) __hs_setting(in, &peer, pl, &n, &seen);
        __hs_frame(sc, u, H3_FRAME_SETTINGS, pl, n);
        if (m->settings_seen) { error = H3_FRAME_UNEXPECTED; break; }
        m->settings_seen = 1;
        m->peer = peer;
        break;
    }
    case 2: {           /* SETTINGS, wrong */
        h3settings_t peer;
        h3settings_defaults(&peer);
        uint32_t seen = 0;
        __hs_setting(in, &peer, pl, &n, &seen);
        const uint8_t how = __hs_u8(in) % 4;
        if (how == 0) {
            n += __hs_pvi(pl + n, 0x02 + __hs_u8(in) % 4);       /* HTTP/2's */
            n += __hs_pvi(pl + n, __hs_u8(in));
            error = H3_SETTINGS_ERROR;
        } else if (how == 1) {
            static const uint64_t known[] = {
                H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
                H3_SETTINGS_QPACK_BLOCKED_STREAMS, H3_SETTINGS_ENABLE_CONNECT_PROTOCOL,
            };
            const uint64_t id = known[__hs_u8(in) % 4];
            n += __hs_pvi(pl + n, id);
            n += __hs_pvi(pl + n, 0);
            n += __hs_pvi(pl + n, id);                             /* again */
            n += __hs_pvi(pl + n, 1);
            error = H3_SETTINGS_ERROR;
        } else if (how == 2) {
            n = 0;
            if (__hs_u8(in) & 1) {
                n += __hs_pvi(pl + n, H3_SETTINGS_QPACK_BLOCKED_STREAMS);
                n += __hs_pvi(pl + n, 0);
            }
            n += __hs_pvi(pl + n, H3_SETTINGS_ENABLE_CONNECT_PROTOCOL);
            n += __hs_pvi(pl + n, 2 + __hs_u8(in));
            error = H3_SETTINGS_ERROR;
        } else {
            n += __hs_pvi(pl + n, 0x4000 + __hs_u8(in));           /* an id and no value */
            error = H3_FRAME_ERROR;
        }
        __hs_frame(sc, u, H3_FRAME_SETTINGS, pl, n);
        if (m->settings_seen) error = H3_FRAME_UNEXPECTED;
        break;
    }
    case 3: case 4: {   /* GOAWAY */
        const int wrong = kind == 4 ? __hs_u8(in) % 3 : -1;
        /* The same id again as often as a lower one: repeating is legal. */
        const uint8_t pick = __hs_u8(in);
        uint64_t id = !m->gs ? __hs_u16(in) << (pick % 30)
                    : (pick & 1) ? m->gid : __hs_u16(in) % (m->gid + 1);
        if (wrong == 0) id = m->gs ? m->gid + 1 + __hs_u8(in) : id;
        n = __hs_pvi(pl, id);
        if (wrong == 1) pl[n++] = __hs_u8(in);                    /* a byte past the id */
        if (wrong == 2) n = 0;                                     /* no id */
        __hs_frame(sc, u, H3_FRAME_GOAWAY, pl, n);

        if (!m->settings_seen) { error = H3_MISSING_SETTINGS; break; }
        if (!__hs_spend(&m->ctrl_tokens, &m->ctrl_epoch, m->now_ms)) { error = H3_EXCESSIVE_LOAD; break; }
        if (wrong == 1 || wrong == 2) { error = H3_FRAME_ERROR; break; }
        if (m->gs && id > m->gid) { error = H3_ID_ERROR; break; }
        m->gs = 1;
        m->gid = id;
        break;
    }
    case 5: {           /* MAX_PUSH_ID */
        const int lower = (__hs_u8(in) % 4) == 0 && m->mps && m->mp > 0;
        const uint8_t pick = __hs_u8(in);
        uint64_t id = !m->mps ? __hs_u16(in) : (pick & 1) ? m->mp : m->mp + 1 + __hs_u16(in);
        if (lower) id = m->mp - 1 - __hs_u8(in) % m->mp;
        n = __hs_pvi(pl, id);
        __hs_frame(sc, u, H3_FRAME_MAX_PUSH_ID, pl, n);

        if (!m->settings_seen) { error = H3_MISSING_SETTINGS; break; }
        if (!__hs_spend(&m->ctrl_tokens, &m->ctrl_epoch, m->now_ms)) { error = H3_EXCESSIVE_LOAD; break; }
        if (lower) { error = H3_ID_ERROR; break; }
        m->mps = 1;
        m->mp = id;
        break;
    }
    case 6: {           /* CANCEL_PUSH: we promise nothing, so any id is too high */
        n = __hs_pvi(pl, __hs_u16(in));
        __hs_frame(sc, u, H3_FRAME_CANCEL_PUSH, pl, n);
        error = m->settings_seen ? H3_ID_ERROR : H3_MISSING_SETTINGS;
        break;
    }
    case 7: case 8: {   /* PRIORITY_UPDATE */
        static const char* fields[] = {
            "", "u=1", "u=5, i", "i", "u=7;x=1", "u=0, i=?0", "u=3,foo=bar",
            "u=", "=", "u=1,,", "u=8", "i=?2", "(", "u=1;", " u=2",
        };
        const uint8_t b = __hs_u8(in);
        const int push = kind == 8 && (b & 0x80);
        const int bad_id = kind == 8 && !push;
        uint64_t element = (uint64_t)(__hs_u8(in) % 64) << 2;
        if (bad_id) element |= 1 + __hs_u8(in) % 3;
        n = __hs_pvi(pl, element);
        const char* f = fields[b % (sizeof fields / sizeof fields[0])];
        memcpy(pl + n, f, strlen(f));
        n += strlen(f);
        __hs_frame(sc, u, push ? H3_FRAME_PRIORITY_UPDATE_PUSH : H3_FRAME_PRIORITY_UPDATE_REQUEST, pl, n);

        if (!m->settings_seen) { error = H3_MISSING_SETTINGS; break; }
        if (m->credit <= 0) { error = H3_EXCESSIVE_LOAD; break; }
        m->credit--;
        if (push || bad_id) { error = H3_ID_ERROR; break; }
        h3priority_t prio;
        if (!h3priority_parse((const uint8_t*)f, strlen(f), &prio)) { error = H3_FRAME_ERROR; break; }
        __hs_prio_queue(m, element, &prio);
        break;
    }
    case 9: {           /* request-stream frames */
        const uint8_t b = __hs_u8(in) % 3;
        const size_t len = __hs_u8(in) % 8;
        for (size_t i = 0; i < len; i++) pl[i] = (uint8_t)(0x80 + i);
        if (b == 0) {
            __hs_frame(sc, u, H3_FRAME_DATA, pl, len);
            error = H3_FRAME_UNEXPECTED;
        } else {
            __hs_frame(sc, u, b == 1 ? H3_FRAME_HEADERS : H3_FRAME_PUSH_PROMISE, pl, len);
            error = m->settings_seen ? H3_FRAME_UNEXPECTED : H3_MISSING_SETTINGS;
        }
        break;
    }
    case 10: {          /* an HTTP/2 type */
        static const uint64_t h2[] = { 0x02, 0x06, 0x08, 0x09 };
        __hs_frame(sc, u, h2[__hs_u8(in) % 4], pl, __hs_u8(in) % 4);
        error = H3_FRAME_UNEXPECTED;
        break;
    }
    case 11: {          /* more than the parser accumulates */
        static const uint64_t kept[] = {
            H3_FRAME_SETTINGS, H3_FRAME_GOAWAY, H3_FRAME_MAX_PUSH_ID, H3_FRAME_HEADERS,
            H3_FRAME_PRIORITY_UPDATE_REQUEST,
        };
        __hs_vi(sc, u, kept[__hs_u8(in) % 5]);
        __hs_vi(sc, u, H3FRAME_MAX_ACCUMULATED + 1 + __hs_u8(in));
        error = H3_EXCESSIVE_LOAD;
        break;
    }
    default: {          /* frames that advance nothing: one grease or unknown, or a flood */
        const size_t frames = kind == 13 ? 1 + (size_t)__hs_u8(in) * 2 : 1;
        for (size_t i = 0; i < frames && error == 0; i++) {
            uint64_t type = 0x21 + 0x1f * (uint64_t)(__hs_u8(in) % 64);
            if (kind == 12 && (__hs_u8(in) & 1))
                type = 0x0a + __hs_u8(in) % 0x14;      /* 0x0a-0x1d: unknown, not HTTP/2's */
            if (type == H3_FRAME_MAX_PUSH_ID) type = 0x0e;
            const size_t len = __hs_u8(in) % 4;
            __hs_frame(sc, u, type, pl, len);
            if (!__hs_spend(&m->ctrl_tokens, &m->ctrl_epoch, m->now_ms)) error = H3_EXCESSIVE_LOAD;
        }
        break;
    }
    }

    __hs_expect(m, u, error);
}

/* One QPACK encoder instruction (RFC 9204 §4.3), onto our decoder's table. */
static void __hs_gen_encoder(hs_in_t* in, hs_model_t* m, hs_script_t* sc) {
    const int slot = __hs_find(m, HS_ENC);
    if (slot < 0) { __hs_gen_open(in, m, sc); return; }
    hs_unit_t* u = __hs_unit(sc, HS_BYTES, (uint8_t)slot);
    if (u == NULL) return;

    uint64_t error = 0;
    if (__hs_u8(in) & 1) {
        /* Set Dynamic Table Capacity. */
        uint64_t cap = __hs_u16(in) % (HS_QCAP + 1);
        if ((__hs_u8(in) % 8) == 0) cap = HS_QCAP + 1 + __hs_u8(in);
        __hs_prefix_int(sc, u, 0x20, 5, cap);
        if (cap > HS_QCAP) error = QPACK_ENCODER_STREAM_ERROR;
        else m->qcap = cap;
    } else {
        /* Insert With Literal Name: a lower-case name, a printable value. */
        const size_t nl = 1 + __hs_u8(in) % 24;
        size_t vl = __hs_u8(in) % 40;
        if ((__hs_u8(in) % 8) == 0) vl = __hs_u16(in) % 4200;
        __hs_prefix_int(sc, u, 0x40, 5, nl);
        for (size_t i = 0; i < nl; i++) __hs_put(sc, u, (uint8_t)('a' + (i * 7 + nl) % 26));
        __hs_prefix_int(sc, u, 0x00, 7, vl);
        for (size_t i = 0; i < vl; i++) __hs_put(sc, u, (uint8_t)('0' + (i * 3) % 40));
        if (nl + vl + 32 > m->qcap) error = QPACK_ENCODER_STREAM_ERROR;
    }
    __hs_expect(m, u, error);
}

/* One QPACK decoder instruction (§4.4), onto an encoder that inserts nothing. */
static void __hs_gen_decoder(hs_in_t* in, hs_model_t* m, hs_script_t* sc) {
    const int slot = __hs_find(m, HS_DEC);
    if (slot < 0) { __hs_gen_open(in, m, sc); return; }
    hs_unit_t* u = __hs_unit(sc, HS_BYTES, (uint8_t)slot);
    if (u == NULL) return;

    if ((__hs_u8(in) % 4) != 0) {
        __hs_prefix_int(sc, u, 0x40, 6, (uint64_t)(__hs_u8(in) % 64) << 2);   /* Stream Cancellation */
        __hs_expect(m, u, 0);
    } else {
        __hs_prefix_int(sc, u, 0x00, 6, __hs_u8(in));                          /* Insert Count Increment */
        __hs_expect(m, u, QPACK_DECODER_STREAM_ERROR);
    }
}

static void __hs_gen_ignored(hs_in_t* in, hs_model_t* m, hs_script_t* sc) {
    const int slot = __hs_find(m, HS_IGNORED);
    if (slot < 0) { __hs_gen_open(in, m, sc); return; }
    hs_unit_t* u = __hs_unit(sc, HS_BYTES, (uint8_t)slot);
    if (u == NULL) return;
    const size_t len = __hs_u8(in) % 64;
    for (size_t i = 0; i < len; i++) __hs_put(sc, u, __hs_u8(in));
    __hs_expect(m, u, 0);
}

/* A FIN or a reset: fatal on the three critical streams (§6.2.1, §4.2 of
 * RFC 9204), the end of the stream on the rest. */
static void __hs_gen_end(hs_in_t* in, hs_model_t* m, hs_script_t* sc, int reset) {
    const int slot = __hs_u8(in) % HS_STREAMS;
    const int kind = m->kind[slot];
    if (kind == HS_NONE || kind == HS_DEAD) return;
    hs_unit_t* u = __hs_unit(sc, reset ? HS_RESET : HS_BYTES, (uint8_t)slot);
    if (u == NULL) return;
    u->fin = !reset;
    m->kind[slot] = HS_DEAD;
    __hs_expect(m, u, kind == HS_IGNORED ? 0 : H3_CLOSED_CRITICAL_STREAM);
}

/* The end state the model predicts for the last generated script. */
static hs_state_t __hs_model_end;

static void __hs_generate(hs_in_t* in, hs_script_t* sc) {
    hs_model_t m;
    memset(&m, 0, sizeof m);
    h3settings_defaults(&m.peer);
    m.now_ms = 1000000;
    m.ctrl_epoch = m.abort_epoch = m.now_ms;
    m.ctrl_tokens = m.abort_tokens = HS_BURST * 1000;
    m.credit = HS_CREDIT0;

    sc->predicted = 1;
    while (!m.closed && in->p < in->end && sc->count < HS_UNITS && sc->used + 8192 < HS_POOL) {
        const uint8_t op = __hs_u8(in) % 16;
        switch (op) {
        case 0: case 1: __hs_gen_open(in, &m, sc); break;
        case 2: case 3: case 4: case 5: case 6: __hs_gen_control(in, &m, sc); break;
        case 7: case 8: __hs_gen_encoder(in, &m, sc); break;
        case 9: __hs_gen_decoder(in, &m, sc); break;
        case 10: __hs_gen_ignored(in, &m, sc); break;
        case 11: __hs_gen_end(in, &m, sc, 0); break;
        case 12: __hs_gen_end(in, &m, sc, 1); break;
        case 13: {
            hs_unit_t* u = __hs_unit(sc, HS_TIME, 0);
            if (u == NULL) break;
            const uint8_t b = __hs_u8(in);
            u->dt_ms = b < 200 ? b : __hs_u16(in) * 10;
            m.now_ms += u->dt_ms;
            break;
        }
        case 14: {
            hs_unit_t* u = __hs_unit(sc, HS_ABORT, 0);
            if (u == NULL) break;
            u->expect_error = (uint64_t)__hs_spend(&m.abort_tokens, &m.abort_epoch, m.now_ms);
            break;
        }
        default: {
            hs_unit_t* u = __hs_unit(sc, HS_EARN, 0);
            if (u == NULL) break;
            m.credit += HS_CREDIT_PER_REQUEST;
            if (m.credit > HS_CREDIT_MAX) m.credit = HS_CREDIT_MAX;
            break;
        }
        }
    }

    hs_state_t* e = &__hs_model_end;
    memset(e, 0, sizeof *e);
    e->peer = m.peer;
    e->peer_seen = m.settings_seen;
    e->mps = m.mps;
    e->mp = m.mp;
    e->gs = m.gs;
    e->gid = m.gid;
    e->ctrl_tokens = m.ctrl_tokens;
    e->abort_tokens = m.abort_tokens;
    e->credit = m.credit;
    e->prio_n = m.prio_n;
    for (size_t i = 0; i < m.prio_n; i++)
        e->prio[i] = m.prio[(m.prio_head + i) % H3SESSION_PRIORITY_QUEUE];
}

static void __hs_raw(hs_in_t* in, hs_script_t* sc) {
    sc->predicted = 0;
    while (in->p < in->end && sc->count < HS_UNITS) {
        const uint8_t b = __hs_u8(in);
        const uint8_t stream = (uint8_t)((b >> 4) % HS_STREAMS);
        switch (b % 8) {
        case 0: __hs_unit(sc, HS_RESET, stream); break;
        case 1: {
            hs_unit_t* u = __hs_unit(sc, HS_TIME, 0);
            if (u != NULL) u->dt_ms = __hs_u8(in);
            break;
        }
        case 2: __hs_unit(sc, HS_ABORT, 0); break;
        case 3: __hs_unit(sc, HS_EARN, 0); break;
        default: {
            hs_unit_t* u = __hs_unit(sc, HS_BYTES, stream);
            if (u == NULL) break;
            u->fin = (b & 0x08) && (b % 8) == 7;
            size_t len = __hs_u8(in);
            if ((size_t)(in->end - in->p) < len) len = (size_t)(in->end - in->p);
            for (size_t i = 0; i < len; i++) __hs_put(sc, u, *in->p++);
            break;
        }
        }
    }
}

/* ---- Playing a script ---- */

static void __hs_check(const h3session_t* s) {
    if (s->ctrl_tokens < 0 || s->abort_tokens < 0 || s->priority_credit < 0) __builtin_trap();
    if (s->ctrl_tokens > HS_BURST * 1000 || s->abort_tokens > HS_BURST * 1000) __builtin_trap();
    if (s->priority_credit > HS_CREDIT_MAX) __builtin_trap();
    if (s->priority_count > H3SESSION_PRIORITY_QUEUE) __builtin_trap();
}

static void __hs_play(const hs_script_t* sc, int split, uint32_t seed, hs_trace_t* tr) {
    memset(tr, 0, sizeof *tr);
    __hs_now_us = 1000000000ULL;

    h3session_t* s = h3session_create(65536, 1);
    if (s == NULL) __builtin_trap();
    h3uni_recv_t* uni[HS_STREAMS] = { 0 };
    int dead[HS_STREAMS] = { 0 };
    int over = 0;
    uint32_t rng = seed | 1;

    for (size_t k = 0; k < sc->count; k++) {
        const hs_unit_t* u = &sc->u[k];
        tr->action[k] = H3SESSION_OK;
        tr->error[k] = HS_NOT_RUN;
        if (over) continue;

        switch (u->kind) {
        case HS_TIME:
            __hs_now_us += u->dt_ms * 1000;
            tr->error[k] = 0;
            break;
        case HS_ABORT:
            tr->error[k] = (uint64_t)h3session_abort_spend(s);
            break;
        case HS_EARN:
            h3session_priority_earn(s);
            tr->error[k] = 0;
            break;
        default: {
            const int i = u->stream;
            if (dead[i]) break;
            if (uni[i] == NULL) uni[i] = h3uni_recv_create((uint64_t)i * 4 + 2);
            if (uni[i] == NULL) __builtin_trap();

            h3session_verdict_t v = { H3SESSION_OK, 0 };
            if (u->kind == HS_RESET) {
                v = h3session_uni_closed(s, uni[i]);
                dead[i] = 1;
            } else {
                const uint8_t* p = sc->pool + u->off;
                size_t left = u->len;
                do {
                    size_t piece = left;
                    if (split == 1 && piece > 1) piece = 1;
                    if (split == 2) {
                        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
                        const size_t want = 1 + rng % 17;
                        if (piece > want) piece = want;
                    }
                    const int fin = u->fin && piece == left;
                    /* Exactly the piece, so a read past it is caught. */
                    uint8_t* copy = piece > 0 ? malloc(piece) : NULL;
                    if (piece > 0 && copy == NULL) __builtin_trap();
                    if (piece > 0) memcpy(copy, p, piece);
                    v = h3session_uni_feed(s, uni[i], copy, piece, fin);
                    free(copy);
                    p += piece;
                    left -= piece;
                    if (fin) dead[i] = 1;
                } while (left > 0 && v.action == H3SESSION_OK);
            }

            tr->action[k] = v.action;
            tr->error[k] = v.error;
            if (v.action == H3SESSION_STOP_SENDING) dead[i] = 1;
            if (v.action == H3SESSION_CONN_ERROR) over = 1;
            break;
        }
        }
        __hs_check(s);
    }

    hs_state_t* e = &tr->end;
    e->peer = s->peer_settings;
    e->peer_seen = s->peer_settings_seen;
    e->mps = s->max_push_id_seen;
    e->mp = s->max_push_id;
    e->gs = s->peer_goaway_seen;
    e->gid = s->peer_goaway_id;
    e->ctrl_tokens = s->ctrl_tokens;
    e->abort_tokens = s->abort_tokens;
    e->credit = s->priority_credit;
    while (e->prio_n < H3SESSION_PRIORITY_QUEUE && h3session_take_priority(s, &e->prio[e->prio_n]))
        e->prio_n++;
    tr->bits = s->peer_uni.bits;
    tr->ins = s->qdec->insertions;
    tr->evi = s->qdec->evictions;

    for (int i = 0; i < HS_STREAMS; i++) h3uni_recv_free(uni[i]);
    h3session_free(s);
}

static int __hs_state_eq(const hs_state_t* a, const hs_state_t* b) {
    if (a->peer.qpack_max_table_capacity != b->peer.qpack_max_table_capacity ||
        a->peer.max_field_section_size != b->peer.max_field_section_size ||
        a->peer.qpack_blocked_streams != b->peer.qpack_blocked_streams ||
        a->peer.enable_connect_protocol != b->peer.enable_connect_protocol) return 0;
    if (a->peer_seen != b->peer_seen || a->mps != b->mps || a->gs != b->gs) return 0;
    if (a->mps && a->mp != b->mp) return 0;
    if (a->gs && a->gid != b->gid) return 0;
    if (a->ctrl_tokens != b->ctrl_tokens || a->abort_tokens != b->abort_tokens) return 0;
    if (a->credit != b->credit || a->prio_n != b->prio_n) return 0;
    for (size_t i = 0; i < a->prio_n; i++) {
        if (a->prio[i].stream_id != b->prio[i].stream_id) return 0;
        if (memcmp(&a->prio[i].priority, &b->prio[i].priority, sizeof a->prio[i].priority) != 0)
            return 0;
    }
    return 1;
}

static hs_script_t __hs_script;
static hs_trace_t __hs_traces[3];

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    quic_time_set_source(__hs_clock);
    const size_t budget_before = quicmemory_current();

    hs_script_t* sc = &__hs_script;
    sc->count = 0;
    sc->used = 0;

    hs_in_t in = { data + 2, data + size };
    if (data[0] & 1) __hs_raw(&in, sc);
    else __hs_generate(&in, sc);

    for (int play = 0; play < 3; play++)
        __hs_play(sc, play, 0x9e3779b9u * (uint32_t)(data[1] + 1), &__hs_traces[play]);

    for (int play = 1; play < 3; play++) {
        const hs_trace_t* a = &__hs_traces[0];
        const hs_trace_t* b = &__hs_traces[play];
        for (size_t k = 0; k < sc->count; k++)
            if (a->action[k] != b->action[k] || a->error[k] != b->error[k]) __builtin_trap();
        if (!__hs_state_eq(&a->end, &b->end)) __builtin_trap();
        if (a->bits != b->bits || a->ins != b->ins || a->evi != b->evi) __builtin_trap();
    }

    if (getenv("FUZZ_TRACE") != NULL)
        for (size_t k = 0; k < sc->count; k++)
            printf("unit %zu: kind %u stream %u len %u fin %u -> %d 0x%llx (expected %d 0x%llx)\n",
                   k, sc->u[k].kind, sc->u[k].stream, sc->u[k].len, sc->u[k].fin,
                   __hs_traces[0].action[k], (unsigned long long)__hs_traces[0].error[k],
                   sc->u[k].expect_action, (unsigned long long)sc->u[k].expect_error);

    if (sc->predicted) {
        const hs_trace_t* t = &__hs_traces[0];
        for (size_t k = 0; k < sc->count; k++) {
            const hs_unit_t* u = &sc->u[k];
            if (u->kind == HS_TIME || u->kind == HS_EARN) continue;
            if (u->kind == HS_ABORT) {
                if (t->error[k] != u->expect_error) __builtin_trap();
                continue;
            }
            if (t->action[k] != u->expect_action || t->error[k] != u->expect_error) __builtin_trap();
        }
        if (!__hs_state_eq(&t->end, &__hs_model_end)) __builtin_trap();
    }

    quic_time_set_source(NULL);
    if (quicmemory_current() != budget_before) __builtin_trap();
    return 0;
}

#elif FUZZ_TARGET == FUZZ_ROUTE

#include "domain.h"
#include "idn_utils.h"
#include "redirect.h"
#include "route.h"
#include "strtemplate.h"

/* Routing: the location templates of routes and redirects, the destinations
 * redirects expand, and the virtual host a Host field selects. The templates
 * come from configuration, but the path and the Host they are matched against
 * come from the request.
 *
 * route (first byte % 6 == 0 or 1): a location built from literal text -- '.'
 * and '?' included -- and {name|expression} params, or from literal text and
 * raw regex with no params. The target writes its own regex for it: literal
 * text escaped, each param a named group around its expression, anchored when
 * there are params or nothing but text, unanchored for a raw regex. A path
 * built to match (then perhaps damaged) or taken from the input must get the
 * same answer from route_match as from that regex, every param the value of
 * its own group and a substring of the path. A static_file placeholder is
 * accepted exactly when the location has that group.
 *
 * raw route (2): any location. When it compiles, route_match agrees with its
 * compiled pattern on any path -- the primitive comparison included -- and
 * params lie inside the path.
 *
 * redirect (3): a location of literal text and capture groups, some optional,
 * and a destination spending every group. On any path -- CR, LF, NUL, '?',
 * UTF-8 -- the result is the destination's own text with each capture
 * percent-encoded as strtemplate.h says, plus the request's query when the
 * destination has none, control bytes encoded: never a byte below 0x21 or
 * above 0x7e. A literal location answers as its pattern does.
 *
 * domain (4, 5): a vhost template of labels, a Unicode one perhaps, with '*'
 * at either end, and a Host built from it -- case changed, labels for the '*',
 * a port, a trailing dot, punycode or not -- or taken from the input.
 * domain_host_normalize agrees with a pattern written here from its header, and
 * domain_matches with a glob match written here; a literal template answers as
 * its pattern does. */

#define RT_TOKENS 8

typedef struct {
    const uint8_t* p;
    const uint8_t* end;
} rt_in_t;

static uint8_t __rt_u8(rt_in_t* in) {
    return in->p < in->end ? *in->p++ : 0;
}

typedef struct {
    char   b[4096];
    size_t n;
} rt_buf_t;

static void __rt_put(rt_buf_t* s, const char* text, size_t n) {
    if (s->n + n >= sizeof s->b) n = sizeof s->b - 1 - s->n;
    memcpy(s->b + s->n, text, n);
    s->n += n;
    s->b[s->n] = 0;
}

static void __rt_puts(rt_buf_t* s, const char* text) {
    __rt_put(s, text, strlen(text));
}

static void __rt_putc(rt_buf_t* s, char c) {
    __rt_put(s, &c, 1);
}

static pcre2_code* __rt_compile(const char* pattern) {
    int error = 0;
    PCRE2_SIZE offset = 0;
    return pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                         PCRE2_DOTALL | PCRE2_DOLLAR_ENDONLY, &error, &offset, NULL);
}

/* Offsets of every group, -1 when unset; the match's return, or 0. */
static int __rt_pcre(const pcre2_code* code, const char* s, size_t n, int* v, int vn) {
    for (int i = 0; i < vn; i++) v[i] = -1;
    pcre2_match_data* md = pcre2_match_data_create_from_pattern(code, NULL);
    if (md == NULL) return -1;
    const int rc = pcre2_match(code, (PCRE2_SPTR)s, n, 0, 0, md, NULL);
    if (rc > 0) {
        const PCRE2_SIZE* ov = pcre2_get_ovector_pointer(md);
        const uint32_t pairs = pcre2_get_ovector_count(md);
        for (uint32_t i = 0; i < pairs && (int)(2 * i + 1) < vn; i++) {
            if (ov[2 * i] == PCRE2_UNSET) continue;
            v[2 * i] = (int)ov[2 * i];
            v[2 * i + 1] = (int)ov[2 * i + 1];
        }
    }
    pcre2_match_data_free(md);
    return rc > 0;
}

/* ---- route ---- */

static const char* __rt_lit_chars = "abcxyz019-_~/.?";

/* Expressions a param may carry, each with a way to write a value it takes.
 * Two open groups of their own, one has a quantifier in braces. */
static const char* __rt_exprs[] = {
    "[0-9]+", "[a-z]+", "[^/]+", "(en|ru)", "[a-z]{2,3}", "(?:x|yz)+", "(a)(b)?",
};

static void __rt_value(rt_in_t* in, int expr, rt_buf_t* out) {
    const size_t n = 1 + __rt_u8(in) % 4;
    switch (expr) {
    case 0: for (size_t i = 0; i < n; i++) __rt_putc(out, (char)('0' + __rt_u8(in) % 10)); break;
    case 1: for (size_t i = 0; i < n; i++) __rt_putc(out, (char)('a' + __rt_u8(in) % 26)); break;
    case 2:
        for (size_t i = 0; i < n; i++) {
            char c = (char)__rt_u8(in);
            if (c == '/' || c == 0) c = 'q';
            __rt_putc(out, c);
        }
        break;
    case 3: __rt_puts(out, __rt_u8(in) & 1 ? "en" : "ru"); break;
    case 4: for (size_t i = 0; i < 2 + (n & 1); i++) __rt_putc(out, (char)('a' + __rt_u8(in) % 26)); break;
    case 5: for (size_t i = 0; i < n; i++) __rt_puts(out, __rt_u8(in) & 1 ? "x" : "yz"); break;
    default: __rt_puts(out, __rt_u8(in) & 1 ? "ab" : "a"); break;
    }
}

typedef struct {
    int  kind;          /* 0 literal text, 1 param, 2 raw regex */
    char text[16];
    int  expr;
} rt_token_t;

static void __rt_route(rt_in_t* in) {
    rt_token_t tok[RT_TOKENS];
    size_t count = 1 + __rt_u8(in) % RT_TOKENS;
    const int regex = (__rt_u8(in) % 4) == 0;      /* raw regex, no params */
    int params = 0;

    for (size_t i = 0; i < count; i++) {
        const uint8_t b = __rt_u8(in);
        rt_token_t* t = &tok[i];
        memset(t, 0, sizeof *t);
        if (regex && (b % 3) == 0) {
            static const char* raw[] = { "(.*)", "[0-9]+", "x*", "(a|b)", "c?", "\\.", "(?:y)+" };
            t->kind = 2;
            snprintf(t->text, sizeof t->text, "%s", raw[__rt_u8(in) % 7]);
        } else if (!regex && (b % 3) == 0 && params < 6) {
            t->kind = 1;
            t->expr = __rt_u8(in) % (int)(sizeof __rt_exprs / sizeof __rt_exprs[0]);
            snprintf(t->text, sizeof t->text, "p%c%d", 'a' + params, params);
            params++;
        } else {
            /* No '?' in a raw regex route: there it is an operator, and one
             * with nothing before it does not compile. */
            const char* chars = regex ? "abcxyz019-_~/." : __rt_lit_chars;
            const size_t n = 1 + __rt_u8(in) % 6;
            for (size_t k = 0; k < n; k++) t->text[k] = chars[__rt_u8(in) % strlen(chars)];
        }
    }

    /* The location as a configuration writes it, and the regex it means. */
    rt_buf_t loc = { .n = 0 }, ref = { .n = 0 };
    loc.b[0] = ref.b[0] = 0;
    for (size_t i = 0; i < count; i++) {
        const rt_token_t* t = &tok[i];
        if (t->kind == 1) {
            __rt_puts(&loc, "{"); __rt_puts(&loc, t->text); __rt_puts(&loc, "|");
            __rt_puts(&loc, __rt_exprs[t->expr]); __rt_puts(&loc, "}");
        } else {
            __rt_puts(&loc, t->text);
        }
    }
    /* A regex is what has an operator outside the params; '.' and '?' alone
     * do not make one ("c?" among plain text is a question mark). */
    int raw = 0;
    if (params == 0)
        for (const char* c = loc.b; *c; c++)
            if (strchr("*+()[]|^$\\", *c) != NULL) raw = 1;
    const int anchored = !raw;

    if (anchored) __rt_putc(&ref, '^');
    for (size_t i = 0; i < count; i++) {
        const rt_token_t* t = &tok[i];
        if (t->kind == 1) {
            __rt_puts(&ref, "(?<"); __rt_puts(&ref, t->text); __rt_puts(&ref, ">");
            __rt_puts(&ref, __rt_exprs[t->expr]); __rt_puts(&ref, ")");
        } else if (raw) {
            __rt_puts(&ref, t->text);
        } else {
            for (const char* c = t->text; *c; c++) {
                /* Plain text: all but letters and digits escaped. */
                if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9'))) __rt_putc(&ref, '\\');
                __rt_putc(&ref, *c);
            }
        }
    }
    if (anchored) __rt_putc(&ref, '$');

    route_t* r = route_create(loc.b);
    pcre2_code* want = __rt_compile(ref.b);
    if (want == NULL) __builtin_trap();
    if (r == NULL) __builtin_trap();                 /* every generated location is valid */
    if (r->params_count != params) __builtin_trap();

    /* A path: built to match, then perhaps damaged, or the input's. */
    rt_buf_t path = { .n = 0 };
    path.b[0] = 0;
    const uint8_t how = __rt_u8(in);
    if (how % 4 != 3) {
        for (size_t i = 0; i < count; i++) {
            const rt_token_t* t = &tok[i];
            if (t->kind == 1) __rt_value(in, t->expr, &path);
            else if (t->kind == 2) __rt_puts(&path, __rt_u8(in) & 1 ? "ab" : "7");
            else __rt_puts(&path, t->text);
        }
        if (how % 4 == 1 && path.n > 0) path.b[__rt_u8(in) % path.n] = (char)__rt_u8(in);
        if (how % 4 == 2) __rt_putc(&path, (char)(__rt_u8(in) % 3 == 0 ? '\n' : 'x'));
    } else {
        const size_t n = __rt_u8(in) % 48;
        for (size_t i = 0; i < n; i++) __rt_putc(&path, (char)__rt_u8(in));
    }

    const int vn = route_vector_size(r);
    int* vector = malloc((size_t)vn * sizeof *vector);
    int wv[64];
    if (vector == NULL) __builtin_trap();
    const int got = route_match(r, path.b, path.n, vector, vn);
    const int expect = __rt_pcre(want, path.b, path.n, wv, 64);
    if (getenv("FUZZ_TRACE") != NULL)
        printf("location %s\nregex    %s\npath     %.*s\nroute_match %d, regex %d, primitive %d\n",
               loc.b, ref.b, (int)path.n, path.b, got, expect, r->is_primitive), fflush(stdout);
    if (got != expect) __builtin_trap();

    if (got == 1) {
        if (vector[0] < 0 || vector[1] > (int)path.n || vector[0] > vector[1]) __builtin_trap();
        for (const route_param_t* p = r->param; p != NULL; p = p->next) {
            if (p->group <= 0 || p->group > r->captures) __builtin_trap();
            const int s = vector[p->group * 2], e = vector[p->group * 2 + 1];
            if (s < 0 || e < s || e > (int)path.n) __builtin_trap();
            const int ng = pcre2_substring_number_from_name(want, (PCRE2_SPTR)p->string);
            if (ng <= 0 || ng >= 32) __builtin_trap();
            if (wv[ng * 2] != s || wv[ng * 2 + 1] != e) __builtin_trap();
        }
    }

    /* static_file: accepted exactly when the group exists. */
    const int k = __rt_u8(in) % (r->captures + 3);
    char tpl[32];
    snprintf(tpl, sizeof tpl, "/f/{%d}", k);
    const int set = route_set_http_static(r, "GET", tpl, NULL, NULL);
    if (set != (k <= r->captures)) __builtin_trap();
    if (set && got == 1) {
        char* file = strtemplate_expand(r->static_file[ROUTE_GET], path.b, r->is_primitive ? NULL : vector);
        if (file == NULL) __builtin_trap();
        free(file);
    }

    free(vector);
    pcre2_code_free(want);
    routes_free(r);
}

static void __rt_route_raw(rt_in_t* in) {
    rt_buf_t loc = { .n = 0 }, path = { .n = 0 };
    loc.b[0] = path.b[0] = 0;
    const size_t ln = __rt_u8(in) % 64;
    for (size_t i = 0; i < ln; i++) {
        const char c = (char)__rt_u8(in);
        if (c != 0) __rt_putc(&loc, c);
    }
    const size_t pn = (size_t)(in->end - in->p);
    __rt_put(&path, (const char*)in->p, pn);

    route_t* r = route_create(loc.b);
    if (r == NULL) return;

    const int vn = route_vector_size(r);
    int* vector = malloc((size_t)vn * sizeof *vector);
    int wv[256];
    if (vector == NULL) __builtin_trap();
    const int got = route_match(r, path.b, path.n, vector, vn);
    /* The primitive shortcut must say what the pattern says. */
    if (got != __rt_pcre(r->location, path.b, path.n, wv, 256)) __builtin_trap();
    if (got == 1)
        for (const route_param_t* p = r->param; p != NULL; p = p->next) {
            const int s = vector[p->group * 2], e = vector[p->group * 2 + 1];
            if (s >= 0 && (e < s || e > (int)path.n)) __builtin_trap();
        }
    free(vector);
    routes_free(r);
}

/* ---- redirect ---- */

static int __rt_uri_keeps(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c != 0 && strchr("-._~/:@!$'()*,;", c) != NULL);
}

static void __rt_encode(rt_buf_t* out, const char* s, size_t n, int (*keeps)(unsigned char)) {
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        const unsigned char c = (unsigned char)s[i];
        if (keeps(c)) {
            __rt_putc(out, (char)c);
        } else {
            __rt_putc(out, '%');
            __rt_putc(out, hex[c >> 4]);
            __rt_putc(out, hex[c & 15]);
        }
    }
}

static int __rt_query_keeps(unsigned char c) {
    return c > 0x20 && c < 0x7f;
}

static void __rt_redirect(rt_in_t* in) {
    static const char* groups[] = { "(.*)", "([^/]*)", "(x|y)?", "([0-9]+)", "(?:z)(w?)" };
    rt_buf_t loc = { .n = 0 }, dst = { .n = 0 };
    loc.b[0] = dst.b[0] = 0;

    const int literal = (__rt_u8(in) % 4) == 0;
    int captures = 0;
    if (literal) {
        const size_t n = 1 + __rt_u8(in) % 5;
        for (size_t i = 0; i < n; i++) __rt_putc(&loc, "abc/-_~"[__rt_u8(in) % 7]);
    } else {
        if (__rt_u8(in) & 1) __rt_putc(&loc, '^');
        const size_t parts = 1 + __rt_u8(in) % 4;
        for (size_t i = 0; i < parts; i++) {
            if (__rt_u8(in) & 1) {
                __rt_puts(&loc, groups[__rt_u8(in) % 5]);
                captures++;
            } else {
                const char c = "abc/-_~."[__rt_u8(in) % 8];
                if (c == '.') __rt_putc(&loc, '\\');
                __rt_putc(&loc, c);
            }
        }
        if (__rt_u8(in) & 1) __rt_putc(&loc, '$');
    }

    /* The destination: its own text and exactly one placeholder per group,
     * any of them, in any order. */
    const char* prefixes[] = { "https://example.com", "/new", "", "/a?x=1&y=" };
    const char* prefix = prefixes[__rt_u8(in) % 4];
    __rt_puts(&dst, prefix);
    for (int i = 0; i < captures; i++) {
        char ph[8];
        snprintf(ph, sizeof ph, "{%d}", 1 + __rt_u8(in) % captures);
        __rt_puts(&dst, ph);
        __rt_puts(&dst, (__rt_u8(in) & 1) ? "/" : "-");
    }
    if (dst.n == 0) __rt_puts(&dst, "/");

    redirect_t* r = redirect_create(loc.b, dst.b);
    if (r == NULL) __builtin_trap();

    /* The decoded path, any bytes; the request target, with a query perhaps. */
    rt_buf_t path = { .n = 0 }, uri = { .n = 0 };
    path.b[0] = uri.b[0] = 0;
    __rt_putc(&path, '/');
    const size_t pn = __rt_u8(in) % 40;
    for (size_t i = 0; i < pn; i++) __rt_putc(&path, (char)__rt_u8(in));
    __rt_puts(&uri, "/orig");
    if (__rt_u8(in) & 1) {
        __rt_putc(&uri, '?');
        const size_t qn = __rt_u8(in) % 16;
        for (size_t i = 0; i < qn; i++) {
            const char c = (char)__rt_u8(in);
            __rt_putc(&uri, c != 0 ? c : 'q');
        }
    }

    const int vn = (r->params_count + 1) * 3;
    int* vector = malloc((size_t)vn * sizeof *vector);
    int wv[64];
    if (vector == NULL) __builtin_trap();
    for (int i = 0; i < vn; i++) vector[i] = -1;

    const int got = redirect_matches(r, path.b, path.n, vector, vn);
    const int expect = __rt_pcre(r->location, path.b, path.n, wv, 64);
    if (got != expect) __builtin_trap();

    if (got) {
        char* out = redirect_uri_with_query(r, path.b, vector, uri.b, uri.n);
        if (out == NULL) __builtin_trap();

        /* The same, written here. */
        rt_buf_t want = { .n = 0 };
        want.b[0] = 0;
        __rt_puts(&want, prefix);
        for (const char* c = dst.b + strlen(prefix); *c; c++) {
            if (*c != '{') { __rt_putc(&want, *c); continue; }
            const int g = atoi(c + 1);
            const int s = wv[g * 2], e = wv[g * 2 + 1];
            if (s >= 0) __rt_encode(&want, path.b + s, (size_t)(e - s), __rt_uri_keeps);
            c = strchr(c, '}');
        }
        const char* q = memchr(uri.b, '?', uri.n);
        if (strchr(dst.b, '?') == NULL && q != NULL && uri.n - (size_t)(q - uri.b) >= 2)
            __rt_encode(&want, q, uri.n - (size_t)(q - uri.b), __rt_query_keeps);

        if (strcmp(out, want.b) != 0) __builtin_trap();
        for (const char* c = out; *c; c++)
            if ((unsigned char)*c < 0x21 || (unsigned char)*c > 0x7e) __builtin_trap();
        free(out);
    }

    free(vector);
    redirect_free(r);
}

/* ---- domain ---- */

static char __rt_fold(char c) {
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

static int __rt_ieq(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (__rt_fold(a[i]) != __rt_fold(b[i])) return 0;
    return 1;
}

/* The template's meaning: '*' at either end stands for anything. */
static int __rt_glob(const char* tpl, const char* host) {
    const size_t tn = strlen(tpl), hn = strlen(host);
    const int lead = tn > 0 && tpl[0] == '*';
    const int trail = tn > 1 && tpl[tn - 1] == '*';
    const char* core = tpl + lead;
    const size_t cn = tn - lead - trail;
    if (tn == 1 && lead) return 1;
    if (hn < cn) return 0;
    if (lead && trail) {
        for (size_t i = 0; i + cn <= hn; i++)
            if (__rt_ieq(host + i, core, cn)) return 1;
        return 0;
    }
    if (lead) return __rt_ieq(host + hn - cn, core, cn);
    if (trail) return __rt_ieq(host, core, cn);
    return hn == cn && __rt_ieq(host, core, cn);
}

/* domain_host_normalize, as the header says it -- but as one pattern over the
 * whole Host rather than the function's walk through it, so that a slip in
 * that walk is not copied here too: a name, bracketed or not, then a port of
 * digits or none. Unbracketed, the name stops at the first ':' and loses one
 * trailing dot, and what is left may neither be empty nor end in another. No
 * control byte, space or DEL anywhere. The name is the group that took part. */
static domain_host_e __rt_normalize(const char* h, size_t n, char* out) {
    static pcre2_code* host;
    if (host == NULL) {
        int err = 0;
        PCRE2_SIZE at = 0;
        host = pcre2_compile((PCRE2_SPTR)
            "^(?:\\[([^\\x00-\\x20\\x7f\\]]+)\\]"
            "|(?!\\[)([^\\x00-\\x20\\x7f:]*[^\\x00-\\x20\\x7f:.])\\.?)"
            "(?::[0-9]*)?$",
            PCRE2_ZERO_TERMINATED, PCRE2_DOLLAR_ENDONLY, &err, &at, NULL);
        if (host == NULL) abort();
    }
    if (n >= DOMAIN_MAX_HOST) return DOMAIN_HOST_BAD;

    int v[6];
    if (__rt_pcre(host, h, n, v, 6) != 1) return DOMAIN_HOST_BAD;
    const int g = v[2] >= 0 ? 1 : 2;
    char name[DOMAIN_MAX_HOST];
    const size_t nn = (size_t)(v[2 * g + 1] - v[2 * g]);
    memcpy(name, h + v[2 * g], nn);
    name[nn] = 0;

    char* ascii = idn_to_ascii(name);
    if (ascii == NULL) return DOMAIN_HOST_UNKNOWN;
    snprintf(out, DOMAIN_MAX_HOST * 4, "%s", ascii);
    free(ascii);
    return DOMAIN_HOST_OK;
}

static void __rt_domain(rt_in_t* in, int raw) {
    static const char* labels[] = { "example", "www", "a", "api-2", "xn--p1ai", "пример", "münchen", "b0" };
    rt_buf_t tpl = { .n = 0 }, host = { .n = 0 };
    tpl.b[0] = host.b[0] = 0;

    if (raw) {
        const size_t n = 1 + __rt_u8(in) % 32;
        for (size_t i = 0; i < n; i++) {
            const char c = (char)__rt_u8(in);
            __rt_putc(&tpl, c != 0 ? c : 'a');
        }
        __rt_put(&host, (const char*)in->p, (size_t)(in->end - in->p));
    } else {
        const uint8_t star = __rt_u8(in) % 5;           /* 0 none, 1 lead, 2 trail, 3 both, 4 alone */
        const size_t nl = 1 + __rt_u8(in) % 3;
        const char* chosen[4];
        for (size_t i = 0; i < nl; i++) chosen[i] = labels[__rt_u8(in) % 8];

        if (star == 4) {
            __rt_puts(&tpl, "*");
        } else {
            if (star == 1 || star == 3) __rt_puts(&tpl, "*.");
            for (size_t i = 0; i < nl; i++) {
                if (i) __rt_putc(&tpl, '.');
                __rt_puts(&tpl, chosen[i]);
            }
            if (star == 2 || star == 3) __rt_puts(&tpl, ".*");
        }

        /* A host built from it: labels for the stars, case changed, punycode or
         * not, a port, a trailing dot; or damaged. */
        const uint8_t how = __rt_u8(in);
        if (star == 1 || star == 3 || star == 4) {
            const size_t extra = __rt_u8(in) % 3;
            for (size_t i = 0; i < extra; i++) { __rt_puts(&host, labels[__rt_u8(in) % 8]); __rt_putc(&host, '.'); }
        }
        if (star != 4)
            for (size_t i = 0; i < nl; i++) {
                if (i) __rt_putc(&host, '.');
                const char* l = chosen[i];
                if ((how & 1) && (unsigned char)l[0] >= 0x80) {
                    char* a = idn_to_ascii(l);
                    if (a != NULL) { __rt_puts(&host, a); free(a); continue; }
                }
                for (const char* c = l; *c; c++)
                    __rt_putc(&host, (how & 2) && *c >= 'a' && *c <= 'z' ? (char)(*c - 32) : *c);
            }
        if (star == 2 || star == 3) { __rt_putc(&host, '.'); __rt_puts(&host, labels[__rt_u8(in) % 8]); }
        if (how & 4) __rt_putc(&host, '.');
        if (how & 8) {
            __rt_putc(&host, ':');
            const size_t pn = __rt_u8(in) % 6;
            for (size_t i = 0; i < pn; i++) __rt_putc(&host, (how & 16) && i == 2 ? 'x' : (char)('0' + __rt_u8(in) % 10));
        }
        if ((how & 0xe0) == 0x20 && host.n > 0) host.b[__rt_u8(in) % host.n] = (char)__rt_u8(in);
        if ((how & 0xe0) == 0x40) __rt_puts(&host, "..");
    }

    domain_t* d = domain_create(tpl.b);
    if (d == NULL) {
        if (!raw) __builtin_trap();
        return;
    }

    char* norm = NULL;
    const domain_host_e st = domain_host_normalize(host.b, host.n, &norm);
    char want[DOMAIN_MAX_HOST * 4];
    if (st != __rt_normalize(host.b, host.n, want)) __builtin_trap();
    if (st == DOMAIN_HOST_OK) {
        if (strcmp(norm, want) != 0) __builtin_trap();
        const size_t nn = strlen(norm);
        const int got = domain_matches(d, norm, nn);

        /* The literal shortcut says what the pattern says. */
        int wv[120];
        if (d->is_literal && got != __rt_pcre(d->pcre_template, norm, nn, wv, 120)) __builtin_trap();

        if (!raw) {
            char* ascii_tpl = idn_to_ascii(tpl.b);
            if (ascii_tpl == NULL) __builtin_trap();
            if (got != __rt_glob(ascii_tpl, norm)) __builtin_trap();
            free(ascii_tpl);
        }
    } else if (norm != NULL) __builtin_trap();
    free(norm);

    /* And on the raw host too: whatever the parser hands over. */
    int wv[120];
    const int any = domain_matches(d, host.b, host.n);
    if (d->is_literal && any != __rt_pcre(d->pcre_template, host.b, host.n, wv, 120)) __builtin_trap();

    domains_free(d);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    rt_in_t in = { data + 1, data + size };

    switch (data[0] % 6) {
    case 0: case 1: __rt_route(&in); break;
    case 2: __rt_route_raw(&in); break;
    case 3: __rt_redirect(&in); break;
    default: __rt_domain(&in, data[0] % 6 == 5 && (data[0] & 0x80)); break;
    }
    return 0;
}

#else
#error "FUZZ_TARGET is not set to a known target"
#endif
