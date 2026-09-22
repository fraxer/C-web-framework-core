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
    FUZZ_TARGET == FUZZ_H3_PRIORITY
#include "h3frame.h"
#include "h3priority.h"
#include "qpack.h"
#include "quicframe.h"
#include "quicpacket.h"
#include "quictp.h"
#include "varint.h"
#endif

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#if FUZZ_TARGET == FUZZ_REQUEST || FUZZ_TARGET == FUZZ_WEBSOCKET || \
    FUZZ_TARGET == FUZZ_H2_SESSION

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
    uint8_t enc[8192];
    const ssize_t n = huffman_encode(enc, sizeof enc, data, size > 2048 ? 2048 : size);
    if (n > 0) (void)huffman_decode(out, sizeof out, enc, (size_t)n);

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

        if (e != NULL) {
            for (int huffman = 0; huffman < 2; huffman++) {
                uint8_t* encoded = NULL;
                size_t encoded_len = 0;

                if (hpack_encoder_encode(e, headers, count, huffman, &encoded, &encoded_len) != HPACK_OK)
                    continue;

                hpack_decoder_t* back = hpack_decoder_create(4096);
                if (back != NULL) {
                    hpack_header_t* again = NULL;
                    size_t again_count = 0;

                    if (hpack_decoder_decode(back, encoded, encoded_len, 1048576,
                                             &again, &again_count) == HPACK_OK)
                        hpack_headers_free(again, again_count);

                    hpack_decoder_free(back);
                }

                free(encoded);
            }

            hpack_encoder_free(e);
        }

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

    (void)json_stringify(doc);
    (void)json_stringify_size(doc);

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

    if (ws_deflate_start(&d) != 0) {
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
        blen = data[0] % 64;
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

    char* buffer = malloc(size > 0 ? size : 1);
    if (buffer == NULL) {
        free(boundary);
        close(fd);
        return 0;
    }
    memcpy(buffer, data, size);

    multipartparser_t parser;
    multipartparser_init(&parser, fd, boundary);

    (void)multipartparser_parse(&parser, buffer, size);

    multipartparser_clear(&parser);
    free(buffer);
    free(boundary);
    close(fd);

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
