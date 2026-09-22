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
#include <unistd.h>

#include "h3frame.h"
#include "cookieparser.h"
#include "hpack.h"
#include "httpcommon.h"
#include "multipartparser.h"
#include "urlencodedparser.h"
#include "h3priority.h"
#include "huffman.h"
#include "qpack.h"
#include "quicframe.h"
#include "quicpacket.h"
#include "quictp.h"
#include "varint.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

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

#else
#error "FUZZ_TARGET is not set to a known target"
#endif
