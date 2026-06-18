#ifndef __WS_UTF8__
#define __WS_UTF8__

#include <stdint.h>
#include <stddef.h>

/* Streaming UTF-8 validator for length-delimited WebSocket TEXT payloads.
 *
 * Unlike misc/utf8.h (libunistring-backed, null-terminated), this validator is
 * binary-safe: it takes (ptr, len) chunks and carries state across feed() calls,
 * so a multi-byte sequence may straddle a read or fragment boundary. Embedded
 * NUL bytes are handled like any other byte. Reset once per message; call
 * finish() at message end to reject a dangling partial sequence.
 *
 * Enforces RFC 3629 (and thus RFC 6455 §8.1): rejects overlong encodings,
 * surrogates (U+D800..U+DFFF), codepoints above U+10FFFF, bare/stray
 * continuation bytes, and incomplete trailing sequences.
 *
 * Header-only and allocation-free so it can be used from the parser and exercised
 * directly by unit tests without a new build target.
 */
typedef struct {
    int needed;         /* continuation bytes still expected (0 == at codepoint boundary) */
    int seq_len;        /* total continuation bytes in the current sequence (1..3) */
    uint8_t min_first;  /* lower bound for the FIRST continuation byte of the sequence */
    uint8_t max_first;  /* upper bound for the FIRST continuation byte of the sequence */
} ws_utf8_validator_t;

static inline void ws_utf8_validator_reset(ws_utf8_validator_t* v) {
    v->needed = 0;
    v->seq_len = 0;
    v->min_first = 0x80;
    v->max_first = 0xBF;
}

/* Feed a chunk. Returns 1 if every byte consumed so far is valid UTF-8 (a
 * trailing partial sequence is tolerated until finish()), 0 on a definitive
 * violation. After returning 0 the validator is poisoned; stop feeding. */
static inline int ws_utf8_validator_feed(ws_utf8_validator_t* v, const unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        const unsigned char b = data[i];

        if (v->needed == 0) {
            /* Start of a new codepoint. */
            if (b <= 0x7F) {
                continue; /* ASCII */
            } else if (b >= 0xC2 && b <= 0xDF) {
                v->needed = 1;
                v->seq_len = 1;
                v->min_first = 0x80;
                v->max_first = 0xBF;
            } else if (b == 0xE0) {
                v->needed = 2;
                v->seq_len = 2;
                v->min_first = 0xA0; /* reject overlong (< U+0800) */
                v->max_first = 0xBF;
            } else if (b >= 0xE1 && b <= 0xEC) {
                v->needed = 2;
                v->seq_len = 2;
                v->min_first = 0x80;
                v->max_first = 0xBF;
            } else if (b == 0xED) {
                v->needed = 2;
                v->seq_len = 2;
                v->min_first = 0x80;
                v->max_first = 0x9F; /* reject surrogates (U+D800..U+DFFF) */
            } else if (b == 0xEE || b == 0xEF) {
                v->needed = 2;
                v->seq_len = 2;
                v->min_first = 0x80;
                v->max_first = 0xBF;
            } else if (b == 0xF0) {
                v->needed = 3;
                v->seq_len = 3;
                v->min_first = 0x90; /* reject overlong (< U+10000) */
                v->max_first = 0xBF;
            } else if (b >= 0xF1 && b <= 0xF3) {
                v->needed = 3;
                v->seq_len = 3;
                v->min_first = 0x80;
                v->max_first = 0xBF;
            } else if (b == 0xF4) {
                v->needed = 3;
                v->seq_len = 3;
                v->min_first = 0x80;
                v->max_first = 0x8F; /* reject > U+10FFFF */
            } else {
                /* 0x80..0xC1 (lone continuation or overlong lead), 0xF5..0xFF */
                return 0;
            }
        } else {
            /* Continuation byte. The first one of the sequence is bounded by the
             * lead byte (overlong/surrogate/range guards); the rest are 0x80..0xBF. */
            const int is_first = (v->needed == v->seq_len);
            const uint8_t lo = is_first ? v->min_first : 0x80;
            const uint8_t hi = is_first ? v->max_first : 0xBF;
            if (b < lo || b > hi)
                return 0;
            v->needed--;
            if (v->needed == 0)
                v->seq_len = 0; /* back to a codepoint boundary */
        }
    }

    return 1;
}

/* Returns 1 if the message ended on a codepoint boundary (no partial sequence
 * pending), 0 otherwise. Call once, after the final feed(). */
static inline int ws_utf8_validator_finish(ws_utf8_validator_t* v) {
    return v->needed == 0;
}

#endif /* __WS_UTF8__ */
