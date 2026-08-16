/* Auto-generated from RFC 9204 Appendix A by gen_qpack_static.py.
 * QPACK static table: 99 entries (0-based; index 0 is :authority).
 *
 * Unlike HPACK's table (RFC 7541 App. A), QPACK's is 0-based, which is why
 * a static index N refers directly to entry N below (no unused slot 0).
 * Do not edit by hand. */
#ifndef __QPACK_STATIC_TABLE__
#define __QPACK_STATIC_TABLE__

#include <stddef.h>

#define QPACK_STATIC_TABLE_SIZE 99  /* entries [0..98], 0-based */

/* The lengths are carried alongside the strings: the encoder scans all 99
 * entries for every header it writes, and strlen() on each one turned that
 * scan into the single largest item of the response profile. */
typedef struct {
    const char* name;
    size_t      name_len;
    const char* value;
    size_t      value_len;
} qpack_static_entry_t;

/* 0-based: the (i+1)-th initializer is index i. */
static const qpack_static_entry_t
qpack_static_table[QPACK_STATIC_TABLE_SIZE] = {
    { ":authority", 10, "", 0 },
    { ":path", 5, "/", 1 },
    { "age", 3, "0", 1 },
    { "content-disposition", 19, "", 0 },
    { "content-length", 14, "0", 1 },
    { "cookie", 6, "", 0 },
    { "date", 4, "", 0 },
    { "etag", 4, "", 0 },
    { "if-modified-since", 17, "", 0 },
    { "if-none-match", 13, "", 0 },
    { "last-modified", 13, "", 0 },
    { "link", 4, "", 0 },
    { "location", 8, "", 0 },
    { "referer", 7, "", 0 },
    { "set-cookie", 10, "", 0 },
    { ":method", 7, "CONNECT", 7 },
    { ":method", 7, "DELETE", 6 },
    { ":method", 7, "GET", 3 },
    { ":method", 7, "HEAD", 4 },
    { ":method", 7, "OPTIONS", 7 },
    { ":method", 7, "POST", 4 },
    { ":method", 7, "PUT", 3 },
    { ":scheme", 7, "http", 4 },
    { ":scheme", 7, "https", 5 },
    { ":status", 7, "103", 3 },
    { ":status", 7, "200", 3 },
    { ":status", 7, "304", 3 },
    { ":status", 7, "404", 3 },
    { ":status", 7, "503", 3 },
    { "accept", 6, "*/*", 3 },
    { "accept", 6, "application/dns-", 16 },
    { "accept-encoding", 15, "gzip, deflate, br", 17 },
    { "accept-ranges", 13, "bytes", 5 },
    { "access-control-allow-headers", 28, "cache-control", 13 },
    { "access-control-allow-headers", 28, "content-type", 12 },
    { "access-control-allow-origin", 27, "*", 1 },
    { "cache-control", 13, "max-age=0", 9 },
    { "cache-control", 13, "max-age=2592000", 15 },
    { "cache-control", 13, "max-age=604800", 14 },
    { "cache-control", 13, "no-cache", 8 },
    { "cache-control", 13, "no-store", 8 },
    { "cache-control", 13, "public, max-", 12 },
    { "content-encoding", 16, "br", 2 },
    { "content-encoding", 16, "gzip", 4 },
    { "content-type", 12, "application/dns-", 16 },
    { "content-type", 12, "application/", 12 },
    { "content-type", 12, "application/json", 16 },
    { "content-type", 12, "application/x-www-", 18 },
    { "content-type", 12, "image/gif", 9 },
    { "content-type", 12, "image/jpeg", 10 },
    { "content-type", 12, "image/png", 9 },
    { "content-type", 12, "text/css", 8 },
    { "content-type", 12, "text/html;", 10 },
    { "content-type", 12, "text/plain", 10 },
    { "content-type", 12, "text/", 5 },
    { "range", 5, "bytes=0-", 8 },
    { "strict-transport-security", 25, "max-age=31536000", 16 },
    { "strict-transport-security", 25, "max-age=31536000;", 17 },
    { "strict-transport-security", 25, "max-age=31536000;", 17 },
    { "vary", 4, "accept-encoding", 15 },
    { "vary", 4, "origin", 6 },
    { "x-content-type-options", 22, "nosniff", 7 },
    { "x-xss-protection", 16, "1; mode=block", 13 },
    { ":status", 7, "100", 3 },
    { ":status", 7, "204", 3 },
    { ":status", 7, "206", 3 },
    { ":status", 7, "302", 3 },
    { ":status", 7, "400", 3 },
    { ":status", 7, "403", 3 },
    { ":status", 7, "421", 3 },
    { ":status", 7, "425", 3 },
    { ":status", 7, "500", 3 },
    { "accept-language", 15, "", 0 },
    { "access-control-allow-credentials", 32, "FALSE", 5 },
    { "access-control-allow-credentials", 32, "TRUE", 4 },
    { "access-control-allow-headers", 28, "*", 1 },
    { "access-control-allow-methods", 28, "get", 3 },
    { "access-control-allow-methods", 28, "get, post, options", 18 },
    { "access-control-allow-methods", 28, "options", 7 },
    { "access-control-expose-headers", 29, "content-length", 14 },
    { "access-control-request-headers", 30, "content-type", 12 },
    { "access-control-request-method", 29, "get", 3 },
    { "access-control-request-method", 29, "post", 4 },
    { "alt-svc", 7, "clear", 5 },
    { "authorization", 13, "", 0 },
    { "content-security-policy", 23, "script-src 'none';", 18 },
    { "early-data", 10, "1", 1 },
    { "expect-ct", 9, "", 0 },
    { "forwarded", 9, "", 0 },
    { "if-range", 8, "", 0 },
    { "origin", 6, "", 0 },
    { "purpose", 7, "prefetch", 8 },
    { "server", 6, "", 0 },
    { "timing-allow-origin", 19, "*", 1 },
    { "upgrade-insecure-requests", 25, "1", 1 },
    { "user-agent", 10, "", 0 },
    { "x-forwarded-for", 15, "", 0 },
    { "x-frame-options", 15, "deny", 4 },
    { "x-frame-options", 15, "sameorigin", 10 },
};

#endif
