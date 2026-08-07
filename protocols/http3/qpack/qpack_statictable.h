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

typedef struct {
    const char* name;
    const char* value;
} qpack_static_entry_t;

/* 0-based: the (i+1)-th initializer is index i. */
static const qpack_static_entry_t
qpack_static_table[QPACK_STATIC_TABLE_SIZE] = {
    { ":authority", "" },
    { ":path", "/" },
    { "age", "0" },
    { "content-disposition", "" },
    { "content-length", "0" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "referer", "" },
    { "set-cookie", "" },
    { ":method", "CONNECT" },
    { ":method", "DELETE" },
    { ":method", "GET" },
    { ":method", "HEAD" },
    { ":method", "OPTIONS" },
    { ":method", "POST" },
    { ":method", "PUT" },
    { ":scheme", "http" },
    { ":scheme", "https" },
    { ":status", "103" },
    { ":status", "200" },
    { ":status", "304" },
    { ":status", "404" },
    { ":status", "503" },
    { "accept", "*/*" },
    { "accept", "application/dns-" },
    { "accept-encoding", "gzip, deflate, br" },
    { "accept-ranges", "bytes" },
    { "access-control-allow-headers", "cache-control" },
    { "access-control-allow-headers", "content-type" },
    { "access-control-allow-origin", "*" },
    { "cache-control", "max-age=0" },
    { "cache-control", "max-age=2592000" },
    { "cache-control", "max-age=604800" },
    { "cache-control", "no-cache" },
    { "cache-control", "no-store" },
    { "cache-control", "public, max-" },
    { "content-encoding", "br" },
    { "content-encoding", "gzip" },
    { "content-type", "application/dns-" },
    { "content-type", "application/" },
    { "content-type", "application/json" },
    { "content-type", "application/x-www-" },
    { "content-type", "image/gif" },
    { "content-type", "image/jpeg" },
    { "content-type", "image/png" },
    { "content-type", "text/css" },
    { "content-type", "text/html;" },
    { "content-type", "text/plain" },
    { "content-type", "text/" },
    { "range", "bytes=0-" },
    { "strict-transport-security", "max-age=31536000" },
    { "strict-transport-security", "max-age=31536000;" },
    { "strict-transport-security", "max-age=31536000;" },
    { "vary", "accept-encoding" },
    { "vary", "origin" },
    { "x-content-type-options", "nosniff" },
    { "x-xss-protection", "1; mode=block" },
    { ":status", "100" },
    { ":status", "204" },
    { ":status", "206" },
    { ":status", "302" },
    { ":status", "400" },
    { ":status", "403" },
    { ":status", "421" },
    { ":status", "425" },
    { ":status", "500" },
    { "accept-language", "" },
    { "access-control-allow-credentials", "FALSE" },
    { "access-control-allow-credentials", "TRUE" },
    { "access-control-allow-headers", "*" },
    { "access-control-allow-methods", "get" },
    { "access-control-allow-methods", "get, post, options" },
    { "access-control-allow-methods", "options" },
    { "access-control-expose-headers", "content-length" },
    { "access-control-request-headers", "content-type" },
    { "access-control-request-method", "get" },
    { "access-control-request-method", "post" },
    { "alt-svc", "clear" },
    { "authorization", "" },
    { "content-security-policy", "script-src 'none';" },
    { "early-data", "1" },
    { "expect-ct", "" },
    { "forwarded", "" },
    { "if-range", "" },
    { "origin", "" },
    { "purpose", "prefetch" },
    { "server", "" },
    { "timing-allow-origin", "*" },
    { "upgrade-insecure-requests", "1" },
    { "user-agent", "" },
    { "x-forwarded-for", "" },
    { "x-frame-options", "deny" },
    { "x-frame-options", "sameorigin" },
};

#endif
