#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "ws_deflate.h"

/** Trailer that zlib appends with Z_SYNC_FLUSH - must be stripped from output */
static const unsigned char WS_DEFLATE_TRAILER[] = {0x00, 0x00, 0xff, 0xff};
#define WS_DEFLATE_TRAILER_SIZE 4

void ws_deflate_init(ws_deflate_t* deflate) {
    memset(&deflate->deflate_stream, 0, sizeof(z_stream));
    memset(&deflate->inflate_stream, 0, sizeof(z_stream));
    deflate->deflate_init = 0;
    deflate->inflate_init = 0;

    deflate->config.server_max_window_bits = 15;
    deflate->config.client_max_window_bits = 15;
    deflate->config.server_no_context_takeover = 0;
    deflate->config.client_no_context_takeover = 0;
}

int ws_deflate_start(ws_deflate_t* deflate) {
    z_stream* ds = &deflate->deflate_stream;
    z_stream* is = &deflate->inflate_stream;

    ds->zalloc = Z_NULL;
    ds->zfree = Z_NULL;
    ds->opaque = Z_NULL;

    /**
     * deflateInit2 with negative windowBits gives raw deflate
     * (no zlib or gzip header/trailer)
     */
    int window_bits = -deflate->config.server_max_window_bits;
    if (deflateInit2(ds, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     window_bits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return 0;
    }
    deflate->deflate_init = 1;

    is->zalloc = Z_NULL;
    is->zfree = Z_NULL;
    is->opaque = Z_NULL;
    is->avail_in = 0;
    is->next_in = Z_NULL;

    window_bits = -deflate->config.client_max_window_bits;
    if (inflateInit2(is, window_bits) != Z_OK) {
        deflateEnd(ds);
        deflate->deflate_init = 0;
        return 0;
    }
    deflate->inflate_init = 1;

    return 1;
}

void ws_deflate_free(ws_deflate_t* deflate) {
    if (deflate->deflate_init) {
        deflateEnd(&deflate->deflate_stream);
        deflate->deflate_init = 0;
    }
    if (deflate->inflate_init) {
        inflateEnd(&deflate->inflate_stream);
        deflate->inflate_init = 0;
    }
}

void ws_deflate_reset_deflate(ws_deflate_t* deflate) {
    if (deflate->deflate_init && deflate->config.server_no_context_takeover) {
        deflateReset(&deflate->deflate_stream);
    }
}

void ws_deflate_reset_inflate(ws_deflate_t* deflate) {
    if (deflate->inflate_init && deflate->config.client_no_context_takeover) {
        inflateReset(&deflate->inflate_stream);
    }
}

ssize_t ws_deflate_compress(ws_deflate_t* ws_ctx,
                            const char* in, size_t in_len,
                            char* out, size_t out_len,
                            int final) {
    z_stream* stream = &ws_ctx->deflate_stream;

    stream->next_in = (Bytef*)in;
    stream->avail_in = (uInt)in_len;
    stream->next_out = (Bytef*)out;
    stream->avail_out = (uInt)out_len;

    const int flush = final ? Z_SYNC_FLUSH : Z_NO_FLUSH;
    const int status_code = deflate(stream, flush);
    if (status_code != Z_OK && status_code != Z_BUF_ERROR)
        return -1;

    size_t compressed = out_len - stream->avail_out;

    /**
     * Per RFC 7692: Remove 0x00 0x00 0xff 0xff trailer from final message.
     * This trailer is always appended by Z_SYNC_FLUSH.
     */
    if (final && compressed >= WS_DEFLATE_TRAILER_SIZE) {
        if (memcmp(out + compressed - WS_DEFLATE_TRAILER_SIZE,
                   WS_DEFLATE_TRAILER, WS_DEFLATE_TRAILER_SIZE) == 0) {
            compressed -= WS_DEFLATE_TRAILER_SIZE;
        }
    }

    return (ssize_t)compressed;
}

ssize_t ws_deflate_decompress(ws_deflate_t* ws_ctx,
                              const char* in, size_t in_len,
                              char* out, size_t out_len) {
    z_stream* stream = &ws_ctx->inflate_stream;

    stream->next_in = (Bytef*)in;
    stream->avail_in = (uInt)in_len;
    stream->next_out = (Bytef*)out;
    stream->avail_out = (uInt)out_len;

    const int status_code = inflate(stream, Z_SYNC_FLUSH);
    if (status_code != Z_OK &&
        status_code != Z_STREAM_END &&
        status_code != Z_BUF_ERROR) {
        return -1;
    }

    return (ssize_t)(out_len - stream->avail_out);
}

int ws_deflate_has_more(ws_deflate_t* ws_ctx) {
    return ws_ctx->inflate_stream.avail_out == 0;
}

/**
 * Parse permessage-deflate parameters from extension header.
 * Example: "permessage-deflate; server_no_context_takeover; client_max_window_bits=12"
 * Parameters can appear in any order, and permessage-deflate can appear anywhere in the header.
 */
int ws_deflate_parse_header(const char* header, ws_deflate_config_t* config) {
    if (header == NULL) return 0;

    config->server_max_window_bits = 15;
    config->client_max_window_bits = 15;
    config->server_no_context_takeover = 0;
    config->client_no_context_takeover = 0;

    int found_deflate = 0;
    const char* p = header;

    while (*p) {
        while (*p == ' ' || *p == ';' || *p == ',') p++;
        if (*p == '\0') break;

        if (strncmp(p, "permessage-deflate", 18) == 0 &&
            (p[18] == '\0' || p[18] == ' ' || p[18] == ';' || p[18] == ',')) {
            found_deflate = 1;
            p += 18;
        }
        else if (strncmp(p, "server_no_context_takeover", 26) == 0 &&
                 (p[26] == '\0' || p[26] == ' ' || p[26] == ';' || p[26] == ',')) {
            config->server_no_context_takeover = 1;
            p += 26;
        }
        else if (strncmp(p, "client_no_context_takeover", 26) == 0 &&
                 (p[26] == '\0' || p[26] == ' ' || p[26] == ';' || p[26] == ',')) {
            config->client_no_context_takeover = 1;
            p += 26;
        }
        else if (strncmp(p, "server_max_window_bits", 22) == 0) {
            p += 22;
            if (*p == '=') {
                p++;
                int val = atoi(p);
                if (val >= 8 && val <= 15)
                    config->server_max_window_bits = val;
                while (*p >= '0' && *p <= '9') p++;
            }
        }
        else if (strncmp(p, "client_max_window_bits", 22) == 0) {
            p += 22;
            if (*p == '=') {
                p++;
                int val = atoi(p);
                if (val >= 8 && val <= 15)
                    config->client_max_window_bits = val;
                while (*p >= '0' && *p <= '9') p++;
            }
        }
        else {
            while (*p && *p != ';' && *p != ',') p++;
        }
    }

    return found_deflate;
}

int ws_deflate_build_header(const ws_deflate_config_t* config, char* buf, size_t buf_size) {
    size_t pos = 0;
    int n;

    n = snprintf(buf + pos, buf_size - pos, "permessage-deflate");
    if (n < 0 || (size_t)n >= buf_size - pos) return -1;
    pos += n;

    if (config->server_no_context_takeover) {
        n = snprintf(buf + pos, buf_size - pos, "; server_no_context_takeover");
        if (n < 0 || (size_t)n >= buf_size - pos) return -1;
        pos += n;
    }

    if (config->client_no_context_takeover) {
        n = snprintf(buf + pos, buf_size - pos, "; client_no_context_takeover");
        if (n < 0 || (size_t)n >= buf_size - pos) return -1;
        pos += n;
    }

    if (config->server_max_window_bits != 15) {
        n = snprintf(buf + pos, buf_size - pos, "; server_max_window_bits=%d",
                     config->server_max_window_bits);
        if (n < 0 || (size_t)n >= buf_size - pos) return -1;
        pos += n;
    }

    if (config->client_max_window_bits != 15) {
        n = snprintf(buf + pos, buf_size - pos, "; client_max_window_bits=%d",
                     config->client_max_window_bits);
        if (n < 0 || (size_t)n >= buf_size - pos) return -1;
        pos += n;
    }

    return (int)pos;
}
