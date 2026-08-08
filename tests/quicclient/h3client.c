#include "h3client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "h3frame.h"
#include "h3unistream.h"
#include "qpack.h"
#include "quictime.h"
#include "varint.h"

/* Our own streams. A client's unidirectional streams are 2, 6, 10, ... and its
 * bidirectional ones 0, 4, 8, ... (RFC 9000 §2.1). */
#define H3CLIENT_CONTROL_STREAM 2

void h3client_response_free(h3client_response_t* r) {
    if (r == NULL) return;

    free(r->body);
    qpack_headers_free(r->fields, r->fields_count);

    r->body = NULL;
    r->fields = NULL;
    r->fields_count = 0;
}

int h3client_start(quicclient_t* client) {
    if (client == NULL) return 0;

    uint8_t buf[128];

    /* Stream type 0x00, then SETTINGS. A client with no dynamic table and no
     * blocked streams says so explicitly, for the same reason the server does:
     * it is how the peer learns not to try. */
    size_t p = h3uni_write_type(buf, sizeof buf, H3_UNI_STREAM_CONTROL);
    if (p == 0) return 0;

    h3settings_t settings;
    h3settings_defaults(&settings);
    settings.qpack_max_table_capacity = 0;
    settings.qpack_blocked_streams = 0;
    settings.max_field_section_size = 65536;

    uint8_t payload[64];
    const size_t plen = h3settings_encode(payload, sizeof payload, &settings);
    if (plen == 0) return 0;

    const size_t n = h3frame_write(buf + p, sizeof buf - p, H3_FRAME_SETTINGS, payload, plen);
    if (n == 0) return 0;
    p += n;

    /* Left open: closing a control stream is H3_CLOSED_CRITICAL_STREAM and
     * would kill the connection we are about to use (§6.2.6). */
    return quicclient_stream_write(client, H3CLIENT_CONTROL_STREAM, buf, p, 0);
}

/* Build a HEADERS frame for a request. `method` and the optional extra field
 * are what tell the two request shapes apart. */
static size_t __build_request_ex(uint8_t* dst, size_t cap, const char* method,
                                 const char* authority, const char* path,
                                 const char* extra_name, const char* extra_value) {
    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    if (enc == NULL) return 0;

    qpack_header_t fields[6];
    size_t n = 0;
    fields[n++] = (qpack_header_t){ (char*)":method", 7, (char*)method, strlen(method), 0 };
    fields[n++] = (qpack_header_t){ (char*)":scheme", 7, (char*)"https", 5, 0 };
    fields[n++] = (qpack_header_t){ (char*)":authority", 10, (char*)authority,
                                    strlen(authority), 0 };
    fields[n++] = (qpack_header_t){ (char*)":path", 5, (char*)path, strlen(path), 0 };
    fields[n++] = (qpack_header_t){ (char*)"user-agent", 10, (char*)"cwfr-h3client", 13, 0 };
    if (extra_name != NULL)
        fields[n++] = (qpack_header_t){ (char*)extra_name, strlen(extra_name),
                                        (char*)extra_value, strlen(extra_value), 0 };

    uint8_t block[1024];
    const size_t blen = qpack_encode_block(enc, fields, n, block, sizeof block);
    qpack_encoder_free(enc);

    if (blen == 0) return 0;

    return h3frame_write(dst, cap, H3_FRAME_HEADERS, block, blen);
}

/* Build the request's HEADERS frame. */
static size_t __build_request(uint8_t* dst, size_t cap,
                              const char* authority, const char* path) {
    qpack_encoder_t* enc = qpack_encoder_create(0, 0);
    if (enc == NULL) return 0;

    const qpack_header_t fields[] = {
        { (char*)":method",    7,  (char*)"GET",   3,               0 },
        { (char*)":scheme",    7,  (char*)"https", 5,               0 },
        { (char*)":authority", 10, (char*)authority, strlen(authority), 0 },
        { (char*)":path",      5,  (char*)path,     strlen(path),     0 },
        { (char*)"user-agent", 10, (char*)"cwfr-h3client", 13,      0 },
    };

    uint8_t block[1024];
    const size_t blen = qpack_encode_block(enc, fields, sizeof fields / sizeof fields[0],
                                           block, sizeof block);
    qpack_encoder_free(enc);

    if (blen == 0) return 0;

    return h3frame_write(dst, cap, H3_FRAME_HEADERS, block, blen);
}

/* Feed everything readable on `id` through the frame parser, collecting the
 * field section and the body. Returns 0 on a protocol error. */
static int __consume(quicclient_t* client, uint64_t id, h3frame_parser_t* parser,
                     h3client_response_t* out, int* headers_seen) {
    uint8_t buf[4096];

    for (;;) {
        const size_t n = quicclient_stream_read(client, id, buf, sizeof buf);
        if (n == 0) return 1;

        const uint8_t* p = buf;
        const uint8_t* end = buf + n;

        while (p < end) {
            const h3frame_status_e st = h3frame_parser_feed(parser, &p, end);

            if (st == H3FRAME_CONTINUE) break;

            if (st == H3FRAME_READY && parser->type == H3_FRAME_HEADERS) {
                qpack_decoder_t* d = qpack_decoder_create(0, 0);
                if (d == NULL) return 0;

                qpack_header_t* fields = NULL;
                size_t count = 0;
                const qpack_status_e qst = qpack_decode_block(d, parser->payload,
                                                              parser->payload_len, 0,
                                                              &fields, &count);
                qpack_decoder_free(d);

                if (qst != QPACK_OK) {
                    printf("  [h3] the field section would not decode (%d)\n", (int)qst);
                    return 0;
                }

                int status = 0;
                for (size_t i = 0; i < count; i++) {
                    if (fields[i].name_len == 7 && memcmp(fields[i].name, ":status", 7) == 0)
                        status = atoi(fields[i].value);
                }

                /* Three kinds of field section arrive on a request stream, and
                 * they are told apart by their status and their position: a 1xx
                 * is interim and more will follow, the first non-1xx is the
                 * response, and anything after that is trailers (§4.1). */
                if (status >= 100 && status < 200) {
                    out->interim_count++;
                    out->interim_status = status;
                    out->interim_fields = count > 0 ? count - 1 : 0;
                    qpack_headers_free(fields, count);
                }
                else if (!*headers_seen) {
                    out->fields = fields;
                    out->fields_count = count;
                    out->status = status;
                    *headers_seen = 1;
                }
                else {
                    out->trailer_count = count;
                    qpack_headers_free(fields, count);
                }

                continue;
            }

            if (st == H3FRAME_DATA_CHUNK) {
                if (parser->payload_len == 0) continue;

                char* grown = realloc(out->body, out->body_len + parser->payload_len + 1);
                if (grown == NULL) return 0;

                memcpy(grown + out->body_len, parser->payload, parser->payload_len);
                out->body = grown;
                out->body_len += parser->payload_len;
                out->body[out->body_len] = '\0';
                continue;
            }

            if (st == H3FRAME_SKIPPED || st == H3FRAME_HEAD) continue;

            if (st == H3FRAME_READY) continue;   /* a control frame here is the
                                                  * server's problem, not ours */

            printf("  [h3] frame error %d on stream %llu\n",
                   (int)st, (unsigned long long)id);
            return 0;
        }
    }
}

int h3client_get(quicclient_t* client, uint64_t stream_id,
                 const char* authority, const char* path,
                 int timeout_ms, h3client_response_t* out) {
    if (client == NULL || out == NULL) return 0;

    memset(out, 0, sizeof * out);

    uint8_t req[1280];
    const size_t n = __build_request(req, sizeof req, authority, path);
    if (n == 0) return 0;

    /* FIN with the request: a GET has no body, and the server cannot dispatch
     * until the request is complete. */
    if (!quicclient_stream_write(client, stream_id, req, n, 1)) return 0;

    h3frame_parser_t parser;
    h3frame_parser_init(&parser);

    int headers_seen = 0;
    int complete = 0;
    const uint64_t deadline = quic_now_us() + (uint64_t)timeout_ms * 1000;

    while (quic_now_us() < deadline) {
        if (!quicclient_pump(client, 100)) break;

        if (!__consume(client, stream_id, &parser, out, &headers_seen)) {
            h3frame_parser_free(&parser);
            return 0;
        }

        /* Done when the server has finished its half and nothing is left in the
         * buffer -- the response body ends with the stream (§4.1). */
        if (quicclient_stream_fin(client, stream_id) &&
            quicclient_stream_readable(client, stream_id) == 0) {
            complete = 1;
            break;
        }
    }

    h3frame_parser_free(&parser);

    if (!complete) {
        printf("  [h3] the response never ended: %zu body bytes and no FIN\n",
               out->body_len);
        return 0;
    }

    /* A Content-Length that disagrees with the body is a truncated transfer,
     * and reporting it as success is how a broken response would be mistaken
     * for a working one. */
    for (size_t i = 0; i < out->fields_count; i++) {
        if (out->fields[i].name_len != 14 ||
            memcmp(out->fields[i].name, "content-length", 14) != 0) continue;

        const unsigned long long declared = strtoull(out->fields[i].value, NULL, 10);
        if (declared != (unsigned long long)out->body_len) {
            printf("  [h3] content-length %llu but %zu bytes arrived\n",
                   declared, out->body_len);
            return 0;
        }
    }

    return headers_seen;
}

int h3client_get_many(quicclient_t* client, size_t count,
                      const char* authority, const char* path,
                      int timeout_ms, h3client_response_t* out) {
    if (client == NULL || out == NULL || count == 0) return 0;
    if (count > CLIENT_MAX_STREAMS / 2) return 0;

    h3frame_parser_t* parsers = calloc(count, sizeof * parsers);
    int* headers_seen = calloc(count, sizeof * headers_seen);
    int* complete = calloc(count, sizeof * complete);
    if (parsers == NULL || headers_seen == NULL || complete == NULL) {
        free(parsers); free(headers_seen); free(complete);
        return 0;
    }

    /* Every request goes out before any response is read. That ordering is the
     * test: the server must have all of them in flight at once, not one after
     * another. */
    for (size_t i = 0; i < count; i++) {
        memset(&out[i], 0, sizeof out[i]);
        h3frame_parser_init(&parsers[i]);

        uint8_t req[1280];
        const size_t n = __build_request(req, sizeof req, authority, path);
        if (n == 0 || !quicclient_stream_write(client, i * 4, req, n, 1)) {
            free(parsers); free(headers_seen); free(complete);
            return 0;
        }
    }

    const uint64_t deadline = quic_now_us() + (uint64_t)timeout_ms * 1000;
    size_t done = 0;

    while (done < count && quic_now_us() < deadline) {
        if (!quicclient_pump(client, 100)) break;

        for (size_t i = 0; i < count; i++) {
            if (complete[i]) continue;

            if (!__consume(client, i * 4, &parsers[i], &out[i], &headers_seen[i]))
                goto finish;

            if (quicclient_stream_fin(client, i * 4) &&
                quicclient_stream_readable(client, i * 4) == 0) {
                complete[i] = 1;
                done++;
            }
        }
    }

finish:
    for (size_t i = 0; i < count; i++) h3frame_parser_free(&parsers[i]);

    const int ok = (done == count);
    if (!ok)
        printf("  [h3] %zu of %zu responses completed\n", done, count);

    free(parsers); free(headers_seen); free(complete);

    return ok;
}

int h3client_post_expect(quicclient_t* client, uint64_t stream_id,
                         const char* authority, const char* path,
                         const char* body, size_t body_len,
                         int timeout_ms, h3client_response_t* out) {
    if (client == NULL || out == NULL) return 0;

    memset(out, 0, sizeof * out);

    uint8_t req[1280];
    const size_t n = __build_request_ex(req, sizeof req, "POST", authority, path,
                                        "expect", "100-continue");
    if (n == 0) return 0;

    /* No FIN: the body is being withheld, which is what the header announces. */
    if (!quicclient_stream_write(client, stream_id, req, n, 0)) return 0;

    h3frame_parser_t parser;
    h3frame_parser_init(&parser);

    int headers_seen = 0;
    const uint64_t deadline = quic_now_us() + (uint64_t)timeout_ms * 1000;

    /* Wait for permission, but not forever: a server that never answers gets
     * the body anyway after a moment, exactly as RFC 9110 §10.1.1 tells a real
     * client to behave. */
    const uint64_t wait_until = quic_now_us() + 1500000;
    while (out->interim_count == 0 && quic_now_us() < wait_until) {
        if (!quicclient_pump(client, 100)) break;
        if (!__consume(client, stream_id, &parser, out, &headers_seen)) {
            h3frame_parser_free(&parser);
            return 0;
        }
    }

    uint8_t data[2048];
    const size_t dlen = h3frame_write(data, sizeof data, H3_FRAME_DATA,
                                      (const uint8_t*)body, body_len);
    if (dlen == 0 || !quicclient_stream_write(client, stream_id, data, dlen, 1)) {
        h3frame_parser_free(&parser);
        return 0;
    }

    int complete = 0;
    while (quic_now_us() < deadline) {
        if (!quicclient_pump(client, 100)) break;

        if (!__consume(client, stream_id, &parser, out, &headers_seen)) {
            h3frame_parser_free(&parser);
            return 0;
        }

        if (quicclient_stream_fin(client, stream_id) &&
            quicclient_stream_readable(client, stream_id) == 0) {
            complete = 1;
            break;
        }
    }

    h3frame_parser_free(&parser);

    return complete && headers_seen;
}

int h3client_peer_settings(quicclient_t* client, h3settings_t* out) {
    if (client == NULL || out == NULL) return 0;

    h3settings_defaults(out);

    /* The server's control stream is its first unidirectional one, but which id
     * that is depends on the order it opened them in, so every server-initiated
     * unidirectional stream (3, 7, 11, ...) is examined until one announces
     * itself as the control stream. */
    for (uint64_t index = 0; index < CLIENT_MAX_STREAMS; index++) {
        const uint64_t id = (index << 2) | 0x03;

        uint8_t buf[2048];
        const size_t n = quicclient_stream_read(client, id, buf, sizeof buf);
        if (n == 0) continue;

        const uint8_t* p = buf;
        const uint8_t* end = buf + n;

        uint64_t type = 0;
        const size_t tn = varint_read(p, (size_t)(end - p), &type);
        if (tn == 0 || type != H3_UNI_STREAM_CONTROL) continue;
        p += tn;

        h3frame_parser_t parser;
        h3frame_parser_init(&parser);

        int found = 0;
        while (p < end) {
            const h3frame_status_e st = h3frame_parser_feed(&parser, &p, end);
            if (st == H3FRAME_CONTINUE) break;

            if (st == H3FRAME_READY && parser.type == H3_FRAME_SETTINGS) {
                found = h3settings_decode(parser.payload, parser.payload_len, out)
                        == H3SETTINGS_OK;
                break;
            }

            if (st == H3FRAME_SKIPPED || st == H3FRAME_READY) continue;
            break;
        }

        h3frame_parser_free(&parser);

        if (found) return 1;
    }

    return 0;
}
