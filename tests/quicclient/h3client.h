#ifndef __H3CLIENT__
#define __H3CLIENT__

#include <stddef.h>
#include <stdint.h>

#include "h3frame.h"
#include "qpack.h"
#include "quicclient.h"

/* An HTTP/3 client, on top of the QUIC one (docs/http3/08-testing.md §2).
 *
 * ## Why this exists
 *
 * Every module of phase 5 is unit-tested against streams built by hand, and
 * that is exactly what such tests cannot check: whether the pieces are wired to
 * each other in the right order. Specifically --
 *
 *  - that our SETTINGS reach the peer before the first response, as §6.2.1
 *    requires, rather than merely being encoded correctly;
 *  - that reading streams, running the filter chain and building packets happen
 *    in that order, so a response goes out in the packet built for it instead
 *    of one round trip later;
 *  - that the stream ids a real client picks are the ones the server expects;
 *  - that a response larger than the write-ahead budget actually resumes.
 *
 * None of those is visible from inside a single module, and all of them are
 * cheap to get wrong. One real request answers all four at once.
 *
 * ## What it is not
 *
 * Not a general-purpose client, and not a conformance tester. It speaks
 * QPACK-lite because that is what the server speaks, it keeps the whole
 * response in memory, and it assumes the exchange fits in the windows both
 * sides advertised at the start. It borrows every codec from the server's own
 * modules -- what is written here is only the client half of the logic, which
 * is the part that has to be independent for the test to mean anything. */

typedef struct h3client_response {
    int    status;

    /* Interim responses seen before the final one (RFC 9110 §15.2): how many,
     * and the status of the last. Recorded rather than skipped, because "the
     * server sent no 103" and "the client threw it away" look the same from a
     * body. */
    int    interim_count;
    int    interim_status;
    size_t interim_fields;

    /* Trailing fields, if a second field section followed the body (§4.1). */
    size_t trailer_count;

    char*  body;
    size_t body_len;

    /* Response fields, as decoded. Freed with h3client_response_free. */
    qpack_header_t* fields;
    size_t          fields_count;
} h3client_response_t;

void h3client_response_free(h3client_response_t* r);

/* Open our control stream and send SETTINGS. Called once the handshake is
 * complete, before any request: §6.2.1 requires SETTINGS to be the first frame
 * of the control stream, and a server is within its rights to close the
 * connection if a request arrives without one. */
int h3client_start(quicclient_t* client);

/* Send a GET on `stream_id` (a client bidirectional stream: 0, 4, 8, ...) and
 * read the whole response. Returns 1 on success. `timeout_ms` bounds the wait
 * for the complete response, not one datagram. */
int h3client_get(quicclient_t* client, uint64_t stream_id,
                 const char* authority, const char* path,
                 int timeout_ms, h3client_response_t* out);

/* Send `count` GETs at once, on streams 0, 4, 8, ... and read all the
 * responses. The whole point is that they are outstanding *together*: one
 * request at a time exercises none of the concurrency the server was built
 * for, and a server that serialises them looks identical from the outside
 * unless several are in flight.
 *
 * `out` receives `count` responses, index i for stream 4*i. Returns 1 only if
 * every one of them completed. */
int h3client_get_many(quicclient_t* client, size_t count,
                      const char* authority, const char* path,
                      int timeout_ms, h3client_response_t* out);

/* A POST that withholds its body until the server says to send it
 * (`Expect: 100-continue`, RFC 9110 §10.1.1).
 *
 * The withholding is the test. A client that sends the body anyway would get
 * the same final response whether or not the server ever sent a 100, so the
 * only way to see the interim response is to wait for it: headers go out
 * without FIN, and the body follows only once a 1xx has arrived (or the wait
 * runs out, which is what a real client does too). `out->interim_count` says
 * which of the two happened. */
int h3client_post_expect(quicclient_t* client, uint64_t stream_id,
                         const char* authority, const char* path,
                         const char* body, size_t body_len,
                         int timeout_ms, h3client_response_t* out);

/* Encode a GET request (HEADERS frame, QPACK static-only) into `dst`, without
 * sending it. Returns its length, or 0.
 *
 * Split out for the scenarios that need the request bytes at a moment they
 * choose rather than when h3client_get chooses -- notably a 0-RTT flight,
 * which has to be written before the handshake completes. */
size_t h3client_request_bytes(uint8_t* dst, size_t cap,
                              const char* authority, const char* path);

/* What the server said on its control stream: whether SETTINGS arrived, and
 * what they contained. Read after a request, because service streams and
 * request streams are delivered independently. */
int h3client_peer_settings(quicclient_t* client, h3settings_t* out);

/* Stream slots kept aside for the service streams both ends open: our control
 * stream and two QPACK streams, the server's three, and a grease stream each
 * (RFC 9114 §6.2, RFC 9287). Eight is the observed count plus room. */
#define H3CLIENT_SERVICE_SLOTS 8

#endif
