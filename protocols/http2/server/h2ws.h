#ifndef __H2WS__
#define __H2WS__

#include <stddef.h>
#include <stdint.h>

#include "connection.h"
#include "cqueue.h"
#include "h2data.h"
#include "websocketsparser.h"
#include "websocketsresponse.h"

struct h2session;

/* WebSocket tunnel on one HTTP/2 stream (RFC 8441) —
 * docs/http2/09-extended-connect.md.
 *
 * The whole point of the design is that this hangs off a *stream*, not off the
 * connection. On HTTP/1.1 "websocket" is a property of the connection: the
 * upgrade swaps connection->read/write, ctx->parser and the output queue, and
 * everything after that belongs to one message stream. Under RFC 8441 the
 * connection stays HTTP/2 and keeps serving ordinary requests, while any number
 * of its streams may independently be tunnels — so every piece of that state
 * has to live here instead.
 *
 * Step 2 of the plan builds the input half only: DATA payloads are handed to
 * the WebSocket frame parser, which needs no changes at all — it reads from a
 * plain `char*` that this module repoints at each DATA payload. The output half
 * (framing responses back into DATA) is step 3, and dispatching parsed messages
 * to handlers is step 4; until then a parsed message is logged and dropped. */

typedef struct h2_ws_tunnel {
    /* The connection this tunnel rides on. Kept so teardown can unsubscribe it
     * from broadcast channels without walking back through the stream. */
    connection_t* connection;

    /* Frame parser for this tunnel. Created with the connection so it can build
     * requests, but deliberately NOT installed anywhere on it — the connection
     * still speaks HTTP/2. */
    websocketsparser_t* parser;

    /* Output order for THIS tunnel. WebSocket has no stream ids, so a peer
     * matches replies by position and the order must be preserved — but only
     * within one tunnel. Two tunnels on the same connection do not order each
     * other; that is what their h2 stream ids are for. Hence a queue here
     * rather than the connection-wide ctx->write_queue the HTTP/1.1 path uses
     * (docs/http2/09 §4.1). */
    cqueue_t* out;                  /* connection_out_slot_t*, in arrival order */
    websocketsresponse_t* writing;  /* head being framed out right now */
    h2_data_writer_t writer;        /* resumable DATA framing state */

    unsigned close_sent : 1;        /* a CLOSE frame has left; the stream is done */

    /* Messages parsed so far, for the step-2 log line and for tests. */
    uint64_t messages;
} h2_ws_tunnel_t;

/* Build a tunnel for a stream whose extended CONNECT was accepted. Returns NULL
 * on allocation failure, in which case the caller must fail the stream. */
h2_ws_tunnel_t* h2_ws_tunnel_create(connection_t* connection, int resource_protocol);
void h2_ws_tunnel_free(h2_ws_tunnel_t* tunnel);

/* Hand one DATA payload to the parser. `data` must be writable: WebSocket
 * payloads are masked, and the parser unmasks in place — exactly as it does
 * with connection->buffer on the HTTP/1.1 path.
 *
 * Returns 1 to keep the tunnel, 0 when the peer's framing is broken badly
 * enough that the stream has to die. A frame split across several DATA frames
 * resumes correctly: the parser keeps its own stage and buffers, and each DATA
 * payload is simply the next read. */
int h2_ws_tunnel_feed(h2_ws_tunnel_t* tunnel, connection_t* connection,
                      uint8_t* data, size_t len);

/* Is anything waiting to go out on this tunnel? Read by the write scheduler to
 * decide whether the stream deserves a turn and whether to arm EPOLLOUT. */
int h2_ws_tunnel_has_output(const h2_ws_tunnel_t* tunnel);

/* Frame queued WebSocket responses into DATA on this stream. Same status
 * vocabulary as h2_data_write, so the caller's scheduling rules — pin on
 * SOCKET, rotate on WINDOW/YIELD — apply unchanged. */
h2_data_status_e h2_ws_tunnel_write(struct h2session* s, h2stream_t* stream);

#endif
