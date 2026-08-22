#include "h2stream.h"

#include <stdlib.h>

#include "h2session.h"
#include "h2ws.h"

/* The table is a plain singly-linked list, kept in arrival order with a tail
 * pointer. SETTINGS_MAX_CONCURRENT_STREAMS caps it at a low hundred, so a linear
 * scan costs far less than the hashing plus key allocation a map would need, and
 * there is nothing to keep in sync.
 *
 * The order is not incidental: the write path walks the table front to back and
 * the scheduler rotates a stream to the tail when it stops short, so list
 * position *is* the round-robin cursor. Anything that unlinks a stream must keep
 * `streams_tail` correct or the rotation quietly turns back into a stack. */

h2stream_t* h2stream_create(h2session_t* session, uint32_t id) {
    h2stream_t* stream = calloc(1, sizeof(*stream));
    if (stream == NULL) return NULL;

    /* From the session's pool when one is parked there (docs/http2/10 §10.7). */
    stream->request = h2_session_take_request(session);
    if (stream->request == NULL) {
        free(stream);
        return NULL;
    }

    /* calloc already zeroed the storage, but an atomic wants an explicit
     * initialisation to have a well-defined value to the memory model. */
    atomic_init(&stream->handler_pending, 0);
    atomic_init(&stream->response_ready, 0);
    atomic_init(&stream->cancelled, 0);

    stream->id = id;
    stream->state = H2_STREAM_OPEN;
    stream->send_window = session->peer_initial_window;
    stream->recv.size = session->stream_recv_learned;
    stream->content_length = -1;

    if (session->streams_tail != NULL) session->streams_tail->next = stream;
    else session->streams = stream;
    session->streams_tail = stream;
    session->stream_count++;

    return stream;
}

h2stream_t* h2stream_find(h2session_t* session, uint32_t id) {
    for (h2stream_t* stream = session->streams; stream != NULL; stream = stream->next)
        if (stream->id == id) return stream;

    return NULL;
}

h2stream_t* h2stream_find_by_response(h2session_t* session, const httpresponse_t* response) {
    if (response == NULL) return NULL;

    for (h2stream_t* stream = session->streams; stream != NULL; stream = stream->next)
        if (stream->response == response) return stream;

    return NULL;
}

/* `session` may be NULL only when there is nowhere to park a response — it is
 * the pool's owner, and a stream torn down with its session has no next stream
 * to hand the object to. */
static void h2stream_destroy(h2session_t* session, h2stream_t* stream) {
    if (stream->request != NULL) h2_session_park_request(session, stream->request);
    if (stream->response != NULL) h2_server_park_response(session, stream->response);
    /* A tunnel dies with its stream — whether the stream ended cleanly, was
     * reset, or went down with the connection (h2stream_free_all). */
    if (stream->ws != NULL) h2_ws_tunnel_free(stream->ws);
    /* Hints the peer will never see: the stream ended before the write pass
     * reached them. */
    http_headers_free(stream->early_hints);

    free(stream);
}

void h2stream_close(h2session_t* session, h2stream_t* stream) {
    if (stream == NULL) return;

    /* A handler thread is about to touch this request/response, or is touching
     * it right now. Keep the stream alive and let the post-handler hook free it;
     * unlinking here would leave the queued item holding dangling pointers. */
    if (atomic_load_explicit(&stream->handler_pending, memory_order_acquire)) {
        stream->state = H2_STREAM_CLOSED;
        atomic_store_explicit(&stream->cancelled, 1, memory_order_release);
        return;
    }

    h2stream_t*  prev = NULL;
    h2stream_t** link = &session->streams;
    while (*link != NULL && *link != stream) {
        prev = *link;
        link = &(*link)->next;
    }

    if (*link == stream) {
        *link = stream->next;
        if (session->streams_tail == stream) session->streams_tail = prev;
        session->stream_count--;
    }

    h2stream_destroy(session, stream);
}

void h2stream_rotate(h2session_t* session, h2stream_t* stream) {
    if (stream == NULL || session->streams_tail == stream) return;

    h2stream_t** link = &session->streams;
    while (*link != NULL && *link != stream) link = &(*link)->next;
    if (*link != stream) return; /* already off the table */

    *link = stream->next;
    stream->next = NULL;

    /* streams_tail is non-NULL here: the table still holds whatever was tail,
     * since it is not this stream. */
    session->streams_tail->next = stream;
    session->streams_tail = stream;
}

void h2stream_free_all(h2session_t* session) {
    h2stream_t* stream = session->streams;

    while (stream != NULL) {
        h2stream_t* next = stream->next;
        /* NULL: the session is going away with these streams, so parking a
         * response in its pool would only mean freeing it twice over. */
        h2stream_destroy(NULL, stream);
        stream = next;
    }

    session->streams = NULL;
    session->streams_tail = NULL;
    session->stream_count = 0;
}

size_t h2stream_active_count(h2session_t* session) {
    size_t count = 0;

    for (h2stream_t* stream = session->streams; stream != NULL; stream = stream->next)
        if (stream->state != H2_STREAM_CLOSED) count++;

    return count;
}
