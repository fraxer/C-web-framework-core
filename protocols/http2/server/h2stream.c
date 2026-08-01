#include "h2stream.h"

#include <stdlib.h>

#include "h2session.h"

/* The table is a plain singly-linked list. SETTINGS_MAX_CONCURRENT_STREAMS caps
 * it at a low hundred, so a linear scan costs far less than the hashing plus key
 * allocation a map would need, and there is nothing to keep in sync. */

h2stream_t* h2stream_create(h2session_t* session, uint32_t id) {
    h2stream_t* stream = calloc(1, sizeof(*stream));
    if (stream == NULL) return NULL;

    stream->request = httprequest_create(session->connection);
    if (stream->request == NULL) {
        free(stream);
        return NULL;
    }

    stream->id = id;
    stream->state = H2_STREAM_OPEN;
    stream->send_window = session->peer_initial_window;
    stream->content_length = -1;

    stream->next = session->streams;
    session->streams = stream;
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

static void h2stream_destroy(h2stream_t* stream) {
    if (stream->request != NULL) httprequest_free(stream->request);
    if (stream->response != NULL) httpresponse_free(stream->response);

    free(stream);
}

void h2stream_close(h2session_t* session, h2stream_t* stream) {
    if (stream == NULL) return;

    /* A handler thread is about to touch this request/response, or is touching
     * it right now. Keep the stream alive and let the post-handler hook free it;
     * unlinking here would leave the queued item holding dangling pointers. */
    if (stream->handler_pending) {
        stream->state = H2_STREAM_CLOSED;
        stream->cancelled = 1;
        return;
    }

    h2stream_t** link = &session->streams;
    while (*link != NULL && *link != stream) link = &(*link)->next;

    if (*link == stream) {
        *link = stream->next;
        session->stream_count--;
    }

    h2stream_destroy(stream);
}

void h2stream_free_all(h2session_t* session) {
    h2stream_t* stream = session->streams;

    while (stream != NULL) {
        h2stream_t* next = stream->next;
        h2stream_destroy(stream);
        stream = next;
    }

    session->streams = NULL;
    session->stream_count = 0;
}

size_t h2stream_active_count(h2session_t* session) {
    size_t count = 0;

    for (h2stream_t* stream = session->streams; stream != NULL; stream = stream->next)
        if (stream->state != H2_STREAM_CLOSED) count++;

    return count;
}
