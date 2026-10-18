#include <stdatomic.h>
#include <stdlib.h>
#include "ws_session.h"

struct ws_session {
    atomic_size_t refs;
    void* data;
    void (*destroy)(void*);
};

ws_session_t* ws_session_create(void* data, void (*destroy)(void*)) {
    ws_session_t* session = malloc(sizeof *session);
    if (session == NULL) return NULL;
    atomic_init(&session->refs, 1);
    session->data = data;
    session->destroy = destroy;
    return session;
}

ws_session_t* ws_session_ref(ws_session_t* session) {
    if (session != NULL)
        atomic_fetch_add_explicit(&session->refs, 1, memory_order_relaxed);
    return session;
}

void ws_session_unref(ws_session_t* session) {
    if (session != NULL &&
        atomic_fetch_sub_explicit(&session->refs, 1, memory_order_acq_rel) == 1) {
        if (session->destroy != NULL) session->destroy(session->data);
        free(session);
    }
}

void* ws_session_data(const ws_session_t* session) {
    return session != NULL ? session->data : NULL;
}
