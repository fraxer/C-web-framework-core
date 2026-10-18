#ifndef CWFR_WS_SESSION_H
#define CWFR_WS_SESSION_H

typedef struct ws_session ws_session_t;

/* On success owns data; on allocation failure ownership stays with caller.
 * A session spans the transport and any in-flight requests. Its payload is
 * application-owned: the application must synchronize mutable fields. */
ws_session_t* ws_session_create(void* data, void (*destroy)(void*));
ws_session_t* ws_session_ref(ws_session_t* session);
void ws_session_unref(ws_session_t* session);
void* ws_session_data(const ws_session_t* session);

#endif
