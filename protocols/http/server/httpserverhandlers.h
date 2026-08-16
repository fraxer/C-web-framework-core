#ifndef __HTTP1_SERVER_HANDLERS__
#define __HTTP1_SERVER_HANDLERS__

#include "connection_s.h"
#include "httprequest.h"
#include "httpresponse.h"
#include "server.h"

int set_tls(connection_t* connection);
int set_http(connection_t* connection);
int http_server_guard_read(connection_t* connection);
int http_server_guard_write(connection_t* connection);
void http_server_init_sni_callbacks(server_t* servers);

/* Dispatch a parsed request through the route + handler pipeline shared with
 * HTTP/1.1. Used by the HTTP/2 layer, which builds httprequest_t from frames and
 * hands it here; the handler fills httpresponse_t and the protocol's write guard
 * serializes it. */
int http_server_dispatch(connection_t* connection, httprequest_t* request);

/* Drive the response filter chain. Shared with the HTTP/2 write guard, which
 * runs the same stages — only the terminal one differs (frames instead of a
 * status line + chunked body). Return values are the CWF_* codes. */
int __run_header_filters(httprequest_t* request, httpresponse_t* response);
int __run_body_filters(httprequest_t* request, httpresponse_t* response);
int __run_flush_filters(httprequest_t* request, httpresponse_t* response);

#endif
