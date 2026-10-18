#ifndef __WEBSOCKETSSWITCH__
#define __WEBSOCKETSSWITCH__

#include <string.h>

#include "httpresponse.h"
#include "httprequest.h"
#include "httpcontext.h"
#include "websocketsprotocoldefault.h"
#include "websocketsprotocolresource.h"
#include "sha1.h"
#include "base64.h"
#include "ws_deflate.h"

typedef struct ws_handshake_data {
    ws_deflate_config_t deflate_config;
    int deflate_enabled;
    ws_session_t* session;
} ws_handshake_data_t;

void switch_to_websockets(httpctx_t* ctx);
/* Consumes session on every path. Session-bearing connections deliberately
 * decline compression: their reserved response slots must precede broadcasts. */
int switch_to_websockets_session(httpctx_t* ctx, ws_session_t* session);

#endif