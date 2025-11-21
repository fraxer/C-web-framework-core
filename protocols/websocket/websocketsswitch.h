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

void switch_to_websockets(httpctx_t* ctx);

#endif