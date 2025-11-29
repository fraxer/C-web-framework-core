#ifndef __HTTPCONTEXT__
#define __HTTPCONTEXT__

#include "httprequest.h"
#include "httpresponse.h"

typedef struct httpctx {
    httprequest_t* request;
    httpresponse_t* response;
    void* user_data;
} httpctx_t;

void httpctx_init(httpctx_t* ctx, void* request, void* response);
void httpctx_clear(httpctx_t* ctx);

#endif
