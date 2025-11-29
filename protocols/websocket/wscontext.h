#ifndef __WSCONTEXT__
#define __WSCONTEXT__

#include "websocketsrequest.h"
#include "websocketsresponse.h"

typedef struct wsctx {
    websocketsrequest_t* request;
    websocketsresponse_t* response;
    void* user_data;
} wsctx_t;

void wsctx_init(wsctx_t* ctx, void* request, void* response);
void wsctx_clear(wsctx_t* ctx);

#endif
