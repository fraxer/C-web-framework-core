#ifndef __WSCONTEXT__
#define __WSCONTEXT__

#include "websocketsrequest.h"
#include "websocketsresponse.h"

typedef struct wsctx {
    websocketsrequest_t* request;
    websocketsresponse_t* response;
    void* user_data;
    /* See httpctx_t: the destructor travels with the context so that a session
     * outliving a reload is freed by the generation that allocated its payload. */
    void (*user_data_free)(void*);
} wsctx_t;

void wsctx_init(wsctx_t* ctx, void* request, void* response,
                void (*user_data_free)(void*));
void wsctx_clear(wsctx_t* ctx);

/** Attach an application-owned payload. See httpctx_set_user_data(). */
void wsctx_set_user_data(wsctx_t* ctx, void* user_data);

/** Register the destructor wsctx_clear() calls. See httpctx_set_user_data_free(). */
int wsctx_set_user_data_free(void (*fn)(void*));

#endif
