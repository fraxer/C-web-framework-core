// Stubs for symbols referenced by httpclient.c that have no definition in any
// of the libraries linked into the unit test runner.
//
// appconfig() (src/config) and run_middlewares() (framework/middleware) ARE
// linked transitively now that the runner links `http_client` — they must NOT
// be stubbed here (a returning-NULL stub would shadow the real implementation
// and break e.g. the session tests).
//
// httpctx_init / httpctx_clear are declared in protocols/http/httpcontext.h but
// have no definition anywhere in the tree (only called from server/client
// self-invocation paths, which the unit tests never reach), so they need stubs.
#include "httpcontext.h"

void httpctx_init(httpctx_t* ctx, void* request, void* response) {
    (void)ctx;
    (void)request;
    (void)response;
}

void httpctx_clear(httpctx_t* ctx) {
    (void)ctx;
}
