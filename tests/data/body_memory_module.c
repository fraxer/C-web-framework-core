/* Integration fixture: validate caller copies and expose storage before fd access. */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "http.h"
#include "wscontext.h"
#include "websocketsswitch.h"

static _Atomic unsigned long calls;
static void result(char* out, size_t cap, const char* data, size_t size, int state, int file) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256((const unsigned char*)(data ? data : ""), size, digest);
    for (size_t i = 0; i < sizeof(digest); ++i) snprintf(hex + 2*i, 3, "%02x", digest[i]);
    snprintf(out, cap, "{\"size\":%zu,\"state\":%d,\"file\":%d,\"sha256\":\"%s\"}", size, state, file, hex);
}
void body_stats(httpctx_t* ctx) {
    char out[64];
    snprintf(out, sizeof(out), "{\"calls\":%lu}", atomic_load(&calls));
    ctx->response->send_data(ctx->response, out);
}
void body_check(httpctx_t* ctx) {
    atomic_fetch_add(&calls, 1);
    httprequest_t* req = ctx->request;
    size_t size = http_payload_size(&req->payload_);
    body_store_state_t state = req->payload_.incoming.state;
    char* copy = http_payload_copy(&req->payload_, 0, size);
    if (size && !copy) { ctx->response->send_default(ctx->response, 500); return; }
    if (strcmp(req->path, "/json") == 0) {
        json_doc_t* doc = req->get_payload_json(req);
        if (!doc) { free(copy); ctx->response->send_default(ctx->response, 400); return; }
        json_free(doc);
    }
    if (strcmp(req->path, "/form") == 0) {
        char* value = req->get_payloadf(req, "value");
        int ok = value && memcmp(value, "x\0y", 3) == 0 && value[3] == 0;
        free(value);
        if (!ok) { free(copy); ctx->response->send_default(ctx->response, 400); return; }
    }
    if (req->payload_.incoming.state != state) {
        free(copy); ctx->response->send_default(ctx->response, 500); return;
    }
    int file = 0;
    if (strcmp(req->path, "/file") == 0) {
        file_content_t a = req->get_payload_file(req);
        file_content_t b = req->get_payload_file(req);
        if (!a.ok || a.fd != b.fd || a.size != size) {
            free(copy); ctx->response->send_default(ctx->response, 500); return;
        }
        char* after = req->get_payload(req);
        if (!after || memcmp(after, copy, size)) {
            free(after); free(copy); ctx->response->send_default(ctx->response, 500); return;
        }
        free(after);
        file = 1;
    }
    char out[256];
    result(out, sizeof(out), copy, size, state, file);
    free(copy);
    ctx->response->send_data(ctx->response, out);
}
void body_upgrade(httpctx_t* ctx) { switch_to_websockets(ctx); }
/* A deliberately slow handler: models an I/O-bound handler (the timeout and
 * reload scenarios need server-side work that outlives a tick or a reload). */
void body_delay(httpctx_t* ctx) {
    int ok = 0;
    long ms = query_param_int(ctx->request->query_, "ms", &ok);
    if (!ok || ms < 0) ms = 500;
    if (ms > 10000) ms = 10000;
    if (ms) usleep((useconds_t)ms * 1000);
    ctx->response->send_data(ctx->response, "{\"delay\":1}");
}
void body_ws(wsctx_t* ctx) {
    atomic_fetch_add(&calls, 1);
    websockets_protocol_t* protocol = ctx->request->protocol;
    size_t size = websocketsrequest_payload_size(protocol);
    char* copy = websocketsrequest_payload(protocol);
    if (size && !copy) { ctx->response->send_text(ctx->response, "error"); return; }
    char out[256];
    result(out, sizeof(out), copy, size, protocol->payload.incoming.state, 0);
    free(copy);
    ctx->response->send_text(ctx->response, out);
}
