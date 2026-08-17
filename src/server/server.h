#ifndef __SERVER__
#define __SERVER__

#include <arpa/inet.h>
#include <stdatomic.h>

#include "ipaddr.h"
#include "map.h"
#include "redirect.h"
#include "route.h"
#include "routeloader.h"
#include "domain.h"
#include "openssl.h"
#include "ratelimiter.h"

struct middleware_item;

typedef struct index {
    char* value;
    int length;
} index_t;

typedef struct server_http {
    route_t* route;
    ratelimiter_t* ratelimiter;
    redirect_t* redirect;
    struct middleware_item* middleware;
} server_http_t;

typedef struct server_websockets {
    route_t* route;
    ratelimiter_t* ratelimiter;
    void(*default_handler)(void*);
    struct middleware_item* middleware;
    /* The vhost actually declared a "websockets" section.
     *
     * default_handler alone cannot answer that: a vhost without the section is
     * given the framework's stub handler anyway (moduleloader), so that an
     * application calling switch_to_websockets() there gets a reply instead of
     * a NULL call. That is fine while the *application* decides to start a
     * WebSocket session — under RFC 8441 the *client* decides, on whatever
     * vhost it likes, and "this vhost was never meant to serve WebSocket"
     * becomes an answer the server has to be able to give
     * (docs/http2/09, step 8). */
    int configured;
} server_websockets_t;

/* HTTP/3 listener settings for one vhost (docs/http3/07-integration.md §1.1).
 *
 * Deliberately NOT behind #ifdef CWFR_HTTP3, unlike the rest of the h3 code.
 * That macro is directory-scoped to core/, so application handlers compile
 * without it; a conditional field here would give core and the handlers two
 * different layouts for server_t, which they share through
 * libcwfr_framework.so. Two ints are not worth an ABI split. */
/* Longest Alt-Svc value this builds: `h3=":65535"; ma=4294967295`. */
#define SERVER_ALT_SVC_MAX 48

typedef struct server_http3 {
    int enabled;
    /* UDP port. Defaults to the vhost's TCP port -- h3 on the same number is
     * what Alt-Svc advertises by default and what clients expect. */
    unsigned short int port;

    /* Advertise HTTP/3 in an `Alt-Svc` response header over HTTP/1.1 and
     * HTTP/2 (RFC 7838, docs/http3/07-integration.md §2).
     *
     * Without it HTTP/3 is unreachable in practice: a browser does not probe
     * UDP on speculation, it learns about h3 from this header or from a DNS
     * HTTPS record. The value is built once here, at config load, because it
     * cannot change while the server runs and building it per response would
     * be a snprintf on the hot path of every single answer. */
    int alt_svc;
    unsigned int alt_svc_max_age;
    char alt_svc_value[SERVER_ALT_SVC_MAX];
    size_t alt_svc_length;
} server_http3_t;

struct broadcast;

typedef struct server {
    unsigned short int port;
    size_t root_length;
    /* The address this vhost is bound to, either family (misc/ipaddr.h). Also
     * the address of its HTTP/3 endpoint: one `ip` per vhost, two transports on
     * it. A vhost that should answer on both families is two vhost entries, the
     * same as two IPv4 addresses have always been -- IPv6 sockets here are
     * v6-only on purpose (src/udp/udpsocket.h). */
    ipaddr_t ip;
    server_http_t http;
    server_websockets_t websockets;
    server_http3_t http3;

    char* root;
    domain_t* domain;
    index_t* index;
    openssl_t* openssl;
    map_t* ratelimits_config; // ratelimiter_config_t
    struct broadcast* broadcast;
    struct server* next;
} server_t;

typedef struct server_chain {
    pthread_mutex_t mutex;
    server_t* server;
    routeloader_lib_t* routeloader;
} server_chain_t;

server_t* server_create();
index_t* server_index_create(const char*);
void server_index_destroy(index_t*);
void servers_free(server_t* server);

server_chain_t* server_chain_create(server_t* server, routeloader_lib_t*);
void server_chain_destroy(server_chain_t*);

#endif
