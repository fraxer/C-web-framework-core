#define _GNU_SOURCE
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "log.h"
#include "server.h"

void broadcast_free(struct broadcast* broadcast);
void middlewares_free(struct middleware_item* middleware_item);

server_t* server_create() {
    server_t* server = malloc(sizeof * server);
    if (server == NULL) return NULL;

    server->port = 0;
    server->root_length = 0;
    server->domain = NULL;
    
    server->ip = 0;
    server->root = NULL;
    server->index = NULL;
    server->http.route = NULL;
    server->http.redirect = NULL;
    server->http.middleware = NULL;
    server->http.ratelimiter = NULL;
    server->websockets.default_handler = NULL;
    server->websockets.route = NULL;
    server->websockets.middleware = NULL;
    server->websockets.ratelimiter = NULL;
    server->openssl = NULL;
    server->broadcast = NULL;
    server->ratelimits_config = NULL;
    server->stat_cache = NULL;
    server->next = NULL;

    return server;
}

void servers_free(server_t* server) {
    while (server != NULL) {
        server_t* next = server->next;

        server->port = 0;
        server->root_length = 0;

        if (server->domain) domains_free(server->domain);
        server->domain = NULL;

        server->ip = 0;

        if (server->root) free(server->root);
        server->root = NULL;
        
        if (server->index) server_index_destroy(server->index);
        server->index = NULL;

        if (server->http.redirect) redirect_free(server->http.redirect);
        server->http.redirect = NULL;

        if (server->http.middleware) middlewares_free(server->http.middleware);
        server->http.middleware = NULL;

        if (server->http.route) routes_free(server->http.route);
        server->http.route = NULL;

        if (server->http.ratelimiter) ratelimiter_free(server->http.ratelimiter);
        server->http.ratelimiter = NULL;

        if (server->websockets.route) routes_free(server->websockets.route);
        server->websockets.route = NULL;

        if (server->websockets.middleware) middlewares_free(server->websockets.middleware);
        server->websockets.middleware = NULL;

        if (server->websockets.ratelimiter) ratelimiter_free(server->websockets.ratelimiter);
        server->websockets.ratelimiter = NULL;

        if (server->openssl) openssl_free(server->openssl);
        server->openssl = NULL;

        if (server->broadcast) broadcast_free(server->broadcast);
        server->broadcast = NULL;

        if (server->ratelimits_config) map_free(server->ratelimits_config);
        server->ratelimits_config = NULL;

        server_stat_cache_free(server);

        server->next = NULL;

        free(server);

        server = next;
    }
}

index_t* server_index_create(const char* value) {
    index_t* result = NULL;
    index_t* index = malloc(sizeof * index);
    if (index == NULL) {
        log_error("server_index_create: alloc memory for index failed\n");
        goto failed;
    }

    index->value = NULL;
    index->length = 0;

    const size_t length = strlen(value);
    if (length == 0) {
        log_error("server_index_create: index value is empty\n");
        goto failed;
    }

    index->value = malloc(length + 1);
    if (index->value == NULL) {
        log_error("server_index_create: alloc memory for index value failed\n");
        goto failed;
    }

    strcpy(index->value, value);
    index->length = length;

    result = index;

    failed:

    if (result == NULL)
        server_index_destroy(index);

    return result;
}

void server_index_destroy(index_t* index) {
    if (index == NULL) return;

    if (index->value != NULL)
        free(index->value);

    free(index);
}

server_chain_t* server_chain_create(server_t* server, routeloader_lib_t* lib) {
    server_chain_t* chain = malloc(sizeof * chain);
    if (chain == NULL) return NULL;

    pthread_mutex_init(&chain->mutex, NULL);
    chain->server = server;
    chain->routeloader = lib;

    return chain;
}

void server_chain_destroy(server_chain_t* server_chain) {
    if (server_chain == NULL) return;

    pthread_mutex_destroy(&server_chain->mutex);
    servers_free(server_chain->server);
    routeloader_free(server_chain->routeloader);

    free(server_chain);
}

// Stat cache implementation

static void stat_cache_entry_free(void* entry) {
    free(entry);
}

int server_stat_cache_init(server_t* server) {
    if (server->stat_cache != NULL) return 1;

    server->stat_cache = map_create_ex(
        map_compare_string,
        (map_copy_fn)strdup,
        free,
        NULL,
        stat_cache_entry_free
    );

    return server->stat_cache != NULL;
}

void server_stat_cache_free(server_t* server) {
    if (server->stat_cache == NULL) return;

    map_free(server->stat_cache);
    server->stat_cache = NULL;
}

stat_cache_entry_t* server_stat_cache_get(server_t* server, const char* path) {
    if (server->stat_cache == NULL) return NULL;

    stat_cache_entry_t* entry = map_find(server->stat_cache, path);
    if (entry == NULL) return NULL;

    time_t now = time(NULL);
    if (now - entry->cached_at > STAT_CACHE_TTL_SEC) {
        map_erase(server->stat_cache, path);
        return NULL;
    }

    return entry;
}

int server_stat_cache_put(server_t* server, const char* path, const struct stat* st) {
    if (server->stat_cache == NULL) {
        if (!server_stat_cache_init(server))
            return 0;
    }

    stat_cache_entry_t* entry = malloc(sizeof(stat_cache_entry_t));
    if (entry == NULL) return 0;

    entry->st = *st;
    entry->cached_at = time(NULL);

    if (!map_insert_or_assign(server->stat_cache, path, entry)) {
        free(entry);
        return 0;
    }

    return 1;
}
