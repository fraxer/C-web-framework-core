#ifndef __CONNECTION_S__
#define __CONNECTION_S__

#include <stdatomic.h>

#include "connection.h"
#include "metrics.h"
#include "multiplexingserver.h"
#include "server.h"
#include "request.h"
#include "response.h"
#include "cqueue.h"

struct mpxapi;

typedef enum {
    CONNECTION_DEC_RESULT_DESTROY = 0,
    CONNECTION_DEC_RESULT_DECREMENT
} connection_dec_result_e;

typedef struct listener {
    cqueue_t servers;
    struct connection* connection;
    struct mpxapi* api;
    struct listener* next;
} listener_t;

typedef struct requestparser {
    void(*free)(void*);
} requestparser_t;

typedef struct switch_to_protocol {
    int(*fn)(struct connection*, void* data);
    void(*data_free)(void*);
    void* data;
} switch_to_protocol_t;

/* One place in a connection's output order.
 *
 * Reserved (empty) when a message is dispatched and filled when its response is
 * ready, so handlers may finish in any order while their frames still leave in
 * the order the messages arrived. Only the WebSocket write path interprets the
 * response; the struct is declared here so the connection layer can drain
 * ctx->write_queue at teardown through the generic response_t::free.
 *
 * docs/concurrency/00 §4.4. */
typedef struct connection_out_slot {
    response_t* response; /* NULL until the producer publishes */
} connection_out_slot_t;

typedef struct {
    connection_ctx_t base;

    listener_t* listener;
    void* parser;
    server_t* server;
    void* request;
    void* response;
    cqueue_t* queue;
    cqueue_t* broadcast_queue;
    /* Ordered output slots (connection_out_slot_t*), WebSocket only. HTTP/1.1
     * has one response in flight and HTTP/2 keeps responses on the stream, so
     * neither needs it — it stays empty for both. */
    cqueue_t* write_queue;

    switch_to_protocol_t switch_to_protocol;

    atomic_int ref_count;
    atomic_int broadcast_ref_count;
    atomic_bool destroyed;
    /* The fd is gone: control_del has run and close(2) has been called, so the
     * kernel is free to hand that number to the next accept(). Any epoll_ctl
     * after this point either fails or — far worse — lands on whatever
     * connection inherited the number and repoints its registration at this
     * (soon to be freed) object.
     *
     * Set under connection_s_lock, which every re-arm path also takes, so the
     * check cannot go stale between test and epoll_ctl. It only became reachable
     * with concurrent handlers: a handler finishing on one core re-arms while
     * the worker on another has already closed the connection
     * (docs/concurrency/00 §4.6). Distinct from `destroyed`, which error paths
     * set on a connection whose fd is still open and still needs an event to be
     * reaped. */
    atomic_bool detached;
    atomic_bool locked;
    /* Call site of the current holder of `locked`, for the lock metrics only
     * (docs/concurrency/01 §6, phase A): a waiter samples it to report what it
     * is waiting behind. Written only while metrics are on, and never read for
     * anything the connection does — a stale or torn value costs a misattributed
     * statistic, nothing more. */
    atomic_int lock_site;
    /* How many handlers of this connection are running right now. Maintained by
     * thread_handler and read by nothing else — it exists so the metrics can
     * answer "did the fan-out actually fan out on THIS connection", which a
     * process-wide gauge cannot (docs/concurrency/00, phase D). Only updated
     * while metrics are enabled, so it reads 0 otherwise. */
    atomic_int handlers_inflight;
    /* A response is staged and needs an EPOLLOUT turn. Atomic, and deliberately
     * not a bitfield: it is set by whichever thread finished the response
     * (a handler thread, via __post_response / h2_server_response_ready) and
     * read by the worker in the event loop *outside* connection_s_lock
     * (multiplexingepoll.c). Sharing a machine word with the bitfields below
     * would make every write to them a read-modify-write of this flag too.
     * Store with release / load with acquire: seeing the flag must imply seeing
     * the response it announces. */
    atomic_bool need_write;
    /* The connection speaks HTTP/2: ctx->parser is an h2session_t and responses
     * must be built with the h2 filter chain (frames instead of a status line +
     * chunked encoding). Set by h2_server_set_http2.
     *
     * Handler threads read this, so it crosses the thread boundary — but it is
     * only ever written before the first handler on the connection can run: at
     * ALPN time, or from connection_after_write on the h2c upgrade path, where
     * h1.1 guarantees no handler is in flight. Once set it never clears. That
     * write-once ordering is what makes a plain bitfield safe here; anything
     * that starts flipping it later must move it out of the word. */
    unsigned is_http2: 1;
    /* Plaintext connection whose first bytes have not yet been inspected for the
     * h2c connection preface (RFC 9113 §3.4). Set once at plaintext accept;
     * cleared as soon as the protocol is settled, so the h1.1 hot path pays a
     * single memcmp per connection. Always 0 for TLS, where ALPN has already
     * settled the protocol. */
    unsigned h2c_preface: 1;
    /* How many bytes of a partially received preface are staged at the front of
     * connection->buffer, when the 24 bytes arrived split across TCP segments.
     * Always < 24, so 5 bits are enough. Meaningful only while h2c_preface. */
    unsigned h2c_peeked: 5;
    /* An interim "100 Continue" is owed to the peer (RFC 9110 §10.1.1), and
     * `cont_sent` is how much of that status line already went out.
     *
     * HTTP/1.1 has no outbound queue of its own — a response is written straight
     * from the filter chain — so the parser writes the line itself when the
     * request headers are in. A socket that cannot take all 25 bytes right then
     * is close to impossible (nothing has been written on the exchange yet), but
     * it must not be able to splice the remainder into the middle of the final
     * response head: whatever is left rides in front of it instead
     * (docs/http2/10, T.2). HTTP/2 needs none of this — it queues the interim
     * response as a HEADERS frame like any other.
     *
     * Worker-thread only, like the bitfields above: the request parser and the
     * write filter both run there. */
    unsigned cont_pending: 1;
    unsigned cont_sent: 6;
} connection_server_ctx_t;

/* The interim status line, shared by the parser that sends it and the write
 * filter that flushes whatever is left of it. */
#define HTTP_CONTINUE_LINE "HTTP/1.1 100 Continue\r\n\r\n"
#define HTTP_CONTINUE_LINE_LEN 25

typedef struct connection_queue_item_data {
    void(*free)(void*);
} connection_queue_item_data_t;

typedef struct connection_queue_item {
    void(*free)(struct connection_queue_item*);
    void(*run)(void*);
    void(*handle)(void*);
    connection_t* connection;
    connection_queue_item_data_t* data;
} connection_queue_item_t;

connection_t* connection_s_create(int fd, in_addr_t ip, unsigned short int port, connection_server_ctx_t* ctx, char* buffer, size_t buffer_size);
connection_t* connection_s_alloc(listener_t* listener, int fd, in_addr_t ip, unsigned short int port, in_addr_t client_ip, unsigned short int client_port, char* buffer, size_t buffer_size);
connection_t* connection_s_create_local(server_t* server);
void connection_s_free_local(connection_t* connection);

/* `site` tags the acquisition for the lock metrics (docs/concurrency/01 §6,
 * phase A) and has no effect on locking itself. It is mandatory so that a new
 * call site is a decision rather than an omission; LOCK_SITE_OTHER is the honest
 * answer where the path has not been classified. */
int connection_s_lock(connection_t*, metrics_lock_site_t site);
int connection_s_trylock(connection_t*);
int connection_s_unlock(connection_t*);
void connection_s_inc(connection_t*);
connection_dec_result_e connection_s_dec(connection_t*);

int connection_close_locked(connection_t*);
int connection_after_write(connection_t*);
/* Serialized dispatch (HTTP/1.1, WebSocket): at most one queue entry per
 * connection, so at most one handler runs at a time. */
int connection_queue_append(connection_queue_item_t*);

/* Fan-out dispatch (HTTP/2): one queue entry per item, so several handlers of
 * the same connection run at once. docs/concurrency/00 §5.2. */
int connection_queue_append_parallel(connection_queue_item_t*);

int connection_queue_append_broadcast(connection_t*);
int connection_after_read(connection_t*);

/* Re-arm the one-shot read of a connection that is still parked (h2 only; a
 * no-op returning 1 otherwise). docs/concurrency/01, phase E. */
int connection_park_rearm(connection_t*);
int connection_close(connection_t* connection);

#endif
