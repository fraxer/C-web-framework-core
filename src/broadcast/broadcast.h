#ifndef __BROADCAST__
#define __BROADCAST__

#include <stddef.h>
#include <stdatomic.h>

#include "connection_queue.h"
#include "connection_s.h"

/**
 * Base structure for broadcast subscriber identifier.
 * Used for filtering recipients when sending messages.
 * Custom structures must inherit this structure (as first field).
 */
typedef struct broadcast_id {
    /** Function to free identifier memory. Called automatically when subscriber is removed */
    void(*free)(void*);
} broadcast_id_t;

/**
 * Broadcast channel subscriber item.
 * Represents a single WebSocket connection subscribed to a channel.
 */
typedef struct broadcast_item {
    /** WebSocket connection of the subscriber */
    connection_t* connection;

    /* Where this subscriber's frames belong when the subscriber is not the
     * connection itself but one RFC 8441 tunnel on it (docs/http2/09, step 5).
     * A connection may host several tunnels, each its own subscriber, so
     * "connection" alone stops identifying anybody. NULL/NULL on HTTP/1.1.
     *
     * Deliberately plain types: broadcast must not learn about HTTP/2 or about
     * WebSocket tunnels — it only needs to know where to put bytes and how to
     * wake whoever writes them. */
    cqueue_t* out_queue;
    void* out_owner;
    int (*out_wake)(connection_t*, void* owner, int handler_done);
    /* permessage-deflate context of that tunnel, or NULL. Opaque here — the
     * response layer is what uses it. */
    void* out_deflate;

    /** Custom identifier for filtering during send. May be NULL */
    broadcast_id_t* id;

    /** Handler for forming response to subscriber */
    void(*response_handler)(response_t* response, const char* payload, size_t size);

    /** Next item in linked list. Protected by the owning list's lock */
    struct broadcast_item* next;
} broadcast_item_t;

/**
 * Named broadcast channel.
 * Contains list of subscribers (broadcast_item_t).
 */
typedef struct broadcast_list {
    /** Unique channel name (e.g., "chat", "notifications") */
    char* name;

    /** Lock protecting the channel's subscribers (item, item_last, next pointers) */
    atomic_bool locked;

    /** First item in subscribers list */
    broadcast_item_t* item;

    /** Last item in subscribers list (for fast append) */
    broadcast_item_t* item_last;

    /** Next channel in linked list */
    struct broadcast_list* next;
} broadcast_list_t;

/**
 * Root structure for broadcast system.
 * Contains list of all server broadcast channels.
 */
typedef struct broadcast {
    /** Lock protecting the channel list structure (list, list_last). Lock order: broadcast before list */
    atomic_bool locked;

    /** First channel in list */
    broadcast_list_t* list;

    /** Last channel in list (for fast append) */
    broadcast_list_t* list_last;
} broadcast_t;

/**
 * Creates and initializes root broadcast structure.
 * @return Pointer to created structure, NULL on memory allocation error
 */
broadcast_t* broadcast_init();

/**
 * Frees all broadcast system resources.
 * Removes all channels and all subscribers.
 * @param broadcast  Pointer to broadcast structure to free
 */
void broadcast_free(broadcast_t* broadcast);

/**
 * Subscribes connection to a broadcast channel.
 * If channel does not exist, it will be created automatically.
 * One connection can subscribe to a channel only once.
 * Ownership of id is always taken: on success it is stored in the
 * subscriber item and freed on unsubscribe; on failure (including
 * duplicate subscription) it is freed via its broadcast_id_t free handler
 * before returning. Do not reuse id after the call.
 * @param broadcast_name   Channel name to subscribe to
 * @param connection       WebSocket connection of subscriber
 * @param id               Custom identifier (must inherit broadcast_id_t). May be NULL
 * @param response_handler Handler function for forming response when message is received
 * @return 1 on success, 0 on error (NULL parameters, connection already subscribed, memory error)
 */
int broadcast_add(const char* broadcast_name, connection_t* connection, void* id, void(*response_handler)(response_t* response, const char* payload, size_t size));

/**
 * Subscribe an output binding rather than a bare connection: the same channel
 * mechanics, but the subscriber is identified by (connection, owner) and its
 * frames go to `out_queue` (docs/http2/09, step 5). Passing NULL for the
 * binding is exactly broadcast_add().
 */
int broadcast_add_out(const char* broadcast_name, connection_t* connection, void* id,
                      void(*response_handler)(response_t* response, const char* payload, size_t size),
                      cqueue_t* out_queue, void* out_owner,
                      int (*out_wake)(connection_t*, void* owner, int handler_done), void* out_deflate);

/**
 * Unsubscribes connection from specified broadcast channel.
 * A channel left without subscribers is destroyed.
 * @param broadcast_name  Channel name
 * @param connection      WebSocket connection to unsubscribe
 */
void broadcast_remove(const char* broadcast_name, connection_t* connection);

/** Unsubscribe one owner on a connection; owner == NULL means the connection itself. */
void broadcast_remove_out(const char* broadcast_name, connection_t* connection, void* out_owner);

/** Drop every subscription belonging to one owner, on every channel. Called when
 *  an RFC 8441 tunnel dies while its connection lives on. */
void broadcast_clear_owner(connection_t* connection, void* out_owner);

/**
 * Unsubscribes connection from all broadcast channels.
 * Called when WebSocket connection is closed.
 * @param connection  WebSocket connection to fully unsubscribe
 */
void broadcast_clear(connection_t* connection);

/**
 * Sends message to all channel subscribers except the sender.
 * `out_owner` identifies which RFC 8441 tunnel on `connection` is the sender
 * (NULL = the connection itself, i.e. HTTP/1.1). Only that exact subscriber is
 * suppressed; other tunnels sharing the connection still receive — comparing
 * connection alone skipped every tunnel on the sender's connection
 * (docs/http2/09, step 5, send path).
 * Note: the sender never receives the message, even if subscribed.
 *
 * @param broadcast_name  Channel name
 * @param connection      Sender connection (will not receive message)
 * @param out_owner       Sender tunnel on the connection, or NULL (HTTP/1.1)
 * @param payload         Data to send
 * @param size            Data size in bytes
 */
void broadcast_send_all(const char* broadcast_name, connection_t* connection, void* out_owner, const char* payload, size_t size);

/**
 * Sends message to channel subscribers with identifier filtering.
 * Allows sending message only to specific subscribers.
 * Filtering applies only when both id and compare_handler are provided;
 * if either is NULL, the message is sent to all subscribers (except sender).
 * `out_owner` identifies the sender tunnel (NULL on HTTP/1.1); see
 * broadcast_send_all for the suppression semantics.
 * Ownership of id is taken by this function: it is always freed via
 * its broadcast_id_t free handler before returning. Do not reuse id after the call.
 *
 * @param broadcast_name   Channel name
 * @param connection       Sender connection (will not receive message)
 * @param out_owner        Sender tunnel on the connection, or NULL (HTTP/1.1)
 * @param payload          Data to send
 * @param size             Data size in bytes
 * @param id               Identifier for filtering (inherits broadcast_id_t). NULL to send to all
 * @param compare_handler  Identifier comparison function. Returns != 0 if subscriber should receive message.
 *                         First argument is subscriber id, second is passed id. NULL to send to all
 */
void broadcast_send(const char* broadcast_name, connection_t* connection, void* out_owner, const char* payload, size_t size, void* id, int(*compare_handler)(void* st1, void* st2));

#endif
