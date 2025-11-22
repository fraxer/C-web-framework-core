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

    /** Custom identifier for filtering during send. May be NULL */
    broadcast_id_t* id;

    /** Handler for forming response to subscriber */
    void(*response_handler)(response_t* response, const char* payload, size_t size);

    /** Lock flag for thread-safe access */
    atomic_bool locked;

    /** Next item in linked list */
    struct broadcast_item* next;
} broadcast_item_t;

/**
 * Named broadcast channel.
 * Contains list of subscribers (broadcast_item_t).
 */
typedef struct broadcast_list {
    /** Unique channel name (e.g., "chat", "notifications") */
    char* name;

    /** Lock flag for thread-safe access */
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
    /** Lock flag for thread-safe access */
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
 * @param broadcast_name   Channel name to subscribe to
 * @param connection       WebSocket connection of subscriber
 * @param id               Custom identifier (must inherit broadcast_id_t). May be NULL
 * @param response_handler Handler function for forming response when message is received
 * @return 1 on success, 0 on error (NULL parameters, connection already subscribed, memory error)
 */
int broadcast_add(const char* broadcast_name, connection_t* connection, void* id, void(*response_handler)(response_t* response, const char* payload, size_t size));

/**
 * Unsubscribes connection from specified broadcast channel.
 * @param broadcast_name  Channel name
 * @param connection      WebSocket connection to unsubscribe
 */
void broadcast_remove(const char* broadcast_name, connection_t* connection);

/**
 * Unsubscribes connection from all broadcast channels.
 * Called when WebSocket connection is closed.
 * @param connection  WebSocket connection to fully unsubscribe
 */
void broadcast_clear(connection_t* connection);

/**
 * Sends message to all channel subscribers (except sender).
 * @param broadcast_name  Channel name
 * @param connection      Sender connection (will not receive message)
 * @param payload         Data to send
 * @param size            Data size in bytes
 */
void broadcast_send_all(const char* broadcast_name, connection_t* connection, const char* payload, size_t size);

/**
 * Sends message to channel subscribers with identifier filtering.
 * Allows sending message only to specific subscribers.
 * @param broadcast_name   Channel name
 * @param connection       Sender connection (will not receive message)
 * @param payload          Data to send
 * @param size             Data size in bytes
 * @param id               Identifier for filtering (inherits broadcast_id_t). NULL to send to all
 * @param compare_handler  Identifier comparison function. Returns != 0 if subscriber should receive message.
 *                         First argument is subscriber id, second is passed id. NULL to send to all
 */
void broadcast_send(const char* broadcast_name, connection_t* connection, const char* payload, size_t size, void* id, int(*compare_handler)(void* st1, void* st2));

#endif
