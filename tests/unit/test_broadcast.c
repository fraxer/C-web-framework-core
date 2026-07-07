/*
 * Unit tests for src/broadcast/broadcast.c: channel registry (add/remove/
 * clear), message fan-out through the per-connection broadcast queue,
 * subscriber filtering and the shared refcounted payload.
 *
 * The epoll api is replaced by stub control_mod/control_del (as in
 * test_connection.c) so the queue scheduling protocol runs without an event
 * loop; connections are fd -1 state-machine objects, queued items are
 * executed directly by the test instead of a worker thread.
 *
 * Several cases are regression guards for bugs fixed alongside these tests
 * (each is marked REGRESSION below):
 *
 *   - __broadcast_queue_add took cqueue_incrementlock on the connection's
 *     broadcast_queue: an unconditional counter increment gives no mutual
 *     exclusion, so senders on two different channels sharing a subscriber
 *     (and the worker thread popping) could mutate the queue's linked list
 *     concurrently and corrupt it or lose messages.
 *   - broadcast_add did not free id when the subscription was rejected
 *     (duplicate subscription, invalid arguments, allocation failure):
 *     the caller cannot know whether ownership was taken, and the real
 *     caller (scheduler channel_join) leaked the id on every re-join.
 *   - broadcast_add/broadcast_remove/broadcast_send dereferenced a NULL
 *     broadcast when the connection's server had none (broadcast_clear had
 *     already been hardened against this), and broadcast_remove/
 *     broadcast_send crashed on a NULL channel name.
 *   - __broadcast_payload_create called memcpy from a NULL payload when
 *     size > 0.
 */

#include "framework.h"
#include "broadcast.h"
#include "connection_s.h"
#include "connection_queue.h"
#include "cqueue.h"
#include "multiplexing.h"
#include "server.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Epoll api stub                                                              */
/* -------------------------------------------------------------------------- */

static int bc_stub_control_mod(connection_t* connection, int events) {
    (void)connection;
    (void)events;
    return 1;
}

static int bc_stub_control_del(connection_t* connection) {
    (void)connection;
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Harness: server + listener + api stub, connections via connection_s_alloc   */
/* -------------------------------------------------------------------------- */

typedef struct {
    server_t server;
    listener_t listener;
    mpxapi_t api;
} bc_harness_t;

static int bc_harness_init(bc_harness_t* h, int with_broadcast) {
    memset(h, 0, sizeof *h);

    if (!connection_queue_init())
        return 0;

    h->api.control_mod = bc_stub_control_mod;
    h->api.control_del = bc_stub_control_del;
    h->listener.api = &h->api;
    cqueue_init(&h->listener.servers);

    if (!cqueue_append(&h->listener.servers, &h->server))
        return 0;

    if (with_broadcast) {
        h->server.broadcast = broadcast_init();
        if (h->server.broadcast == NULL) {
            cqueue_clear(&h->listener.servers);
            return 0;
        }
    }

    return 1;
}

static void bc_harness_free(bc_harness_t* h) {
    broadcast_free(h->server.broadcast);
    h->server.broadcast = NULL;
    cqueue_clear(&h->listener.servers);
}

static connection_t* bc_conn_create(bc_harness_t* h) {
    return connection_s_alloc(&h->listener, -1, 0, 80, 0, 0, NULL, 0);
}

static void bc_conn_free(connection_t* conn) {
    if (conn == NULL) return;

    connection_s_dec(conn); /* последняя ссылка: connection_free */
}

/* Забирает соединение из глобальной очереди воркеров, снимая ссылку и лок,
 * которые оставил connection_queue_guard_pop. Вызывать ровно столько раз,
 * сколько постановок ожидает тест: пустая очередь ждёт таймаут в 1 секунду. */
static connection_t* bc_worker_queue_pop(void) {
    connection_t* popped = connection_queue_guard_pop();
    if (popped == NULL) return NULL;

    connection_s_unlock(popped);
    connection_s_dec(popped);
    return popped;
}

/* Снимает все сообщения из broadcast_queue соединения.
 * run == 1 исполняет item->run (создание websockets-ответа + вызов
 * response_handler) и сбрасывает соединение, освобождая созданный ответ. */
static int bc_drain_broadcast_queue(connection_t* conn, int run) {
    connection_server_ctx_t* ctx = conn->ctx;
    int count = 0;

    for (;;) {
        cqueue_lock(ctx->broadcast_queue);
        connection_queue_item_t* item = cqueue_pop(ctx->broadcast_queue);
        cqueue_unlock(ctx->broadcast_queue);

        if (item == NULL) break;

        if (run) {
            item->run(item);
            connection_reset(conn);
        }

        item->free(item);
        count++;
    }

    return count;
}

static int bc_broadcast_queue_size(connection_t* conn) {
    connection_server_ctx_t* ctx = conn->ctx;

    cqueue_lock(ctx->broadcast_queue);
    const int size = cqueue_size(ctx->broadcast_queue);
    cqueue_unlock(ctx->broadcast_queue);

    return size;
}

static int bc_list_item_count(broadcast_list_t* list) {
    int count = 0;
    for (broadcast_item_t* item = list->item; item != NULL; item = item->next)
        count++;

    return count;
}

static int bc_channel_count(broadcast_t* broadcast) {
    int count = 0;
    for (broadcast_list_t* list = broadcast->list; list != NULL; list = list->next)
        count++;

    return count;
}

static broadcast_list_t* bc_find_channel(broadcast_t* broadcast, const char* name) {
    for (broadcast_list_t* list = broadcast->list; list != NULL; list = list->next)
        if (strcmp(list->name, name) == 0)
            return list;

    return NULL;
}

/* -------------------------------------------------------------------------- */
/* Subscriber id and response handler stubs                                    */
/* -------------------------------------------------------------------------- */

typedef struct {
    broadcast_id_t base;
    int user_id;
} bc_test_id_t;

static int bc_id_free_calls = 0;

static void bc_test_id_free(void* id) {
    if (id == NULL) return;

    bc_id_free_calls++;
    free(id);
}

static bc_test_id_t* bc_test_id_create(int user_id) {
    bc_test_id_t* id = malloc(sizeof *id);
    if (id == NULL) return NULL;

    id->base.free = bc_test_id_free;
    id->user_id = user_id;

    return id;
}

static int bc_compare_user(void* subscriber_id, void* sent_id) {
    bc_test_id_t* s = subscriber_id;
    bc_test_id_t* t = sent_id;

    if (s == NULL || t == NULL) return 0;

    return s->user_id == t->user_id;
}

static int bc_handler_calls = 0;
static char bc_handler_payload[64];
static size_t bc_handler_size = 0;
static response_t* bc_handler_response = NULL;

static void bc_capture_handler(response_t* response, const char* payload, size_t size) {
    bc_handler_calls++;
    bc_handler_response = response;
    bc_handler_size = size;

    memset(bc_handler_payload, 0, sizeof bc_handler_payload);
    if (payload != NULL && size > 0 && size < sizeof bc_handler_payload)
        memcpy(bc_handler_payload, payload, size);
}

static void bc_stubs_reset(void) {
    bc_id_free_calls = 0;
    bc_handler_calls = 0;
    bc_handler_size = 0;
    bc_handler_response = NULL;
    memset(bc_handler_payload, 0, sizeof bc_handler_payload);
}

/* -------------------------------------------------------------------------- */
/* broadcast_init / broadcast_free                                             */
/* -------------------------------------------------------------------------- */

TEST(test_broadcast_init_and_free) {
    TEST_SUITE("broadcast");
    TEST_CASE("broadcast_init creates empty registry, broadcast_free tolerates NULL");

    broadcast_free(NULL); /* no-op */

    broadcast_t* broadcast = broadcast_init();
    TEST_REQUIRE_NOT_NULL(broadcast, "broadcast_init");

    TEST_ASSERT_NULL(broadcast->list, "no channels after init");
    TEST_ASSERT_NULL(broadcast->list_last, "no last channel after init");

    broadcast_free(broadcast);
}

TEST(test_broadcast_free_releases_channels_and_ids) {
    TEST_CASE("broadcast_free frees channels, items and subscriber ids");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* conn = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(conn, "connection alloc", cleanup);

    TEST_ASSERT_EQUAL(1, broadcast_add("a", conn, bc_test_id_create(1), bc_capture_handler), "subscribe to a");
    TEST_ASSERT_EQUAL(1, broadcast_add("b", conn, bc_test_id_create(2), bc_capture_handler), "subscribe to b");
    TEST_ASSERT_EQUAL(2, bc_channel_count(h.server.broadcast), "two channels");

    broadcast_free(h.server.broadcast);
    h.server.broadcast = NULL;

    TEST_ASSERT_EQUAL(2, bc_id_free_calls, "both subscriber ids freed by broadcast_free");

    cleanup:

    bc_conn_free(conn);
    bc_harness_free(&h);
}

/* -------------------------------------------------------------------------- */
/* broadcast_add                                                               */
/* -------------------------------------------------------------------------- */

TEST(test_broadcast_add_creates_channel_and_subscribes) {
    TEST_CASE("broadcast_add creates channel and stores subscriber");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* first = bc_conn_create(&h);
    connection_t* second = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(first, "first connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(second, "second connection alloc", cleanup);

    bc_test_id_t* id = bc_test_id_create(7);
    TEST_ASSERT_EQUAL(1, broadcast_add("room", first, id, bc_capture_handler), "first subscribe ok");

    broadcast_list_t* channel = bc_find_channel(h.server.broadcast, "room");
    TEST_REQUIRE_NOT_NULL_GOTO(channel, "channel created", cleanup);
    TEST_ASSERT(h.server.broadcast->list_last == channel, "list_last points to the only channel");
    TEST_ASSERT_EQUAL(1, bc_list_item_count(channel), "one subscriber");
    TEST_ASSERT(channel->item->connection == first, "subscriber connection stored");
    TEST_ASSERT(channel->item->id == (broadcast_id_t*)id, "subscriber id stored");
    TEST_ASSERT(channel->item->response_handler == bc_capture_handler, "handler stored");

    /* id may be NULL */
    TEST_ASSERT_EQUAL(1, broadcast_add("room", second, NULL, bc_capture_handler), "second subscribe without id");
    TEST_ASSERT_EQUAL(1, bc_channel_count(h.server.broadcast), "existing channel reused");
    TEST_ASSERT_EQUAL(2, bc_list_item_count(channel), "two subscribers");
    TEST_ASSERT(channel->item_last->connection == second, "item_last tracks appended subscriber");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(first);
    bc_conn_free(second);
}

TEST(test_broadcast_add_duplicate_rejected_and_id_freed) {
    /* REGRESSION: rejected subscription must free id (scheduler channel_join
     * leaked one mybroadcast_id_t on every repeated join). */
    TEST_CASE("duplicate broadcast_add returns 0 and frees id");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* conn = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(conn, "connection alloc", cleanup);

    TEST_ASSERT_EQUAL(1, broadcast_add("room", conn, bc_test_id_create(1), bc_capture_handler), "first subscribe ok");
    TEST_ASSERT_EQUAL(0, bc_id_free_calls, "accepted id not freed");

    TEST_ASSERT_EQUAL(0, broadcast_add("room", conn, bc_test_id_create(2), bc_capture_handler), "duplicate rejected");
    TEST_ASSERT_EQUAL(1, bc_id_free_calls, "rejected id freed");

    broadcast_list_t* channel = bc_find_channel(h.server.broadcast, "room");
    TEST_REQUIRE_NOT_NULL_GOTO(channel, "channel exists", cleanup);
    TEST_ASSERT_EQUAL(1, bc_list_item_count(channel), "still one subscriber");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(conn);
}

TEST(test_broadcast_add_invalid_args) {
    /* REGRESSION: NULL arguments and a server without broadcast must not
     * crash, must return 0 and must free id. */
    TEST_CASE("broadcast_add guards invalid arguments and frees id");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* conn = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(conn, "connection alloc", cleanup);

    TEST_ASSERT_EQUAL(0, broadcast_add(NULL, conn, bc_test_id_create(1), bc_capture_handler), "NULL name rejected");
    TEST_ASSERT_EQUAL(0, broadcast_add("room", NULL, bc_test_id_create(2), bc_capture_handler), "NULL connection rejected");
    TEST_ASSERT_EQUAL(0, broadcast_add("room", conn, bc_test_id_create(3), NULL), "NULL handler rejected");
    TEST_ASSERT_EQUAL(3, bc_id_free_calls, "each rejected id freed");
    TEST_ASSERT_EQUAL(0, bc_channel_count(h.server.broadcast), "no channels created");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(conn);
}

TEST(test_broadcast_add_without_server_broadcast) {
    /* REGRESSION: ctx->server->broadcast == NULL dereferenced NULL inside
     * __broadcast_find_list. */
    TEST_CASE("broadcast_add/remove/send on server without broadcast are no-ops");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 0), "harness init without broadcast");

    connection_t* conn = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(conn, "connection alloc", cleanup);

    TEST_ASSERT_EQUAL(0, broadcast_add("room", conn, bc_test_id_create(1), bc_capture_handler), "add rejected");
    TEST_ASSERT_EQUAL(1, bc_id_free_calls, "id freed when broadcast is missing");

    broadcast_remove("room", conn); /* no crash */
    broadcast_clear(conn);          /* no crash */
    broadcast_send("room", conn, "x", 1, bc_test_id_create(2), bc_compare_user); /* no crash */
    TEST_ASSERT_EQUAL(2, bc_id_free_calls, "send id freed when broadcast is missing");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(conn);
}

/* -------------------------------------------------------------------------- */
/* broadcast_remove                                                            */
/* -------------------------------------------------------------------------- */

TEST(test_broadcast_remove_subscriber_and_empty_channel) {
    TEST_CASE("broadcast_remove unsubscribes, frees id and destroys empty channel");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* first = bc_conn_create(&h);
    connection_t* second = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(first, "first connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(second, "second connection alloc", cleanup);

    TEST_ASSERT_EQUAL(1, broadcast_add("room", first, bc_test_id_create(1), bc_capture_handler), "subscribe first");
    TEST_ASSERT_EQUAL(1, broadcast_add("room", second, bc_test_id_create(2), bc_capture_handler), "subscribe second");

    broadcast_remove("room", first);
    TEST_ASSERT_EQUAL(1, bc_id_free_calls, "removed subscriber id freed");

    broadcast_list_t* channel = bc_find_channel(h.server.broadcast, "room");
    TEST_REQUIRE_NOT_NULL_GOTO(channel, "channel kept while non-empty", cleanup);
    TEST_ASSERT_EQUAL(1, bc_list_item_count(channel), "one subscriber left");
    TEST_ASSERT(channel->item->connection == second, "remaining subscriber is second");
    TEST_ASSERT(channel->item_last == channel->item, "item_last updated after head removal");

    broadcast_remove("room", second);
    TEST_ASSERT_EQUAL(2, bc_id_free_calls, "second subscriber id freed");
    TEST_ASSERT_NULL(h.server.broadcast->list, "empty channel destroyed");
    TEST_ASSERT_NULL(h.server.broadcast->list_last, "list_last cleared with last channel");

    /* no-op branches: unknown channel, unknown connection, NULL args */
    broadcast_remove("room", first);
    broadcast_remove(NULL, first);
    broadcast_remove("room", NULL);
    TEST_ASSERT_EQUAL(2, bc_id_free_calls, "no-op removals free nothing");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(first);
    bc_conn_free(second);
}

TEST(test_broadcast_remove_tail_keeps_append_working) {
    TEST_CASE("removing tail subscriber keeps item_last consistent for append");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* first = bc_conn_create(&h);
    connection_t* second = bc_conn_create(&h);
    connection_t* third = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(first, "first connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(second, "second connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(third, "third connection alloc", cleanup);

    TEST_ASSERT_EQUAL(1, broadcast_add("room", first, NULL, bc_capture_handler), "subscribe first");
    TEST_ASSERT_EQUAL(1, broadcast_add("room", second, NULL, bc_capture_handler), "subscribe second");

    broadcast_remove("room", second); /* tail removal */

    broadcast_list_t* channel = bc_find_channel(h.server.broadcast, "room");
    TEST_REQUIRE_NOT_NULL_GOTO(channel, "channel exists", cleanup);
    TEST_ASSERT(channel->item_last == channel->item, "item_last rolled back to previous item");

    TEST_ASSERT_EQUAL(1, broadcast_add("room", third, NULL, bc_capture_handler), "append after tail removal");
    TEST_ASSERT_EQUAL(2, bc_list_item_count(channel), "both subscribers linked");
    TEST_ASSERT(channel->item->connection == first, "head is first");
    TEST_ASSERT(channel->item_last->connection == third, "tail is third");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(first);
    bc_conn_free(second);
    bc_conn_free(third);
}

/* -------------------------------------------------------------------------- */
/* broadcast_clear                                                             */
/* -------------------------------------------------------------------------- */

TEST(test_broadcast_clear_unsubscribes_everywhere) {
    TEST_CASE("broadcast_clear removes connection from all channels, destroys empty ones");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* leaver = bc_conn_create(&h);
    connection_t* stayer = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(leaver, "leaver connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(stayer, "stayer connection alloc", cleanup);

    /* leaver in a, b, c; stayer only in b: a and c become empty and must be
     * unlinked (b is in the middle — checks the prev-chain during unlink) */
    TEST_ASSERT_EQUAL(1, broadcast_add("a", leaver, bc_test_id_create(1), bc_capture_handler), "leaver in a");
    TEST_ASSERT_EQUAL(1, broadcast_add("b", leaver, bc_test_id_create(2), bc_capture_handler), "leaver in b");
    TEST_ASSERT_EQUAL(1, broadcast_add("b", stayer, bc_test_id_create(3), bc_capture_handler), "stayer in b");
    TEST_ASSERT_EQUAL(1, broadcast_add("c", leaver, bc_test_id_create(4), bc_capture_handler), "leaver in c");

    broadcast_clear(leaver);

    TEST_ASSERT_EQUAL(3, bc_id_free_calls, "leaver ids freed in all channels");
    TEST_ASSERT_EQUAL(1, bc_channel_count(h.server.broadcast), "empty channels destroyed");

    broadcast_list_t* channel = bc_find_channel(h.server.broadcast, "b");
    TEST_REQUIRE_NOT_NULL_GOTO(channel, "channel b kept", cleanup);
    TEST_ASSERT(h.server.broadcast->list == channel, "list head is b");
    TEST_ASSERT(h.server.broadcast->list_last == channel, "list_last is b");
    TEST_ASSERT_EQUAL(1, bc_list_item_count(channel), "stayer kept");
    TEST_ASSERT(channel->item->connection == stayer, "remaining subscriber is stayer");

    broadcast_clear(leaver); /* repeated clear is a no-op */
    TEST_ASSERT_EQUAL(1, bc_channel_count(h.server.broadcast), "no-op clear keeps channels");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(leaver);
    bc_conn_free(stayer);
}

/* -------------------------------------------------------------------------- */
/* broadcast_send / broadcast_send_all                                         */
/* -------------------------------------------------------------------------- */

TEST(test_broadcast_send_all_delivers_and_excludes_sender) {
    TEST_CASE("broadcast_send_all queues message for every subscriber except sender");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* sender = bc_conn_create(&h);
    connection_t* first = bc_conn_create(&h);
    connection_t* second = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(sender, "sender connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(first, "first connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(second, "second connection alloc", cleanup);

    TEST_ASSERT_EQUAL(1, broadcast_add("room", sender, NULL, bc_capture_handler), "sender subscribed");
    TEST_ASSERT_EQUAL(1, broadcast_add("room", first, NULL, bc_capture_handler), "first subscribed");
    TEST_ASSERT_EQUAL(1, broadcast_add("room", second, NULL, bc_capture_handler), "second subscribed");

    broadcast_send_all("room", sender, "hello", 5);

    TEST_ASSERT_EQUAL(0, bc_broadcast_queue_size(sender), "sender receives nothing");
    TEST_ASSERT_EQUAL(1, bc_broadcast_queue_size(first), "first got one message");
    TEST_ASSERT_EQUAL(1, bc_broadcast_queue_size(second), "second got one message");

    /* both receivers were scheduled into the worker queue exactly once */
    TEST_ASSERT_NOT_NULL(bc_worker_queue_pop(), "first worker queue entry");
    TEST_ASSERT_NOT_NULL(bc_worker_queue_pop(), "second worker queue entry");

    /* executing the queued item builds a websockets response and calls the
     * subscriber's handler with the shared payload */
    TEST_ASSERT_EQUAL(1, bc_drain_broadcast_queue(first, 1), "first item executed");
    TEST_ASSERT_EQUAL(1, bc_handler_calls, "handler called once");
    TEST_ASSERT_NOT_NULL(bc_handler_response, "handler got a response");
    TEST_ASSERT_EQUAL_SIZE(5, bc_handler_size, "payload size delivered");
    TEST_ASSERT_STR_EQUAL("hello", bc_handler_payload, "payload content delivered");

    TEST_ASSERT_EQUAL(1, bc_drain_broadcast_queue(second, 1), "second item executed");
    TEST_ASSERT_EQUAL(2, bc_handler_calls, "handler called for second subscriber");
    TEST_ASSERT_STR_EQUAL("hello", bc_handler_payload, "shared payload intact after first release");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(sender);
    bc_conn_free(first);
    bc_conn_free(second);
}

TEST(test_broadcast_send_filters_by_id) {
    TEST_CASE("broadcast_send delivers only to subscribers matched by compare_handler");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* sender = bc_conn_create(&h);
    connection_t* matched = bc_conn_create(&h);
    connection_t* other = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(sender, "sender connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(matched, "matched connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(other, "other connection alloc", cleanup);

    TEST_ASSERT_EQUAL(1, broadcast_add("room", matched, bc_test_id_create(1), bc_capture_handler), "matched subscribed");
    TEST_ASSERT_EQUAL(1, broadcast_add("room", other, bc_test_id_create(2), bc_capture_handler), "other subscribed");

    broadcast_send("room", sender, "ping", 4, bc_test_id_create(1), bc_compare_user);

    TEST_ASSERT_EQUAL(1, bc_id_free_calls, "sent id freed after send");
    TEST_ASSERT_EQUAL(1, bc_broadcast_queue_size(matched), "matched subscriber got message");
    TEST_ASSERT_EQUAL(0, bc_broadcast_queue_size(other), "other subscriber filtered out");

    TEST_ASSERT_NOT_NULL(bc_worker_queue_pop(), "matched scheduled into worker queue");

    TEST_ASSERT_EQUAL(1, bc_drain_broadcast_queue(matched, 1), "matched item executed");
    TEST_ASSERT_STR_EQUAL("ping", bc_handler_payload, "payload delivered to matched");

    /* NULL compare_handler disables filtering even when id is set */
    broadcast_send("room", sender, "all", 3, bc_test_id_create(1), NULL);
    TEST_ASSERT_EQUAL(2, bc_id_free_calls, "unfiltered send id freed too");
    TEST_ASSERT_EQUAL(1, bc_broadcast_queue_size(matched), "matched got unfiltered message");
    TEST_ASSERT_EQUAL(1, bc_broadcast_queue_size(other), "other got unfiltered message");

    TEST_ASSERT_NOT_NULL(bc_worker_queue_pop(), "other scheduled into worker queue");
    TEST_ASSERT_EQUAL(1, bc_drain_broadcast_queue(matched, 0), "matched queue drained");
    TEST_ASSERT_EQUAL(1, bc_drain_broadcast_queue(other, 0), "other queue drained");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(sender);
    bc_conn_free(matched);
    bc_conn_free(other);
}

TEST(test_broadcast_send_edge_cases) {
    /* REGRESSION: unknown channel / NULL name freed id but NULL name crashed
     * in strcmp; NULL payload with size > 0 hit memcpy(NULL). */
    TEST_CASE("broadcast_send edge cases: unknown channel, NULL name, NULL payload");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* sender = bc_conn_create(&h);
    connection_t* receiver = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(sender, "sender connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(receiver, "receiver connection alloc", cleanup);

    /* unknown channel: nothing delivered, id still freed */
    broadcast_send("nowhere", sender, "x", 1, bc_test_id_create(1), bc_compare_user);
    TEST_ASSERT_EQUAL(1, bc_id_free_calls, "id freed for unknown channel");

    /* NULL channel name: no crash, id freed */
    broadcast_send(NULL, sender, "x", 1, bc_test_id_create(2), bc_compare_user);
    TEST_ASSERT_EQUAL(2, bc_id_free_calls, "id freed for NULL channel name");

    TEST_ASSERT_EQUAL(1, broadcast_add("room", receiver, NULL, bc_capture_handler), "receiver subscribed");

    /* NULL payload with size > 0: message dropped instead of memcpy(NULL) */
    broadcast_send_all("room", sender, NULL, 5);
    TEST_ASSERT_EQUAL(0, bc_broadcast_queue_size(receiver), "NULL payload dropped");

    /* empty payload is a valid message */
    broadcast_send_all("room", sender, "", 0);
    TEST_ASSERT_EQUAL(1, bc_broadcast_queue_size(receiver), "empty payload delivered");

    TEST_ASSERT_NOT_NULL(bc_worker_queue_pop(), "receiver scheduled into worker queue");

    TEST_ASSERT_EQUAL(1, bc_drain_broadcast_queue(receiver, 1), "empty message executed");
    TEST_ASSERT_EQUAL(1, bc_handler_calls, "handler called for empty message");
    TEST_ASSERT_EQUAL_SIZE(0, bc_handler_size, "empty message size is 0");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(sender);
    bc_conn_free(receiver);
}

TEST(test_broadcast_send_queue_overflow_drops_message) {
    TEST_CASE("message is dropped when subscriber broadcast queue exceeds the limit");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* sender = bc_conn_create(&h);
    connection_t* receiver = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(sender, "sender connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(receiver, "receiver connection alloc", cleanup);

    TEST_ASSERT_EQUAL(1, broadcast_add("room", receiver, NULL, bc_capture_handler), "receiver subscribed");

    /* заполняем очередь заглушками сверх лимита в 3000 сообщений */
    connection_server_ctx_t* ctx = receiver->ctx;
    int prefilled = 0;
    cqueue_lock(ctx->broadcast_queue);
    for (int i = 0; i < 3001; i++) {
        connection_queue_item_t* stub_item = connection_queue_item_create();
        if (stub_item == NULL || !cqueue_append(ctx->broadcast_queue, stub_item)) {
            if (stub_item != NULL) stub_item->free(stub_item);
            break;
        }
        prefilled++;
    }
    cqueue_unlock(ctx->broadcast_queue);
    TEST_REQUIRE_GOTO(prefilled == 3001, "queue prefilled over the limit", cleanup);

    broadcast_send_all("room", sender, "late", 4);
    TEST_ASSERT_EQUAL(3001, bc_broadcast_queue_size(receiver), "overflowing message dropped");

    TEST_ASSERT_EQUAL(3001, bc_drain_broadcast_queue(receiver, 0), "prefilled stubs drained");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(sender);
    bc_conn_free(receiver);
}

/* -------------------------------------------------------------------------- */
/* Concurrency                                                                 */
/* -------------------------------------------------------------------------- */

typedef struct {
    const char* channel;
    connection_t* sender;
    int count;
} bc_sender_args_t;

static void* bc_sender_thread(void* arg) {
    bc_sender_args_t* args = arg;

    for (int i = 0; i < args->count; i++)
        broadcast_send_all(args->channel, args->sender, "x", 1);

    return NULL;
}

TEST(test_broadcast_send_concurrent_channels_shared_subscriber) {
    /* REGRESSION: __broadcast_queue_add used cqueue_incrementlock, which does
     * not exclude concurrent producers: two channels sharing a subscriber
     * corrupted its broadcast_queue and lost messages. With a real lock every
     * message must arrive. */
    TEST_CASE("concurrent sends on two channels to one subscriber lose nothing");

    bc_stubs_reset();

    bc_harness_t h;
    TEST_REQUIRE(bc_harness_init(&h, 1), "harness init");

    connection_t* receiver = bc_conn_create(&h);
    connection_t* first_sender = bc_conn_create(&h);
    connection_t* second_sender = bc_conn_create(&h);
    TEST_REQUIRE_NOT_NULL_GOTO(receiver, "receiver connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(first_sender, "first sender connection alloc", cleanup);
    TEST_REQUIRE_NOT_NULL_GOTO(second_sender, "second sender connection alloc", cleanup);

    TEST_ASSERT_EQUAL(1, broadcast_add("ch1", receiver, NULL, bc_capture_handler), "receiver in ch1");
    TEST_ASSERT_EQUAL(1, broadcast_add("ch2", receiver, NULL, bc_capture_handler), "receiver in ch2");

    enum { MESSAGES_PER_CHANNEL = 500 }; /* 2 * 500 < лимит очереди в 3000 */

    bc_sender_args_t first_args = { "ch1", first_sender, MESSAGES_PER_CHANNEL };
    bc_sender_args_t second_args = { "ch2", second_sender, MESSAGES_PER_CHANNEL };

    pthread_t first_thread, second_thread;
    TEST_REQUIRE_GOTO(pthread_create(&first_thread, NULL, bc_sender_thread, &first_args) == 0, "first thread", cleanup);
    TEST_REQUIRE_GOTO(pthread_create(&second_thread, NULL, bc_sender_thread, &second_args) == 0, "second thread", cleanup2);

    pthread_join(second_thread, NULL);
    cleanup2:
    pthread_join(first_thread, NULL);

    TEST_ASSERT_EQUAL(2 * MESSAGES_PER_CHANNEL, bc_broadcast_queue_size(receiver), "no messages lost");
    TEST_ASSERT_EQUAL(2 * MESSAGES_PER_CHANNEL, bc_drain_broadcast_queue(receiver, 0), "queue linked list intact");

    /* ровно одна постановка в глобальную очередь: CAS 1->2 срабатывает один раз */
    TEST_ASSERT_NOT_NULL(bc_worker_queue_pop(), "receiver scheduled into worker queue once");

    cleanup:

    bc_harness_free(&h);
    bc_conn_free(receiver);
    bc_conn_free(first_sender);
    bc_conn_free(second_sender);
}
