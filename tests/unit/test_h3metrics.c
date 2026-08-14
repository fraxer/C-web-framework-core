#include "framework.h"

#include "json.h"
#include "metrics.h"
#include "quicstream.h"

#include <string.h>

/* QUIC and HTTP/3 counters (docs/http3/07-integration.md §3).
 *
 * Three things are worth asserting about a counter, and only three: that it
 * counts the event it is named after, that it costs nothing when metrics are
 * off, and that it reaches the snapshot under the name an operator will grep
 * for. The last one matters more than it looks -- the names are index-matched
 * to enums by hand, and a name array one entry short of its enum reports every
 * counter after the gap under the wrong key while every test still passes.
 *
 * The counters are process-wide, so each case resets them first. That is also
 * why metrics are switched back off at the end of every case: leaving them on
 * would make unrelated suites that run afterwards record into the same pile. */

#define STREAM_WINDOW (64 * 1024)

/* One counter out of the snapshot, by section and key. Returns -1 when the key
 * is absent, which is a distinct failure from the value being zero. */
static long long snapshot_value(const char* section, const char* key) {
    json_doc_t* doc = metrics_snapshot_json();
    if (doc == NULL) return -1;

    long long result = -1;
    const json_token_t* object = json_object_get(json_root(doc), section);

    if (object != NULL) {
        const json_token_t* value = json_object_get(object, key);
        int ok = 0;

        if (value != NULL) {
            const double n = json_double(value, &ok);
            if (ok) result = (long long)n;
        }
    }

    json_free(doc);

    return result;
}

/* Same, one level deeper: the sample series are objects inside `quic`. */
static long long snapshot_sample(const char* series, const char* key) {
    json_doc_t* doc = metrics_snapshot_json();
    if (doc == NULL) return -1;

    long long result = -1;
    const json_token_t* quic = json_object_get(json_root(doc), "quic");
    const json_token_t* object = quic == NULL ? NULL : json_object_get(quic, series);

    if (object != NULL) {
        const json_token_t* value = json_object_get(object, key);
        int ok = 0;

        if (value != NULL) {
            const double n = json_double(value, &ok);
            if (ok) result = (long long)n;
        }
    }

    json_free(doc);

    return result;
}

static long long hist_value(const char* series, const char* bucket) {
    json_doc_t* doc = metrics_snapshot_json();
    if (doc == NULL) return -1;

    long long result = -1;
    const json_token_t* quic = json_object_get(json_root(doc), "quic");
    const json_token_t* object = quic == NULL ? NULL : json_object_get(quic, series);
    const json_token_t* hist = object == NULL ? NULL : json_object_get(object, "hist");

    if (hist != NULL) {
        const json_token_t* value = json_object_get(hist, bucket);
        int ok = 0;

        if (value != NULL) {
            const double n = json_double(value, &ok);
            if (ok) result = (long long)n;
        }
    }

    json_free(doc);

    return result;
}

TEST(test_h3metrics_disabled) {
    TEST_SUITE("h3metrics");

    TEST_CASE("with metrics off nothing is recorded");
    /* The point of the flag: these sit on the datagram and ACK paths, so a
     * counter that updated regardless would be a permanent cost paid by every
     * server that never looks at /metrics. */
    metrics_init(1);
    metrics_reset();
    metrics_init(0);

    metrics_quic(METRICS_QUIC_PACKETS_LOST);
    metrics_quic_add(METRICS_QUIC_BYTES_SENT, 1000);
    metrics_quic_rtt(5000);
    metrics_quic_cwnd(32768);
    metrics_h3(METRICS_H3_REQUESTS);
    metrics_h3_status(200);

    metrics_init(1);   /* the snapshot itself must still work */

    TEST_ASSERT(snapshot_value("quic", "packets_lost") == 0, "packets_lost stayed zero");
    TEST_ASSERT(snapshot_value("quic", "bytes_sent") == 0, "bytes_sent stayed zero");
    TEST_ASSERT(snapshot_value("http3", "requests") == 0, "requests stayed zero");
    TEST_ASSERT(snapshot_value("http3", "responses.2xx") == 0, "responses.2xx stayed zero");
    TEST_ASSERT(snapshot_sample("rtt_us", "samples") == 0, "rtt took no sample");
    TEST_ASSERT(snapshot_sample("cwnd_bytes", "samples") == 0, "cwnd took no sample");

    metrics_init(0);
}

TEST(test_h3metrics_quic_counters) {
    TEST_SUITE("h3metrics");

    TEST_CASE("every quic counter reaches the snapshot under its own name");
    /* Each counter is bumped a different number of times, so a name array
     * shifted against its enum shows up as a wrong value rather than as a
     * missing key -- which is what a simple presence check would miss. */
    metrics_init(1);
    metrics_reset();

    metrics_quic(METRICS_QUIC_HANDSHAKE_COMPLETED);
    for (int i = 0; i < 2; i++) metrics_quic(METRICS_QUIC_HANDSHAKE_FAILED_TLS);
    for (int i = 0; i < 3; i++) metrics_quic(METRICS_QUIC_HANDSHAKE_FAILED_TIMEOUT);
    for (int i = 0; i < 4; i++) metrics_quic(METRICS_QUIC_DECRYPT_FAILURE);
    for (int i = 0; i < 5; i++) metrics_quic(METRICS_QUIC_PACKETS_LOST);
    for (int i = 0; i < 6; i++) metrics_quic(METRICS_QUIC_PTO_FIRED);
    for (int i = 0; i < 7; i++) metrics_quic(METRICS_QUIC_FLOW_BLOCKED_CONN);
    for (int i = 0; i < 8; i++) metrics_quic(METRICS_QUIC_FLOW_BLOCKED_STREAM);
    for (int i = 0; i < 9; i++) metrics_quic(METRICS_QUIC_AMPLIFICATION_LIMITED);
    for (int i = 0; i < 10; i++) metrics_quic(METRICS_QUIC_CLOSED_IDLE);
    for (int i = 0; i < 11; i++) metrics_quic(METRICS_QUIC_CLOSED_PEER);

    TEST_ASSERT(snapshot_value("quic", "handshakes_completed") == 1, "handshakes_completed");
    TEST_ASSERT(snapshot_value("quic", "handshakes_failed.tls") == 2, "handshakes_failed.tls");
    TEST_ASSERT(snapshot_value("quic", "handshakes_failed.timeout") == 3, "handshakes_failed.timeout");
    TEST_ASSERT(snapshot_value("quic", "decrypt_failures") == 4, "decrypt_failures");
    TEST_ASSERT(snapshot_value("quic", "packets_lost") == 5, "packets_lost");
    TEST_ASSERT(snapshot_value("quic", "pto_fired") == 6, "pto_fired");
    TEST_ASSERT(snapshot_value("quic", "flow_blocked.connection") == 7, "flow_blocked.connection");
    TEST_ASSERT(snapshot_value("quic", "flow_blocked.stream") == 8, "flow_blocked.stream");
    TEST_ASSERT(snapshot_value("quic", "amplification_limited") == 9, "amplification_limited");
    TEST_ASSERT(snapshot_value("quic", "closed.idle_timeout") == 10, "closed.idle_timeout");
    TEST_ASSERT(snapshot_value("quic", "closed.peer") == 11, "closed.peer");

    /* Zeroes are reported, not omitted: "no handshake has failed" is an answer,
     * and a missing key reads as "this build has no HTTP/3". */
    TEST_ASSERT(snapshot_value("quic", "aead_limit_reached") == 0, "an untouched counter is still printed");

    TEST_CASE("an out-of-range kind is dropped, not written past the array");
    metrics_quic((metrics_quic_t)METRICS_QUIC__COUNT);
    metrics_quic((metrics_quic_t)-1);
    TEST_ASSERT(snapshot_value("quic", "datagrams_received") == 0, "neighbouring counter untouched");

    metrics_reset();
    metrics_init(0);
}

TEST(test_h3metrics_h3_counters) {
    TEST_SUITE("h3metrics");

    TEST_CASE("http3 counters and the status-class mapping");
    metrics_init(1);
    metrics_reset();

    metrics_h3(METRICS_H3_REQUESTS);
    metrics_h3(METRICS_H3_REQUESTS);
    metrics_h3(METRICS_H3_STREAMS_CANCELLED);
    metrics_h3(METRICS_H3_GOAWAY_SENT);
    metrics_h3(METRICS_H3_ABUSE_CTRL_BUDGET);

    /* The edges of every class, in both directions. */
    metrics_h3_status(100);
    metrics_h3_status(199);
    metrics_h3_status(200);
    metrics_h3_status(299);
    metrics_h3_status(301);
    metrics_h3_status(404);
    metrics_h3_status(499);
    metrics_h3_status(500);
    metrics_h3_status(599);

    TEST_ASSERT(snapshot_value("http3", "requests") == 2, "requests");
    TEST_ASSERT(snapshot_value("http3", "streams_cancelled") == 1, "streams_cancelled");
    TEST_ASSERT(snapshot_value("http3", "goaway_sent") == 1, "goaway_sent");
    TEST_ASSERT(snapshot_value("http3", "abuse.ctrl_budget") == 1, "abuse.ctrl_budget");
    TEST_ASSERT(snapshot_value("http3", "abuse.abort_budget") == 0, "abuse.abort_budget untouched");

    TEST_ASSERT(snapshot_value("http3", "responses.1xx") == 2, "1xx spans 100..199");
    TEST_ASSERT(snapshot_value("http3", "responses.2xx") == 2, "2xx spans 200..299");
    TEST_ASSERT(snapshot_value("http3", "responses.3xx") == 1, "3xx");
    TEST_ASSERT(snapshot_value("http3", "responses.4xx") == 2, "4xx spans 404..499");
    TEST_ASSERT(snapshot_value("http3", "responses.5xx") == 2, "5xx spans 500..599");

    TEST_CASE("a status outside 100..599 is not counted as anything");
    /* Counting one of our own bugs as a 5xx would put it in the bucket
     * operators page on, which is exactly where it must not appear. */
    metrics_h3_status(99);
    metrics_h3_status(600);
    metrics_h3_status(0);
    metrics_h3_status(-1);

    TEST_ASSERT(snapshot_value("http3", "responses.1xx") == 2, "99 did not become a 1xx");
    TEST_ASSERT(snapshot_value("http3", "responses.5xx") == 2, "600 did not become a 5xx");

    metrics_reset();
    metrics_init(0);
}

TEST(test_h3metrics_samples) {
    TEST_SUITE("h3metrics");

    TEST_CASE("rtt samples land in the bucket their value names");
    metrics_init(1);
    metrics_reset();

    /* One on each side of every boundary. */
    metrics_quic_rtt(0);        /* <100us */
    metrics_quic_rtt(99);       /* <100us */
    metrics_quic_rtt(100);      /* <1ms   */
    metrics_quic_rtt(999);      /* <1ms   */
    metrics_quic_rtt(1000);     /* <10ms  */
    metrics_quic_rtt(9999);     /* <10ms  */
    metrics_quic_rtt(10000);    /* <50ms  */
    metrics_quic_rtt(50000);    /* <200ms */
    metrics_quic_rtt(200000);   /* >=200ms */
    metrics_quic_rtt(1000000);  /* >=200ms */

    TEST_ASSERT(hist_value("rtt_us", "<100us") == 2, "rtt <100us");
    TEST_ASSERT(hist_value("rtt_us", "<1ms") == 2, "rtt <1ms");
    TEST_ASSERT(hist_value("rtt_us", "<10ms") == 2, "rtt <10ms");
    TEST_ASSERT(hist_value("rtt_us", "<50ms") == 1, "rtt <50ms");
    TEST_ASSERT(hist_value("rtt_us", "<200ms") == 1, "rtt <200ms");
    TEST_ASSERT(hist_value("rtt_us", ">=200ms") == 2, "rtt >=200ms");

    TEST_ASSERT(snapshot_sample("rtt_us", "samples") == 10, "every sample counted");
    TEST_ASSERT(snapshot_sample("rtt_us", "max") == 1000000, "max is the largest sample");

    TEST_CASE("the average is over the samples, not the buckets");
    metrics_reset();
    metrics_quic_rtt(10);
    metrics_quic_rtt(30);
    TEST_ASSERT(snapshot_sample("rtt_us", "avg") == 20, "avg of 10 and 30");

    TEST_CASE("cwnd buckets separate a window that never grew from one that did");
    metrics_reset();
    metrics_quic_cwnd(12000);     /* the initial window: <16k */
    metrics_quic_cwnd(16383);     /* <16k  */
    metrics_quic_cwnd(16384);     /* <64k  */
    metrics_quic_cwnd(262144);    /* <1M   */
    metrics_quic_cwnd(8388608);   /* >=4M  */

    TEST_ASSERT(hist_value("cwnd_bytes", "<16k") == 2, "cwnd <16k");
    TEST_ASSERT(hist_value("cwnd_bytes", "<64k") == 1, "cwnd <64k");
    TEST_ASSERT(hist_value("cwnd_bytes", "<256k") == 0, "cwnd <256k");
    TEST_ASSERT(hist_value("cwnd_bytes", "<1M") == 1, "cwnd <1M");
    TEST_ASSERT(hist_value("cwnd_bytes", ">=4M") == 1, "cwnd >=4M");
    TEST_ASSERT(snapshot_sample("cwnd_bytes", "samples") == 5, "every cwnd sample counted");

    TEST_CASE("an empty series reports zero rather than dividing by it");
    metrics_reset();
    TEST_ASSERT(snapshot_sample("rtt_us", "samples") == 0, "no samples");
    TEST_ASSERT(snapshot_sample("rtt_us", "avg") == 0, "avg of nothing is zero");
    TEST_ASSERT(snapshot_sample("rtt_us", "max") == 0, "max of nothing is zero");

    metrics_init(0);
}

TEST(test_h3metrics_process_gauges) {
    TEST_SUITE("h3metrics");
    TEST_CASE("connection and handshake gauges expose current limits and peak");

    metrics_init(1);
    metrics_reset();

    metrics_quic_connections(3, 65536);
    metrics_quic_connections(7, 65536);
    metrics_quic_connections(2, 65536);
    metrics_quic_handshakes(5);
    metrics_quic_memory(4096, 1048576, 3);
    metrics_quic_reload_handoff(1);
    metrics_quic_reload_handoff(1);
    metrics_quic_reload_handoff(0);

    TEST_ASSERT(snapshot_sample("connections", "current") == 2, "current connections");
    TEST_ASSERT(snapshot_sample("connections", "limit") == 65536, "connection limit");
    TEST_ASSERT(snapshot_sample("connections", "peak") == 7, "connection peak");
    TEST_ASSERT(snapshot_sample("handshakes", "inflight") == 5, "handshakes inflight");
    TEST_ASSERT(snapshot_sample("memory", "current_bytes") == 4096, "memory current");
    TEST_ASSERT(snapshot_sample("memory", "limit_bytes") == 1048576, "memory limit");
    TEST_ASSERT(snapshot_sample("memory", "refused") == 3, "memory refusals");
    TEST_ASSERT(snapshot_sample("reload", "handoffs") == 2, "reload handoffs");
    TEST_ASSERT(snapshot_sample("reload", "handoff_failures") == 1, "reload failures");

    metrics_reset();
    metrics_init(0);
}

TEST(test_h3metrics_stream_events) {
    TEST_SUITE("h3metrics");

    TEST_CASE("opening and resetting a stream is what the counters count");
    /* Driven through the real functions rather than by calling metrics_quic
     * directly: what is being checked is that the call sites are on the paths
     * they claim to be on, which no amount of testing the counter can show. */
    metrics_init(1);
    metrics_reset();

    quicstream_t* a = quicstream_create(0, STREAM_WINDOW, STREAM_WINDOW, STREAM_WINDOW);
    quicstream_t* b = quicstream_create(4, STREAM_WINDOW, STREAM_WINDOW, STREAM_WINDOW);

    TEST_REQUIRE(a != NULL && b != NULL, "streams created");
    TEST_ASSERT(snapshot_value("quic", "streams_opened") == 2, "two streams opened");
    TEST_ASSERT(snapshot_value("quic", "streams_reset_sent") == 0, "nothing reset yet");

    quicstream_reset(a, 0x010c);

    TEST_ASSERT(snapshot_value("quic", "streams_reset_sent") == 1, "one reset");

    TEST_CASE("a repeated reset is one abandoned stream, not two");
    /* quicstream_reset is idempotent by design -- the send state guards it --
     * and a counter placed after that guard would report a retry as a second
     * victim. */
    quicstream_reset(a, 0x010c);
    quicstream_reset(a, 0x0102);

    TEST_ASSERT(snapshot_value("quic", "streams_reset_sent") == 1, "still one reset");

    quicstream_free(a);
    quicstream_free(b);

    metrics_reset();
    metrics_init(0);
}
