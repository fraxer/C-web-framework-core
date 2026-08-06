#include "framework.h"

#include "quiccidtable.h"

#include <string.h>

/* The CID routing table is consulted twice per datagram on every worker, and it
 * is the only thing standing between an unauthenticated datagram and a
 * connection object. Lookup correctness, refusal to double-map, and the acquire
 * hook are all load-bearing. */

static int __acquire_calls = 0;

static void __count_acquire(void* value) {
    (void)value;
    __acquire_calls++;
}

static quiccid_t __cid(const char* bytes, uint8_t len) {
    quiccid_t cid = { .len = len };
    memcpy(cid.data, bytes, len);
    return cid;
}

TEST(test_quic_cidtable_basics) {
    TEST_SUITE("quiccidtable");

    quiccidtable_t* table = quiccidtable_create(64, 8, 0x0123456789abcdefULL,
                                                __count_acquire);
    TEST_REQUIRE_NOT_NULL(table, "table created");

    __acquire_calls = 0;

    int a = 1, b = 2;
    const quiccid_t cid_a = __cid("\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    const quiccid_t cid_b = __cid("\x11\x12\x13\x14\x15\x16\x17\x18", 8);

    TEST_CASE("insert and look up");
    TEST_ASSERT(quiccidtable_insert(table, &cid_a, &a) == QUICCIDTABLE_OK, "insert a");
    TEST_ASSERT(quiccidtable_insert(table, &cid_b, &b) == QUICCIDTABLE_OK, "insert b");
    TEST_ASSERT(quiccidtable_count(table) == 2, "count");
    TEST_ASSERT(quiccidtable_lookup_acquire(table, &cid_a) == &a, "finds a");
    TEST_ASSERT(quiccidtable_lookup_acquire(table, &cid_b) == &b, "finds b");
    TEST_ASSERT(__acquire_calls == 2, "acquire ran once per successful lookup");

    TEST_CASE("a miss does not acquire");
    const quiccid_t missing = __cid("\xff\xff\xff\xff\xff\xff\xff\xff", 8);
    TEST_ASSERT(quiccidtable_lookup_acquire(table, &missing) == NULL, "miss");
    TEST_ASSERT(__acquire_calls == 2, "acquire not called on a miss");

    TEST_CASE("length is part of the key");
    /* A prefix of another id is a different id. Treating them as equal would
     * route a datagram to the wrong connection. */
    const quiccid_t prefix = __cid("\x01\x02\x03\x04", 4);
    TEST_ASSERT(quiccidtable_lookup_acquire(table, &prefix) == NULL,
                "prefix of an existing id does not match");
    TEST_ASSERT(quiccidtable_insert(table, &prefix, &b) == QUICCIDTABLE_OK,
                "and can be inserted separately");
    TEST_ASSERT(quiccidtable_count(table) == 3, "count");

    TEST_CASE("duplicates are refused, not overwritten");
    /* A replayed Initial must route to the existing connection rather than
     * silently rebind the id to a new one. */
    TEST_ASSERT(quiccidtable_insert(table, &cid_a, &b) == QUICCIDTABLE_DUPLICATE,
                "duplicate refused");
    TEST_ASSERT(quiccidtable_lookup_acquire(table, &cid_a) == &a,
                "original mapping intact");
    TEST_ASSERT(quiccidtable_count(table) == 3, "count unchanged");

    TEST_CASE("remove");
    TEST_ASSERT(quiccidtable_remove(table, &cid_a) == 1, "removed");
    TEST_ASSERT(quiccidtable_remove(table, &cid_a) == 0, "second remove is a no-op");
    TEST_ASSERT(quiccidtable_lookup_acquire(table, &cid_a) == NULL, "gone");
    TEST_ASSERT(quiccidtable_count(table) == 2, "count");
    /* Re-insertable after removal: a retired id may legitimately be reissued. */
    TEST_ASSERT(quiccidtable_insert(table, &cid_a, &a) == QUICCIDTABLE_OK, "reinsert");

    quiccidtable_free(table);
}

TEST(test_quic_cidtable_edges) {
    TEST_SUITE("quiccidtable");

    quiccidtable_t* table = quiccidtable_create(16, 4, 42, NULL);
    TEST_REQUIRE_NOT_NULL(table, "table created");

    int v = 7;

    TEST_CASE("no acquire hook is allowed");
    const quiccid_t cid = __cid("\xaa\xbb", 2);
    TEST_ASSERT(quiccidtable_insert(table, &cid, &v) == QUICCIDTABLE_OK, "insert");
    TEST_ASSERT(quiccidtable_lookup_acquire(table, &cid) == &v, "raw value returned");

    TEST_CASE("zero-length id");
    const quiccid_t empty = { .len = 0 };
    TEST_ASSERT(quiccidtable_insert(table, &empty, &v) == QUICCIDTABLE_OK, "insert");
    TEST_ASSERT(quiccidtable_lookup_acquire(table, &empty) == &v, "found");

    TEST_CASE("maximum length id");
    quiccid_t max = { .len = QUIC_MAX_CID_LEN };
    memset(max.data, 0x5a, QUIC_MAX_CID_LEN);
    TEST_ASSERT(quiccidtable_insert(table, &max, &v) == QUICCIDTABLE_OK, "insert");
    TEST_ASSERT(quiccidtable_lookup_acquire(table, &max) == &v, "found");

    TEST_CASE("NULL arguments are refused, not dereferenced");
    TEST_ASSERT(quiccidtable_lookup_acquire(NULL, &cid) == NULL, "NULL table");
    TEST_ASSERT(quiccidtable_lookup_acquire(table, NULL) == NULL, "NULL cid");
    TEST_ASSERT(quiccidtable_remove(NULL, &cid) == 0, "NULL table");
    TEST_ASSERT(quiccidtable_count(NULL) == 0, "NULL table");
    quiccidtable_free(NULL);

    quiccidtable_free(table);
}

TEST(test_quic_cidtable_spread) {
    TEST_SUITE("quiccidtable");

    /* 512 ids that differ only in their last two bytes -- the shape a peer
     * opening many connections from one client produces. If the hash keyed only
     * on a prefix, or the shard and bucket indexes came from the same bits,
     * chains would blow up here rather than in production. */
    TEST_CASE("ids sharing a prefix still spread");

    quiccidtable_t* table = quiccidtable_create(1024, 16, 0xdeadbeefcafeULL, NULL);
    TEST_REQUIRE_NOT_NULL(table, "table created");

    static int values[512];
    int inserted = 1;

    for (int i = 0; i < 512; i++) {
        quiccid_t cid = { .len = 8 };
        memcpy(cid.data, "\xc0\xff\xee\x00\xba\xad", 6);
        cid.data[6] = (uint8_t)(i >> 8);
        cid.data[7] = (uint8_t)(i & 0xff);

        values[i] = i;
        if (quiccidtable_insert(table, &cid, &values[i]) != QUICCIDTABLE_OK)
            inserted = 0;
    }

    TEST_ASSERT(inserted, "all inserted");
    TEST_ASSERT(quiccidtable_count(table) == 512, "count");

    int all_found = 1;
    for (int i = 0; i < 512; i++) {
        quiccid_t cid = { .len = 8 };
        memcpy(cid.data, "\xc0\xff\xee\x00\xba\xad", 6);
        cid.data[6] = (uint8_t)(i >> 8);
        cid.data[7] = (uint8_t)(i & 0xff);

        if (quiccidtable_lookup_acquire(table, &cid) != &values[i])
            all_found = 0;
    }
    TEST_ASSERT(all_found, "all found, each mapping to its own value");

    /* 512 entries over 16 shards x 128 buckets = 2048 bins at a load of 0.25;
     * balls-in-bins puts the longest chain at 3-4. This assertion is why the
     * hash has a finaliser: plain FNV-1a produced chains of 32 here, using 16
     * of the 2048 buckets, because the bucket index reads the high half of the
     * hash and FNV barely moves it for keys that share a prefix. */
    const size_t longest = quiccidtable_max_chain(table);
    TEST_ASSERT(longest <= 6, "no pathological chain");

    quiccidtable_free(table);
}
