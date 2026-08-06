#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "quiccidtable.h"

#define QUICCIDTABLE_MIN_BUCKETS 16

typedef struct quiccid_node {
    quiccid_t cid;
    void* value;
    uint64_t hash;
    struct quiccid_node* next;
} quiccid_node_t;

typedef struct quiccid_shard {
    pthread_mutex_t lock;
    quiccid_node_t** buckets;
    atomic_size_t count;
} quiccid_shard_t;

struct quiccidtable {
    quiccid_shard_t* shards;
    size_t shard_count;   /* power of two */
    size_t bucket_count;  /* per shard, power of two */
    uint64_t seed;
    quiccidtable_acquire_fn acquire;
};

static size_t __round_up_pow2(size_t v) {
    size_t p = 1;
    while (p < v && p < (SIZE_MAX / 2)) p <<= 1;
    return p;
}

/* Keyed FNV-1a with a splitmix64 finaliser.
 *
 * Not a cryptographic hash and not claimed to be: the seed is a per-process
 * secret an off-path attacker cannot read, which is what makes precomputing
 * colliding connection ids impractical. The ids this server issues are random
 * anyway; the exposure is the client-chosen id in a first Initial, which lives
 * only for the handshake. quiccidtable_max_chain() exists so that an attack
 * that does find a way through is visible rather than merely slow.
 *
 * The finaliser is not optional. FNV-1a alone avalanches badly in its high
 * bits for short keys -- the multiply carries propagate upward too slowly -- so
 * ids differing only in their last bytes come out with a near-identical top
 * half. Since the bucket index is taken from that half, 512 such ids landed in
 * 16 of 2048 buckets, with chains of 32, which is precisely the shape one
 * client opening many connections produces. Folding (h ^= h >> 32) does not
 * fix it: it rewrites the low half and leaves the high half, which is the half
 * being read, untouched. */
static uint64_t __hash(uint64_t seed, const quiccid_t* cid) {
    uint64_t h = 0xcbf29ce484222325ULL ^ seed;

    for (uint8_t i = 0; i < cid->len; i++) {
        h ^= (uint64_t)cid->data[i];
        h *= 0x100000001b3ULL;
    }

    /* The length is part of the key: two ids where one is a prefix of the other
     * are different ids. */
    h ^= (uint64_t)cid->len;
    h *= 0x100000001b3ULL;

    h ^= h >> 30;
    h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27;
    h *= 0x94d049bb133111ebULL;
    h ^= h >> 31;

    return h;
}

static int __cid_equal(const quiccid_t* a, const quiccid_t* b) {
    return a->len == b->len && memcmp(a->data, b->data, a->len) == 0;
}

quiccidtable_t* quiccidtable_create(size_t expected_entries, size_t shard_count,
                                    uint64_t seed, quiccidtable_acquire_fn acquire) {
    if (shard_count == 0) shard_count = 1;
    shard_count = __round_up_pow2(shard_count);

    quiccidtable_t* table = malloc(sizeof * table);
    if (table == NULL) return NULL;

    /* Two buckets per expected entry keeps chains at one node in the common
     * case without the table dominating the connection's memory. */
    size_t per_shard = (expected_entries * 2) / shard_count;
    if (per_shard < QUICCIDTABLE_MIN_BUCKETS) per_shard = QUICCIDTABLE_MIN_BUCKETS;
    per_shard = __round_up_pow2(per_shard);

    table->shards = calloc(shard_count, sizeof * table->shards);
    if (table->shards == NULL) {
        free(table);
        return NULL;
    }

    table->shard_count = shard_count;
    table->bucket_count = per_shard;
    table->seed = seed;
    table->acquire = acquire;

    for (size_t i = 0; i < shard_count; i++) {
        quiccid_shard_t* shard = &table->shards[i];

        shard->buckets = calloc(per_shard, sizeof * shard->buckets);
        if (shard->buckets == NULL) {
            /* Unwind: the shards already initialised own a mutex and an array. */
            for (size_t j = 0; j < i; j++) {
                pthread_mutex_destroy(&table->shards[j].lock);
                free(table->shards[j].buckets);
            }
            free(table->shards);
            free(table);
            return NULL;
        }

        if (pthread_mutex_init(&shard->lock, NULL) != 0) {
            free(shard->buckets);
            for (size_t j = 0; j < i; j++) {
                pthread_mutex_destroy(&table->shards[j].lock);
                free(table->shards[j].buckets);
            }
            free(table->shards);
            free(table);
            return NULL;
        }

        atomic_init(&shard->count, 0);
    }

    return table;
}

void quiccidtable_free(quiccidtable_t* table) {
    if (table == NULL) return;

    for (size_t i = 0; i < table->shard_count; i++) {
        quiccid_shard_t* shard = &table->shards[i];

        for (size_t b = 0; b < table->bucket_count; b++) {
            quiccid_node_t* node = shard->buckets[b];
            while (node != NULL) {
                quiccid_node_t* next = node->next;
                free(node);
                node = next;
            }
        }

        pthread_mutex_destroy(&shard->lock);
        free(shard->buckets);
    }

    free(table->shards);
    free(table);
}

static quiccid_shard_t* __shard_of(quiccidtable_t* table, uint64_t hash) {
    return &table->shards[hash & (table->shard_count - 1)];
}

static size_t __bucket_of(quiccidtable_t* table, uint64_t hash) {
    /* A different slice of the hash than the shard index, so that two ids in
     * the same shard are not also forced into the same bucket. */
    return (hash >> 32) & (table->bucket_count - 1);
}

quiccidtable_status_e quiccidtable_insert(quiccidtable_t* table,
                                          const quiccid_t* cid, void* value) {
    if (table == NULL || cid == NULL) return QUICCIDTABLE_OOM;
    if (cid->len > QUIC_MAX_CID_LEN) return QUICCIDTABLE_OOM;

    const uint64_t hash = __hash(table->seed, cid);
    quiccid_shard_t* shard = __shard_of(table, hash);
    const size_t bucket = __bucket_of(table, hash);

    /* Allocated before the lock: malloc can be slow, and this lock is taken
     * twice per datagram. */
    quiccid_node_t* node = malloc(sizeof * node);
    if (node == NULL) return QUICCIDTABLE_OOM;

    node->cid = *cid;
    node->value = value;
    node->hash = hash;

    pthread_mutex_lock(&shard->lock);

    for (quiccid_node_t* it = shard->buckets[bucket]; it != NULL; it = it->next) {
        if (it->hash == hash && __cid_equal(&it->cid, cid)) {
            pthread_mutex_unlock(&shard->lock);
            free(node);
            return QUICCIDTABLE_DUPLICATE;
        }
    }

    node->next = shard->buckets[bucket];
    shard->buckets[bucket] = node;
    atomic_fetch_add_explicit(&shard->count, 1, memory_order_relaxed);

    pthread_mutex_unlock(&shard->lock);

    return QUICCIDTABLE_OK;
}

void* quiccidtable_lookup_acquire(quiccidtable_t* table, const quiccid_t* cid) {
    if (table == NULL || cid == NULL) return NULL;
    if (cid->len > QUIC_MAX_CID_LEN) return NULL;

    const uint64_t hash = __hash(table->seed, cid);
    quiccid_shard_t* shard = __shard_of(table, hash);
    const size_t bucket = __bucket_of(table, hash);

    void* value = NULL;

    pthread_mutex_lock(&shard->lock);

    for (quiccid_node_t* it = shard->buckets[bucket]; it != NULL; it = it->next) {
        if (it->hash == hash && __cid_equal(&it->cid, cid)) {
            value = it->value;
            /* Under the lock on purpose: between finding the value and the
             * caller touching it, another worker may be closing that
             * connection and dropping its last reference. */
            if (value != NULL && table->acquire != NULL)
                table->acquire(value);
            break;
        }
    }

    pthread_mutex_unlock(&shard->lock);

    return value;
}

int quiccidtable_remove(quiccidtable_t* table, const quiccid_t* cid) {
    if (table == NULL || cid == NULL) return 0;
    if (cid->len > QUIC_MAX_CID_LEN) return 0;

    const uint64_t hash = __hash(table->seed, cid);
    quiccid_shard_t* shard = __shard_of(table, hash);
    const size_t bucket = __bucket_of(table, hash);

    quiccid_node_t* removed = NULL;

    pthread_mutex_lock(&shard->lock);

    quiccid_node_t** link = &shard->buckets[bucket];
    while (*link != NULL) {
        if ((*link)->hash == hash && __cid_equal(&(*link)->cid, cid)) {
            removed = *link;
            *link = removed->next;
            atomic_fetch_sub_explicit(&shard->count, 1, memory_order_relaxed);
            break;
        }
        link = &(*link)->next;
    }

    pthread_mutex_unlock(&shard->lock);

    /* Freed outside the lock, matching the allocation in insert. */
    free(removed);

    return removed != NULL;
}

size_t quiccidtable_count(const quiccidtable_t* table) {
    if (table == NULL) return 0;

    size_t total = 0;
    for (size_t i = 0; i < table->shard_count; i++)
        total += atomic_load_explicit(&table->shards[i].count, memory_order_relaxed);

    return total;
}

size_t quiccidtable_max_chain(quiccidtable_t* table) {
    if (table == NULL) return 0;

    size_t longest = 0;

    for (size_t i = 0; i < table->shard_count; i++) {
        quiccid_shard_t* shard = &table->shards[i];

        pthread_mutex_lock(&shard->lock);
        for (size_t b = 0; b < table->bucket_count; b++) {
            size_t n = 0;
            for (quiccid_node_t* it = shard->buckets[b]; it != NULL; it = it->next)
                n++;
            if (n > longest) longest = n;
        }
        pthread_mutex_unlock(&shard->lock);
    }

    return longest;
}
