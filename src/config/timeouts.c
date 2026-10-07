#include "timeouts.h"
#include "log.h"
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>

static const char* const protocols[] = { "http1", "h2", "h3", "websocket", "h2_ws" };
static const char* const reasons[] = { "headers", "body_idle", "body_total", "body", "tls_handshake", "idle", "send_idle", "pong", "message_idle", "message_total", "application_idle", "close", "handshake", "slow" };
static const char* const stages[] = { "headers", "body", "queue", "handler", "send", "total" };
static atomic_uint_fast64_t counts[5][14][2];
static atomic_uint_fast64_t duration_count[6], duration_sum[6], duration_hist[6][8];
static const uint64_t duration_bounds[] = { 1, 10, 100, 1000, 10000, 60000, 600000 };

unsigned timeout_event_bit(const char* reason, int enforce) {
    for (unsigned r = 0; r < sizeof reasons / sizeof reasons[0]; r++)
        if (!strcmp(reasons[r], reason)) return 1u << (r * 2 + !!enforce);
    return 0;
}

void timeout_event_clear(unsigned* reported, const char* reason) {
    *reported &= ~(timeout_event_bit(reason, 0) | timeout_event_bit(reason, 1));
}

int timeout_report(unsigned* reported, const char* protocol, const char* reason,
                   int enforce, int fd, uint64_t stream_id) {
    if (!reason) return 0;
    const unsigned bit = timeout_event_bit(reason, enforce);
    if (*reported & bit) return 0;
    *reported |= bit;
    timeout_record(protocol, reason, enforce);
    const int websocket = !strcmp(protocol, "websocket") || !strcmp(protocol, "h2_ws");
    log_info("%s protocol=%s reason=%s mode=%s fd=%d stream=%llu\n",
        websocket ? "websocket_timeout" : "request_timeout", protocol, reason,
        enforce ? "enforce" : "observe", fd, (unsigned long long)stream_id);
    return 1;
}

void timeout_record(const char* protocol, const char* reason, int enforce) {
    size_t p, r;
    for (p = 0; p < 5; p++) if (!strcmp(protocols[p], protocol)) break;
    for (r = 0; r < 14; r++) if (!strcmp(reasons[r], reason)) break;
    if (p < 5 && r < 14) atomic_fetch_add_explicit(&counts[p][r][!!enforce], 1, memory_order_relaxed);
}

void timeout_duration_record(unsigned stage, uint64_t ms) {
    if (stage >= 6) return;
    unsigned bucket = 0;
    while (bucket < 7 && ms > duration_bounds[bucket]) bucket++;
    atomic_fetch_add_explicit(&duration_count[stage], 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&duration_sum[stage], ms, memory_order_relaxed);
    atomic_fetch_add_explicit(&duration_hist[stage][bucket], 1, memory_order_relaxed);
}

void timeout_metrics_reset(void) {
    for (unsigned p = 0; p < 5; p++) for (unsigned r = 0; r < 14; r++) for (unsigned m = 0; m < 2; m++) atomic_store(&counts[p][r][m], 0);
    for (unsigned s = 0; s < 6; s++) {
        atomic_store(&duration_count[s], 0); atomic_store(&duration_sum[s], 0);
        for (unsigned b = 0; b < 8; b++) atomic_store(&duration_hist[s][b], 0);
    }
}

json_token_t* timeout_metrics_json(void) {
    json_token_t* root = json_create_object();
    if (!root) return NULL;
    for (unsigned p = 0; p < 5; p++) {
        json_token_t* events = json_create_object();
        for (unsigned r = 0; r < 14; r++) {
            json_token_t* modes = json_create_object();
            json_object_set(modes, "observe", json_create_number(atomic_load(&counts[p][r][0])));
            json_object_set(modes, "enforce", json_create_number(atomic_load(&counts[p][r][1])));
            json_object_set(events, reasons[r], modes);
        }
        json_object_set(root, protocols[p], events);
    }
    json_token_t* durations = json_create_object();
    json_token_t* bounds = json_create_array();
    for (unsigned b = 0; b < 7; b++) json_array_append(bounds, json_create_number(duration_bounds[b]));
    json_object_set(durations, "bucket_upper_bounds_ms", bounds);
    for (unsigned s = 0; s < 6; s++) {
        json_token_t* item = json_create_object();
        json_token_t* hist = json_create_array();
        for (unsigned b = 0; b < 8; b++) json_array_append(hist, json_create_number(atomic_load(&duration_hist[s][b])));
        json_object_set(item, "samples", json_create_number(atomic_load(&duration_count[s])));
        json_object_set(item, "sum_ms", json_create_number(atomic_load(&duration_sum[s])));
        json_object_set(item, "hist", hist);
        json_object_set(durations, stages[s], item);
    }
    json_object_set(root, "durations_ms", durations);
    return root;
}

typedef struct { const char* name; size_t offset; uint32_t value; } timeout_field_t;
static const timeout_field_t fields[] = {
#define TIMEOUT_ENTRY(name, value) { #name, offsetof(timeout_policy_t, name), value },
    TIMEOUT_FIELDS(TIMEOUT_ENTRY)
#undef TIMEOUT_ENTRY
};

void timeout_policy_defaults(timeout_policy_t* p) {
    memset(p, 0, sizeof(*p));
    p->legacy_h2_timeout_ms = 120000;
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++)
        *(uint32_t*)((char*)p + fields[i].offset) = fields[i].value;
}

int timeout_policy_load(timeout_policy_t* p, const json_token_t* object, const char* path) {
    if (object == NULL) return 1;
    if (!json_is_object(object)) {
        log_error_stderr("%s must be an object\n", path);
        return 0;
    }
    timeout_policy_t candidate = *p;
    for (json_it_t it = json_init_it(object); !json_end_it(&it); json_next_it(&it)) {
        const char* name = json_it_key(&it);
        const json_token_t* token = json_it_value(&it);
        if (strcmp(name, "request_timeout_mode") == 0) {
            const char* mode = json_is_string(token) ? json_string(token) : NULL;
            if (mode == NULL || (strcmp(mode, "observe") && strcmp(mode, "enforce"))) {
                log_error_stderr("%s.%s must be observe or enforce\n", path, name);
                return 0;
            }
            candidate.enforce = strcmp(mode, "enforce") == 0;
            continue;
        }
        size_t i;
        for (i = 0; i < sizeof fields / sizeof fields[0]; i++)
            if (strcmp(name, fields[i].name) == 0) break;
        if (i == sizeof fields / sizeof fields[0]) {
            log_error_stderr("%s.%s is an unknown timeout\n", path, name);
            return 0;
        }
        long double value = json_is_number(token) ? json_ldouble(token) : -1;
        if (!(value >= 0 && value <= 86400000) || value != (uint32_t)value ||
            (value == 0 && (!strcmp(name, "slow_request_threshold_ms") ||
                            !strcmp(name, "ws_close_timeout_ms")))) {
            log_error_stderr("%s.%s must be an integer in 0..86400000 ms (slow threshold and close timeout must be positive)\n", path, name);
            return 0;
        }
        *(uint32_t*)((char*)&candidate + fields[i].offset) = (uint32_t)value;
        candidate.explicit_fields |= UINT64_C(1) << i;
    }
    if (!timeout_policy_validate(&candidate, path)) return 0;
    *p = candidate;
    return 1;
}

int timeout_policy_validate(const timeout_policy_t* p, const char* path) {
    if (p->enforce && (!p->request_header_timeout_ms ||
        !p->request_body_idle_timeout_ms ||
        (p->ws_ping_interval_ms && !p->ws_pong_timeout_ms))) {
        log_error_stderr("%s: enforce requires positive header/body idle and Pong timeout when Ping is enabled\n", path);
        return 0;
    }
    return 1;
}

static uint64_t (*test_clock)(void);
void timeout_set_clock(uint64_t (*clock_ms)(void)) { test_clock = clock_ms; }
uint64_t timeout_now_ms(void) {
    if (test_clock) return test_clock();
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

void timeout_policy_merge(timeout_policy_t* p, const timeout_policy_t* overrides) {
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++)
        if (overrides->explicit_fields & (UINT64_C(1) << i))
            *(uint32_t*)((char*)p + fields[i].offset) = *(const uint32_t*)((const char*)overrides + fields[i].offset);
    p->explicit_fields |= overrides->explicit_fields;
}

int timeout_policy_load_route(timeout_policy_t* p, const json_token_t* object, const char* path, int ws) {
    if (!object) return 1;
    if (!json_is_object(object)) return timeout_policy_load(p, object, path);
    for (json_it_t it = json_init_it(object); !json_end_it(&it); json_next_it(&it)) {
        const char* name = json_it_key(&it);
        int allowed = ws ? (!strncmp(name, "ws_", 3) && strcmp(name, "ws_handshake_timeout_ms")) :
            (!strcmp(name, "request_body_idle_timeout_ms") || !strcmp(name, "request_body_total_timeout_ms") ||
             !strcmp(name, "slow_request_threshold_ms"));
        if (!allowed) {
            log_error_stderr("%s.%s cannot be overridden on this route\n", path, name);
            return 0;
        }
    }
    return timeout_policy_load(p, object, path);
}

int timeout_expired(uint64_t now, uint64_t start, uint32_t budget) {
    return budget != 0 && start != 0 && now >= start && now - start >= budget;
}

const char* timeout_request_reason(uint64_t now, uint64_t headers, uint64_t body,
                                   uint64_t progress, const timeout_policy_t* p) {
    if (!body) return timeout_expired(now, headers, p->request_header_timeout_ms) ? "headers" : NULL;
    if (timeout_expired(now, progress, p->request_body_idle_timeout_ms)) return "body_idle";
    return timeout_expired(now, body, p->request_body_total_timeout_ms) ? "body_total" : NULL;
}
