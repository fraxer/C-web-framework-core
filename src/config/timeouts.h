#ifndef CWFR_TIMEOUTS_H
#define CWFR_TIMEOUTS_H

#include <stdint.h>
#include "json.h"

#define TIMEOUT_FIELDS(X) \
    X(request_header_timeout_ms, 60000) \
    X(request_body_idle_timeout_ms, 60000) \
    X(request_body_total_timeout_ms, 0) \
    X(slow_request_threshold_ms, 1000) \
    X(ws_handshake_timeout_ms, 10000) \
    X(ws_ping_interval_ms, 30000) \
    X(ws_pong_timeout_ms, 10000) \
    X(ws_message_idle_timeout_ms, 60000) \
    X(ws_message_total_timeout_ms, 0) \
    X(ws_send_idle_timeout_ms, 60000) \
    X(ws_close_timeout_ms, 5000) \
    X(ws_application_idle_timeout_ms, 0) \
    X(tls_handshake_timeout_ms, 10000) \
    X(keepalive_timeout_ms, 75000) \
    X(response_send_idle_timeout_ms, 60000)

enum timeout_field_index {
#define TIMEOUT_INDEX(name, value) TIMEOUT_INDEX_##name,
    TIMEOUT_FIELDS(TIMEOUT_INDEX)
#undef TIMEOUT_INDEX
};
#define TIMEOUT_EXPLICIT(name) (UINT64_C(1) << TIMEOUT_INDEX_##name)

typedef struct timeout_policy {
#define TIMEOUT_MEMBER(name, value) uint32_t name;
    TIMEOUT_FIELDS(TIMEOUT_MEMBER)
#undef TIMEOUT_MEMBER
    uint64_t explicit_fields;
    uint32_t legacy_h2_timeout_ms;
    int enforce;
} timeout_policy_t;

void timeout_policy_defaults(timeout_policy_t* policy);
/* Merge a partial object into an inherited policy; errors include JSON path. */
int timeout_policy_load(timeout_policy_t* policy, const json_token_t* object,
                        const char* path);
int timeout_policy_load_route(timeout_policy_t* policy, const json_token_t* object,
                              const char* path, int websocket);
int timeout_policy_validate(const timeout_policy_t* policy, const char* path);
void timeout_policy_merge(timeout_policy_t* policy, const timeout_policy_t* overrides);
uint64_t timeout_now_ms(void);
/* Test clock; install only while no workers are running. NULL restores monotonic time. */
void timeout_set_clock(uint64_t (*clock_ms)(void));
int timeout_expired(uint64_t now, uint64_t start, uint32_t budget);
const char* timeout_request_reason(uint64_t now, uint64_t headers, uint64_t body,
                                   uint64_t progress, const timeout_policy_t* policy);
unsigned timeout_event_bit(const char* reason, int enforce);
void timeout_event_clear(unsigned* reported, const char* reason);
int timeout_report(unsigned* reported, const char* protocol, const char* reason,
                   int enforce, int fd, uint64_t stream_id);
void timeout_record(const char* protocol, const char* reason, int enforce);
void timeout_duration_record(unsigned stage, uint64_t duration_ms);
json_token_t* timeout_metrics_json(void);
void timeout_metrics_reset(void);

#endif
