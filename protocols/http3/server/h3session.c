#include "h3session.h"

#include <stdlib.h>
#include <string.h>

#include "appconfig.h"
#include "log.h"
#include "metrics.h"
#include "qpack.h"
#include "quictime.h"
#include "varint.h"

/* ---- Policy ---- */

#define H3_DEFAULT_MAX_FIELD_SECTION_SIZE (1024 * 1024)
#define H3_DEFAULT_ABORT_RATE  100   /* tokens/s */
#define H3_DEFAULT_ABORT_BURST 200   /* tokens */
#define H3_DEFAULT_CTRL_RATE   100
#define H3_DEFAULT_CTRL_BURST  200

/* Set once by h3_policy_init(), read by every worker afterwards. The values
 * below are what applies when it has not run at all -- a unit test, say. */
static uint64_t h3_max_field_section_size = H3_DEFAULT_MAX_FIELD_SECTION_SIZE;
static int64_t  h3_abort_rate  = H3_DEFAULT_ABORT_RATE;
static int64_t  h3_abort_burst = H3_DEFAULT_ABORT_BURST;
static int64_t  h3_ctrl_rate   = H3_DEFAULT_CTRL_RATE;
static int64_t  h3_ctrl_burst  = H3_DEFAULT_CTRL_BURST;

static int64_t __policy_int(const char* key, int64_t fallback, int64_t min) {
    int64_t v = env_get_int(key, (int)fallback);
    if (v < min) v = min;

    return v;
}

void h3_policy_init(void) {
    h3_max_field_section_size =
        (uint64_t)__policy_int("http3_max_field_section_size",
                               H3_DEFAULT_MAX_FIELD_SECTION_SIZE, 0);

    /* 0 disables a bucket, which is why the floor is 0 and not 1. */
    h3_abort_rate  = __policy_int("http3_abort_rate",  H3_DEFAULT_ABORT_RATE, 0);
    h3_abort_burst = __policy_int("http3_abort_burst", H3_DEFAULT_ABORT_BURST, 1);
    h3_ctrl_rate   = __policy_int("http3_ctrl_rate",   H3_DEFAULT_CTRL_RATE, 0);
    h3_ctrl_burst  = __policy_int("http3_ctrl_burst",  H3_DEFAULT_CTRL_BURST, 1);
}

uint64_t h3_policy_max_field_section_size(void) {
    return h3_max_field_section_size;
}

/* ---- Budgets ---- */

static uint64_t __now_ms(void) {
    return quic_now_us() / 1000;
}

/* Spend one token of a leaky bucket. Kept in milli-tokens so the refill is
 * exact integer arithmetic: a rate of R tokens per second is R milli-tokens per
 * elapsed millisecond, with no remainder dropped however often this is called.
 * A rate of 0 disables the limit. */
static int __budget_spend(int64_t* tokens, uint64_t* epoch_ms,
                          int64_t rate, int64_t burst) {
    if (rate == 0) return 1;

    const uint64_t now = __now_ms();
    const uint64_t elapsed = now > *epoch_ms ? now - *epoch_ms : 0;
    const int64_t cap = burst * 1000;

    *epoch_ms = now;
    *tokens += (int64_t)elapsed * rate;
    if (*tokens > cap) *tokens = cap;

    if (*tokens < 1000) return 0;

    *tokens -= 1000;

    return 1;
}

/* Both budgets are counted here rather than at the call sites: exhaustion is
 * one event with four ways to reach it, and a counter per call site would only
 * split the number an operator has to add back up. */
int h3session_abort_spend(h3session_t* s) {
    if (s == NULL) return 1;

    if (__budget_spend(&s->abort_tokens, &s->abort_epoch_ms,
                       h3_abort_rate, h3_abort_burst))
        return 1;

    metrics_h3(METRICS_H3_ABUSE_ABORT_BUDGET);

    return 0;
}

int h3session_ctrl_spend(h3session_t* s) {
    if (s == NULL) return 1;

    if (__budget_spend(&s->ctrl_tokens, &s->ctrl_epoch_ms,
                       h3_ctrl_rate, h3_ctrl_burst))
        return 1;

    metrics_h3(METRICS_H3_ABUSE_CTRL_BUDGET);

    return 0;
}

/* ---- Verdict helpers ---- */

static h3session_verdict_t __ok(void) {
    h3session_verdict_t v = { H3SESSION_OK, 0 };
    return v;
}

static h3session_verdict_t __conn(uint64_t error) {
    h3session_verdict_t v = { H3SESSION_CONN_ERROR, error };
    return v;
}

static h3session_verdict_t __stop(uint64_t error) {
    h3session_verdict_t v = { H3SESSION_STOP_SENDING, error };
    return v;
}

/* ---- Lifecycle ---- */

h3uni_recv_t* h3uni_recv_create(uint64_t id) {
    h3uni_recv_t* uni = malloc(sizeof * uni);
    if (uni == NULL) return NULL;

    uni->id = id;
    h3uni_parser_init(&uni->prefix);
    h3frame_parser_init(&uni->frames);
    uni->typed = 0;
    uni->type = 0;
    uni->action = H3UNI_ROUTE;
    uni->settings_seen = 0;
    uni->closed = 0;

    return uni;
}

void h3uni_recv_free(h3uni_recv_t* uni) {
    if (uni == NULL) return;

    h3frame_parser_free(&uni->frames);
    free(uni);
}

h3session_t* h3session_create(uint64_t max_field_section_size, int enable_connect_protocol) {
    h3session_t* s = calloc(1, sizeof * s);
    if (s == NULL) return NULL;

    /* Lite QPACK: no dynamic table, so no stream can ever block on one
     * (docs/http3/06-qpack.md §6, step 6.1). Both zeros are advertised
     * explicitly rather than left to default, because a peer reading them is
     * how it learns not to try. */
    s->qdec = qpack_decoder_create(0, 0);
    s->qenc = qpack_encoder_create(0, 0);
    if (s->qdec == NULL || s->qenc == NULL) {
        h3session_free(s);
        return NULL;
    }

    h3settings_defaults(&s->local_settings);
    s->local_settings.qpack_max_table_capacity = 0;
    s->local_settings.qpack_blocked_streams = 0;
    s->local_settings.max_field_section_size = max_field_section_size;
    s->local_settings.enable_connect_protocol = enable_connect_protocol ? 1 : 0;

    h3settings_defaults(&s->peer_settings);

    h3uni_seen_init(&s->peer_uni);

    /* Full buckets at the start: a burst is what a legitimate client does on a
     * fresh connection, and starting empty would punish exactly that. */
    s->abort_epoch_ms = __now_ms();
    s->ctrl_epoch_ms = s->abort_epoch_ms;
    s->abort_tokens = h3_abort_burst * 1000;
    s->ctrl_tokens = h3_ctrl_burst * 1000;

    return s;
}

void h3session_free(h3session_t* s) {
    if (s == NULL) return;

    qpack_decoder_free(s->qdec);
    qpack_encoder_free(s->qenc);
    free(s);
}

/* ---- Our own service streams ---- */

size_t h3session_control_preamble(const h3session_t* s, uint8_t* dst, size_t cap) {
    if (s == NULL || dst == NULL) return 0;

    const size_t type = h3uni_write_type(dst, cap, H3_UNI_STREAM_CONTROL);
    if (type == 0) return 0;

    /* The SETTINGS payload is encoded first because the frame header carries
     * its length, and that length is a varint whose own width depends on it. */
    uint8_t payload[64];
    const size_t plen = h3settings_encode(payload, sizeof payload, &s->local_settings);
    if (plen == 0) return 0;

    const size_t frame = h3frame_write(dst + type, cap - type, H3_FRAME_SETTINGS, payload, plen);
    if (frame == 0) return 0;

    return type + frame;
}

size_t h3session_uni_preamble(uint8_t* dst, size_t cap, uint64_t type) {
    return h3uni_write_type(dst, cap, type);
}

size_t h3session_goaway_encode(h3session_t* s, uint8_t* dst, size_t cap, uint64_t stream_id) {
    if (s == NULL || dst == NULL) return 0;

    /* §5.2: successive GOAWAYs may only ever name a lower id. Raising it would
     * un-reject a request the client has already been told to retry, so this is
     * refused here rather than left for the peer to catch. */
    if (s->goaway_sent && stream_id > s->goaway_id) return 0;

    uint8_t payload[8];
    const size_t plen = varint_write(payload, sizeof payload, stream_id);
    if (plen == 0) return 0;

    const size_t n = h3frame_write(dst, cap, H3_FRAME_GOAWAY, payload, plen);
    if (n == 0) return 0;

    s->goaway_sent = 1;
    s->goaway_id = stream_id;

    metrics_h3(METRICS_H3_GOAWAY_SENT);

    return n;
}

int h3session_accepts_request(const h3session_t* s, uint64_t stream_id) {
    if (s == NULL) return 0;
    if (!s->goaway_sent) return 1;

    return stream_id < s->goaway_id;
}

/* ---- The control stream ---- */

static int __priority_key_char(uint8_t c, int first) {
    if (c >= 'a' && c <= 'z') return 1;
    if (!first && c >= '0' && c <= '9') return 1;
    return !first && (c == '_' || c == '-' || c == '.' || c == '*');
}

/* RFC 9218 carries an RFC 8941 Dictionary. We consume the two defined keys and
 * validate unknown members conservatively so a syntactically broken value is
 * never mistaken for an extension we can ignore. */
static int __priority_value_valid(const uint8_t* p, size_t len) {
    size_t i = 0;
    while (i < len) {
        while (i < len && p[i] == ' ') i++;
        if (i == len) return 1; /* empty dictionary means defaults */

        const size_t key_start = i;
        if (!__priority_key_char(p[i], 1)) return 0;
        while (++i < len && __priority_key_char(p[i], 0)) {}
        const size_t key_len = i - key_start;

        while (i < len && p[i] == ' ') i++;
        const size_t value_start = i;
        if (i < len && p[i] == '=') {
            i++;
            if (i == len) return 0;
            if (p[i] == '?') {
                i++;
                if (i == len || (p[i] != '0' && p[i] != '1')) return 0;
                i++;
            } else {
                if (p[i] == '-') i++;
                const size_t digits = i;
                while (i < len && p[i] >= '0' && p[i] <= '9') i++;
                if (i == digits) return 0;
            }
        }

        /* Parameters and extension members use visible ASCII up to the next
         * comma. This accepts extensions while excluding control characters,
         * non-ASCII and malformed empty list members. */
        while (i < len && p[i] != ',') {
            if (p[i] < 0x20 || p[i] > 0x7e) return 0;
            i++;
        }

        if (key_len == 1 && p[key_start] == 'u') {
            if (value_start >= len || p[value_start] != '=' ||
                value_start + 1 >= len || p[value_start + 1] < '0' ||
                p[value_start + 1] > '7') return 0;
            if (value_start + 2 < i && p[value_start + 2] != ';' &&
                p[value_start + 2] != ' ') return 0;
        } else if (key_len == 1 && p[key_start] == 'i' && value_start < len &&
                   p[value_start] == '=') {
            if (value_start + 2 >= len || p[value_start + 1] != '?' ||
                (p[value_start + 2] != '0' && p[value_start + 2] != '1')) return 0;
        }

        if (i == len) return 1;
        i++; /* comma */
        if (i == len) return 0;
    }
    return 1;
}

static h3session_verdict_t __priority_update(h3session_t* s, h3uni_recv_t* uni,
                                             int push) {
    if (!h3session_ctrl_spend(s)) return __conn(H3_EXCESSIVE_LOAD);

    uint64_t element = 0;
    const size_t n = varint_read(uni->frames.payload, uni->frames.payload_len, &element);
    if (n == 0) return __conn(H3_FRAME_ERROR);

    if ((!push && (element & 0x03) != 0) || push)
        return __conn(H3_ID_ERROR);

    if (!__priority_value_valid(uni->frames.payload + n, uni->frames.payload_len - n))
        return __conn(H3_FRAME_ERROR);

    return __ok(); /* scheduling intentionally unchanged */
}

/* One frame off the peer's control stream. `uni->frames.payload` holds it. */
static h3session_verdict_t __control_frame(h3session_t* s, h3uni_recv_t* uni) {
    const uint64_t type = uni->frames.type;

    /* §6.2.1: SETTINGS must be the first frame, and there must be exactly one.
     * The check comes before the per-type handling so that a GOAWAY sent ahead
     * of SETTINGS is reported as the missing SETTINGS it is, not as a GOAWAY
     * with a defensible id. */
    if (!uni->settings_seen && type != H3_FRAME_SETTINGS)
        return __conn(H3_MISSING_SETTINGS);

    switch (type) {
    case H3_FRAME_SETTINGS: {
        if (uni->settings_seen) return __conn(H3_FRAME_UNEXPECTED);

        h3settings_t peer;
        h3settings_defaults(&peer);

        switch (h3settings_decode(uni->frames.payload, uni->frames.payload_len, &peer)) {
        case H3SETTINGS_OK:           break;
        case H3SETTINGS_ERR_SETTINGS: return __conn(H3_SETTINGS_ERROR);
        default:                      return __conn(H3_FRAME_ERROR);
        }

        s->peer_settings = peer;
        s->peer_settings_seen = 1;
        uni->settings_seen = 1;
        return __ok();
    }

    case H3_FRAME_GOAWAY: {
        /* Charged whatever it says: a client can repeat a GOAWAY with the same
         * push id forever, and each one is a frame we parse for nothing. */
        if (!h3session_ctrl_spend(s)) return __conn(H3_EXCESSIVE_LOAD);

        uint64_t id = 0;
        const size_t n = varint_read(uni->frames.payload, uni->frames.payload_len, &id);
        if (n == 0 || n != uni->frames.payload_len) return __conn(H3_FRAME_ERROR);

        /* From a client GOAWAY carries a push id, and it says the client will
         * accept no push above it. We never push, so recording it is the whole
         * of the handling -- except for §5.2's monotonicity, which is a
         * connection error and must be enforced whether the value matters to us
         * or not. */
        if (s->peer_goaway_seen && id > s->peer_goaway_id) return __conn(H3_ID_ERROR);

        s->peer_goaway_seen = 1;
        s->peer_goaway_id = id;
        return __ok();
    }

    case H3_FRAME_MAX_PUSH_ID: {
        /* Same shape: repeating the current limit is legal and free to send. */
        if (!h3session_ctrl_spend(s)) return __conn(H3_EXCESSIVE_LOAD);

        uint64_t id = 0;
        const size_t n = varint_read(uni->frames.payload, uni->frames.payload_len, &id);
        if (n == 0 || n != uni->frames.payload_len) return __conn(H3_FRAME_ERROR);

        /* §7.2.7: the value may only grow. We never push, so a raised limit
         * changes nothing here, but a lowered one is an H3_ID_ERROR. */
        if (s->max_push_id_seen && id < s->max_push_id) return __conn(H3_ID_ERROR);

        s->max_push_id_seen = 1;
        s->max_push_id = id;
        return __ok();
    }

    case H3_FRAME_CANCEL_PUSH: {
        uint64_t id = 0;
        const size_t n = varint_read(uni->frames.payload, uni->frames.payload_len, &id);
        if (n == 0 || n != uni->frames.payload_len) return __conn(H3_FRAME_ERROR);

        /* §7.2.3: a push id above what the connection currently allows is an
         * H3_ID_ERROR. This server never promises a push, so every id is above
         * it and every CANCEL_PUSH is that error. Answering "we sent no such
         * push" any more politely would require inventing state for a feature
         * that does not exist. */
        return __conn(H3_ID_ERROR);
    }

    case H3_FRAME_PRIORITY_UPDATE_REQUEST:
        return __priority_update(s, uni, 0);

    case H3_FRAME_PRIORITY_UPDATE_PUSH:
        return __priority_update(s, uni, 1);

    case H3_FRAME_DATA:
    case H3_FRAME_HEADERS:
    case H3_FRAME_PUSH_PROMISE:
        /* §7.2.1/§7.2.2/§7.2.5: request-stream frames on the control stream. */
        return __conn(H3_FRAME_UNEXPECTED);

    default:
        /* Unknown types never reach here -- the parser reports them as SKIPPED
         * and steps over them, which is §9's whole point. */
        return __conn(H3_FRAME_UNEXPECTED);
    }
}

static h3session_verdict_t __control_feed(h3session_t* s, h3uni_recv_t* uni,
                                          const uint8_t** pp, const uint8_t* end) {
    for (;;) {
        const h3frame_status_e fst = h3frame_parser_feed(&uni->frames, pp, end);

        switch (fst) {
        case H3FRAME_CONTINUE:
            return __ok();

        case H3FRAME_READY: {
            const h3session_verdict_t v = __control_frame(s, uni);
            if (v.action != H3SESSION_OK) return v;
            continue;
        }

        case H3FRAME_SKIPPED:
            /* An unknown or grease frame type, already stepped over. But §6.2.1
             * still wants SETTINGS first, and "first" means first frame of any
             * kind -- a grease frame ahead of SETTINGS is legal, so this is
             * deliberately not a violation.
             *
             * Charged, though: §9 says to ignore the *type*, not to accept an
             * unbounded stream of them. Skipping is cheap but not free, and a
             * peer can generate them faster than we can read them. */
            if (!h3session_ctrl_spend(s)) return __conn(H3_EXCESSIVE_LOAD);
            continue;

        case H3FRAME_DATA_CHUNK:
            /* DATA is not accumulated, so it arrives as chunks rather than as
             * READY; on the control stream it is illegal either way. */
            return __conn(H3_FRAME_UNEXPECTED);

        case H3FRAME_HEAD:
            continue;

        case H3FRAME_ERR_RESERVED:
            return __conn(H3_FRAME_UNEXPECTED);
        case H3FRAME_ERR_ENCODING:
            return __conn(H3_FRAME_ERROR);
        case H3FRAME_ERR_TOO_LARGE:
            return __conn(H3_EXCESSIVE_LOAD);
        case H3FRAME_ERR_OOM:
            return __conn(H3_INTERNAL_ERROR);
        }
    }
}

/* ---- The QPACK streams ---- */

static h3session_verdict_t __qpack_encoder_feed(h3session_t* s,
                                                const uint8_t* data, size_t len) {
    /* In lite the only legal instruction is `Set Dynamic Table Capacity 0`;
     * qpack_decoder_read_encoder knows the rule and the opcodes. A partial
     * instruction is not an error -- but it also cannot be carried over,
     * because a 5-bit-prefix integer of capacity 0 is a single octet and the
     * only multi-octet form legal here would already be over capacity. */
    size_t consumed = 0;
    if (qpack_decoder_read_encoder(s->qdec, data, len, &consumed) != QPACK_OK)
        return __conn(QPACK_ENCODER_STREAM_ERROR);

    return __ok();
}

static h3session_verdict_t __qpack_decoder_feed(h3session_t* s,
                                                const uint8_t* data, size_t len) {
    (void)s;

    size_t consumed = 0;
    if (qpack_encoder_read_decoder(data, len, &consumed) != QPACK_OK)
        return __conn(QPACK_DECODER_STREAM_ERROR);

    return __ok();
}

/* ---- Feeding ---- */

h3session_verdict_t h3session_uni_closed(h3session_t* s, h3uni_recv_t* uni) {
    if (s == NULL || uni == NULL) return __conn(H3_INTERNAL_ERROR);

    uni->closed = 1;

    /* §6.2.6: the control stream and both QPACK streams must live as long as
     * the connection. A stream whose type we never learned cannot be critical,
     * so an aborted prefix is harmless. */
    if (uni->typed && h3uni_type_is_critical(uni->type))
        return __conn(H3_CLOSED_CRITICAL_STREAM);

    return __ok();
}

h3session_verdict_t h3session_uni_feed(h3session_t* s, h3uni_recv_t* uni,
                                       const uint8_t* data, size_t len, int fin) {
    if (s == NULL || uni == NULL || (data == NULL && len != 0)) return __conn(H3_INTERNAL_ERROR);

    const uint8_t* p = data;
    const uint8_t* end = data + len;

    if (!uni->typed) {
        const h3uni_status_e ust = h3uni_parser_feed(&uni->prefix, &p, end);
        if (ust == H3UNI_ERR_ENCODING) return __conn(H3_GENERAL_PROTOCOL_ERROR);

        if (ust != H3UNI_READY) {
            /* Not even the type has arrived. A FIN here ends a stream we never
             * identified: it cannot have been critical, so it is not fatal. */
            return fin ? h3session_uni_closed(s, uni) : __ok();
        }

        uni->typed = 1;
        uni->type = uni->prefix.type;

        const h3uni_verdict_t verdict = h3uni_server_classify(&s->peer_uni, uni->type);
        uni->action = verdict.action;

        switch (verdict.action) {
        case H3UNI_CONN_ERROR:
            return __conn(verdict.error);
        case H3UNI_STOP_DROP:
            /* Each one costs us a STOP_SENDING frame and a stream slot, and a
             * peer may open them as fast as its stream limit allows. */
            if (!h3session_ctrl_spend(s)) return __conn(H3_EXCESSIVE_LOAD);

            log_info("h3: unknown unidirectional stream type 0x%llx, discarded\n",
                     (unsigned long long)uni->type);
            return __stop(verdict.error);
        case H3UNI_IGNORE:
            break;
        case H3UNI_ROUTE:
            switch (uni->type) {
            case H3_UNI_STREAM_CONTROL:       s->ctrl_recv_id = uni->id;      break;
            case H3_UNI_STREAM_QPACK_ENCODER: s->qpack_enc_recv_id = uni->id; break;
            case H3_UNI_STREAM_QPACK_DECODER: s->qpack_dec_recv_id = uni->id; break;
            default: break;
            }
            break;
        }
    }

    /* A stream already judged not worth reading: swallow the rest. Its bytes
     * still have to be consumed so flow control keeps moving. */
    if (uni->action != H3UNI_ROUTE)
        return fin ? h3session_uni_closed(s, uni) : __ok();

    h3session_verdict_t v = __ok();

    switch (uni->type) {
    case H3_UNI_STREAM_CONTROL:
        v = __control_feed(s, uni, &p, end);
        break;

    case H3_UNI_STREAM_QPACK_ENCODER:
        v = __qpack_encoder_feed(s, p, (size_t)(end - p));
        break;

    case H3_UNI_STREAM_QPACK_DECODER:
        /* Acknowledgements for an encoder that never inserts anything. With a
         * Required Insert Count of 0 on every section we emit, RFC 9204 §2.2.2
         * leaves the peer nothing it must say and almost nothing it may -- but
         * "almost" is the point: an Insert Count Increment is a connection
         * error whatever its value (§4.4.3), so the stream is parsed to that
         * depth rather than drained. Full QPACK (6.2) is where the rest of
         * these instructions start to matter. */
        v = __qpack_decoder_feed(s, p, (size_t)(end - p));
        break;

    default:
        break;
    }

    if (v.action != H3SESSION_OK) return v;

    return fin ? h3session_uni_closed(s, uni) : __ok();
}
