#include <string.h>

#include "quictp.h"
#include "varint.h"

/* §18.2 defaults for parameters that are simply absent. */
#define QUICTP_DEFAULT_MAX_UDP_PAYLOAD   65527
#define QUICTP_DEFAULT_ACK_DELAY_EXP     3
#define QUICTP_DEFAULT_MAX_ACK_DELAY     25
#define QUICTP_DEFAULT_ACTIVE_CID_LIMIT  2

/* One reserved parameter of our own, so that a peer cannot start depending on
 * the exact set we send (§18.1). 31 * 1000 + 27. */
#define QUICTP_GREASE_ID                 31027

void quictp_defaults(quictp_t* tp) {
    if (tp == NULL) return;

    memset(tp, 0, sizeof * tp);

    tp->max_udp_payload_size = QUICTP_DEFAULT_MAX_UDP_PAYLOAD;
    tp->ack_delay_exponent = QUICTP_DEFAULT_ACK_DELAY_EXP;
    tp->max_ack_delay = QUICTP_DEFAULT_MAX_ACK_DELAY;
    tp->active_connection_id_limit = QUICTP_DEFAULT_ACTIVE_CID_LIMIT;
}

int quictp_is_reserved(uint64_t id) {
    return id >= 27 && (id - 27) % 31 == 0;
}

/* Read a parameter whose value is itself a varint. */
static quictp_status_e __value_varint(const uint8_t* p, size_t len, uint64_t* out) {
    uint64_t value = 0;
    const size_t n = varint_read(p, len, &value);

    /* The value must fill the declared length exactly: trailing bytes would
     * mean the sender and we disagree about where the parameter ends. */
    if (n == 0 || n != len) return QUICTP_ERR_TRUNCATED;

    *out = value;

    return QUICTP_OK;
}

static quictp_status_e __value_cid(const uint8_t* p, size_t len, quiccid_t* out) {
    if (len > QUIC_MAX_CID_LEN) return QUICTP_ERR_VALUE;

    out->len = (uint8_t)len;
    if (len > 0) memcpy(out->data, p, len);

    return QUICTP_OK;
}

quictp_status_e quictp_decode(const uint8_t* buf, size_t len, int from_client,
                              quictp_t* out) {
    if (buf == NULL || out == NULL) return QUICTP_ERR_TRUNCATED;

    /* Duplicate detection covers the identifiers we understand; a repeated
     * reserved parameter is meaningless and harmless. */
    uint32_t seen = 0;

    size_t p = 0;
    while (p < len) {
        uint64_t id = 0;
        size_t n = varint_read(buf + p, len - p, &id);
        if (n == 0) return QUICTP_ERR_TRUNCATED;
        p += n;

        uint64_t value_len = 0;
        n = varint_read(buf + p, len - p, &value_len);
        if (n == 0) return QUICTP_ERR_TRUNCATED;
        p += n;

        if (value_len > len - p) return QUICTP_ERR_TRUNCATED;

        const uint8_t* value = buf + p;
        const size_t vlen = (size_t)value_len;
        p += vlen;

        if (quictp_is_reserved(id)) continue;

        /* Unknown but not reserved: §18.1 says ignore it too. Only the
         * identifiers below carry meaning. */
        if (id > QUICTP_RETRY_SCID) continue;

        const uint32_t bit = 1u << id;
        if (seen & bit) return QUICTP_ERR_DUPLICATE;
        seen |= bit;

        quictp_status_e st = QUICTP_OK;

        switch ((quictp_id_e)id) {
        /* Server-only parameters. A client sending one fails the connection
         * (§18.2) -- it is either broken or trying to confuse the roles. */
        case QUICTP_ORIGINAL_DCID:
            if (from_client) return QUICTP_ERR_ROLE;
            st = __value_cid(value, vlen, &out->original_dcid);
            out->has_original_dcid = 1;
            break;

        case QUICTP_RETRY_SCID:
            if (from_client) return QUICTP_ERR_ROLE;
            st = __value_cid(value, vlen, &out->retry_scid);
            out->has_retry_scid = 1;
            break;

        case QUICTP_PREFERRED_ADDRESS:
            if (from_client) return QUICTP_ERR_ROLE;
            /* Parsed no further: this server never offers one, and as a server
             * it will never receive one. */
            break;

        case QUICTP_STATELESS_RESET_TOKEN:
            if (from_client) return QUICTP_ERR_ROLE;
            if (vlen != 16) return QUICTP_ERR_VALUE;
            memcpy(out->stateless_reset_token, value, 16);
            out->has_stateless_reset_token = 1;
            break;

        case QUICTP_INITIAL_SCID:
            st = __value_cid(value, vlen, &out->initial_scid);
            out->has_initial_scid = 1;
            break;

        case QUICTP_MAX_IDLE_TIMEOUT:
            st = __value_varint(value, vlen, &out->max_idle_timeout);
            break;

        case QUICTP_MAX_UDP_PAYLOAD_SIZE:
            st = __value_varint(value, vlen, &out->max_udp_payload_size);
            /* §18.2: below 1200 the peer could not receive an Initial. */
            if (st == QUICTP_OK && out->max_udp_payload_size < QUIC_MIN_INITIAL_DATAGRAM)
                return QUICTP_ERR_VALUE;
            break;

        case QUICTP_INITIAL_MAX_DATA:
            st = __value_varint(value, vlen, &out->initial_max_data);
            break;

        case QUICTP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            st = __value_varint(value, vlen, &out->initial_max_stream_data_bidi_local);
            break;

        case QUICTP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            st = __value_varint(value, vlen, &out->initial_max_stream_data_bidi_remote);
            break;

        case QUICTP_INITIAL_MAX_STREAM_DATA_UNI:
            st = __value_varint(value, vlen, &out->initial_max_stream_data_uni);
            break;

        case QUICTP_INITIAL_MAX_STREAMS_BIDI:
            st = __value_varint(value, vlen, &out->initial_max_streams_bidi);
            /* §18.2: above 2^60 the derived stream ids leave the varint range. */
            if (st == QUICTP_OK && out->initial_max_streams_bidi > (1ULL << 60))
                return QUICTP_ERR_VALUE;
            break;

        case QUICTP_INITIAL_MAX_STREAMS_UNI:
            st = __value_varint(value, vlen, &out->initial_max_streams_uni);
            if (st == QUICTP_OK && out->initial_max_streams_uni > (1ULL << 60))
                return QUICTP_ERR_VALUE;
            break;

        case QUICTP_ACK_DELAY_EXPONENT:
            st = __value_varint(value, vlen, &out->ack_delay_exponent);
            /* §18.2: above 20 the shift would overflow the delay it scales. */
            if (st == QUICTP_OK && out->ack_delay_exponent > 20)
                return QUICTP_ERR_VALUE;
            break;

        case QUICTP_MAX_ACK_DELAY:
            st = __value_varint(value, vlen, &out->max_ack_delay);
            if (st == QUICTP_OK && out->max_ack_delay >= (1ULL << 14))
                return QUICTP_ERR_VALUE;
            break;

        case QUICTP_DISABLE_ACTIVE_MIGRATION:
            /* A flag: presence is the value, so it must carry none. */
            if (vlen != 0) return QUICTP_ERR_VALUE;
            out->disable_active_migration = 1;
            break;

        case QUICTP_ACTIVE_CONNECTION_ID_LIMIT:
            st = __value_varint(value, vlen, &out->active_connection_id_limit);
            /* §18.2: below 2 the peer could not rotate connection ids at all. */
            if (st == QUICTP_OK && out->active_connection_id_limit < 2)
                return QUICTP_ERR_VALUE;
            break;
        }

        if (st != QUICTP_OK) return st;
    }

    return QUICTP_OK;
}

/* Write one {id, length, value} triple whose value is a varint. */
static size_t __put_varint(uint8_t* dst, size_t cap, size_t p, uint64_t id, uint64_t value) {
    const size_t value_size = varint_size(value);
    if (value_size == 0) return 0;

    size_t n = varint_write(dst + p, cap - p, id);
    if (n == 0) return 0;
    p += n;

    n = varint_write(dst + p, cap - p, value_size);
    if (n == 0) return 0;
    p += n;

    n = varint_write(dst + p, cap - p, value);
    if (n == 0) return 0;
    p += n;

    return p;
}

static size_t __put_bytes(uint8_t* dst, size_t cap, size_t p, uint64_t id,
                          const uint8_t* value, size_t len) {
    size_t n = varint_write(dst + p, cap - p, id);
    if (n == 0) return 0;
    p += n;

    n = varint_write(dst + p, cap - p, len);
    if (n == 0) return 0;
    p += n;

    if (len > 0) {
        if (len > cap - p) return 0;
        memcpy(dst + p, value, len);
        p += len;
    }

    return p;
}

size_t quictp_encode(uint8_t* dst, size_t cap, const quictp_t* tp) {
    if (dst == NULL || tp == NULL) return 0;

    size_t p = 0;

#define PUT_VARINT(id, value)                       \
    do {                                            \
        p = __put_varint(dst, cap, p, (id), (value)); \
        if (p == 0) return 0;                       \
    } while (0)

#define PUT_BYTES(id, value, len)                        \
    do {                                                 \
        p = __put_bytes(dst, cap, p, (id), (value), (len)); \
        if (p == 0) return 0;                            \
    } while (0)

    PUT_VARINT(QUICTP_MAX_IDLE_TIMEOUT, tp->max_idle_timeout);
    PUT_VARINT(QUICTP_MAX_UDP_PAYLOAD_SIZE, tp->max_udp_payload_size);
    PUT_VARINT(QUICTP_INITIAL_MAX_DATA, tp->initial_max_data);
    PUT_VARINT(QUICTP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
               tp->initial_max_stream_data_bidi_local);
    PUT_VARINT(QUICTP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
               tp->initial_max_stream_data_bidi_remote);
    PUT_VARINT(QUICTP_INITIAL_MAX_STREAM_DATA_UNI, tp->initial_max_stream_data_uni);
    PUT_VARINT(QUICTP_INITIAL_MAX_STREAMS_BIDI, tp->initial_max_streams_bidi);
    PUT_VARINT(QUICTP_INITIAL_MAX_STREAMS_UNI, tp->initial_max_streams_uni);
    PUT_VARINT(QUICTP_ACK_DELAY_EXPONENT, tp->ack_delay_exponent);
    PUT_VARINT(QUICTP_MAX_ACK_DELAY, tp->max_ack_delay);
    PUT_VARINT(QUICTP_ACTIVE_CONNECTION_ID_LIMIT, tp->active_connection_id_limit);

    if (tp->disable_active_migration)
        PUT_BYTES(QUICTP_DISABLE_ACTIVE_MIGRATION, NULL, 0);

    /* Mandatory for a server (§7.3): the client checks them against the
     * connection ids it actually saw, which is what binds the handshake to
     * this connection. */
    if (tp->has_original_dcid)
        PUT_BYTES(QUICTP_ORIGINAL_DCID, tp->original_dcid.data, tp->original_dcid.len);

    if (tp->has_initial_scid)
        PUT_BYTES(QUICTP_INITIAL_SCID, tp->initial_scid.data, tp->initial_scid.len);

    if (tp->has_retry_scid)
        PUT_BYTES(QUICTP_RETRY_SCID, tp->retry_scid.data, tp->retry_scid.len);

    if (tp->has_stateless_reset_token)
        PUT_BYTES(QUICTP_STATELESS_RESET_TOKEN, tp->stateless_reset_token, 16);

    /* One reserved parameter, to keep peers honest about ignoring them. */
    PUT_BYTES(QUICTP_GREASE_ID, (const uint8_t*)"\x00", 1);

#undef PUT_VARINT
#undef PUT_BYTES

    return p;
}
