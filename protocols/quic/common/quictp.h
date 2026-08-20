#ifndef __QUICTP__
#define __QUICTP__

#include <stddef.h>
#include <stdint.h>

#include "quic.h"

/* QUIC transport parameters (RFC 9000 §18).
 *
 * A sequence of {id, length, value} triples carried inside a TLS extension.
 * They are how the two endpoints agree on every limit the connection will run
 * under -- flow control windows, stream counts, idle timeout, the ack delay
 * exponent -- and they are exchanged exactly once, during the handshake.
 *
 * Two things make the validation load-bearing rather than defensive:
 *
 *  - Several parameters are asymmetric. original_destination_connection_id,
 *    preferred_address, retry_source_connection_id and stateless_reset_token
 *    may only come from a server. A client that sends one is either broken or
 *    trying something, and §18.2 requires the connection to fail.
 *  - initial_source_connection_id has to match the Source Connection ID of the
 *    packet that carried the handshake (§7.3). That check is what stops an
 *    attacker from splicing a handshake between two connections, and it is
 *    routinely left out. It belongs to the connection layer, which has the
 *    packet; this module only decodes the value. */

typedef enum {
    QUICTP_ORIGINAL_DCID                 = 0x00,
    QUICTP_MAX_IDLE_TIMEOUT              = 0x01,
    QUICTP_STATELESS_RESET_TOKEN         = 0x02,
    QUICTP_MAX_UDP_PAYLOAD_SIZE          = 0x03,
    QUICTP_INITIAL_MAX_DATA              = 0x04,
    QUICTP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  = 0x05,
    QUICTP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06,
    QUICTP_INITIAL_MAX_STREAM_DATA_UNI   = 0x07,
    QUICTP_INITIAL_MAX_STREAMS_BIDI      = 0x08,
    QUICTP_INITIAL_MAX_STREAMS_UNI       = 0x09,
    QUICTP_ACK_DELAY_EXPONENT            = 0x0a,
    QUICTP_MAX_ACK_DELAY                 = 0x0b,
    QUICTP_DISABLE_ACTIVE_MIGRATION      = 0x0c,
    QUICTP_PREFERRED_ADDRESS             = 0x0d,
    QUICTP_ACTIVE_CONNECTION_ID_LIMIT    = 0x0e,
    QUICTP_INITIAL_SCID                  = 0x0f,
    QUICTP_RETRY_SCID                    = 0x10,
    /* RFC 9368 §3. Not in RFC 9000's table: version negotiation got its own
     * document, and its own parameter. */
    QUICTP_VERSION_INFORMATION           = 0x11
} quictp_id_e;

/* How many versions of a peer's `available_versions` list are kept. The list is
 * whatever the peer chose to advertise and has no bound of its own, so it needs
 * one here; four is more than any deployed stack offers, and a peer with more
 * simply has the tail ignored -- which costs nothing, because a version we
 * cannot find in the prefix is a version we would not have chosen anyway. */
#define QUICTP_MAX_AVAILABLE_VERSIONS 4

typedef struct quictp {
    uint64_t max_idle_timeout;                        /* ms; 0 = no timeout */
    uint64_t max_udp_payload_size;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_streams_bidi;
    uint64_t initial_max_streams_uni;
    uint64_t ack_delay_exponent;
    uint64_t max_ack_delay;                           /* ms */
    uint64_t active_connection_id_limit;
    int      disable_active_migration;

    quiccid_t original_dcid;  int has_original_dcid;
    quiccid_t initial_scid;   int has_initial_scid;
    quiccid_t retry_scid;     int has_retry_scid;

    uint8_t  stateless_reset_token[16];
    int      has_stateless_reset_token;

    /* RFC 9368 §3: the version the peer believes it is using, and the versions
     * it would accept. `has_version_information` is load-bearing rather than
     * informational -- a peer that sends none gets no compatible negotiation,
     * because §2.3 forbids choosing a version it never offered. */
    uint32_t chosen_version;
    uint32_t available_versions[QUICTP_MAX_AVAILABLE_VERSIONS];
    size_t   available_count;
    int      has_version_information;
} quictp_t;

typedef enum {
    QUICTP_OK = 0,
    /* The buffer ends inside a triple, or a length runs past it. */
    QUICTP_ERR_TRUNCATED,
    /* §18.2: a parameter appears twice. */
    QUICTP_ERR_DUPLICATE,
    /* A value outside the range §18.2 permits. */
    QUICTP_ERR_VALUE,
    /* A parameter the sender's role is not allowed to send. */
    QUICTP_ERR_ROLE
} quictp_status_e;

/* Fill in the defaults §18.2 assigns to absent parameters. Not zeroes:
 * ack_delay_exponent defaults to 3 and max_ack_delay to 25 ms, and treating
 * either as zero silently corrupts every RTT sample. */
void quictp_defaults(quictp_t* tp);

/* Decode a parameter block. `from_client` selects which asymmetric parameters
 * are legal; a server decoding its peer passes 1. Absent parameters are left at
 * whatever the struct already holds, so callers start from quictp_defaults. */
quictp_status_e quictp_decode(const uint8_t* buf, size_t len, int from_client,
                              quictp_t* out);

/* Encode our own parameters. Only what differs from the default is written,
 * plus one reserved parameter so peers cannot come to depend on the exact set
 * we send. Returns bytes written, or 0 if `cap` is too small. */
size_t quictp_encode(uint8_t* dst, size_t cap, const quictp_t* tp);

/* Reserved identifiers of the form 31 * N + 27 (§18.1) exist to be ignored.
 * Exposed so the test can assert that we ignore them rather than inferring it. */
int quictp_is_reserved(uint64_t id);

#endif
