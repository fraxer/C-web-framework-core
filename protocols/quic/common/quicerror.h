#ifndef __QUICERROR__
#define __QUICERROR__

#include <stdint.h>

/* QUIC transport error codes (RFC 9000 §20.1).
 *
 * Kept apart from the HTTP/3 codes (protocols/http3/frame/h3error.h) because
 * they travel in different places: these go in a CONNECTION_CLOSE frame of type
 * 0x1c, the h3 ones in type 0x1d. Sending an application code as a transport
 * code is a protocol violation, not a cosmetic mistake.
 *
 * The distinctions are worth keeping precise for the same reason they were
 * split in the HTTP/2 frame parser (docs/http2/08, phase C.1): the code is what
 * a peer implementer reads to find their own bug, and a uniform
 * PROTOCOL_VIOLATION tells them nothing. */

#define QUIC_NO_ERROR                   0x00
#define QUIC_INTERNAL_ERROR             0x01
#define QUIC_CONNECTION_REFUSED         0x02
#define QUIC_FLOW_CONTROL_ERROR         0x03
#define QUIC_STREAM_LIMIT_ERROR         0x04
#define QUIC_STREAM_STATE_ERROR         0x05
#define QUIC_FINAL_SIZE_ERROR           0x06
#define QUIC_FRAME_ENCODING_ERROR       0x07
#define QUIC_TRANSPORT_PARAMETER_ERROR  0x08
#define QUIC_CONNECTION_ID_LIMIT_ERROR  0x09
#define QUIC_PROTOCOL_VIOLATION         0x0a
#define QUIC_INVALID_TOKEN              0x0b
/* The application layer failed but the frame carrying the reason is one the
 * transport had to send itself -- e.g. a failure during the handshake, where
 * CONNECTION_CLOSE of type 0x1d is not yet allowed (§10.2.3). */
#define QUIC_APPLICATION_ERROR          0x0c
#define QUIC_CRYPTO_BUFFER_EXCEEDED     0x0d
#define QUIC_KEY_UPDATE_ERROR           0x0e
#define QUIC_AEAD_LIMIT_REACHED         0x0f
#define QUIC_NO_VIABLE_PATH             0x10

/* A TLS alert becomes a transport error in the range 0x0100-0x01ff (§20.1):
 * the low byte is the alert description from RFC 8446. */
#define QUIC_CRYPTO_ERROR(alert)        (0x0100u | ((alert) & 0xffu))
#define QUIC_IS_CRYPTO_ERROR(code)      (((code) & ~0xffu) == 0x0100u)

/* Human-readable name for logs and qlog. Returns a static string; never NULL
 * (unknown codes report "UNKNOWN"). */
const char* quic_error_name(uint64_t code);

#endif
