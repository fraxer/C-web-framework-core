#ifndef __H3ERROR__
#define __H3ERROR__

#include <stdint.h>

/* HTTP/3 and QPACK error codes (RFC 9114 §8.1, RFC 9204 §6).
 *
 * These are *application* error codes: they travel in a QUIC CONNECTION_CLOSE
 * frame of type 0x1d, or in RESET_STREAM / STOP_SENDING. The transport codes
 * (protocols/quic/common/quicerror.h) travel in type 0x1c. Mixing the two is a
 * protocol violation -- and note that an application code cannot be sent at all
 * before the handshake completes, where QUIC_APPLICATION_ERROR stands in.
 *
 * The stream/connection split matters as much as the value. A malformed
 * message (H3_MESSAGE_ERROR) kills one stream; a malformed frame or a closed
 * critical stream kills the connection. Conflating them is the most common
 * thing h3spec reports (docs/http3/05-http3.md §10). */

#define H3_NO_ERROR                 0x0100
#define H3_GENERAL_PROTOCOL_ERROR   0x0101
#define H3_INTERNAL_ERROR           0x0102
#define H3_STREAM_CREATION_ERROR    0x0103
#define H3_CLOSED_CRITICAL_STREAM   0x0104
#define H3_FRAME_UNEXPECTED         0x0105
#define H3_FRAME_ERROR              0x0106
#define H3_EXCESSIVE_LOAD           0x0107
#define H3_ID_ERROR                 0x0108
#define H3_SETTINGS_ERROR           0x0109
#define H3_MISSING_SETTINGS         0x010a
#define H3_REQUEST_REJECTED         0x010b
#define H3_REQUEST_CANCELLED        0x010c
#define H3_REQUEST_INCOMPLETE       0x010d
#define H3_MESSAGE_ERROR            0x010e
#define H3_CONNECT_ERROR            0x010f
#define H3_VERSION_FALLBACK         0x0110

#define QPACK_DECOMPRESSION_FAILED  0x0200
#define QPACK_ENCODER_STREAM_ERROR  0x0201
#define QPACK_DECODER_STREAM_ERROR  0x0202

/* Human-readable name for logs and qlog. Returns a static string; never NULL
 * (unknown codes report "UNKNOWN"). */
const char* h3_error_name(uint64_t code);

#endif
