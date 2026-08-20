#ifndef __QUIC__
#define __QUIC__

#include <stdint.h>

/* Cross-cutting QUIC v1 definitions (RFC 8999, RFC 9000).
 *
 * Everything here is fixed by the specification or by a design decision that
 * every QUIC module has to agree on. Module-specific declarations live with
 * their module -- this header exists so that the packet codec, the frame codec,
 * the crypto layer, the transport and the UDP endpoint can share types without
 * depending on each other. See docs/http3/02-quic-core.md. */

/* ---- Versions (RFC 9000 §15) ---- */

#define QUIC_VERSION_1              0x00000001u
/* RFC 9369. The same protocol with four constants moved -- see quicversion.h
 * for the whole of the difference, and 09-options.md §3.2 for why a second
 * version exists at all. */
#define QUIC_VERSION_2              0x6b3343cfu
/* A Version Negotiation packet carries version 0 in the header (§17.2.1). */
#define QUIC_VERSION_NEGOTIATION    0x00000000u
/* Versions matching 0x?a?a?a?a are reserved to exercise version negotiation
 * (§15). We advertise one so that a peer cannot hard-code our exact list. */
#define QUIC_VERSION_GREASE         0x1a2a3a4au

/* ---- Connection IDs (§5.1) ---- */

#define QUIC_MAX_CID_LEN            20

/* Length of the connection IDs this server issues. Fixed rather than variable
 * on purpose: a short header does not carry the DCID length, so only the
 * issuer can know it, and the demultiplexer has to read it from every 1-RTT
 * packet before anything else (docs/http3/01-udp-endpoint.md §5.1). Eight bytes
 * = one worker index + seven random, which is enough to keep two connections of
 * the same client unlinkable. */
#define QUIC_LOCAL_CID_LEN          8

typedef struct quiccid {
    uint8_t data[QUIC_MAX_CID_LEN];
    uint8_t len;
} quiccid_t;

/* ---- Datagram sizing (§14) ---- */

/* A client Initial must arrive in a datagram of at least this size, and a
 * server must not send an Initial in a smaller one. Both directions pad. */
#define QUIC_MIN_INITIAL_DATAGRAM   1200

/* Theoretical maxima on a 1500-byte link: 1500 - 20 (IPv4) or 40 (IPv6) - 8 (UDP). */
#define QUIC_MAX_UDP_PAYLOAD_V4     1472
#define QUIC_MAX_UDP_PAYLOAD_V6     1452

/* What we actually send before path MTU discovery exists (phase 9). Chosen to
 * survive PPPoE, IPsec and the common tunnel encapsulations, which is worth
 * more than the ~8 % of payload the theoretical maximum would add: a datagram
 * over the real path MTU is dropped silently, and with DF set there is nothing
 * to notice it by. */
#define QUIC_DEFAULT_UDP_PAYLOAD    1350

/* ---- Packet number spaces / encryption levels (§12.3, RFC 9001 §4) ----
 *
 * Initial, Handshake and Application are the three packet number spaces; 0-RTT
 * shares the Application space for numbering but has its own keys, which is why
 * it is a level here and not a space. Used as an array index throughout. */
typedef enum {
    QUIC_ENC_INITIAL = 0,
    QUIC_ENC_EARLY,
    QUIC_ENC_HANDSHAKE,
    QUIC_ENC_APP,
    QUIC_ENC_COUNT
} quic_enc_level_e;

/* ---- Packet types ----
 *
 * These are *names*, not wire values. They happen to equal the v1 Type bits,
 * which is convenient and nothing more: v2 rotates the same four codes
 * (RFC 9369 §3.2), so anything that reads or writes the two Type bits of a long
 * header goes through quicversion_wire_type / quicversion_type_of_wire and
 * never through the numbers below. SHORT and VERSION_NEGOTIATION have no Type
 * field at all: they are how the parser reports a form that has none. */
typedef enum {
    QUIC_PKT_INITIAL             = 0x00,
    QUIC_PKT_0RTT                = 0x01,
    QUIC_PKT_HANDSHAKE           = 0x02,
    QUIC_PKT_RETRY               = 0x03,
    QUIC_PKT_SHORT               = 0xfe,
    QUIC_PKT_VERSION_NEGOTIATION = 0xff
} quic_pkt_type_e;

/* ---- Varints (§16) ----
 *
 * The 62-bit ceiling is also the ceiling on stream ids, stream offsets and
 * every flow-control limit, so it is a transport-wide constant rather than a
 * detail of the varint codec. */
#define QUIC_VARINT_MAX             0x3FFFFFFFFFFFFFFFULL

#endif
