#ifndef __QUICRETRY__
#define __QUICRETRY__

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "quic.h"

/* Retry packets and address validation tokens (RFC 9000 §8, RFC 9001 §5.8).
 *
 * ## The problem these solve
 *
 * A QUIC server answers the very first packet from an address it has never
 * heard from, and the reply -- certificate chain included -- is far larger than
 * the request. Without a check, an attacker who spoofs a victim's source
 * address turns the server into an amplifier pointed at that victim.
 *
 * Two mechanisms answer this, and they are different in kind:
 *
 *  - The **anti-amplification limit** (§8.1, phase 4) caps what may be sent to
 *    an unvalidated address at three times what was received. It always
 *    applies and needs no cooperation from anyone.
 *  - A **Retry packet** proves the address is real before any state is
 *    allocated: the server replies with a token and no connection, and only a
 *    client that actually receives the reply can echo it back. This costs the
 *    client a round trip, so it is worth turning on under load rather than
 *    always.
 *
 * A NEW_TOKEN frame is the same token machinery pointed at the future: after a
 * successful handshake the server hands out a token the client can present on
 * its *next* connection, skipping the Retry round trip. */

/* Compute the Retry Integrity Tag (RFC 9001 §5.8).
 *
 * Not a signature and not a secret: the key and nonce are constants published
 * in the RFC. The tag exists so that an off-path attacker, who cannot see the
 * original connection id, cannot forge a Retry -- an on-path one could forge it
 * regardless, and QUIC does not pretend otherwise.
 *
 * `retry` is the Retry packet without its tag; `odcid` is the Destination
 * Connection ID of the Initial that provoked it. Writes 16 bytes. */
int quicretry_integrity_tag(const quiccid_t* odcid,
                            const uint8_t* retry, size_t retry_len,
                            uint8_t tag[16]);

/* Build a complete Retry packet, tag included. Returns its length, or 0. */
size_t quicretry_write(uint8_t* dst, size_t cap,
                       const quiccid_t* odcid,
                       const quiccid_t* dcid, const quiccid_t* scid,
                       const uint8_t* token, size_t token_len);

/* ---- Address validation tokens ----
 *
 * The format is ours; the RFC deliberately leaves it open, requiring only that
 * the server be able to tell its own tokens from anything else.
 *
 * Encrypted with AES-256-GCM under a per-process key, so a token is opaque and
 * unforgeable. What it carries:
 *
 *   kind       Retry or NEW_TOKEN. They must not be interchangeable: a Retry
 *              token proves *this* handshake reached the client and carries the
 *              original connection id the transport parameters are checked
 *              against, while a NEW_TOKEN merely says the address was good some
 *              time ago. Accepting one where the other is meant would let a
 *              client skip the Retry it was asked for.
 *   timestamp  Bounds replay to a window.
 *   address    The client address it was issued to.
 *   odcid      Retry tokens only.
 */

typedef enum {
    QUIC_TOKEN_RETRY = 0,
    QUIC_TOKEN_NEW_TOKEN
} quic_token_kind_e;

typedef enum {
    QUIC_TOKEN_OK = 0,
    QUIC_TOKEN_BAD,        /* not ours, or tampered with */
    QUIC_TOKEN_EXPIRED,
    QUIC_TOKEN_WRONG_ADDR,
    QUIC_TOKEN_WRONG_KIND
} quic_token_status_e;

/* Largest token this produces: nonce + kind + timestamp + address + odcid + tag. */
#define QUIC_TOKEN_MAX_LEN 128

/* Issue a token for `peer`. `odcid` is required for a Retry token and ignored
 * otherwise. Returns the length written, or 0. */
size_t quic_token_write(uint8_t* dst, size_t cap,
                        const uint8_t key[32],
                        quic_token_kind_e kind,
                        const struct sockaddr* peer, socklen_t peer_len,
                        const quiccid_t* odcid,
                        uint64_t now_us);

/* Validate a token.
 *
 * `expect_kind` is what the caller is willing to accept. `lifetime_us` differs
 * sharply between the two: a Retry token is answered within a round trip, so it
 * lives seconds, while a NEW_TOKEN is meant to be presented on a future
 * connection and lives hours.
 *
 * For a NEW_TOKEN only the address is compared, not the port: a client behind
 * NAT will have a different port next time, and requiring a match would make
 * the token useless to exactly the clients it helps most.
 *
 * On success `out_odcid` receives the original connection id for a Retry token
 * (needed to derive the Initial keys of the retried handshake). */
quic_token_status_e quic_token_read(const uint8_t* token, size_t token_len,
                                    const uint8_t key[32],
                                    quic_token_kind_e expect_kind,
                                    const struct sockaddr* peer, socklen_t peer_len,
                                    uint64_t now_us, uint64_t lifetime_us,
                                    quiccid_t* out_odcid);

#endif
