#ifndef __QUICHP__
#define __QUICHP__

#include <stddef.h>
#include <stdint.h>

#include "quiccrypto.h"

/* Header protection (RFC 9001 §5.4).
 *
 * A second, separately keyed layer over the packet number and the low bits of
 * the first byte. Its purpose is not confidentiality of the contents -- the
 * AEAD already covers those -- but to deny a passive observer the fields that
 * would let it link and track a connection across paths: the packet number
 * sequence and the key phase.
 *
 * The mask is one block of keystream derived from a *sample of the packet's own
 * ciphertext*, taken at a fixed offset. That fixed offset is the subtle part:
 * the sample starts four bytes after the packet number begins, regardless of
 * how long the packet number actually is, precisely so that a receiver -- which
 * cannot know the length until the protection is removed -- can find it. */

/* Where the sample sits relative to the packet number, and how long it is. */
#define QUICHP_SAMPLE_OFFSET 4
#define QUICHP_SAMPLE_LEN    16

/* Smallest number of bytes that must follow pn_offset for a sample to exist.
 * A sender pads short packets to reach it; a receiver drops packets that do
 * not. */
#define QUICHP_MIN_AFTER_PN  (QUICHP_SAMPLE_OFFSET + QUICHP_SAMPLE_LEN)

/* Apply protection to a packet that has already been AEAD-sealed.
 *
 * `pkt` is the whole packet, `pn_offset` where its packet number starts and
 * `pn_len` how long it is. Must run *after* the AEAD, since the sample comes
 * from the ciphertext. Returns 1 on success. */
int quichp_apply(quickeys_t* keys, uint8_t* pkt, size_t pkt_len,
                 size_t pn_offset, size_t pn_len);

/* Remove protection from a received packet, in place.
 *
 * Must run *before* the AEAD: it is what reveals the packet number length and
 * the key phase, and the AEAD needs the packet number to build its nonce.
 *
 * Returns 1 on success, 0 if the packet is too short to carry a sample.
 * `out_pn_len`, `out_truncated_pn` and `out_key_phase` are the fields that were
 * hidden; key_phase is meaningless on a long header and reads 0 there. */
int quichp_remove(quickeys_t* keys, uint8_t* pkt, size_t pkt_len,
                  size_t pn_offset, size_t* out_pn_len,
                  uint64_t* out_truncated_pn, int* out_key_phase);

#endif
