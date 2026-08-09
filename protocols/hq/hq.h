#ifndef __HQ__
#define __HQ__

/* HTTP/0.9 over QUIC, ALPN `hq-interop`. Test scaffolding, not a feature.
 *
 * The quic-interop-runner moves files with HTTP/0.9 in almost every test case,
 * keeping HTTP/3 out of the way so that what is being tested is the transport:
 * loss, corruption, Retry, resumption, connection migration, rebinding. Serving
 * it is how an implementation gets into that matrix, and every implementation in
 * the matrix carries a shim just like this one (docs/http3/08 §3e).
 *
 * The protocol, in full: the client opens a bidirectional stream, writes
 * `GET <path>\r\n` and closes its side; the server writes the file's bytes and
 * closes its side. No status, no headers, no length, no host -- which is why
 * this whole directory is behind a build flag and cannot be turned on by
 * configuration.
 *
 * There is no connection object. Everything a request needs lives on its own
 * stream, hung off quicstream_t::app the way the h3 layer does it, so the
 * transport's existing reaping and freeing applies unchanged. */

#include <stdint.h>

struct quicconn;

/* Read what has arrived on every request stream, answer what is complete, and
 * push out as much of each answer as the write-ahead budget allows. Called once
 * per connection turn, with the connection lock held.
 *
 * Returns 0 if the connection must close, in which case *error carries an
 * application error code. */
int hq_turn(struct quicconn* conn, uint64_t* error);

/* Whether an answer is still only partly written, so the turn deserves to be
 * asked for again. */
int hq_has_pending(struct quicconn* conn);

#endif
