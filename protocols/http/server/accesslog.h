#ifndef __HTTP_ACCESS_LOG__
#define __HTTP_ACCESS_LOG__

#include "httprequest.h"
#include "httpresponse.h"
#include "server.h"

/* One record per answered request -- who asked, for what, and what they got
 * (docs/webserver/00 §3).
 *
 * This is a log of *requests*, not of server events: misc/log.c carries the
 * latter, and mixing the two would make `journalctl -t cwfr` unreadable at any
 * real request rate. The records therefore go to syslog under their own
 * facility (local7, the one web servers have used for this since the nineties),
 * which is what keeps them separable:
 *
 *     journalctl -t cwfr SYSLOG_FACILITY=23     # access
 *     journalctl -t cwfr SYSLOG_FACILITY=1      # events
 *
 * Syslog and not a file of our own because the framework already owns no log
 * rotation, and inventing one for this would be the larger half of the feature.
 *
 * The format is Apache's `vhost_combined` with the request duration appended --
 * fixed, not configurable, because a template costs a parser and every reader
 * of these logs already understands this shape. For GoAccess:
 *
 *     log-format %v:%^ %h %^[%d:%t %^] "%r" %s %b "%R" "%u" %T
 *     date-format %d/%b/%Y
 *     time-format %H:%M:%S
 *
 * Switched on with `"access": true` in `main.log`. It is independent of
 * `main.log.enabled`, which governs the event log: wanting request records
 * without debug chatter is the normal case, not an exotic one.
 *
 * Records are staged per worker and delivered a batch at a time -- see the
 * comment on the batch in accesslog.c for why, and for what that means for
 * anything reading the journal.
 */

/* Arm the log for this response and start its clock. Called once, where the
 * response object is taken for a request, with the vhost that request resolved
 * to; a vhost with the log switched off leaves the response unarmed and nothing
 * downstream does any work for it. */
void http_access_log_start(httpresponse_t* response, const server_t* server);

/* Keep the target the client asked for, for the record. Used where the request
 * is about to lose it -- a redirect replaces `request->uri` with its
 * destination, and a record naming the destination does not say what was
 * requested.
 *
 * Copies rather than adopting: the caller frees its own string, which is what
 * lets the ownership stay readable there (and to gcc's -fanalyzer). Only the
 * first call is kept -- that is the one holding the target the client sent --
 * and with the log off nothing is copied at all, which is why a redirect on a
 * server without an access log pays nothing for this. */
void http_access_log_keep_uri(httpresponse_t* response, const char* uri, size_t length);

/* One worker's staging area: the batch of records waiting to be delivered, and
 * the formatted timestamp they share. Opaque -- the event loop carries it and
 * does not look inside, the same arrangement mpxapi_t::quic_endpoints has.
 *
 * Per worker and not per connection, because a batch is only worth having if
 * many connections fill it; per worker and not per process, because that is
 * what makes it lock-free. It is reached as
 * `connection->ctx->listener->api->access_log`, and every protocol's write path
 * runs on the worker that owns the connection (connection.h's write
 * invariant) -- so the thread that stages a record is the thread that drains
 * it, and nothing here is shared between threads. */
typedef struct accesslog accesslog_t;

accesslog_t* http_access_log_create(void);
void http_access_log_free(accesslog_t* log);

/* Stage the record, if this response was armed. Called at the point each
 * protocol finishes putting the response on the wire -- that is the first
 * moment the status, the byte count and the duration are all known.
 *
 * The worker's staging area is found from the response's connection, so the
 * write paths do not each have to know where it lives. A response with no
 * worker behind it (no connection, or one built outside a listener) is
 * delivered on the spot rather than dropped. */
void http_access_log(httprequest_t* request, httpresponse_t* response);

/* Deliver whatever this worker has staged. Called from the worker's timer sweep
 * and on its way out, so records never wait on a quiet server for longer than a
 * tick, and none are left behind at shutdown. Costs nothing when there is
 * nothing staged, which is every tick of a server with the log off. */
void http_access_log_flush(accesslog_t* log);

#endif
