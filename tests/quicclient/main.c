#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include "h3client.h"
#include "h3frame.h"
#include "quicclient.h"
#include "quictime.h"

/* Drive a QUIC handshake and one HTTP/3 request against this server, and report
 * what happened.
 *
 *   quicclient [host] [port] [-q] [-p /path] [-a authority] [-n N] [--expect]
 *              [--handshake-only] [--path-challenge] [--key-update] [--cid]
 *              [--migrate] [--new-token [--pause N]]
 *              [--loss N] [--loss-in N] [--reorder N] [--dup N] [--seed N]
 *              [--timeout MS]
 *
 * --loss impairs what this client sends and --loss-in what it receives. Only
 * the second tests the server's loss recovery; the first tests that the server
 * survives a peer that goes quiet, because this client has no recovery of its
 * own (see quicclient.h).
 *
 * `-a` sets both the TLS server name and the :authority pseudo-header. They are
 * one flag because a server matches the virtual host on one and validates it
 * against the other, so setting them apart only ever produces a 421.
 *
 * Exists because nothing else on this machine can: the system curl is built
 * without HTTP/3, and no QUIC library is installed. Until phase 8 stands up the
 * interop runner, this is the only thing that can say whether the whole path --
 * handshake, SETTINGS, request, dispatch, response -- works end to end. Every
 * module below it is unit-tested; what only this can check is that they are
 * wired to each other in the right order. */

int main(int argc, char* argv[]) {
    const char* host = argc > 1 ? argv[1] : "127.0.0.1";
    const uint16_t port = argc > 2 ? (uint16_t)atoi(argv[2]) : 18443;

    int verbose = 1;
    int handshake_only = 0;
    const char* path = "/";
    const char* authority = "localhost";
    int concurrent = 1;
    int expect_continue = 0;
    int path_challenge = 0;
    int key_update = 0;
    int cid_test = 0;
    int migrate = 0;
    int new_token = 0;
    int pause_ms = 0;
    unsigned loss = 0, loss_in = 0, reorder = 0, dup = 0;
    unsigned long long seed = 0;
    /* How long to wait for a response. Five seconds is generous for the small
     * replies most runs fetch and far too little for a large one in a
     * sanitised build -- 2 MB takes half a second there, so 16 MB does not
     * fit. Raised per run rather than globally, so an ordinary failure is still
     * reported in five seconds instead of thirty. */
    int timeout_ms = 5000;

    /* Where to put the body, for the checks that only bytes can settle. A
     * response of the right *length* proves nothing about a send path that
     * reorders or mis-splits datagrams -- and segmentation offload
     * (docs/http3/08 §7e) is exactly such a path. */
    const char* out_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-q") == 0) verbose = 0;
        else if (strcmp(argv[i], "--handshake-only") == 0) handshake_only = 1;
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) authority = argv[++i];
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) concurrent = atoi(argv[++i]);
        else if (strcmp(argv[i], "--expect") == 0) expect_continue = 1;
        else if (strcmp(argv[i], "--path-challenge") == 0) path_challenge = 1;
        else if (strcmp(argv[i], "--key-update") == 0) key_update = 1;
        else if (strcmp(argv[i], "--cid") == 0) cid_test = 1;
        else if (strcmp(argv[i], "--migrate") == 0) migrate = 1;
        else if (strcmp(argv[i], "--new-token") == 0) new_token = 1;
        else if (strcmp(argv[i], "--pause") == 0 && i + 1 < argc) pause_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--loss") == 0 && i + 1 < argc) loss = (unsigned)atoi(argv[++i]);
        else if (strcmp(argv[i], "--loss-in") == 0 && i + 1 < argc) loss_in = (unsigned)atoi(argv[++i]);
        else if (strcmp(argv[i], "--reorder") == 0 && i + 1 < argc) reorder = (unsigned)atoi(argv[++i]);
        else if (strcmp(argv[i], "--dup") == 0 && i + 1 < argc) dup = (unsigned)atoi(argv[++i]);
        else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) seed = strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out_path = argv[++i];
    }

    if (concurrent < 1) concurrent = 1;

    printf("connecting to %s:%u\n", host, port);

    /* Two connections, so the second can present what the first was given.
     * Meaningful only against a server configured to Retry -- that is the round
     * trip the token is supposed to skip, and against a server that never
     * retries there is nothing to see. */
    if (new_token) {
        quicclient_t first;
        uint8_t token[256];
        size_t token_len = 0;

        if (quicclient_connect(&first, host, port, authority, 0) &&
            quicclient_run(&first, 5000)) {
            for (int i = 0; i < 20 && !first.new_token_received; i++)
                quicclient_pump(&first, 100);

            token_len = quicclient_take_token(&first, token, sizeof token);
        }

        const int first_retried = first.retry_seen;
        quicclient_free(&first);

        printf("\nNEW TOKEN\n");
        printf("first connection retried:  %s\n", first_retried ? "yes" : "no");
        printf("token issued:              %s (%zu bytes)\n",
               token_len > 0 ? "yes" : "no", token_len);

        if (token_len == 0) {
            printf("\nFAIL: no token to present\n");
            return 1;
        }

        /* Room for something to happen to the server in between -- a reload,
         * say. A token that survives one proves the keys did. */
        if (pause_ms > 0) {
            printf("pausing %d ms\n", pause_ms);
            fflush(stdout);
            usleep((useconds_t)pause_ms * 1000);
        }

        quicclient_t second;
        const int ok2 = quicclient_connect_token(&second, host, port, authority, verbose,
                                                 token, token_len) &&
                        quicclient_run(&second, 5000);
        const int retried = second.retry_seen;
        const int done = second.handshake_complete;
        quicclient_free(&second);

        printf("second connection retried: %s\n", retried ? "yes" : "no");
        printf("second handshake complete: %s\n", done ? "yes" : "no");

        /* The point of the whole exercise: the token replaced the round trip. */
        const int good = ok2 && done && !retried;
        printf("\n%s\n", good ? "OK: the token skipped the Retry"
                                : "FAIL: the token did not skip the Retry");
        return good ? 0 : 1;
    }

    quicclient_t client;

    /* Impairment has to be installed before the first Initial goes out, so the
     * handshake itself is exposed to it -- that is where loss recovery is
     * least forgiving, because there is no data to piggyback retransmissions
     * on. quicclient_connect zeroes the struct, hence the ordering dance. */
    if (loss > 0 || loss_in > 0 || reorder > 0 || dup > 0)
        printf("network: %u%% loss out, %u%% loss in, %u%% reorder, %u%% duplicate (seed %llu)\n",
               loss, loss_in, reorder, dup, seed);

    if (!quicclient_connect_impaired(&client, host, port, authority, verbose,
                                     loss, loss_in, reorder, dup, seed)) {
        printf("FAIL: could not send the first Initial\n");
        quicclient_free(&client);
        return 1;
    }

    int ok = quicclient_run(&client, 5000);

    printf("\n");
    printf("handshake complete:        %s\n", client.handshake_complete ? "yes" : "no");
    printf("HANDSHAKE_DONE received:   %s\n",
           client.handshake_done_received ? "yes" : "no");
    printf("server Initial seen:       %s\n", client.got_server_initial ? "yes" : "no");
    printf("server Handshake seen:     %s\n", client.got_server_handshake ? "yes" : "no");

    if (client.handshake_complete) {
        const unsigned char* alpn = NULL;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(client.tls.ssl, &alpn, &alpn_len);
        printf("ALPN:                      %.*s\n",
               (int)alpn_len, alpn_len > 0 ? (const char*)alpn : "(none)");

        const SSL_CIPHER* cipher = SSL_get_current_cipher(client.tls.ssl);
        printf("cipher:                    %s\n",
               cipher != NULL ? SSL_CIPHER_get_name(cipher) : "(none)");
    }

    /* Path validation, before HTTP/3: RFC 9000 §8.2.2 makes answering a
     * challenge unconditional, so it must work on a connection that has done
     * nothing else. Driven from here rather than from the h3 layer for the
     * same reason -- it is a transport obligation, not an HTTP one. */
    if (ok && path_challenge) {
        printf("\nPATH_CHALLENGE\n");

        if (!quicclient_path_challenge(&client))
            printf("FAIL: could not queue a challenge\n");
        else {
            /* §8.2.2 forbids delaying the response, so a couple of pumps is
             * already generous; anything slower is the bug being looked for.
             * The challenge is re-queued each turn because on a lossy path
             * either half of the exchange can vanish, and §8.2.1 has the
             * challenger repeat rather than wait. */
            for (int i = 0; i < 20 && !client.path_response_received; i++) {
                if (i > 0) quicclient_path_challenge(&client);
                quicclient_pump(&client, 100);
            }
        }

        printf("PATH_RESPONSE received:    %s\n",
               client.path_response_received ? "yes" : "no");
        printf("echoed data matches:       %s\n",
               client.path_response_matched ? "yes" : "no");

        if (!client.path_response_matched) ok = 0;
    }

    /* Alternate connection ids (RFC 9000 §5.1.1). An id the server announced
     * but does not route is indistinguishable from one it never announced, so
     * the check is to address it by one and see an answer come back. */
    if (ok && cid_test) {
        printf("\nCONNECTION IDS\n");

        /* They ride in 1-RTT packets, which may not have arrived by the time
         * the handshake reports done. */
        for (int i = 0; i < 20 && client.server_cid_count == 0; i++)
            quicclient_pump(&client, 100);

        printf("ids issued:                %zu\n", client.server_cid_count);

        if (client.server_cid_count == 0) ok = 0;
        else {
            quicclient_use_cid(&client, 0);
            quicclient_path_challenge(&client);

            for (int i = 0; i < 20 && !client.path_response_received; i++) {
                if (i > 0) quicclient_path_challenge(&client);
                quicclient_pump(&client, 100);
            }

            printf("answers on the new id:     %s\n",
                   client.path_response_matched ? "yes" : "no");
            if (!client.path_response_matched) ok = 0;

            /* §5.1.1: retiring one is also a request for a replacement.
             * Sequence 0 -- the id from the handshake -- because §19.16 forbids
             * retiring the id the packet carrying the frame is addressed to,
             * and that is now the one we just switched to. */
            const size_t before = client.server_cid_count;
            quicclient_retire_cid(&client, 0);

            /* A PING each turn, for the same reason as everywhere else in this
             * file: the replacement is retransmitted when the server notices
             * the announcement was lost, and it notices only from an
             * acknowledgement of something newer. A client that waits in
             * silence gives it nothing to notice with. */
            for (int i = 0; i < 20 && client.server_cid_count == before; i++) {
                quicclient_ping(&client);
                quicclient_pump(&client, 100);
            }

            const int replaced = client.server_cid_count > before;

            printf("replacement after retire:  %s\n", replaced ? "yes" : "no");

            if (!replaced) ok = 0;

            /* §19.16 makes retiring a sequence number that was never issued a
             * protocol violation -- a MUST, and the only way to notice a peer
             * that is guessing. Deliberately last: it ends the connection.
             *
             * And therefore skipped when a later phase still needs that
             * connection. `--cid --migrate` together used to report "the
             * connection did not migrate": the migration ran against a
             * connection this check had just made the server close, so the
             * rebound port got a stateless reset -- correct behaviour by §10.3,
             * read as a server defect. A harness must not destroy the thing it
             * is about to test, and when it declines a check it must say so
             * (docs/http3/08 §7g). */
            if (migrate) {
                printf("unissued retire:           skipped, --migrate needs "
                       "this connection alive\n");
            }
            else {
            quicclient_retire_cid(&client, 4242);

            /* A PING each turn, because §10.2.1 has a closing endpoint re-send
             * its CONNECTION_CLOSE *in response to an incoming packet* rather
             * than on a timer. A client that goes quiet after provoking the
             * error would wait forever if that one packet were lost -- which is
             * exactly what happened the first time this ran over a lossy
             * path. */
            for (int i = 0; i < 20 && !client.close_received && !client.reset_received; i++) {
                quicclient_ping(&client);
                quicclient_pump(&client, 100);
            }

            /* Either answer proves the refusal. On a lossy path the
             * CONNECTION_CLOSE can be the packet that vanishes, and by the time
             * our next PING arrives the closing period is over and the server
             * has forgotten the connection -- at which point a stateless reset
             * is exactly what §10.3 requires of it. Demanding the close frame
             * would be demanding that the loss happen somewhere else. */
            const int refused = (client.close_received && client.close_error == 0x0a) ||
                                client.reset_received;

            printf("unissued retire refused:   %s%s\n", refused ? "yes" : "no",
                   client.reset_received ? " (by stateless reset)" : "");
            if (!refused) ok = 0;
            }
        }
    }

    /* Migration (RFC 9000 §9). The server must notice the new address, validate
     * it before trusting it, and only then move -- so what is checked is not
     * "did anything arrive" but the whole sequence, in order. */
    if ((loss > 0 || loss_in > 0 || reorder > 0 || dup > 0) && verbose == 0) {
        printf("dropped out/in:            %llu / %llu\n",
               (unsigned long long)client.net_dropped_out,
               (unsigned long long)client.net_dropped_in);
        printf("reordered / duplicated:    %llu / %llu\n",
               (unsigned long long)client.net_reordered,
               (unsigned long long)client.net_duplicated);
    }

    if (ok && migrate) {
        printf("\nMIGRATION\n");

        for (int i = 0; i < 20 && client.server_cid_count == 0; i++)
            quicclient_pump(&client, 100);

        if (!quicclient_rebind(&client))
            printf("FAIL: could not rebind\n");

        /* Something non-probing from the new address, or §9.3 says the server
         * is right to ignore it: a probing packet tests a path, it does not
         * claim one. A PING is the smallest thing that qualifies. */
        quicclient_ping(&client);

        for (int i = 0; i < 30 && !client.path_challenge_received; i++)
            quicclient_pump(&client, 100);

        printf("challenged on the new path: %s\n",
               client.path_challenge_received ? "yes" : "no");
        if (!client.path_challenge_received) ok = 0;

        /* Our answer to it is what completes the validation; then the server's
         * next response must arrive at the new address, which it can only do
         * if it moved.
         *
         * Provoked with a PING rather than waited for: once the path is
         * validated the server has nothing of its own to send, so "a datagram
         * arrived" would be measuring whatever incidental traffic happened to
         * be in flight -- which is why this check passed or failed by seed
         * before the PING was added. */
        const uint64_t before = client.datagrams_received;

        for (int i = 0; i < 30 && client.datagrams_received == before; i++) {
            quicclient_ping(&client);
            quicclient_pump(&client, 100);
        }

        printf("server answers the new one: %s\n",
               client.datagrams_received > before ? "yes" : "no");
        if (client.datagrams_received <= before) ok = 0;
    }

    /* Key update (RFC 9001 §6). Like the challenge above, this belongs before
     * HTTP/3: it is a transport obligation, and the exchange that proves it has
     * to be one the application layer plays no part in. */
    if (ok && key_update) {
        printf("\nKEY UPDATE\n");

        if (!quicclient_key_update(&client))
            printf("FAIL: could not move to the next key generation\n");
        else {
            /* Something ack-eliciting in the new phase, so the server has to
             * answer in it: a PATH_CHALLENGE does nicely and needs no streams. */
            quicclient_path_challenge(&client);

            for (int i = 0; i < 30 && !client.read_after_update; i++) {
                if (i > 0) quicclient_path_challenge(&client);
                quicclient_pump(&client, 100);
            }
        }

        printf("server followed the update: %s\n",
               client.read_after_update ? "yes" : "no");
        printf("PATH_RESPONSE after update: %s\n",
               client.path_response_matched ? "yes" : "no");

        if (!client.read_after_update || !client.path_response_matched) ok = 0;
    }

    /* --migrate deliberately falls through to the HTTP/3 exchange below when it
     * succeeded: "a datagram came back" only proves the server answered, and
     * what the migration is for is carrying requests. The failure path still
     * stops here, with the message that names the step that failed. */
    if (!ok || handshake_only || path_challenge || key_update || cid_test) {
        const char* what = migrate      ? "the connection migrated"
                         : cid_test     ? "the alternate connection ids work"
                         : key_update   ? "the key update was followed"
                         : path_challenge ? "the path challenge was answered"
                                          : "the handshake completed end to end";
        const char* why = migrate      ? "the connection did not migrate"
                        : cid_test     ? "the alternate connection ids do not work"
                        : key_update   ? "the key update was not followed"
                        : path_challenge ? "the path challenge went unanswered"
                                         : "the handshake did not complete";

        quicclient_free(&client);
        printf("\n%s: %s\n", ok ? "OK" : "FAIL", ok ? what : why);
        return ok ? 0 : 1;
    }

    /* ---- HTTP/3 ---- */

    printf("\nGET https://%s%s\n", authority, path);

    int h3_ok = h3client_start(&client);
    if (!h3_ok) printf("FAIL: could not open the control stream\n");

    h3client_response_t response;
    memset(&response, 0, sizeof response);

    /* Several at once when asked. They go out together, so the server has to
     * hold them all open -- the case a single request cannot distinguish from
     * a server that serialises everything. */
    /* What the request cost *this process*, wall and CPU both. A transfer
     * measured by a client that cannot keep up reports the client's own
     * backlog as the server's round trip (docs/http3/08 §7c), and these two
     * numbers plus the dwell below are what separate the two. */
    struct rusage ru_before;
    getrusage(RUSAGE_SELF, &ru_before);
    const uint64_t wall_before = quic_now_us();

    h3client_response_t* many = NULL;
    if (h3_ok && concurrent > 1) {
        many = calloc((size_t)concurrent, sizeof * many);
        h3_ok = many != NULL &&
                h3client_get_many(&client, (size_t)concurrent, authority, path,
                                  timeout_ms > 15000 ? timeout_ms : 15000, many);
        if (!h3_ok) printf("FAIL: not every response completed\n");
        else response = many[0];
    }
    else if (h3_ok && expect_continue) {
        h3_ok = h3client_post_expect(&client, 0, authority, path,
                                     "body-after-permission", 21, 8000, &response);
        if (!h3_ok) printf("FAIL: no response\n");
    }
    else if (h3_ok) {
        h3_ok = h3client_get(&client, 0, authority, path, timeout_ms, &response);
        if (!h3_ok) printf("FAIL: no response\n");
    }

    const uint64_t wall_us = quic_now_us() - wall_before;

    struct rusage ru_after;
    getrusage(RUSAGE_SELF, &ru_after);

    const uint64_t cpu_us =
        (uint64_t)((ru_after.ru_utime.tv_sec - ru_before.ru_utime.tv_sec) * 1000000LL +
                   (ru_after.ru_utime.tv_usec - ru_before.ru_utime.tv_usec) +
                   (ru_after.ru_stime.tv_sec - ru_before.ru_stime.tv_sec) * 1000000LL +
                   (ru_after.ru_stime.tv_usec - ru_before.ru_stime.tv_usec));

    /* Read after the request, not before: service streams and request streams
     * are delivered independently, so the server's SETTINGS may well arrive
     * alongside the response rather than ahead of it. */
    h3settings_t peer;
    const int settings_seen = h3client_peer_settings(&client, &peer);

    printf("server SETTINGS:           %s\n", settings_seen ? "yes" : "no");
    if (settings_seen) {
        printf("  qpack capacity:          %llu\n",
               (unsigned long long)peer.qpack_max_table_capacity);
        printf("  blocked streams:         %llu\n",
               (unsigned long long)peer.qpack_blocked_streams);
        printf("  max field section:       %llu\n",
               (unsigned long long)peer.max_field_section_size);
    }

    if (h3_ok && concurrent > 1) {
        printf("concurrent requests:       %d\n", concurrent);

        /* Same status and a body on every one. Not identical *lengths*: a
         * handler that reports its own timings answers differently every time,
         * and demanding byte-equality there would fail a server that is working
         * exactly as intended. */
        int all_ok = 1;
        size_t shortest = many[0].body_len, longest = many[0].body_len;
        for (int i = 1; i < concurrent; i++) {
            if (many[i].status != many[0].status || many[i].body_len == 0) all_ok = 0;
            if (many[i].body_len < shortest) shortest = many[i].body_len;
            if (many[i].body_len > longest) longest = many[i].body_len;
        }

        printf("all same status:           %s\n", all_ok ? "yes" : "no");
        printf("body lengths:              %zu..%zu\n", shortest, longest);
        if (!all_ok) h3_ok = 0;
    }

    if (h3_ok) {
        printf("status:                    %d\n", response.status);
        printf("fields:                    %zu\n", response.fields_count);
        printf("interim responses:         %d%s", response.interim_count,
               response.interim_count > 0 ? "" : "\n");
        if (response.interim_count > 0)
            printf(" (last %d, %zu fields)\n", response.interim_status, response.interim_fields);
        printf("trailers:                  %zu\n", response.trailer_count);
        printf("body:                      %zu bytes\n", response.body_len);

        if (out_path != NULL && response.body_len > 0) {
            FILE* out = fopen(out_path, "wb");
            const size_t written = out != NULL
                ? fwrite(response.body, 1, response.body_len, out) : 0;
            if (out != NULL) fclose(out);

            printf("body written:              %s (%zu bytes)\n",
                   written == response.body_len ? out_path : "FAILED", written);
        }

        quicclient_rxstats_t rx;
        quicclient_rxstats(&client, &rx);

        const double mb = (double)response.body_len / (1024.0 * 1024.0);
        printf("client wall:               %.1f ms%s", wall_us / 1000.0,
               mb > 0 ? "" : "\n");
        if (mb > 0)
            printf(" (%.1f MB/s)\n", mb / (wall_us / 1000000.0));

        printf("client cpu:                %.1f ms%s", cpu_us / 1000.0,
               mb > 0 ? "" : "\n");
        if (mb > 0) printf(" (%.2f ms/MB)\n", (cpu_us / 1000.0) / mb);

        printf("client rx:                 %llu datagrams, %llu bytes, "
               "burst max %llu\n",
               (unsigned long long)rx.datagrams, (unsigned long long)rx.bytes,
               (unsigned long long)rx.burst_max);

        /* How long a datagram waited in *our* receive queue after the kernel
         * took it. This is the part of the server's srtt that belongs to the
         * client. */
        if (rx.stamped > 0)
            printf("client rx dwell:           avg %.2f ms, max %.2f ms "
                   "(%llu stamped)\n",
                   (rx.dwell_sum_us / (double)rx.stamped) / 1000.0,
                   rx.dwell_max_us / 1000.0, (unsigned long long)rx.stamped);

        if (verbose && response.body_len > 0) {
            const size_t show = response.body_len > 512 ? 512 : response.body_len;
            printf("---\n%.*s%s\n---\n", (int)show, response.body,
                   show < response.body_len ? "\n[truncated]" : "");
        }
    }

    const int all_ok = h3_ok && settings_seen && response.status > 0;

    if (many != NULL) {
        for (int i = 0; i < concurrent; i++) h3client_response_free(&many[i]);
        free(many);
        memset(&response, 0, sizeof response);   /* aliased many[0] */
    }

    h3client_response_free(&response);

    /* Say goodbye rather than walking away.
     *
     * A client that simply exits leaves the server holding the connection for
     * its whole idle timeout -- thirty seconds of state per run, and, for
     * anything that measures a server per connection, thirty seconds of window
     * in which the *next* run's traffic is counted against this one. That is
     * how the first per-connection measurement of docs/http3/08 §7b came out
     * unreadable: three consecutive connections reported the same overflow
     * figure because their lifetimes overlapped.
     *
     * It is also simply what a real client does (§10.2). */
    quicclient_close(&client, 0, 1);
    quicclient_flush(&client);

    quicclient_free(&client);

    printf("\n%s\n", all_ok ? "OK: request and response completed end to end"
                            : "FAIL: the HTTP/3 exchange did not complete");

    return all_ok ? 0 : 1;
}
