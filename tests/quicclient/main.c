#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "h3client.h"
#include "h3frame.h"
#include "quicclient.h"
#include "quictime.h"

/* Drive a QUIC handshake and one HTTP/3 request against this server, and report
 * what happened.
 *
 *   quicclient [host] [port] [-q] [-p /path] [-a authority] [-n N] [--expect]
 *              [--handshake-only] [--path-challenge] [--key-update] [--cid]
 *              [--migrate] [--new-token [--pause N]] [--0rtt] [--0rtt-stall]
 *              [--pause-after-handshake N] [--idle MS]
 *              [--pause-after-request N]
 *              [--pause-after-response N]
 *              [--loss N] [--loss-in N] [--reorder N] [--dup N] [--seed N]
 *              [--timeout MS] [--version [HEX]] [--version-flood N]
 *              [--quic-version HEX] [--offer-versions HEX[,HEX...]]
 *              [--mix /small [--mix-delay MS] [--mix-priority VALUE]]
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
    /* Requests sent one after another on the same connection, each on its own
     * stream. Distinct from -n on purpose: `-n` has them all outstanding at
     * once, which is the concurrency case, while this is the keep-alive case —
     * a connection that serves a sequence, the way a browser does. Anything the
     * server reuses between exchanges (pooled request/response objects) only
     * shows up here; with -n every object is alive at the same time and nothing
     * can be handed on. */
    int repeat = 1;
    int expect_continue = 0;
    int path_challenge = 0;
    int key_update = 0;
    int cid_test = 0;
    int migrate = 0;
    int new_token = 0;
    int zero_rtt = 0;
    int zero_rtt_stall = 0;
    int version_probe = 0;
    uint32_t speak_version = 0;
    uint32_t offer[4];
    int offer_count = 0;
    int version_flood = 0;
    /* QUIC v2 (RFC 9369). It is now implemented, so as a *probe* version it
     * tests something narrower than it used to: that a version this build
     * knows but the operator has switched off draws a Version Negotiation
     * packet rather than a handshake. For the original question -- an unknown
     * version -- pass a number nobody has registered.
     *
     * Was: a version that exists, that we deliberately do not
     * implement (docs/http3/09 §3.2), and that therefore models the real case
     * this checks -- a peer from the future, not a random number. */
    uint32_t probe_version = 0x6b3343cfu;
    /* The second, small request of the mixed-size scenario; `-p` is the large
     * one. 20 ms of stagger, because the case is a small request arriving while
     * a large response is under way -- not one that races it to the server. */
    const char* mix_path = NULL;
    int mix_delay_ms = 20;
    /* What the small request asks for. `u=0` is the most urgent bucket there
     * is, which is what a browser puts a blocking stylesheet in. */
    const char* mix_priority = "u=0";
    int pause_ms = 0;
    int pause_after_handshake_ms = 0;
    int idle_ms = 0;
    int pause_after_request_ms = 0;
    int pause_after_response_ms = 0;
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
        else if (strcmp(argv[i], "--repeat") == 0 && i + 1 < argc) repeat = atoi(argv[++i]);
        else if (strcmp(argv[i], "--expect") == 0) expect_continue = 1;
        else if (strcmp(argv[i], "--path-challenge") == 0) path_challenge = 1;
        else if (strcmp(argv[i], "--key-update") == 0) key_update = 1;
        else if (strcmp(argv[i], "--cid") == 0) cid_test = 1;
        else if (strcmp(argv[i], "--migrate") == 0) migrate = 1;
        else if (strcmp(argv[i], "--new-token") == 0) new_token = 1;
        else if (strcmp(argv[i], "--0rtt") == 0) zero_rtt = 1;
        else if (strcmp(argv[i], "--0rtt-stall") == 0) zero_rtt_stall = 1;
        else if (strcmp(argv[i], "--pause") == 0 && i + 1 < argc) pause_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--idle") == 0 && i + 1 < argc) idle_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--pause-after-handshake") == 0 && i + 1 < argc)
            pause_after_handshake_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--pause-after-request") == 0 && i + 1 < argc)
            pause_after_request_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--pause-after-response") == 0 && i + 1 < argc)
            pause_after_response_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--loss") == 0 && i + 1 < argc) loss = (unsigned)atoi(argv[++i]);
        else if (strcmp(argv[i], "--loss-in") == 0 && i + 1 < argc) loss_in = (unsigned)atoi(argv[++i]);
        else if (strcmp(argv[i], "--reorder") == 0 && i + 1 < argc) reorder = (unsigned)atoi(argv[++i]);
        else if (strcmp(argv[i], "--dup") == 0 && i + 1 < argc) dup = (unsigned)atoi(argv[++i]);
        else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) seed = strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out_path = argv[++i];
        else if (strcmp(argv[i], "--version") == 0) {
            version_probe = 1;
            /* The version is optional: without it the probe uses QUIC v2, which
             * is what a peer from the future would actually send. */
            if (i + 1 < argc && argv[i + 1][0] != '-')
                probe_version = (uint32_t)strtoul(argv[++i], NULL, 16);
        }
        else if (strcmp(argv[i], "--quic-version") == 0 && i + 1 < argc)
            speak_version = (uint32_t)strtoul(argv[++i], NULL, 16);
        else if (strcmp(argv[i], "--offer-versions") == 0 && i + 1 < argc) {
            /* Comma-separated hex, most preferred first: the client's
             * `available_versions` (RFC 9368 §3). */
            const char* list = argv[++i];
            offer_count = 0;
            while (*list != '\0' && offer_count < (int)(sizeof offer / sizeof offer[0])) {
                char* end = NULL;
                const unsigned long v = strtoul(list, &end, 16);
                if (end == list) break;
                offer[offer_count++] = (uint32_t)v;
                list = (*end == ',') ? end + 1 : end;
            }
        }
        else if (strcmp(argv[i], "--version-flood") == 0 && i + 1 < argc)
            version_flood = atoi(argv[++i]);
        else if (strcmp(argv[i], "--mix") == 0 && i + 1 < argc) mix_path = argv[++i];
        else if (strcmp(argv[i], "--mix-delay") == 0 && i + 1 < argc)
            mix_delay_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--mix-priority") == 0 && i + 1 < argc)
            mix_priority = argv[++i];
    }

    if (mix_delay_ms < 0) mix_delay_ms = 0;

    if (concurrent < 1) concurrent = 1;
    if (repeat < 1) repeat = 1;
    if (timeout_ms < 1) timeout_ms = 1;

    /* Before any connect: both are process-wide knobs the client reads when it
     * builds a connection (quicclient.h). */
    if (speak_version != 0) quicclient_use_version(speak_version);
    if (offer_count > 0) quicclient_offer_versions(offer, (size_t)offer_count);

    /* ---- Version negotiation (RFC 9000 §6.1, §14.1, §17.2.1) ----
     *
     * No handshake, because there cannot be one: the whole point is that this
     * peer speaks a version the server does not implement. Two datagrams settle
     * the entire behaviour -- a full-sized one, which must be answered, and an
     * undersized one, which must not, because answering it would make the
     * server an amplifier for a spoofed source address. */
    if (version_flood > 0) {
        int sent = 0, answered = 0;

        printf("flooding %s:%u with %d version 0x%08x probes\n",
               host, port, version_flood, probe_version);

        for (int i = 0; i < version_flood; i++) {
            quicvnprobe_t probe;

            /* Short timeout on purpose: a probe that was rate-limited away is
             * answered by nothing, and waiting the usual five seconds for that
             * would make the run longer than the token bucket it measures. */
            if (!quicclient_probe_version(host, port, probe_version,
                                          QUIC_MIN_INITIAL_DATAGRAM, 200, 0, &probe))
                break;

            sent++;
            if (probe.answered && probe.is_vn) answered++;
        }

        printf("probes sent:               %d\n", sent);
        printf("version negotiation:       %d\n", answered);

        return sent == version_flood ? 0 : 1;
    }

    if (version_probe) {
        printf("\nVERSION NEGOTIATION\n");

        quicvnprobe_t probe;
        if (!quicclient_probe_version(host, port, probe_version,
                                      QUIC_MIN_INITIAL_DATAGRAM, timeout_ms,
                                      verbose, &probe)) {
            printf("FAIL: the probe could not be sent\n");
            return 1;
        }

        int offers_v1 = 0, offers_grease = 0, offers_probed = 0;
        for (size_t i = 0; i < probe.count; i++) {
            if (probe.versions[i] == QUIC_VERSION_1) offers_v1 = 1;
            /* §15: the reserved 0x?a?a?a?a pattern. A server that offers one
             * cannot be depended on for an exact list, which is the point of
             * offering it. */
            if ((probe.versions[i] & 0x0f0f0f0fu) == 0x0a0a0a0au) offers_grease = 1;
            if (probe.versions[i] == probe_version) offers_probed = 1;
        }

        printf("probed version:            0x%08x\n", probe_version);
        printf("answered:                  %s\n", probe.answered ? "yes" : "no");
        printf("version negotiation:       %s\n", probe.is_vn ? "yes" : "no");
        printf("connection ids echoed:     %s\n", probe.cids_echoed ? "yes" : "no");
        printf("version 1 offered:         %s\n", offers_v1 ? "yes" : "no");
        printf("reserved version offered:  %s\n", offers_grease ? "yes" : "no");
        printf("probed version offered:    %s\n", offers_probed ? "yes" : "no");
        printf("reply / probe bytes:       %zu / %zu\n",
               probe.datagram_len, probe.probe_len);

        /* And the other half of the rule: below the minimum datagram size the
         * server must stay silent (§14.1). Tested at one byte under, not at
         * some obviously tiny size, because the interesting failure is an
         * off-by-one in the comparison. */
        quicvnprobe_t small;
        const int small_ok =
            quicclient_probe_version(host, port, probe_version,
                                     QUIC_MIN_INITIAL_DATAGRAM - 1,
                                     timeout_ms < 1000 ? timeout_ms : 1000,
                                     verbose, &small);

        printf("undersized probe answered: %s\n",
               !small_ok ? "could not be sent" : small.answered ? "yes" : "no");

        const int good = probe.answered && probe.is_vn && probe.cids_echoed &&
                         offers_v1 && offers_grease && !offers_probed &&
                         probe.datagram_len < probe.probe_len &&
                         small_ok && !small.answered;

        printf("\n%s\n", good
               ? "OK: an unknown version is answered with the versions we do speak"
               : "FAIL: version negotiation is not what RFC 9000 §6 requires");

        return good ? 0 : 1;
    }

    printf("connecting to %s:%u\n", host, port);

    /* Two connections, so the second can present what the first was given.
     * Meaningful only against a server configured to Retry -- that is the round
     * trip the token is supposed to skip, and against a server that never
     * retries there is nothing to see. */
    /* 0-RTT (RFC 9001 §4.6): two connections, the second resuming the first and
     * sending its whole HTTP/3 request -- control stream, SETTINGS and all --
     * before the handshake completes.
     *
     * What this can and cannot prove. It proves the request travelled in 0-RTT
     * packets and was answered, which is the feature. It does not prove the
     * server delayed dispatch until the handshake finished: that is invisible
     * from a client that completes the handshake anyway, and is checked by the
     * unit test instead (docs/http3/09 §3.1). */
    /* The anti-replay property, made observable (RFC 8470 §5.2).
     *
     * A replaying attacker can deliver a captured 0-RTT flight but cannot
     * answer the server's -- it holds no key material. This models exactly
     * that: the request goes out in 0-RTT and every later client packet is
     * then dropped, so the handshake never completes. The server must not act
     * on the request, and the only way that is visible from out here is that
     * nothing of a response ever arrives.
     *
     * What it cannot see is a handler that ran and whose output went nowhere.
     * That distinction is enforced in __h3_attach (quicendpoint.c), where the
     * HTTP/3 layer is not attached at all before the connection is ACTIVE. */
    if (zero_rtt_stall) {
        quicclient_t first;

        printf("\n0-RTT REPLAY\n");

        if (!quicclient_connect(&first, host, port, authority, 0) ||
            !quicclient_run(&first, timeout_ms)) {
            printf("FAIL: the first connection did not complete\n");
            quicclient_free(&first);
            return 1;
        }

        for (int i = 0; i < 20 && first.session == NULL; i++)
            quicclient_pump(&first, 100);

        SSL_SESSION* session = quicclient_session_take(&first);
        quicclient_free(&first);

        if (session == NULL) {
            printf("FAIL: no ticket, so there is nothing to replay\n");
            return 1;
        }

        quicclient_t second;
        if (!quicclient_connect_resume(&second, host, port, authority, verbose,
                                       session, 1)) {
            printf("FAIL: the resumed connection did not start\n");
            SSL_SESSION_free(session);
            return 1;
        }

        uint8_t req[1024];
        const size_t reqlen = h3client_request_bytes(req, sizeof req, authority, path);
        const int sent = reqlen > 0 &&
                         h3client_start(&second) &&
                         quicclient_stream_write(&second, 0, req, reqlen, 1) &&
                         quicclient_flush(&second);

        const uint64_t early_packets = second.early_data_sent_packets;

        /* From here the client is deaf-mute in one direction: everything it
         * would send is dropped, so the server never gets a Finished and the
         * handshake cannot complete -- which is the position a replaying
         * attacker is in. */
        quicclient_impair(&second, 100, 0, 0, 0, 1);

        for (int i = 0; i < 20; i++) quicclient_pump(&second, 100);

        const size_t readable = quicclient_stream_readable(&second, 0);
        const int completed = second.handshake_done_received;

        quicclient_free(&second);
        SSL_SESSION_free(session);

        printf("0-RTT packets sent:        %llu\n", (unsigned long long)early_packets);
        printf("handshake confirmed:       %s\n", completed ? "yes" : "no");
        printf("response bytes received:   %zu\n", readable);

        const int good = sent && early_packets > 0 && !completed && readable == 0;
        printf("\n%s\n", good
               ? "OK: the request was not served without a completed handshake"
               : "FAIL: a 0-RTT request was answered before the handshake finished");
        return good ? 0 : 1;
    }

    if (zero_rtt) {
        quicclient_t first;

        printf("\n0-RTT\n");

        if (!quicclient_connect(&first, host, port, authority, 0) ||
            !quicclient_run(&first, timeout_ms)) {
            printf("FAIL: the first connection did not complete\n");
            quicclient_free(&first);
            return 1;
        }

        /* The ticket arrives after HANDSHAKE_DONE, so run() has already
         * returned by the time the server sends it. */
        for (int i = 0; i < 20 && first.session == NULL; i++)
            quicclient_pump(&first, 100);

        SSL_SESSION* session = quicclient_session_take(&first);
        quicclient_free(&first);

        printf("session ticket:            %s\n", session != NULL ? "yes" : "no");

        if (session == NULL) {
            printf("\nFAIL: no ticket, so there is nothing to resume\n");
            return 1;
        }

        quicclient_t second;
        if (!quicclient_connect_resume(&second, host, port, authority, verbose,
                                       session, 1)) {
            printf("\nFAIL: the resumed connection did not start\n");
            SSL_SESSION_free(session);
            return 1;
        }

        /* Everything below goes out before a single server packet has been
         * read: the control stream, SETTINGS and the request itself ride in
         * 0-RTT packets alongside the ClientHello. */
        const int started = h3client_start(&second);

        h3client_response_t early;
        const int got = started &&
                        h3client_get(&second, 0, authority, path, timeout_ms, &early);

        const uint64_t early_packets = second.early_data_sent_packets;
        const int accepted = quicclient_early_data_accepted(&second);
        const int status = early.status;
        const size_t body_len = early.body_len;

        h3client_response_free(&early);
        quicclient_free(&second);
        SSL_SESSION_free(session);

        printf("0-RTT packets sent:        %llu\n", (unsigned long long)early_packets);
        printf("early data accepted:       %s\n", accepted ? "yes" : "no");
        printf("response:                  %d, %zu bytes\n", status, body_len);

        const int good = got && accepted && early_packets > 0 &&
                         status >= 200 && status < 400;
        printf("\n%s\n", good ? "OK: the request was served from 0-RTT"
                                : "FAIL: 0-RTT did not carry the request");
        return good ? 0 : 1;
    }

    if (new_token) {
        quicclient_t first;
        uint8_t token[256];
        size_t token_len = 0;

        if (quicclient_connect(&first, host, port, authority, 0) &&
            quicclient_run(&first, timeout_ms)) {
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
                        quicclient_run(&second, timeout_ms);
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

    int ok = quicclient_run(&client, timeout_ms);
    client.pause_after_request_ms = pause_after_request_ms;
    client.pause_after_response_ms = pause_after_response_ms;

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

    /* A reload test needs a deterministic point at which the connection has a
     * live 1-RTT CID but no request has been sent yet.  Sleeping before the
     * handshake would test only Initial routing; sleeping after the response
     * would not prove the old routing/config context can still dispatch. */
    if (ok && pause_after_handshake_ms > 0) {
        printf("pausing after handshake %d ms\n", pause_after_handshake_ms);
        fflush(stdout);
        usleep((useconds_t)pause_after_handshake_ms * 1000);
    }

    /* An idle peer, as opposed to a dead one -- the only way to test a server's
     * keep-alive.
     *
     * --pause-after-handshake sleeps, and a sleeping client acknowledges
     * nothing. That is the wrong model here: RFC 9000 §10.1 restarts the idle
     * timer on a packet *received*, so a server's keep-alive PING preserves the
     * connection only because the peer answers it. Against a sleeping client
     * the PINGs go unanswered, the server's own timer runs out regardless, and
     * the connection dies -- which looks exactly like a keep-alive that does
     * not work, and is not.
     *
     * A browser with a quiet tab is not asleep; its stack still acknowledges.
     * So this pumps the loop and sends nothing of its own. */
    if (ok && idle_ms > 0) {
        printf("idling %d ms (acknowledging, sending nothing)\n", idle_ms);
        fflush(stdout);

        const uint64_t deadline = quic_now_us() + (uint64_t)idle_ms * 1000;
        uint64_t now;

        while ((now = quic_now_us()) < deadline) {
            const uint64_t left_ms = (deadline - now) / 1000;
            const int slice = left_ms > 200 ? 200 : (int)left_ms + 1;

            if (!quicclient_pump(&client, slice)) {
                printf("FAIL: the connection failed during %d ms of silence\n",
                       idle_ms);
                ok = 0;
                break;
            }

            quicclient_tick(&client);
        }

        /* Deliberately not "still connected": a server that gave up on an idle
         * connection says nothing at all about it, so silence here is not
         * evidence of a live connection. The request that follows is the only
         * thing that can tell the two apart. */
        if (ok)
            printf("idle period elapsed without error\n");
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

    /* Printed always and not only under -v: it is what a gate stage greps for,
     * and the version a connection ended in is the whole observable of
     * compatible version negotiation (RFC 9368). */
    if (ok) {
        printf("quic version: %08x\n", quicclient_version(&client));
        printf("switch packet carried crypto: %s\n",
               quicclient_switch_packet_carried_crypto(&client) ? "yes" : "no");
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

    /* ---- Mixed response sizes on one connection ---- *
     *
     * What the send path does when a small response is asked for while a large
     * one is already flowing. The three phases are not three measurements of
     * the same thing; the second and third are what make the first mean
     * anything:
     *
     *  1. the small response alone, which is what it costs when nothing else is
     *     in the way;
     *  2. the large one first on the lower stream id, the small one after
     *     `--mix-delay`;
     *  3. the same two, the same delay, the same bytes moving -- with only the
     *     stream ids swapped, so the small one sits ahead of the large one in
     *     the server's list.
     *
     * Phase 3 is the control, and it is the reason this can conclude anything
     * at all. A small response that is slow in phase 2 could be the server's
     * choice of what to send next or it could be this client, busy reading tens
     * of megabytes and getting to the small stream late (docs/http3/08 §7c is
     * that mistake, made once already). Phase 3 keeps the client's load
     * identical and changes only the order the server sees, so whatever
     * survives that swap is the server's. */
    if (mix_path != NULL) {
        printf("\nMIXED SIZES (big %s, small %s)\n", path, mix_path);

        if (!h3client_start(&client)) {
            printf("FAIL: could not open the control stream\n");
            quicclient_free(&client);
            return 1;
        }

        /* Generous, and per phase: a 64 MB body over loopback is fast, the same
         * body under a sanitiser is not, and a timeout that fits the first
         * would report the second as a server failure. */
        const int mix_timeout = timeout_ms > 30000 ? timeout_ms : 30000;

        h3client_leg_t alone = { .stream_id = 0, .path = mix_path, .start_ms = 0 };

        h3client_leg_t behind[2] = {
            { .stream_id = 4, .path = path,     .start_ms = 0 },
            { .stream_id = 8, .path = mix_path, .start_ms = mix_delay_ms },
        };

        /* The big one on the higher id, so the small one is ahead of it in the
         * server's list: streams are opened in id order regardless of which was
         * used first, so asking for 16 creates 12 alongside it. */
        h3client_leg_t ahead[2] = {
            { .stream_id = 16, .path = path,     .start_ms = 0 },
            { .stream_id = 12, .path = mix_path, .start_ms = mix_delay_ms },
        };

        /* The same arrangement as `behind` -- large one first, small one second
         * and later -- with the small request carrying a `priority` header
         * field. Everything the server could use to serve it sooner is
         * identical except the signal, which is the only way to attribute a
         * difference to the signal. */
        h3client_leg_t signalled[2] = {
            { .stream_id = 20, .path = path,     .start_ms = 0 },
            { .stream_id = 24, .path = mix_path, .start_ms = mix_delay_ms,
              .priority = mix_priority },
        };

        /* And the same again, signalled by a PRIORITY_UPDATE frame that is sent
         * *before* the request it prioritises -- the case where the server has
         * no stream to apply it to yet. */
        h3client_leg_t framed[2] = {
            { .stream_id = 28, .path = path,     .start_ms = 0 },
            { .stream_id = 32, .path = mix_path, .start_ms = mix_delay_ms },
        };

        /* Two large responses of the same size, asked for together. Whether
         * they come back one after the other or side by side is the whole of
         * what `i` means (§10), and the ratio of their completion times says
         * which happened without needing a byte-level trace. */
        h3client_leg_t sequential[2] = {
            { .stream_id = 36, .path = path, .start_ms = 0 },
            { .stream_id = 40, .path = path, .start_ms = 0 },
        };

        h3client_leg_t incremental[2] = {
            { .stream_id = 44, .path = path, .start_ms = 0, .priority = "u=3, i" },
            { .stream_id = 48, .path = path, .start_ms = 0, .priority = "u=3, i" },
        };

        int mix_ok = h3client_get_staggered(&client, &alone, 1, authority, mix_timeout);
        if (mix_ok)
            mix_ok = h3client_get_staggered(&client, behind, 2, authority, mix_timeout);
        if (mix_ok)
            mix_ok = h3client_get_staggered(&client, ahead, 2, authority, mix_timeout);
        if (mix_ok)
            mix_ok = h3client_get_staggered(&client, signalled, 2, authority, mix_timeout);
        if (mix_ok)
            mix_ok = h3client_priority_update(&client, framed[1].stream_id, mix_priority) &&
                     h3client_get_staggered(&client, framed, 2, authority, mix_timeout);
        if (mix_ok)
            mix_ok = h3client_get_staggered(&client, sequential, 2, authority, mix_timeout);
        if (mix_ok)
            mix_ok = h3client_get_staggered(&client, incremental, 2, authority, mix_timeout);

        if (!mix_ok) {
            printf("FAIL: not every response completed\n");
            quicclient_free(&client);
            return 1;
        }

        const double alone_ms   = (double)(alone.done_us - alone.sent_us) / 1000.0;
        const double big_ms     = (double)(behind[0].done_us - behind[0].sent_us) / 1000.0;
        const double behind_ms  = (double)(behind[1].done_us - behind[1].sent_us) / 1000.0;
        const double behind_fb  = (double)(behind[1].first_byte_us - behind[1].sent_us) / 1000.0;
        const double ahead_big  = (double)(ahead[0].done_us - ahead[0].sent_us) / 1000.0;
        const double ahead_ms   = (double)(ahead[1].done_us - ahead[1].sent_us) / 1000.0;
        const double ahead_fb   = (double)(ahead[1].first_byte_us - ahead[1].sent_us) / 1000.0;
        const double signal_big = (double)(signalled[0].done_us - signalled[0].sent_us) / 1000.0;
        const double signal_ms  = (double)(signalled[1].done_us - signalled[1].sent_us) / 1000.0;
        const double framed_big = (double)(framed[0].done_us - framed[0].sent_us) / 1000.0;
        const double framed_ms  = (double)(framed[1].done_us - framed[1].sent_us) / 1000.0;

        printf("stagger:                   %d ms\n", mix_delay_ms);
        printf("priority signalled:        %s\n", mix_priority);
        printf("big body:                  %zu bytes\n", behind[0].body_len);
        printf("small body:                %zu bytes\n", alone.body_len);
        printf("small alone:               %.1f ms\n", alone_ms);
        printf("small behind the big one:  %.1f ms (first byte %.1f)\n", behind_ms, behind_fb);
        printf("  big alongside it:        %.1f ms\n", big_ms);
        printf("small ahead of it:         %.1f ms (first byte %.1f)\n", ahead_ms, ahead_fb);
        printf("  big alongside it:        %.1f ms\n", ahead_big);
        printf("small with priority field: %.1f ms\n", signal_ms);
        printf("  big alongside it:        %.1f ms\n", signal_big);
        printf("small with priority frame: %.1f ms\n", framed_ms);
        printf("  big alongside it:        %.1f ms\n", framed_big);

        /* Which of the pair finished first, over which finished last. One means
         * they shared the connection all the way; a half means one was served
         * to completion before the other started. */
        const double seq_first = (double)(sequential[0].done_us - sequential[0].sent_us) / 1000.0;
        const double seq_last  = (double)(sequential[1].done_us - sequential[1].sent_us) / 1000.0;
        const double inc_first = (double)(incremental[0].done_us - incremental[0].sent_us) / 1000.0;
        const double inc_last  = (double)(incremental[1].done_us - incremental[1].sent_us) / 1000.0;

        const double seq_ratio = seq_last > 0 ? seq_first / seq_last : 0;
        const double inc_ratio = inc_last > 0 ? inc_first / inc_last : 0;

        printf("two large, sequential:     %.1f / %.1f ms (ratio %.2f)\n",
               seq_first, seq_last, seq_ratio);
        printf("two large, incremental:    %.1f / %.1f ms (ratio %.2f)\n",
               inc_first, inc_last, inc_ratio);

        /* The number this exists to produce: what the small response pays for
         * being asked for second, with the client's own load subtracted by the
         * control rather than assumed away. */
        printf("scheduling cost:           %.1f ms\n", behind_ms - ahead_ms);

        const h3client_leg_t* every[] = {
            &alone, &behind[0], &behind[1], &ahead[0], &ahead[1],
            &signalled[0], &signalled[1], &framed[0], &framed[1],
            &sequential[0], &sequential[1], &incremental[0], &incremental[1]
        };

        int sizes_ok = alone.body_len > 0 && behind[0].body_len > 0;
        int status_ok = 1;

        for (size_t i = 0; i < sizeof every / sizeof every[0]; i++) {
            const size_t expected = every[i]->path == path ? behind[0].body_len
                                                           : alone.body_len;
            if (every[i]->body_len != expected) sizes_ok = 0;
            if (every[i]->status != 200) status_ok = 0;
        }

        if (!sizes_ok) printf("FAIL: the same file arrived at different lengths\n");
        if (!status_ok) printf("FAIL: not every response was a 200\n");

        quicclient_free(&client);
        printf("\n%s: mixed-size scheduling measured\n",
               sizes_ok && status_ok ? "OK" : "FAIL");
        return sizes_ok && status_ok ? 0 : 1;
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
    else if (h3_ok && repeat > 1) {
        for (int i = 0; i < repeat && h3_ok; i++) {
            h3client_response_free(&response);
            memset(&response, 0, sizeof response);

            /* Client-initiated bidirectional stream ids: 0, 4, 8, ... */
            h3_ok = h3client_get(&client, (uint64_t)(4 * i), authority, path,
                                 timeout_ms, &response);
        }

        if (!h3_ok) printf("FAIL: a request in the sequence did not complete\n");
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

    if (h3_ok && repeat > 1)
        printf("sequential requests:       %d\n", repeat);

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
