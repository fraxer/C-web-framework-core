#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quicclient.h"

/* Drive a QUIC handshake against this server and report what happened.
 *
 *   quicclient [host] [port] [-q]
 *
 * Exists because nothing else on this machine can: the system curl is built
 * without HTTP/3, and no QUIC library is installed. Until phase 8 stands up the
 * interop runner, this is the only thing that can say whether a real handshake
 * completes. */

int main(int argc, char* argv[]) {
    const char* host = argc > 1 ? argv[1] : "127.0.0.1";
    const uint16_t port = argc > 2 ? (uint16_t)atoi(argv[2]) : 18443;

    int verbose = 1;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "-q") == 0) verbose = 0;

    printf("connecting to %s:%u\n", host, port);

    quicclient_t client;
    if (!quicclient_connect(&client, host, port, "localhost", verbose)) {
        printf("FAIL: could not send the first Initial\n");
        quicclient_free(&client);
        return 1;
    }

    const int ok = quicclient_run(&client, 5000);

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

    quicclient_free(&client);

    printf("\n%s\n", ok ? "OK: the handshake completed end to end"
                        : "FAIL: the handshake did not complete");

    return ok ? 0 : 1;
}
