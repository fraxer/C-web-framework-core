/* Real QUIC body probe using the existing test client's transport and codecs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <dirent.h>
#include "quictime.h"
#include "h3client.h"
#include "bodystore.h"

static int body_files(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) return -1;
    int count = 0;
    struct dirent* entry;
    while ((entry = readdir(dir)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    closedir(dir);
    return count;
}

int main(int argc, char** argv) {
    if (argc != 3 && argc != 6) return 2;
    const char* mode = argc == 6 ? argv[3] : "auto";
    size_t threshold = argc == 6 ? strtoul(argv[4], NULL, 10) : BODY_STORE_DEFAULT_FILE_THRESHOLD;
    int policy_only = argc == 6 && atoi(argv[5]);
    quicclient_t* client = calloc(1, sizeof(*client));
    if (!client || !quicclient_connect(client, "127.0.0.1", atoi(argv[1]), "localhost", 0) ||
        !quicclient_run(client, 8000) || !h3client_start(client)) return 1;
    const size_t sizes[] = {0, 1, 200, 20000, BODY_STORE_DEFAULT_FILE_THRESHOLD-1,
                            BODY_STORE_DEFAULT_FILE_THRESHOLD, BODY_STORE_DEFAULT_FILE_THRESHOLD+1,
                            threshold ? threshold-1 : 0, threshold, threshold+1};
    unsigned calls = 0;
    for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); ++i) {
        if (i >= 7 && !policy_only) break;
        size_t size = sizes[i];
        if (size > 2097153) continue;
        char* body = malloc(size+1);
        if (!body) return 1;
        for (size_t j = 0; j < size; ++j) body[j] = (char)(j % 256);
        unsigned char digest[32]; char hex[65];
        SHA256((unsigned char*)body, size, digest);
        for (size_t j = 0; j < 32; ++j) snprintf(hex+2*j, 3, "%02x", digest[j]);
        h3client_response_t response = {0};
        uint64_t id = 4*i;
        if (!h3client_post_expect(client, id, "localhost", "/body", body, size, 15000, &response) ||
            response.status != 200 || !response.body || !strstr(response.body, hex)) return 1;
        char expected[80];
        snprintf(expected, sizeof(expected), "\"size\":%zu,\"state\":%d", size,
                 size == 0 ? BODY_STORE_EMPTY : (strcmp(mode, "file") == 0 || (strcmp(mode, "auto") == 0 && size >= threshold)) ? BODY_STORE_FILE : BODY_STORE_MEMORY);
        if (!strstr(response.body, expected)) return 1;
        calls++;
        h3client_response_free(&response);
        quicclient_stream_release(client, id);
        free(body);
    }
    if (policy_only) {
        quicclient_close(client,0,0);
        for (int j = 0; j < 3; ++j) quicclient_pump(client,10);
        quicclient_free(client);
        free(client);
        printf("{\"calls\":%u,\"cancelled_streams\":0,\"spilled_cancelled_streams\":0}\n", calls);
        return 0;
    }
    const uint64_t cancel_base = 4 * calls;
    /* Several unfinished POSTs coexist, then RESET_STREAM must drain them. */
    qpack_encoder_t* enc = qpack_encoder_create(0,0);
    qpack_header_t fields[] = {{":method",7,"POST",4,0}, {":scheme",7,"https",5,0},
        {":authority",10,"localhost",9,0}, {":path",5,"/body",5,0}};
    uint8_t block[512], wire[4096], data[2048];
    memset(data, 'x', sizeof(data));
    size_t n = qpack_encode_block(enc, fields, 4, block, sizeof(block));
    qpack_encoder_free(enc);
    n = h3frame_write(wire, sizeof(wire), H3_FRAME_HEADERS, block, n);
    for (unsigned i = 0; i < 4; ++i) {
        uint64_t id = cancel_base+4*i;
        if (!quicclient_stream_write(client,id,wire,n,0)) return 1;
    }
    for (unsigned j = 0; j < 520; ++j) {
        size_t len = h3frame_write(wire,sizeof(wire),H3_FRAME_DATA,data,sizeof(data));
        for (unsigned i = 0; i < 4; ++i)
            if (!quicclient_stream_write(client,cancel_base+4*i,wire,len,0)) return 1;
        if (!quicclient_pump(client,1)) return 1;
    }
    for (int j = 0; j < 10; ++j) if (!quicclient_pump(client,20)) return 1;
    uint64_t deadline = quic_now_us() + 8000000;
    while (body_files(argv[2]) != 4 && quic_now_us() < deadline)
        if (!quicclient_pump(client,20)) return 1;
    if (body_files(argv[2]) != 4) {
        fprintf(stderr, "H3 cancellation did not reach four spilled bodies\n");
        return 1;
    }
    for (unsigned i = 0; i < 4; ++i)
        if (!quicclient_reset_stream(client,cancel_base+4*i,0x10c)) return 1;
    for (int j = 0; j < 10; ++j) if (!quicclient_pump(client,20)) return 1;
    h3client_response_t response = {0};
    if (!h3client_get(client,cancel_base+20,"localhost","/stats",8000,&response) || response.status != 200) return 1;
    h3client_response_free(&response);
    quicclient_close(client,0,0);
    for (int j = 0; j < 3; ++j) quicclient_pump(client,10);
    quicclient_free(client);
    free(client);
    printf("{\"calls\":%u,\"cancelled_streams\":4,\"spilled_cancelled_streams\":4}\n",calls);
    return 0;
}
