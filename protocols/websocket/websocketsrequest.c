#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "helpers.h"
#include "websocketsrequest.h"
#include "connection_s.h"

static void websocketsrequest_payload_free(websockets_payload_t*);
static void websocketsrequest_reset(void* arg);

void websockets_protocol_init_payload(websockets_protocol_t* protocol) {
    protocol->payload.fd = -1;
    protocol->payload.path = NULL;
}

void websocketsrequest_free(void* arg) {
    websocketsrequest_t* request = (websocketsrequest_t*)arg;

    /* can_reset == 0 makes reset a no-op, but on destruction the payload
     * tmpfile must be released unconditionally: protocol->free below does
     * not touch payload, so a skipped reset here leaks fd + path + inode. */
    request->can_reset = 1;
    websocketsrequest_reset(request);
    request->protocol->free(request->protocol);

    free(request);
}

websocketsrequest_t* websocketsrequest_create(connection_t* connection, websockets_protocol_t* protocol) {
    if (protocol == NULL) return NULL;

    websocketsrequest_t* request = malloc(sizeof * request);
    if (request == NULL) return NULL;

    request->type = WEBSOCKETS_NONE;
    request->can_reset = 1;
    request->fragmented = 0;
    request->compressed = 0;
    request->protocol = protocol;
    request->connection = connection;
    request->base.reset = websocketsrequest_reset;
    request->base.free = websocketsrequest_free;

    return request;
}

void websocketsrequest_reset(void* arg) {
    websocketsrequest_t* request = (websocketsrequest_t*)arg;

    if (request->can_reset) {
        if (request->type != WEBSOCKETS_PING && request->type != WEBSOCKETS_PONG)
            request->fragmented = 0;

        request->type = WEBSOCKETS_NONE;
        request->protocol->reset(request->protocol);

        websocketsrequest_payload_free(&request->protocol->payload);
    }

    request->can_reset = 1;
}

void websocketsrequest_payload_free(websockets_payload_t* payload) {
    if (payload->fd == -1) return;

    close(payload->fd);
    unlink(payload->path);

    payload->fd = -1;

    free(payload->path);
    payload->path = NULL;
}

int websockets_create_tmpfile(websockets_protocol_t* protocol, const char* tmp_dir) {
    if (protocol->payload.fd >= 0) return 1;

    protocol->payload.path = create_tmppath(tmp_dir);
    if (protocol->payload.path == NULL)
        return 0;

    protocol->payload.fd = mkstemp(protocol->payload.path);
    if (protocol->payload.fd == -1) {
        free(protocol->payload.path);
        protocol->payload.path = NULL;
        return 0;
    }

    return 1;
}

char* websocketsrequest_payload(websockets_protocol_t* protocol) {
    if (protocol->payload.fd < 0) return NULL;

    /* A failed lseek returns -1; without the guard malloc(payload_size + 1)
     * becomes malloc(0) and buffer[payload_size] writes at buffer[-1]. */
    off_t payload_size = lseek(protocol->payload.fd, 0, SEEK_END);
    if (payload_size < 0) return NULL;

    lseek(protocol->payload.fd, 0, SEEK_SET);

    char* buffer = malloc(payload_size + 1);
    if (buffer == NULL) return NULL;

    /* A single pread may legally return short (EINTR, the ~2 GiB Linux cap
     * per call, network filesystems), so read until the measured size. */
    size_t total = 0;
    while (total < (size_t)payload_size) {
        ssize_t r = pread(protocol->payload.fd, buffer + total, (size_t)payload_size - total, (off_t)total);

        if (r < 0) {
            if (errno == EINTR)
                continue;
            free(buffer);
            return NULL;
        }
        /* Early EOF: the file is shorter than measured — fail instead of
         * returning a string with an uninitialized tail. */
        if (r == 0) {
            free(buffer);
            return NULL;
        }

        total += (size_t)r;
    }

    buffer[payload_size] = 0;

    return buffer;
}

file_content_t websocketsrequest_payload_file(websockets_protocol_t* protocol) {
    const char* filename = "tmpfile";
    /* Start from an invalid descriptor so the no-payload result never leaks
     * fd 0 (stdin) to a caller that ignores .ok. */
    file_content_t file_content = file_content_create(-1, filename, 0, 0);

    if (protocol->payload.fd == -1) {
        file_content.ok = 0;
        return file_content;
    }

    off_t payload_size = lseek(protocol->payload.fd, 0, SEEK_END);
    lseek(protocol->payload.fd, 0, SEEK_SET);

    file_content.ok = payload_size > 0;
    file_content.fd = protocol->payload.fd;
    file_content.offset = 0;
    file_content.size = payload_size > 0 ? (size_t)payload_size : 0;

    return file_content;
}

json_doc_t* websocketsrequest_payload_json(websockets_protocol_t* protocol) {
    char* payload = websocketsrequest_payload(protocol);
    if (payload == NULL) return NULL;

    json_doc_t* document = json_parse(payload);

    free(payload);

    return document;
}
