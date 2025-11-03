#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>

#include "helpers.h"
#include "websocketsrequest.h"

void websocketsrequest_payload_free(websockets_payload_t*);
int websocketsrequest_get_default(connection_t*);
int websocketsrequest_get_resource(connection_t*);

void websockets_protocol_init_payload(websockets_protocol_t* protocol) {
    protocol->payload.fd = 0;
    protocol->payload.path = NULL;
}

websocketsrequest_t* websocketsrequest_alloc() {
    return malloc(sizeof(websocketsrequest_t));
}

void websocketsrequest_free(void* arg) {
    websocketsrequest_t* request = (websocketsrequest_t*)arg;

    websocketsrequest_reset(request);
    request->protocol->free(request->protocol);

    free(request);

    request = NULL;
}

websocketsrequest_t* websocketsrequest_create(connection_t* connection, websockets_protocol_t* protocol) {
    if (protocol == NULL) return NULL;

    websocketsrequest_t* request = websocketsrequest_alloc();
    if (request == NULL) return NULL;

    request->type = WEBSOCKETS_NONE;
    request->can_reset = 1;
    request->fragmented = 0;
    request->protocol = protocol;
    request->connection = connection;
    request->base.reset = (void(*)(void*))websocketsrequest_reset;
    request->base.free = (void(*)(void*))websocketsrequest_free;

    return request;
}

void websocketsrequest_reset(websocketsrequest_t* request) {
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
    if (payload->fd <= 0) return;

    close(payload->fd);
    unlink(payload->path);

    payload->fd = 0;

    free(payload->path);
    payload->path = NULL;
}

int websockets_create_tmpfile(websockets_protocol_t* protocol, const char* tmp_dir) {
    if (protocol->payload.fd) return 1;

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
    if (protocol->payload.fd <= 0) return NULL;

    off_t payload_size = lseek(protocol->payload.fd, 0, SEEK_END);
    lseek(protocol->payload.fd, 0, SEEK_SET);

    char* buffer = malloc(payload_size + 1);
    if (buffer == NULL) return NULL;

    int r = read(protocol->payload.fd, buffer, payload_size);
    lseek(protocol->payload.fd, 0, SEEK_SET);

    buffer[payload_size] = 0;

    if (r < 0) {
        free(buffer);
        buffer = NULL;
    }

    return buffer;
}

file_content_t websocketsrequest_payload_file(websockets_protocol_t* protocol) {
    const char* filename = "tmpfile";
    file_content_t file_content = file_content_create(0, filename, 0, 0);

    off_t payload_size = lseek(protocol->payload.fd, 0, SEEK_END);
    lseek(protocol->payload.fd, 0, SEEK_SET);

    file_content.ok = payload_size > 0;
    file_content.fd = protocol->payload.fd;
    file_content.offset = 0;
    file_content.size = payload_size;

    return file_content;
}

json_doc_t* websocketsrequest_payload_json(websockets_protocol_t* protocol) {
    char* payload = websocketsrequest_payload(protocol);
    if (payload == NULL) return NULL;

    json_doc_t* document = json_parse(payload);

    free(payload);

    return document;
}
