#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "helpers.h"
#include "appconfig.h"
#include "websocketsrequest.h"
#include "connection_s.h"

static void websocketsrequest_payload_free(websockets_payload_t*);
static void websocketsrequest_reset(void* arg);

void websockets_protocol_init_payload(websockets_protocol_t* protocol) {
    const env_t* cfg = env();
    body_store_init(&protocol->payload.incoming, SIZE_MAX,
        cfg != NULL ? cfg->main.body_store.file_threshold : BODY_STORE_DEFAULT_FILE_THRESHOLD,
        cfg != NULL ? cfg->main.body_store.mode : BODY_STORE_MODE_FILE);
    protocol->payload.fd = -1;
    protocol->payload.path = NULL;
}

void websocketsrequest_free(void* arg) {
    websocketsrequest_t* request = (websocketsrequest_t*)arg;

    /* can_reset == 0 makes reset a no-op, but destruction must release
     * memory and files unconditionally: protocol->free does not own them. */
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
    request->out_queue = NULL;
    request->out_owner = NULL;
    request->out_wake = NULL;
    request->out_parallel = 0;
    request->out_deflate = NULL;

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
    body_store_reset(&payload->incoming);
    if (payload->fd >= 0)
        close(payload->fd);

    if (payload->path != NULL)
        unlink(payload->path);

    payload->fd = -1;

    free(payload->path);
    payload->path = NULL;
}

int websockets_create_tmpfile(websockets_protocol_t* protocol, const char* tmp_dir) {
    if (protocol->payload.incoming.failed) return 0;
    if (protocol->payload.fd >= 0) return 1;

    body_store_t* incoming = &protocol->payload.incoming;
    if (incoming->state != BODY_STORE_EMPTY) {
        if (!body_store_materialize(incoming, tmp_dir))
            return 0;

        protocol->payload.fd = incoming->fd;
        protocol->payload.path = incoming->path;
        incoming->fd = -1;
        incoming->path = NULL;
        body_store_reset(incoming);
        return 1;
    }

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

/* Borrow a custom protocol's fd only for this operation; never reset it. */
static const body_store_t* websockets_payload_reader(websockets_protocol_t* protocol,
                                                     body_store_t* legacy) {
    if (protocol->payload.incoming.state != BODY_STORE_EMPTY || protocol->payload.incoming.failed)
        return &protocol->payload.incoming;

    off_t size = lseek(protocol->payload.fd, 0, SEEK_END);
    lseek(protocol->payload.fd, 0, SEEK_SET);
    *legacy = (body_store_t){
        .state = BODY_STORE_FILE,
        .fd = protocol->payload.fd,
        .size = size >= 0 ? (size_t)size : 0,
        .failed = size < 0
    };

    return legacy;
}

size_t websocketsrequest_payload_size(websockets_protocol_t* protocol) {
    body_store_t legacy;
    return websockets_payload_reader(protocol, &legacy)->size;
}

int websocketsrequest_payload_read(websockets_protocol_t* protocol, size_t offset,
                                  void* data, size_t size) {
    body_store_t legacy;
    return body_store_read(websockets_payload_reader(protocol, &legacy), offset, data, size);
}

int websocketsrequest_payload_append(websockets_protocol_t* protocol, const void* data, size_t size) {
    env_t* cfg = env();
    const char* tmp = cfg != NULL && cfg->main.tmp != NULL ? cfg->main.tmp : "/tmp";
    size_t max = cfg != NULL ? cfg->main.client_max_body_size : SIZE_MAX;
    body_store_t* incoming = &protocol->payload.incoming;

    if (incoming->failed)
        return 0;

    if (protocol->payload.fd >= 0) {
        body_store_t legacy;
        websockets_payload_reader(protocol, &legacy);
        legacy.max_size = max;
        int ok = body_store_append(&legacy, data, size, tmp);
        if (!ok)
            incoming->failed = 1;

        return ok;
    }
    incoming->max_size = max;

    return body_store_append(incoming, data, size, tmp);
}

char* websocketsrequest_payload(websockets_protocol_t* protocol) {
    body_store_t legacy;
    const body_store_t* reader = websockets_payload_reader(protocol, &legacy);
    return body_store_copy(reader, 0, reader->size);
}

file_content_t websocketsrequest_payload_file(websockets_protocol_t* protocol) {
    const char* filename = "tmpfile";
    /* Start from an invalid descriptor so the no-payload result never leaks
     * fd 0 (stdin) to a caller that ignores .ok. */
    file_content_t file_content = file_content_create(-1, filename, 0, 0);
    file_content.ok = 0;

    if (protocol->payload.incoming.failed)
        return file_content;

    if (protocol->payload.fd < 0) {
        if (protocol->payload.incoming.state == BODY_STORE_EMPTY)
            return file_content;

        env_t* cfg = env();
        const char* tmp = cfg != NULL && cfg->main.tmp != NULL ? cfg->main.tmp : "/tmp";
        if (!websockets_create_tmpfile(protocol, tmp))
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
    if (protocol->payload.incoming.failed)
        return NULL;
    if (protocol->payload.incoming.state == BODY_STORE_MEMORY)
        return json_parse(protocol->payload.incoming.data);

    char* payload = websocketsrequest_payload(protocol);
    if (payload == NULL) return NULL;

    json_doc_t* document = json_parse(payload);

    free(payload);

    return document;
}
