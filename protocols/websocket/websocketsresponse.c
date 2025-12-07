#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <zlib.h>

#include "helpers.h"
#include "websocketsresponse.h"
#include "wscontext.h"
#include "connection_s.h"
#include "websocketsparser.h"

/** Minimum payload size to enable compression */
#define WS_COMPRESS_THRESHOLD 128

typedef enum {
    FILE_OK = 0,
    FILE_FORBIDDEN = 0,
    FILE_NOTFOUND = 0,
} file_status_e;

void websocketsresponse_text(websocketsresponse_t*, const char*);
void websocketsresponse_textn(websocketsresponse_t*, const char*, size_t);
void websocketsresponse_binary(websocketsresponse_t*, const char*);
void websocketsresponse_binaryn(websocketsresponse_t*, const char*, size_t);
void websocketsresponse_data(wsctx_t*, const char*);
void websocketsresponse_datan(wsctx_t*, const char*, size_t);
int websocketsresponse_file(websocketsresponse_t*, const char*);
int websocketsresponse_filen(websocketsresponse_t*, const char*, size_t);
size_t websocketsresponse_data_size(size_t);
size_t websocketsresponse_file_size(size_t);
int websocketsresponse_prepare(websocketsresponse_t*, const char*, size_t);
void websocketsresponse_reset(websocketsresponse_t*);
int websocketsresponse_set_payload_length(char*, size_t*, size_t);
file_status_e __get_file_full_path(server_t* server, char* file_full_path, size_t file_full_path_size, const char* path, size_t length);
static int __compress_and_send(websocketsresponse_t* response, unsigned char opcode, const char* data, size_t length);

websocketsresponse_t* websocketsresponse_alloc() {
    return malloc(sizeof(websocketsresponse_t));
}

void websocketsresponse_free(void* arg) {
    websocketsresponse_t* response = (websocketsresponse_t*)arg;

    websocketsresponse_reset(response);

    free(response);

    response = NULL;
}

websocketsresponse_t* websocketsresponse_create(connection_t* connection) {
    websocketsresponse_t* response = websocketsresponse_alloc();

    if (response == NULL) return NULL;

    response->frame_code = 0;
    response->body.data = NULL;
    response->body.pos = 0;
    response->body.size = 0;
    response->file_.fd = 0;
    response->file_.pos = 0;
    response->file_.size = 0;
    response->connection = connection;
    response->send_text = websocketsresponse_text;
    response->send_textn = websocketsresponse_textn;
    response->send_binary = websocketsresponse_binary;
    response->send_binaryn = websocketsresponse_binaryn;
    response->send_data = websocketsresponse_data;
    response->send_datan = websocketsresponse_datan;
    response->send_file = websocketsresponse_file;
    response->send_filen = websocketsresponse_filen;
    response->base.reset = (void(*)(void*))websocketsresponse_reset;
    response->base.free = (void(*)(void*))websocketsresponse_free;

    connection_server_ctx_t* ctx = connection->ctx;
    websocketsparser_t* parser = ctx->parser;
    response->ws_deflate = parser ? &parser->ws_deflate : NULL;

    return response;
}

void websocketsresponse_reset(websocketsresponse_t* response) {
    response->frame_code = 0;
    response->body.pos = 0;
    response->body.size = 0;

    if (response->file_.fd > 0) {
        lseek(response->file_.fd, 0, SEEK_SET);
        close(response->file_.fd);
    }

    response->file_.fd = 0;
    response->file_.pos = 0;
    response->file_.size = 0;

    if (response->body.data) free(response->body.data);
    response->body.data = NULL;
}

size_t websocketsresponse_data_size(size_t length) {
    size_t size = 0;

    size += 1; // fin, opcode

    // mask, payload length
    if (length <= 125) {
        size += 1;
    }
    else if (length <= 65535) {
        size += 3;
    }
    else {
        size += 9;
    }

    size += length;

    return size;
}

size_t websocketsresponse_file_size(size_t length) {
    size_t size = 0;

    size += 1; // fin, opcode

    // mask, payload length
    if (length <= 125) {
        size += 1;
    }
    else if (length <= 65535) {
        size += 3;
    }
    else {
        size += 9;
    }

    return size;
}

int websocketsresponse_prepare(websocketsresponse_t* response, const char* body, size_t length) {
    char* data = malloc(response->body.size);
    if (data == NULL) return -1;

    size_t pos = 0;

    if (!data_append(data, &pos, (const char*)&response->frame_code, 1)) return -1;

    if (websocketsresponse_set_payload_length(data, &pos, length) == -1) return -1;

    if (body != NULL && !data_append(data, &pos, body, length)) return -1;

    response->body.data = data;

    return 0;
}

int websocketsresponse_set_payload_length(char* data, size_t* pos, size_t payload_length) {
    if (payload_length <= 125) {
        data[(*pos)++] = payload_length;
    }
    else if (payload_length <= 65535) {
        data[(*pos)++] = 126; // 16 bit length follows
        data[(*pos)++] = (payload_length >> 8) & 0xFF; // leftmost first
        data[(*pos)++] = payload_length & 0xFF;
    }
    else { // >2^16-1 (65535)
        data[(*pos)++] = 127; // 64 bit length follows

        // since msg_length is int it can be no longer than 4 bytes = 2^32-1
        // padd zeroes for the first 4 bytes
        for (int i = 3; i >= 0; i--) {
            data[(*pos)++] = 0;
        }
        // write the actual 32bit msg_length in the next 4 bytes
        for (int i = 3; i >= 0; i--) {
            data[(*pos)++] = ((payload_length >> 8*i) & 0xFF);
        }
    }

    return 0;
}

void websocketsresponse_text(websocketsresponse_t* response, const char* data) {
    websocketsresponse_textn(response, data, strlen(data));
}

void websocketsresponse_textn(websocketsresponse_t* response, const char* data, size_t length) {
    /* Try compression if extension is enabled and payload is large enough */
    if (response->ws_deflate && response->ws_deflate->deflate_init && length >= WS_COMPRESS_THRESHOLD) {
        if (__compress_and_send(response, 0x01, data, length))
            return;
        /* Fall through to uncompressed on compression failure */
    }

    response->frame_code = 0x81;  /* FIN=1, opcode=text */
    response->body.size = websocketsresponse_data_size(length);
    websocketsresponse_prepare(response, data, length);
}

void websocketsresponse_binary(websocketsresponse_t* response, const char* data) {
    websocketsresponse_binaryn(response, data, strlen(data));
}

void websocketsresponse_binaryn(websocketsresponse_t* response, const char* data, size_t length) {
    /* Try compression if extension is enabled and payload is large enough */
    if (response->ws_deflate && response->ws_deflate->deflate_init && length >= WS_COMPRESS_THRESHOLD) {
        if (__compress_and_send(response, 0x02, data, length))
            return;
        /* Fall through to uncompressed on compression failure */
    }

    response->frame_code = 0x82;  /* FIN=1, opcode=binary */
    response->body.size = websocketsresponse_data_size(length);
    websocketsresponse_prepare(response, data, length);
}

void websocketsresponse_data(wsctx_t* ctx, const char* data) {
    websocketsresponse_datan(ctx, data, strlen(data));
}

void websocketsresponse_datan(wsctx_t* ctx, const char* data, size_t length) {
    if (ctx->request->type == WEBSOCKETS_TEXT) {
        websocketsresponse_textn(ctx->response, data, length);
        return;
    }

    websocketsresponse_binaryn(ctx->response, data, length);
}

int websocketsresponse_file(websocketsresponse_t* response, const char* path) {
    return websocketsresponse_filen(response, path, strlen(path));
}

int websocketsresponse_filen(websocketsresponse_t* response, const char* path, size_t length) {
    char file_full_path[PATH_MAX];
    connection_t* connection = response->connection;
    connection_server_ctx_t* ctx = connection->ctx;
    const file_status_e status = __get_file_full_path(ctx->server, file_full_path, PATH_MAX, path, length);
    if (status == FILE_FORBIDDEN) {
        websocketsresponse_default(response, "resource forbidden");
        return -1;
    }
    else if (status == FILE_NOTFOUND) {
        websocketsresponse_default(response, "resource not found");
        return -1;
    }

    response->file_.fd = open(file_full_path, O_RDONLY);
    if (response->file_.fd == -1) return -1;

    response->file_.size = (size_t)lseek(response->file_.fd, 0, SEEK_END);

    lseek(response->file_.fd, 0, SEEK_SET);

    response->frame_code = 0x82;
    response->body.size = websocketsresponse_file_size(response->file_.size);

    if (websocketsresponse_prepare(response, NULL, response->file_.size) == -1) return -1;

    return 0;
}

file_status_e __get_file_full_path(server_t* server, char* file_full_path, size_t file_full_path_size, const char* path, size_t length) {
    size_t pos = 0;

    if (!data_appendn(file_full_path, &pos, file_full_path_size, server->root, server->root_length))
        return FILE_NOTFOUND;

    if (path[0] != '/')
        if (!data_appendn(file_full_path, &pos, file_full_path_size, "/", 1))
            return FILE_NOTFOUND;

    if (!data_appendn(file_full_path, &pos, file_full_path_size, path, length))
        return FILE_NOTFOUND;

    file_full_path[pos] = 0;

    struct stat stat_obj;
    if (stat(file_full_path, &stat_obj) == -1 && errno == ENOENT)
        return FILE_NOTFOUND;

    if (S_ISDIR(stat_obj.st_mode))
        return FILE_FORBIDDEN;

    if (!S_ISREG(stat_obj.st_mode))
        return FILE_NOTFOUND;

    return FILE_OK;
}

void websocketsresponse_default(websocketsresponse_t* response, const char* text) {
    websocketsresponse_reset(response);
    websocketsresponse_text(response, text);
}

void websocketsresponse_pong(websocketsresponse_t* response, const char* data, size_t length) {
    websocketsresponse_reset(response);

    response->frame_code = 0x8A;

    response->body.size = websocketsresponse_data_size(length);

    websocketsresponse_prepare(response, data, length);
}

void websocketsresponse_close(websocketsresponse_t* response, const char* data, size_t length) {
    websocketsresponse_reset(response);

    response->frame_code = 0x88;

    response->body.size = websocketsresponse_data_size(length);

    websocketsresponse_prepare(response, data, length);
}

/**
 * Compress data and prepare WebSocket frame with RSV1 bit set.
 * Per RFC 7692: use raw deflate, remove trailing 0x00 0x00 0xff 0xff.
 * @return 1 on success, 0 on failure (caller should fall back to uncompressed)
 */
static int __compress_and_send(websocketsresponse_t* response, unsigned char opcode, const char* data, size_t length) {
    ws_deflate_t* ws_deflate_ctx = response->ws_deflate;
    z_stream* stream = &ws_deflate_ctx->deflate_stream;

    /* Allocate compression buffer (worst case: slightly larger than input) */
    size_t comp_capacity = length + 64;
    char* compressed = malloc(comp_capacity);
    if (compressed == NULL)
        return 0;

    stream->next_in = (Bytef*)data;
    stream->avail_in = (uInt)length;
    stream->next_out = (Bytef*)compressed;
    stream->avail_out = (uInt)comp_capacity;

    int status = deflate(stream, Z_SYNC_FLUSH);
    if (status != Z_OK && status != Z_BUF_ERROR) {
        free(compressed);
        return 0;
    }

    size_t comp_size = comp_capacity - stream->avail_out;

    /* Remove trailing 0x00 0x00 0xff 0xff per RFC 7692 */
    if (comp_size >= 4 &&
        (unsigned char)compressed[comp_size - 4] == 0x00 &&
        (unsigned char)compressed[comp_size - 3] == 0x00 &&
        (unsigned char)compressed[comp_size - 2] == 0xff &&
        (unsigned char)compressed[comp_size - 1] == 0xff) {
        comp_size -= 4;
    }

    /* Only use compression if it actually reduces size */
    if (comp_size >= length) {
        free(compressed);
        ws_deflate_reset_deflate(ws_deflate_ctx);
        return 0;
    }

    /* Set frame code: FIN=1, RSV1=1 (compressed), opcode */
    response->frame_code = 0x80 | 0x40 | opcode;  /* 0xC1 for text, 0xC2 for binary */
    response->body.size = websocketsresponse_data_size(comp_size);

    int result = websocketsresponse_prepare(response, compressed, comp_size);

    free(compressed);

    /* Reset deflate stream if server_no_context_takeover */
    ws_deflate_reset_deflate(ws_deflate_ctx);

    return result == 0 ? 1 : 0;
}
