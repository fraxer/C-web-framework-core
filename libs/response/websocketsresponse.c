#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "mimetype.h"
#include "helpers.h"
#include "websocketsrequest.h"
#include "websocketsresponse.h"

typedef enum {
    FILE_OK = 0,
    FILE_FORBIDDEN = 0,
    FILE_NOTFOUND = 0,
} file_status_e;

void websocketsresponse_text(websocketsresponse_t*, const char*);
void websocketsresponse_textn(websocketsresponse_t*, const char*, size_t);
void websocketsresponse_binary(websocketsresponse_t*, const char*);
void websocketsresponse_binaryn(websocketsresponse_t*, const char*, size_t);
void websocketsresponse_data(websocketsresponse_t*, const char*);
void websocketsresponse_datan(websocketsresponse_t*, const char*, size_t);
int websocketsresponse_file(websocketsresponse_t*, const char*);
int websocketsresponse_filen(websocketsresponse_t*, const char*, size_t);
size_t websocketsresponse_data_size(size_t);
size_t websocketsresponse_file_size(size_t);
int websocketsresponse_prepare(websocketsresponse_t*, const char*, size_t);
void websocketsresponse_reset(websocketsresponse_t*);
int websocketsresponse_set_payload_length(char*, size_t*, size_t);
file_status_e __get_file_full_path(server_t* server, char* file_full_path, size_t file_full_path_size, const char* path, size_t length);

websocketsresponse_t* websocketsresponse_alloc() {
    return (websocketsresponse_t*)malloc(sizeof(websocketsresponse_t));
}

void websocketsresponse_free(void* arg) {
    websocketsresponse_t* response = (websocketsresponse_t*)arg;

    websocketsresponse_reset(response);

    free(response);

    response = NULL;
}

websocketsresponse_t* websocketsresponse_create(connection_s_t* connection) {
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
    response->text = websocketsresponse_text;
    response->textn = websocketsresponse_textn;
    response->binary = websocketsresponse_binary;
    response->binaryn = websocketsresponse_binaryn;
    response->data = websocketsresponse_data;
    response->datan = websocketsresponse_datan;
    response->file = websocketsresponse_file;
    response->filen = websocketsresponse_filen;
    response->base.reset = (void(*)(void*))websocketsresponse_reset;
    response->base.free = (void(*)(void*))websocketsresponse_free;

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
    response->frame_code = 0x81;

    response->body.size = websocketsresponse_data_size(length);

    websocketsresponse_prepare(response, data, length);
}

void websocketsresponse_binary(websocketsresponse_t* response, const char* data) {
    websocketsresponse_binaryn(response, data, strlen(data));
}

void websocketsresponse_binaryn(websocketsresponse_t* response, const char* data, size_t length) {
    response->frame_code = 0x82;

    response->body.size = websocketsresponse_data_size(length);

    websocketsresponse_prepare(response, data, length);
}

void websocketsresponse_data(websocketsresponse_t* response, const char* data) {
    websocketsresponse_datan(response, data, strlen(data));
}

void websocketsresponse_datan(websocketsresponse_t* response, const char* data, size_t length) {
    connection_s_t* connection = response->connection;
    if (((websocketsrequest_t*)connection->request)->type == WEBSOCKETS_TEXT) {
        websocketsresponse_textn(response, data, length);
        return;
    }

    websocketsresponse_binaryn(response, data, length);
}

int websocketsresponse_file(websocketsresponse_t* response, const char* path) {
    return websocketsresponse_filen(response, path, strlen(path));
}

int websocketsresponse_filen(websocketsresponse_t* response, const char* path, size_t length) {
    char file_full_path[PATH_MAX];
    connection_s_t* connection = response->connection;
    const file_status_e status = __get_file_full_path(connection->listener->server, file_full_path, PATH_MAX, path, length);
    if (status == FILE_FORBIDDEN) {
        websocketsresponse_default_response(response, "resource forbidden");
        return -1;
    }
    else if (status == FILE_NOTFOUND) {
        websocketsresponse_default_response(response, "resource not found");
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

void websocketsresponse_default_response(websocketsresponse_t* response, const char* text) {
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
