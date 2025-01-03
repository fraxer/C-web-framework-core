#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>

#include "http1response.h"
#include "cookieparser.h"
#include "domain.h"
#include "log.h"
#include "appconfig.h"
#include "http1common.h"
#include "http1requestparser.h"
#include "helpers.h"

int http1parser_parse_payload(http1requestparser_t*);
int http1parser_set_method(http1request_t*, http1requestparser_t*);
int http1parser_set_protocol(http1request_t*, http1requestparser_t*);
int http1parser_set_header_key(http1request_t*, http1requestparser_t*);
int http1parser_set_header_value(http1request_t*, http1requestparser_t*);
int http1parser_set_path(http1request_t*, const char*, size_t);
int http1parser_set_ext(http1request_t*, const char*, size_t);
int http1parser_set_query(http1request_t*, const char*, size_t, size_t);
int http1parser_host_not_found(http1requestparser_t*);
void http1parser_try_set_keepalive(http1requestparser_t*);
void http1parser_try_set_range(http1requestparser_t*);
void http1parser_try_set_cookie(http1requestparser_t*);
void http1parser_try_set_content_length(http1requestparser_t*);
void http1parser_flush(http1requestparser_t*);


void http1parser_init(http1requestparser_t* parser) {
    parser->stage = HTTP1PARSER_METHOD;
    parser->host_found = 0;
    parser->bytes_readed = 0;
    parser->pos_start = 0;
    parser->pos = 0;
    parser->buffer = NULL;
    parser->connection = NULL;
    parser->content_length = 0;
    parser->content_saved_length = 0;

    bufferdata_init(&parser->buf);
}

void http1parser_set_connection(http1requestparser_t* parser, connection_t* connection) {
    parser->connection = connection;
}

void http1parser_set_buffer(http1requestparser_t* parser, char* buffer) {
    parser->buffer = buffer;
}

void http1parser_free(http1requestparser_t* parser) {
    http1parser_flush(parser);
    free(parser);
}

void http1parser_reset(http1requestparser_t* parser) {
    http1parser_flush(parser);
    http1parser_init(parser);
}

void http1parser_flush(http1requestparser_t* parser) {
    if (parser->buf.dynamic_buffer) free(parser->buf.dynamic_buffer);
    parser->buf.dynamic_buffer = NULL;
}

int http1parser_run(http1requestparser_t* parser) {
    http1request_t* request = (http1request_t*)parser->connection->request;
    parser->pos_start = 0;
    parser->pos = 0;

    if (parser->stage == HTTP1PARSER_PAYLOAD)
        return http1parser_parse_payload(parser);

    for (parser->pos = parser->pos_start; parser->pos < parser->bytes_readed; parser->pos++) {
        char ch = parser->buffer[parser->pos];

        switch (parser->stage)
        {
        case HTTP1PARSER_METHOD:
            if (ch == ' ') {
                parser->stage = HTTP1PARSER_URI;

                bufferdata_complete(&parser->buf);
                if (!http1parser_set_method(request, parser))
                    return HTTP1PARSER_BAD_REQUEST;

                bufferdata_reset(&parser->buf);
                break;
            }
            else {
                if (bufferdata_writed(&parser->buf) > 7)
                    return HTTP1PARSER_BAD_REQUEST;

                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1PARSER_URI:
            if (ch == ' ') {
                parser->stage = HTTP1PARSER_PROTOCOL;

                bufferdata_complete(&parser->buf);

                size_t length = bufferdata_writed(&parser->buf);
                char* uri = bufferdata_copy(&parser->buf);
                if (uri == NULL)
                    return HTTP1PARSER_OUT_OF_MEMORY;

                int result = http1parser_set_uri(request, uri, length);
                if (result != HTTP1PARSER_CONTINUE)
                    return result;

                bufferdata_reset(&parser->buf);
                break;
            }
            else if (http1parser_is_ctl(ch)) {
                return HTTP1PARSER_BAD_REQUEST;
            }
            else {
                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1PARSER_PROTOCOL:
            if (ch == '\r') {
                parser->stage = HTTP1PARSER_NEWLINE1;

                bufferdata_complete(&parser->buf);
                if (!http1parser_set_protocol(request, parser))
                    return HTTP1PARSER_BAD_REQUEST;

                bufferdata_reset(&parser->buf);

                break;
            }
            else {
                if (bufferdata_writed(&parser->buf) > 8)
                    return HTTP1PARSER_BAD_REQUEST;

                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1PARSER_NEWLINE1:
            if (ch == '\n') {
                parser->stage = HTTP1PARSER_HEADER_KEY;
                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1PARSER_HEADER_KEY:
            if (ch == '\r') {
                if (bufferdata_writed(&parser->buf) > 0)
                    return HTTP1PARSER_BAD_REQUEST;

                parser->stage = HTTP1PARSER_NEWLINE3;
                break;
            }
            else if (ch == ':') {
                parser->stage = HTTP1PARSER_HEADER_SPACE;

                bufferdata_complete(&parser->buf);
                int r = http1parser_set_header_key(request, parser);
                if (r != HTTP1PARSER_CONTINUE)
                    return r;

                bufferdata_reset(&parser->buf);

                break;
            }
            else if (http1parser_is_ctl(ch)) {
                return HTTP1PARSER_BAD_REQUEST;
            }
            else {
                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1PARSER_HEADER_SPACE:
            if (ch == ' ') {
                parser->stage = HTTP1PARSER_HEADER_VALUE;
                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1PARSER_HEADER_VALUE:
            if (ch == '\r') {
                parser->stage = HTTP1PARSER_NEWLINE2;

                bufferdata_complete(&parser->buf);
                int r = http1parser_set_header_value(request, parser);
                if (r != HTTP1PARSER_CONTINUE)
                    return r;

                bufferdata_reset(&parser->buf);

                break;
            }
            else if (http1parser_is_ctl(ch)) {
                return HTTP1PARSER_BAD_REQUEST;
            }
            else
            {
                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1PARSER_NEWLINE2:
            if (ch == '\n') {
                parser->stage = HTTP1PARSER_HEADER_KEY;
                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1PARSER_NEWLINE3:
            if (ch == '\n') {
                parser->stage = HTTP1PARSER_PAYLOAD;

                if (parser->content_length == 0)
                    return HTTP1PARSER_COMPLETE;

                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1PARSER_PAYLOAD:
            return http1parser_parse_payload(parser);
        default:
            return HTTP1PARSER_BAD_REQUEST;
        }
    }

    return HTTP1PARSER_CONTINUE;
}

void http1parser_set_bytes_readed(http1requestparser_t* parser, int readed) {
    parser->bytes_readed = readed;
}

int http1parser_parse_payload(http1requestparser_t* parser) {
    http1request_t* request = (http1request_t*)parser->connection->request;

    if (!http1request_has_payload(request))
        return HTTP1PARSER_BAD_REQUEST;

    parser->pos_start = parser->pos;
    parser->pos = parser->bytes_readed;

    if (request->payload_.file.fd <= 0) {
        request->payload_.path = create_tmppath(env()->main.tmp);
        if (request->payload_.path == NULL)
            return HTTP1PARSER_ERROR;

        request->payload_.file.fd = mkstemp(request->payload_.path);
        if (request->payload_.file.fd == -1)
            return HTTP1PARSER_ERROR;
    }

    size_t string_len = parser->pos - parser->pos_start;
    if (parser->content_saved_length + string_len > env()->main.client_max_body_size) {
        return HTTP1PARSER_PAYLOAD_LARGE;
    }

    if (!request->payload_.file.append_content(&request->payload_.file, &parser->buffer[parser->pos_start], string_len))
        return HTTP1PARSER_ERROR;

    parser->content_saved_length += string_len;
    if (parser->content_saved_length >= parser->content_length)
        return HTTP1PARSER_COMPLETE;

    return HTTP1PARSER_CONTINUE;
}

int http1parser_set_method(http1request_t* request, http1requestparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);
    size_t length = bufferdata_writed(&parser->buf);

    if (length == 3 && string[0] == 'G' && string[1] == 'E' && string[2] == 'T') {
        request->method = ROUTE_GET;
    }
    else if (length == 3 && string[0] == 'P' && string[1] == 'U' && string[2] == 'T') {
        request->method = ROUTE_PUT;
    }
    else if (length == 4 && string[0] == 'P' && string[1] == 'O' && string[2] == 'S' && string[3] == 'T') {
        request->method = ROUTE_POST;
    }
    else if (length == 5 && string[0] == 'P' && string[1] == 'A' && string[2] == 'T' && string[3] == 'C' && string[4] == 'H') {
        request->method = ROUTE_PATCH;
    }
    else if (length == 6 && string[0] == 'D' && string[1] == 'E' && string[2] == 'L' && string[3] == 'E' && string[4] == 'T' && string[5] == 'E') {
        request->method = ROUTE_DELETE;
    }
    else if (length == 7 && string[0] == 'O' && string[1] == 'P' && string[2] == 'T' && string[3] == 'I' && string[4] == 'O' && string[5] == 'N' && string[6] == 'S') {
        request->method = ROUTE_OPTIONS;
    }
    else if (length == 4 && string[0] == 'H' && string[1] == 'E' && string[2] == 'A' && string[3] == 'D') {
        request->method = ROUTE_HEAD;
    }
    else return 0;

    return 1;
}

int http1parser_set_uri(http1request_t* request, const char* string, size_t length) {
    if (string[0] != '/')
        return HTTP1PARSER_BAD_REQUEST;

    request->uri = string;
    request->uri_length = length;

    size_t path_point_end = 0;
    size_t ext_point_start = 0;

    for (size_t pos = 0; pos < length; pos++) {
        switch (string[pos]) {
        case '?':
            if (path_point_end == 0) path_point_end = pos;

            int result = http1parser_set_query(request, string, length, pos);

            if (result == HTTP1PARSER_CONTINUE) goto next;
            else return result;

            break;
        case '#':
            if (path_point_end == 0) path_point_end = pos;
            goto next;
            break;
        }
    }

    next:

    if (path_point_end == 0) path_point_end = length;

    int result = http1parser_set_path(request, string, path_point_end);

    if (result != HTTP1PARSER_CONTINUE) return result;

    if (ext_point_start == 0) ext_point_start = path_point_end;

    result = http1parser_set_ext(request, &string[ext_point_start], path_point_end - ext_point_start);

    if (result != HTTP1PARSER_CONTINUE) return result;

    return HTTP1PARSER_CONTINUE;
}

int http1parser_set_protocol(http1request_t* request, http1requestparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);

    if (string[0] == 'H' && string[1] == 'T' && string[2] == 'T' && string[3] == 'P' && string[4] == '/'  && string[5] == '1' && string[6] == '.' && string[7] == '1') {
        request->version = HTTP1_VER_1_1;
        return HTTP1PARSER_CONTINUE;
    }
    else if (string[0] == 'H' && string[1] == 'T' && string[2] == 'T' && string[3] == 'P' && string[4] == '/'  && string[5] == '1' && string[6] == '.' && string[7] == '0') {
        request->version = HTTP1_VER_1_0;
        return HTTP1PARSER_CONTINUE;
    }

    log_error("HTTP error: version error\n");

    return HTTP1PARSER_BAD_REQUEST;
}

int http1parser_set_path(http1request_t* request, const char* string, size_t length) {
    char* path = (char*)malloc(length + 1);

    if (path == NULL) return HTTP1PARSER_OUT_OF_MEMORY;

    memcpy(path, string, length);

    path[length] = 0;

    request->path = path;
    request->path_length = length;

    char ch_1 = 0;
    char ch_2 = 0;
    char ch_3 = 0;
    for (size_t i = 0; i <= length; i++) {
        if (ch_1 == '/' && ch_2 == '.' && ch_3 == '.' && path[i] == '/')
            return HTTP1PARSER_BAD_REQUEST;
        else if (ch_1 == '/' && ch_2 == '.' && ch_3 == '.' && path[i] == '\0')
            return HTTP1PARSER_BAD_REQUEST;

        ch_1 = ch_2;
        ch_2 = ch_3;
        ch_3 = path[i];
    }

    return HTTP1PARSER_CONTINUE;
}

int http1parser_set_ext(http1request_t* request, const char* string, size_t length) {
    char* ext = (char*)malloc(length + 1);

    if (ext == NULL) return HTTP1PARSER_OUT_OF_MEMORY;

    strncpy(ext, string, length);

    ext[length] = 0;

    request->ext = ext;
    request->ext_length = length;

    return HTTP1PARSER_CONTINUE;
}

int http1parser_set_query(http1request_t* request, const char* string, size_t length, size_t pos) {
    size_t point_start = pos + 1;

    enum { KEY, VALUE } stage = KEY;

    http1_query_t* query = http1_query_create(NULL, 0, NULL, 0);

    if (query == NULL) return HTTP1PARSER_OUT_OF_MEMORY;

    request->query_ = query;
    request->last_query = query;

    for (++pos; pos < length; pos++) {
        switch (string[pos]) {
        case '=':
            if (string[pos - 1] == '=') continue;

            stage = VALUE;

            query->key = http1_set_field(&string[point_start], pos - point_start);
            if (query->key == NULL) return HTTP1PARSER_OUT_OF_MEMORY;

            point_start = pos + 1;
            break;
        case '&':
            stage = KEY;

            query->value = http1_set_field(&string[point_start], pos - point_start);

            if (query->value == NULL) return HTTP1PARSER_OUT_OF_MEMORY;

            http1_query_t* query_new = http1_query_create(NULL, 0, NULL, 0);

            if (query_new == NULL) return HTTP1PARSER_OUT_OF_MEMORY;

            http1parser_append_query(request, query_new);

            query = query_new;

            point_start = pos + 1;
            break;
        case '#':
            if (stage == KEY) {
                query->key = http1_set_field(&string[point_start], pos - point_start);
                if (query->key == NULL) return HTTP1PARSER_OUT_OF_MEMORY;
            }
            else if (stage == VALUE) {
                query->value = http1_set_field(&string[point_start], pos - point_start);
                if (query->value == NULL) return HTTP1PARSER_OUT_OF_MEMORY;
            }

            return HTTP1PARSER_CONTINUE;
        }
    }

    if (stage == KEY) {
        query->key = http1_set_field(&string[point_start], pos - point_start);
        if (query->key == NULL) return HTTP1PARSER_OUT_OF_MEMORY;

        query->value = http1_set_field("", 1);
        if (query->value == NULL) return HTTP1PARSER_OUT_OF_MEMORY;
    }
    else if (stage == VALUE) {
        query->value = http1_set_field(&string[point_start], pos - point_start);
        if (query->value == NULL) return HTTP1PARSER_OUT_OF_MEMORY;
    }

    return HTTP1PARSER_CONTINUE;
}

void http1parser_append_query(http1request_t* request, http1_query_t* query) {
    if (request->query_ == NULL) {
        request->query_ = query;
    }
    if (request->last_query) {
        request->last_query->next = query;
    }

    request->last_query = query;
}

int http1parser_host_not_found(http1requestparser_t* parser) {
    if (parser->host_found) return HTTP1PARSER_CONTINUE;

    http1request_t* request = (http1request_t*)parser->connection->request;
    http1_header_t* header = request->last_header;

    const char* host_key = "host";
    size_t host_key_length = 4;

    if (!cmpstrn_lower(header->key, header->key_length, host_key, host_key_length))
        return HTTP1PARSER_CONTINUE;

    const size_t MAX_DOMAIN_LENGTH = 255;
    char domain[MAX_DOMAIN_LENGTH];

    strncpy(domain, header->value, MAX_DOMAIN_LENGTH - 1);
    size_t domain_length = 0;
    const size_t max_domain_length = header->value_length < MAX_DOMAIN_LENGTH ?
        header->value_length :
        MAX_DOMAIN_LENGTH;

    for (; domain_length < max_domain_length; domain_length++) {
        if (domain[domain_length] == ':') {
            domain[domain_length] = 0;
            break;
        }
    }

    int vector_struct_size = 6;
    int substring_count = 20;
    int vector_size = substring_count * vector_struct_size;
    int vector[vector_size];

    server_t* server = parser->connection->server;
    while (server) {
        if (server->ip == parser->connection->ip && server->port == parser->connection->port) {
            domain_t* server_domain = server->domain;

            while (server_domain) {
                int matches_count = pcre_exec(server_domain->pcre_template, NULL, domain, domain_length, 0, 0, vector, vector_size);

                if (matches_count > 0) {
                    parser->host_found = 1;
                    parser->connection->server = server;
                    return HTTP1PARSER_CONTINUE;
                }

                server_domain = server_domain->next;
            }
        }

        server = server->next;
    }

    return HTTP1PARSER_HOST_NOT_FOUND;
}

void http1parser_try_set_keepalive(http1requestparser_t* parser) {
    http1request_t* request = (http1request_t*)parser->connection->request;
    http1_header_t* header = request->last_header;

    const char* connection_key = "connection";
    ssize_t connection_key_length = 10;
    const char* connection_value = "keep-alive";
    ssize_t connection_value_length = 10;

    if ((ssize_t)header->key_length != connection_key_length) return;
    if (!cmpstrn_lower(header->key, header->key_length, connection_key, connection_key_length)) return;

    parser->connection->keepalive_enabled = 0;
    if (cmpstrn_lower(header->value, header->value_length, connection_value, connection_value_length)) {
        parser->connection->keepalive_enabled = 1;
    }
}

void http1parser_try_set_range(http1requestparser_t* parser) {
    http1request_t* request = (http1request_t*)parser->connection->request;
    http1response_t* response = (http1response_t*)parser->connection->response;

    if (cmpstrn_lower(request->last_header->key, request->last_header->key_length, "range", 5)) {
        response->ranges = http1parser_parse_range((char*)request->last_header->value, request->last_header->value_length);
    }
}

void http1parser_try_set_cookie(http1requestparser_t* parser) {
    http1request_t* request = (http1request_t*)parser->connection->request;
    http1_header_t* header = request->last_header;

    const char* key = "cookie";
    ssize_t key_length = 6;

    if ((ssize_t)header->key_length != key_length) return;
    if (!cmpstrn_lower(header->key, header->key_length, key, key_length)) return;

    cookieparser_t cparser;
    cookieparser_init(&cparser);
    cookieparser_parse(&cparser, header->value, header->value_length);

    request->cookie_ = cookieparser_cookie(&cparser);
}

void http1parser_try_set_content_length(http1requestparser_t* parser) {
    http1request_t* request = (http1request_t*)parser->connection->request;
    http1_header_t* header = request->last_header;

    const char* key = "content-length";
    ssize_t key_length = 14;

    if ((ssize_t)header->key_length != key_length) return;
    if (!cmpstrn_lower(header->key, header->key_length, key, key_length)) return;
    if (!http1request_has_payload(request)) return;

    parser->content_length = atoll(header->value);
}

http1_ranges_t* http1parser_parse_range(char* str, size_t length) {
    int result = -1;
    int max = 2147483647;
    long long int start_finded = 0;
    size_t start_position = 6;
    http1_ranges_t* ranges = NULL;
    http1_ranges_t* last_range = NULL;

    if (!(str[0] == 'b' && str[1] == 'y' && str[2] == 't' && str[3] == 'e' && str[4] == 's' && str[5] == '=')) return NULL;

    for (size_t i = start_position; i <= length; i++) {
        long long int end = -1;

        if (isdigit(str[i])) continue;
        else if (str[i] == '-') {
            if (last_range && last_range->end == -1) goto failed;
            if (last_range && last_range->start == -1) goto failed;

            long long int start = -1;

            start_finded = 1;
            if (i > start_position) {
                if (i - start_position > 10) goto failed;

                str[i] = 0;
                start = atoll(&str[start_position]);
                str[i] = '-';

                if (start > max) goto failed;

                if (last_range && last_range->start > start) goto failed;

                if (last_range && last_range->start > -1 && last_range->end >= start) {
                    start_position = i + 1;
                    continue;
                }
            }

            http1_ranges_t* range = http1response_init_ranges();
            if (range == NULL) goto failed;

            if (ranges == NULL) ranges = range;

            if (last_range != NULL) {
                last_range->next = range;
            }
            last_range = range;

            if (i > start_position) {
                range->start = start;
            }

            start_position = i + 1;
        }
        else if (str[i] == ',') {
            if (i > start_position) {
                if (i - start_position > 10) goto failed;

                str[i] = 0;
                end = atoll(&str[start_position]);
                str[i] = ',';

                if (end > max) goto failed;
                if (last_range && end < last_range->start) goto failed;
                if (start_finded == 0) goto failed;

                if (last_range->end <= end) {
                    last_range->end = end;
                }
            }

            start_finded = 0;
            start_position = i + 1;
        }
        else if (str[i] == 0) {
            if (i > start_position) {
                if (i - start_position > 10) goto failed;

                end = atoll(&str[start_position]);

                if (end > max) goto failed;
                if (last_range && end < last_range->start) goto failed;
                if (start_finded == 0) goto failed;

                if (last_range->end <= end) {
                    last_range->end = end;
                }
            }
            else if (last_range && start_finded) {
                last_range->end = -1;
            }
        }
        else if (str[i] == ' ') {
            if (!(i > 0 && str[i - 1] == ',')) goto failed;
            start_position = i + 1;
        }
        else goto failed;
    }

    result = 0;

    failed:

    if (result == -1) {
        http1response_free_ranges(ranges);
        return NULL;
    }

    return ranges;
}

int http1parser_set_header_key(http1request_t* request, http1requestparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);
    size_t length = bufferdata_writed(&parser->buf);
    http1_header_t* header = http1_header_create(string, length, NULL, 0);

    if (header == NULL) {
        log_error("HTTP error: can't alloc header memory\n");
        return HTTP1PARSER_OUT_OF_MEMORY;
    }
    
    if (header->key == NULL)
        return HTTP1PARSER_OUT_OF_MEMORY;

    if (request->header_ == NULL) {
        request->header_ = header;
    }

    if (request->last_header) {
        request->last_header->next = header;
    }

    request->last_header = header;

    return HTTP1PARSER_CONTINUE;
}

int http1parser_set_header_value(http1request_t* request, http1requestparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);
    size_t length = bufferdata_writed(&parser->buf);

    request->last_header->value = http1_set_field(string, length);
    request->last_header->value_length = length;

    if (request->last_header->value == NULL)
        return HTTP1PARSER_OUT_OF_MEMORY;

    int r = http1parser_host_not_found(parser);
    if (r == HTTP1PARSER_HOST_NOT_FOUND)
        return r;

    http1parser_try_set_keepalive(parser);
    http1parser_try_set_range(parser);
    http1parser_try_set_cookie(parser);
    http1parser_try_set_content_length(parser);

    return HTTP1PARSER_CONTINUE;
}
