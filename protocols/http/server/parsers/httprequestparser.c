#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>

#include "httpresponse.h"
#include "cookieparser.h"
#include "domain.h"
#include "log.h"
#include "appconfig.h"
#include "httpcommon.h"
#include "httprequestparser.h"
#include "helpers.h"
#include "queryparser.h"

static int __parse_payload(httprequestparser_t* parser);
static int __set_method(httprequest_t* request, bufferdata_t* buf);
static int __set_protocol(httprequest_t* request, bufferdata_t* buf);
static int __set_header_key(httprequest_t* request, bufferdata_t* buf);
static int __set_header_value(httprequest_t* request, httprequestparser_t* parser);
static int __set_path(httprequest_t* request, const char* string, size_t length);
static int __set_query(httprequest_t* request, const char* string, size_t length, size_t pos);
static int __try_set_server(httprequestparser_t* parser, http_header_t* header);
static void __try_set_keepalive(httprequestparser_t* parser);
static void __try_set_range(httprequestparser_t* parser);
static void __try_set_cookie(httprequest_t* request);
static void __flush(httprequestparser_t* parser);
static int __header_is_host(http_header_t* header);
static int __header_is_content_length(http_header_t* header);

httprequestparser_t* httpparser_create(connection_t* connection) {
    httprequestparser_t* parser = malloc(sizeof * parser);
    if (parser == NULL) return NULL;

    httpparser_init(parser, connection);

    return parser;
}

void httpparser_init(httprequestparser_t* parser, connection_t* connection) {
    parser->base.free = httpparser_free;
    parser->stage = HTTP1REQUESTPARSER_METHOD;
    parser->host_found = connection->ssl != NULL;
    parser->bytes_readed = 0;
    parser->pos_start = 0;
    parser->pos = 0;
    parser->buffer = connection->buffer;
    parser->connection = connection;
    parser->content_length = 0;
    parser->content_saved_length = 0;
    parser->request = NULL;

    bufferdata_init(&parser->buf);
}

void httpparser_free(void* arg) {
    httprequestparser_t* parser = arg;

    __flush(parser);
    free(parser);
}

void httpparser_reset(httprequestparser_t* parser) {
    __flush(parser);
    httpparser_init(parser, parser->connection);
}

void __flush(httprequestparser_t* parser) {
    if (parser->buf.dynamic_buffer) free(parser->buf.dynamic_buffer);
    parser->buf.dynamic_buffer = NULL;
}

int httpparser_run(httprequestparser_t* parser) {
    if (parser->stage == HTTP1REQUESTPARSER_PAYLOAD)
        return __parse_payload(parser);

    for (parser->pos = parser->pos_start; parser->pos < parser->bytes_readed; parser->pos++) {
        char ch = parser->buffer[parser->pos];

        switch (parser->stage)
        {
        case HTTP1REQUESTPARSER_METHOD:
            if (parser->request == NULL) {
                parser->request = httprequest_create(parser->connection);

                const size_t log_size = parser->bytes_readed < 500 ? parser->bytes_readed : 500;
                log_debug("HTTP Request head (%zu bytes): %.*s", log_size, (int)log_size, parser->buffer);
            }

            if (ch == ' ') {
                parser->stage = HTTP1REQUESTPARSER_URI;

                bufferdata_complete(&parser->buf);
                if (!__set_method(parser->request, &parser->buf))
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
        case HTTP1REQUESTPARSER_URI:
            if (ch == ' ') {
                parser->stage = HTTP1REQUESTPARSER_PROTOCOL;

                bufferdata_complete(&parser->buf);

                size_t length = bufferdata_writed(&parser->buf);
                char* uri = bufferdata_copy(&parser->buf);
                if (uri == NULL)
                    return HTTP1PARSER_OUT_OF_MEMORY;

                int result = httpparser_set_uri(parser->request, uri, length);
                if (result != HTTP1PARSER_CONTINUE)
                    return result;

                bufferdata_reset(&parser->buf);
                break;
            }
            else if (httpparser_is_ctl(ch)) {
                return HTTP1PARSER_BAD_REQUEST;
            }
            else {
                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1REQUESTPARSER_PROTOCOL:
            if (ch == '\r') {
                parser->stage = HTTP1REQUESTPARSER_NEWLINE1;

                bufferdata_complete(&parser->buf);
                if (__set_protocol(parser->request, &parser->buf) == HTTP1PARSER_BAD_REQUEST)
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
        case HTTP1REQUESTPARSER_NEWLINE1:
            if (ch == '\n') {
                parser->stage = HTTP1REQUESTPARSER_HEADER_KEY;
                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1REQUESTPARSER_HEADER_KEY:
            if (ch == '\r') {
                if (bufferdata_writed(&parser->buf) > 0)
                    return HTTP1PARSER_BAD_REQUEST;

                parser->stage = HTTP1REQUESTPARSER_NEWLINE3;
                break;
            }
            else if (ch == ':') {
                parser->stage = HTTP1REQUESTPARSER_HEADER_SPACE;

                bufferdata_complete(&parser->buf);
                int r = __set_header_key(parser->request, &parser->buf);
                if (r != HTTP1PARSER_CONTINUE)
                    return r;

                bufferdata_reset(&parser->buf);

                break;
            }
            else if (httpparser_is_ctl(ch)) {
                return HTTP1PARSER_BAD_REQUEST;
            }
            else {
                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1REQUESTPARSER_HEADER_SPACE:
            if (ch == ' ') {
                parser->stage = HTTP1REQUESTPARSER_HEADER_VALUE;
                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1REQUESTPARSER_HEADER_VALUE:
            if (ch == '\r') {
                parser->stage = HTTP1REQUESTPARSER_NEWLINE2;

                bufferdata_complete(&parser->buf);
                int r = __set_header_value(parser->request, parser);
                if (r != HTTP1PARSER_CONTINUE)
                    return r;

                bufferdata_reset(&parser->buf);

                break;
            }
            else if (httpparser_is_ctl(ch)) {
                return HTTP1PARSER_BAD_REQUEST;
            }
            else
            {
                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1REQUESTPARSER_NEWLINE2:
            if (ch == '\n') {
                parser->stage = HTTP1REQUESTPARSER_HEADER_KEY;
                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1REQUESTPARSER_NEWLINE3:
            if (ch == '\n') {
                parser->stage = HTTP1REQUESTPARSER_PAYLOAD;

                if (parser->content_length == 0) {
                    if (parser->bytes_readed - parser->pos - 1 > 0) {
                        parser->pos++;
                        return HTTP1PARSER_HANDLE_AND_CONTINUE;
                    }

                    return HTTP1PARSER_COMPLETE;
                }

                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1REQUESTPARSER_PAYLOAD:
            return __parse_payload(parser);
        default:
            return HTTP1PARSER_BAD_REQUEST;
        }
    }

    return HTTP1PARSER_CONTINUE;
}

void httpparser_set_bytes_readed(httprequestparser_t* parser, int readed) {
    parser->bytes_readed = readed;
}

void httpparser_prepare_continue(httprequestparser_t* parser) {
    bufferdata_clear(&parser->buf);

    parser->stage = HTTP1REQUESTPARSER_METHOD;
    parser->pos_start = parser->pos;
    parser->content_length = 0;
    parser->content_saved_length = 0;
    parser->request = NULL;
    parser->host_found = 0;
}

int __parse_payload(httprequestparser_t* parser) {
    httprequest_t* request = parser->request;

    if (!httprequest_allow_payload(request))
        return HTTP1PARSER_BAD_REQUEST;

    size_t string_len = parser->bytes_readed - parser->pos;
    int has_data_for_next_request = 0;

    if (string_len + parser->content_saved_length > parser->content_length) {
        // printf("has_data_for_next_request: %ld > %ld\n", string_len + parser->content_saved_length, parser->content_length);
        string_len = parser->content_length - parser->content_saved_length;
        has_data_for_next_request = 1;
    }

    if (parser->content_saved_length + string_len > env()->main.client_max_body_size)
        return HTTP1PARSER_PAYLOAD_LARGE;

    if (request->payload_.file.fd < 0) {
        request->payload_.path = create_tmppath(env()->main.tmp);
        if (request->payload_.path == NULL)
            return HTTP1PARSER_ERROR;

        request->payload_.file.fd = mkstemp(request->payload_.path);
        if (request->payload_.file.fd == -1)
            return HTTP1PARSER_ERROR;
    }

    parser->content_saved_length += string_len;

    if (!request->payload_.file.append_content(&request->payload_.file, &parser->buffer[parser->pos], string_len))
        return HTTP1PARSER_ERROR;

    if (has_data_for_next_request) {
        parser->pos += string_len;

        return HTTP1PARSER_HANDLE_AND_CONTINUE;
    }

    if (parser->content_saved_length == parser->content_length)
        return HTTP1PARSER_COMPLETE;

    return HTTP1PARSER_CONTINUE;
}

int __set_method(httprequest_t* request, bufferdata_t* buf) {
    char* s = bufferdata_get(buf);
    size_t l = bufferdata_writed(buf);

    if (l == 3 && s[0] == 'G' && s[1] == 'E' && s[2] == 'T')
        request->method = ROUTE_GET;
    else if (l == 3 && s[0] == 'P' && s[1] == 'U' && s[2] == 'T')
        request->method = ROUTE_PUT;
    else if (l == 4 && s[0] == 'P' && s[1] == 'O' && s[2] == 'S' && s[3] == 'T')
        request->method = ROUTE_POST;
    else if (l == 5 && s[0] == 'P' && s[1] == 'A' && s[2] == 'T' && s[3] == 'C' && s[4] == 'H')
        request->method = ROUTE_PATCH;
    else if (l == 6 && s[0] == 'D' && s[1] == 'E' && s[2] == 'L' && s[3] == 'E' && s[4] == 'T' && s[5] == 'E')
        request->method = ROUTE_DELETE;
    else if (l == 7 && s[0] == 'O' && s[1] == 'P' && s[2] == 'T' && s[3] == 'I' && s[4] == 'O' && s[5] == 'N' && s[6] == 'S')
        request->method = ROUTE_OPTIONS;
    else if (l == 4 && s[0] == 'H' && s[1] == 'E' && s[2] == 'A' && s[3] == 'D')
        request->method = ROUTE_HEAD;
    else
        return 0;

    return 1;
}

int httpparser_set_uri(httprequest_t* request, const char* string, size_t length) {
    if (string[0] != '/')
        return HTTP1PARSER_BAD_REQUEST;

    request->uri = string;
    request->uri_length = length;

    size_t path_point_end = 0;
    for (size_t pos = 0; pos < length; pos++) {
        switch (string[pos]) {
        case '?':
            path_point_end = pos;

            int result = __set_query(request, string, length, pos);
            if (result == HTTP1PARSER_CONTINUE)
                goto next;

            return result;
        case '#':
            path_point_end = pos;
            goto next;
        }
    }

    next:

    if (path_point_end == 0) path_point_end = length;

    return __set_path(request, string, path_point_end);
}

int __set_protocol(httprequest_t* request, bufferdata_t* buf) {
    char* s = bufferdata_get(buf);

    if (s[0] == 'H' && s[1] == 'T' && s[2] == 'T' && s[3] == 'P' && s[4] == '/'  && s[5] == '1' && s[6] == '.' && s[7] == '1') {
        request->version = HTTP1_VER_1_1;
        return HTTP1PARSER_CONTINUE;
    }
    else if (s[0] == 'H' && s[1] == 'T' && s[2] == 'T' && s[3] == 'P' && s[4] == '/'  && s[5] == '1' && s[6] == '.' && s[7] == '0') {
        request->version = HTTP1_VER_1_0;
        return HTTP1PARSER_CONTINUE;
    }

    log_error("HTTP error: version error\n");

    return HTTP1PARSER_BAD_REQUEST;
}

int __set_path(httprequest_t* request, const char* string, size_t length) {
    size_t decoded_length = 0;
    char* path = urldecodel(string, length, &decoded_length);
    if (path == NULL) return HTTP1PARSER_OUT_OF_MEMORY;

    request->path = path;
    request->path_length = decoded_length;

    if (is_path_traversal(path, decoded_length))
        return HTTP1PARSER_BAD_REQUEST;

    return HTTP1PARSER_CONTINUE;
}

static void __httpparser_append_query_callback(void* context, query_t* query) {
    httprequest_t* request = (httprequest_t*)context;
    httpparser_append_query(request, query);
}

int __set_query(httprequest_t* request, const char* string, size_t length, size_t pos) {
    query_t* first_query = NULL;
    query_t* last_query = NULL;

    queryparser_result_t result = queryparser_parse(
        string,
        length,
        pos + 1,  // Start after '?'
        request,
        __httpparser_append_query_callback,
        &first_query,
        &last_query
    );

    if (result != QUERYPARSER_OK) {
        return HTTP1PARSER_OUT_OF_MEMORY;
    }

    request->query_ = first_query;
    request->last_query = last_query;

    return HTTP1PARSER_CONTINUE;
}

void httpparser_append_query(httprequest_t* request, query_t* query) {
    if (request->query_ == NULL)
        request->query_ = query;

    if (request->last_query)
        request->last_query->next = query;

    request->last_query = query;
}

int __try_set_server(httprequestparser_t* parser, http_header_t* header) {
    if (parser->host_found) return HTTP1PARSER_CONTINUE;
    
    if (!__header_is_host(header)) return HTTP1PARSER_CONTINUE;

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

    connection_server_ctx_t* ctx = parser->connection->ctx;
    cqueue_item_t* item = cqueue_first(&ctx->listener->servers);
    while (item) {
        server_t* server = item->data;

        if (server->ip == parser->connection->ip && server->port == parser->connection->port) {
            domain_t* server_domain = server->domain;

            while (server_domain) {
                int matches_count = pcre_exec(server_domain->pcre_template, NULL, domain, domain_length, 0, 0, vector, vector_size);

                if (matches_count > 0) {
                    ctx->server = server;
                    parser->host_found = 1;
                    return HTTP1PARSER_CONTINUE;
                }

                server_domain = server_domain->next;
            }
        }

        item = item->next;
    }

    return HTTP1PARSER_HOST_NOT_FOUND;
}

void __try_set_keepalive(httprequestparser_t* parser) {
    httprequest_t* request = parser->request;
    http_header_t* header = request->last_header;

    const char* connection_key = "connection";
    const size_t connection_key_length = 10;
    const char* connection_value = "keep-alive";
    const size_t connection_value_length = 10;

    if (header->key_length != connection_key_length) return;
    if (!cmpstrn_lower(header->key, header->key_length, connection_key, connection_key_length)) return;

    parser->connection->keepalive = cmpstrn_lower(header->value, header->value_length, connection_value, connection_value_length);
}

void __try_set_range(httprequestparser_t* parser) {
    httprequest_t* request = parser->request;

    if (cmpstrn_lower(request->last_header->key, request->last_header->key_length, "range", 5))
        request->ranges = httpparser_parse_range((char*)request->last_header->value, request->last_header->value_length);
}

void __try_set_cookie(httprequest_t* request) {
    http_header_t* header = request->last_header;

    const char* key = "cookie";
    const size_t key_length = 6;

    if (header->key_length != key_length) return;
    if (!cmpstrn_lower(header->key, header->key_length, key, key_length)) return;

    cookieparser_t cparser;
    cookieparser_init(&cparser);
    cookieparser_parse(&cparser, header->value, header->value_length);

    request->cookie_ = cookieparser_cookie(&cparser);
}

http_ranges_t* httpparser_parse_range(char* str, size_t length) {
    int result = -1;
    long long int max = 9223372036854775807;
    long long int start_finded = 0;
    size_t start_position = 6;
    http_ranges_t* ranges = NULL;
    http_ranges_t* last_range = NULL;

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

            http_ranges_t* range = httpresponse_init_ranges();
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
        http_ranges_free(ranges);
        return NULL;
    }

    return ranges;
}

int __set_header_key(httprequest_t* request, bufferdata_t* buf) {
    char* string = bufferdata_get(buf);
    size_t length = bufferdata_writed(buf);
    http_header_t* header = http_header_create(string, length, NULL, 0);

    if (header == NULL) {
        log_error("HTTP error: can't alloc header memory\n");
        return HTTP1PARSER_OUT_OF_MEMORY;
    }
    
    if (header->key == NULL)
        return HTTP1PARSER_OUT_OF_MEMORY;

    if (request->header_ == NULL)
        request->header_ = header;

    if (request->last_header)
        request->last_header->next = header;

    request->last_header = header;

    return HTTP1PARSER_CONTINUE;
}

int __set_header_value(httprequest_t* request, httprequestparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);
    size_t length = bufferdata_writed(&parser->buf);

    request->last_header->value = copy_cstringn(string, length);
    request->last_header->value_length = length;

    if (request->last_header->value == NULL)
        return HTTP1PARSER_OUT_OF_MEMORY;

    int r = __try_set_server(parser, request->last_header);
    if (r == HTTP1PARSER_HOST_NOT_FOUND)
        return r;

    __try_set_keepalive(parser);
    __try_set_range(parser);
    __try_set_cookie(parser->request);

    if (__header_is_content_length(request->last_header))
        parser->content_length = atoll(request->last_header->value); // TODO: Проверить на переполнение

    return HTTP1PARSER_CONTINUE;
}

int __header_is_host(http_header_t* header) {
    return cmpstrn_lower(header->key, header->key_length, "host", 4);
}

int __header_is_content_length(http_header_t* header) {
    return cmpstrn_lower(header->key, header->key_length, "content-length", 14);
}