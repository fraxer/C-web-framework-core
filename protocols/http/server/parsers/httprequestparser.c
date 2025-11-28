#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

#include "httpresponse.h"
#include "cookieparser.h"
#include "domain.h"
#include "log.h"
#include "appconfig.h"
#include "httpcommon.h"
#include "httprequestparser.h"
#include "helpers.h"
#include "queryparser.h"

#define MAX_HEADER_KEY_SIZE 256
#define MAX_HEADER_VALUE_SIZE 8192
#define MAX_URI_SIZE 32768             // Maximum URI size to prevent DoS
#define MAX_HEADERS_COUNT 30           // Maximum number of headers to prevent DoS
#define PCRE_VECTOR_SIZE 120           // Use static array instead of VLA for better portability

static int __parse_payload(httprequestparser_t* parser);
static void __clear(httprequestparser_t* parser);
static int __validate_content_length(const char* value, size_t* out_length);
static int __set_method(httprequest_t* request, bufferdata_t* buf);
static int __set_protocol(httprequest_t* request, bufferdata_t* buf);
static int __set_header_key(httprequest_t* request, httprequestparser_t* parser, bufferdata_t* buf);
static int __set_header_value(httprequest_t* request, httprequestparser_t* parser);
static int __set_path(httprequest_t* request, const char* string, size_t length);
static int __set_query(httprequest_t* request, const char* string, size_t length, size_t pos);
static int __try_set_server(httprequestparser_t* parser, http_header_t* header);
static void __try_set_keepalive(httprequestparser_t* parser);
static void __try_set_range(httprequestparser_t* parser);
static void __try_set_cookie(httprequest_t* request);
static void __clear(httprequestparser_t* parser);
static void __clear_buf(httprequestparser_t* parser);
static int __clear_and_return(httprequestparser_t* parser, int error);
static int __header_is_host(http_header_t* header);
static int __header_is_content_length(http_header_t* header);
static int __header_is_transfer_encoding(http_header_t* header);

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
    parser->host_header_seen = 0;
    parser->content_length_found = 0;
    parser->transfer_encoding_found = 0;
    parser->headers_count = 0;
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

void httpparser_free(void* parser) {
    __clear(parser);
    free(parser);
}

void httpparser_reset(httprequestparser_t* parser) {
    __clear_buf(parser);
    httpparser_init(parser, parser->connection);
}

void __clear_buf(httprequestparser_t* parser) {
    if (parser->buf.dynamic_buffer) free(parser->buf.dynamic_buffer);
    parser->buf.dynamic_buffer = NULL;
}

int __clear_and_return(httprequestparser_t* parser, int error) {
    __clear(parser);
    return error;
}

void __clear(httprequestparser_t* parser) {
    __clear_buf(parser);

    // Clean up partially parsed request if it was created but not yet handled by connection layer
    // This prevents memory leaks when parsing fails early (e.g., invalid method, URI)
    if (parser->request != NULL) {
        // Only free if the request hasn't been registered with the connection yet
        // The connection layer will handle cleanup if the request was successfully registered
        httprequest_free(parser->request);
        parser->request = NULL;
    }
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
                if (parser->request == NULL)
                    return __clear_and_return(parser, HTTP1PARSER_OUT_OF_MEMORY);

                const size_t log_size = parser->bytes_readed < 500 ? parser->bytes_readed : 500;
                log_debug("HTTP Request head (%zu bytes): %.*s", log_size, (int)log_size, parser->buffer);
            }

            if (ch == ' ') {
                parser->stage = HTTP1REQUESTPARSER_URI;

                bufferdata_complete(&parser->buf);
                if (!__set_method(parser->request, &parser->buf))
                    return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);

                bufferdata_reset(&parser->buf);
                break;
            }
            else {
                if (bufferdata_writed(&parser->buf) >= 7)
                    return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);

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
                    return __clear_and_return(parser, HTTP1PARSER_OUT_OF_MEMORY);

                int result = httpparser_set_uri(parser->request, uri, length);
                if (result != HTTP1PARSER_CONTINUE)
                    return __clear_and_return(parser, result);

                bufferdata_reset(&parser->buf);
                break;
            }
            else if (httpparser_is_ctl(ch)) {
                return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
            }
            else {
                // Ограничение на длину URI для защиты от DoS
                if (bufferdata_writed(&parser->buf) >= MAX_URI_SIZE) {
                    log_error("HTTP error: URI too large (max: %d)\n", MAX_URI_SIZE);
                    return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
                }
                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1REQUESTPARSER_PROTOCOL:
            if (ch == '\r') {
                parser->stage = HTTP1REQUESTPARSER_NEWLINE1;

                bufferdata_complete(&parser->buf);
                if (__set_protocol(parser->request, &parser->buf) == HTTP1PARSER_BAD_REQUEST)
                    return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);

                bufferdata_reset(&parser->buf);

                break;
            }
            else {
                if (bufferdata_writed(&parser->buf) >= 8)
                    return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);

                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1REQUESTPARSER_NEWLINE1:
            if (ch == '\n') {
                parser->stage = HTTP1REQUESTPARSER_HEADER_KEY;
                break;
            }
            else {
                return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
            }
        case HTTP1REQUESTPARSER_HEADER_KEY:
            if (ch == '\r') {
                if (bufferdata_writed(&parser->buf) > 0)
                    return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);

                parser->stage = HTTP1REQUESTPARSER_NEWLINE3;
                break;
            }
            else if (ch == ':') {
                parser->stage = HTTP1REQUESTPARSER_HEADER_SPACE;

                bufferdata_complete(&parser->buf);
                int r = __set_header_key(parser->request, parser, &parser->buf);
                if (r != HTTP1PARSER_CONTINUE)
                    return __clear_and_return(parser, r);

                bufferdata_reset(&parser->buf);

                break;
            }
            else if (httpparser_is_ctl(ch)) {
                return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
            }
            else {
                // Ограничение на длину ключа заголовка
                if (bufferdata_writed(&parser->buf) >= MAX_HEADER_KEY_SIZE) {
                    log_error("HTTP error: header key too large (max: %d)\n", MAX_HEADER_KEY_SIZE);
                    return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
                }
                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1REQUESTPARSER_HEADER_SPACE:
            // RFC 7230: OWS (optional whitespace) after colon
            if (ch == ' ' || ch == '\t') {
                // Skip whitespace, stay in same state
                break;
            }
            else {
                // No whitespace or non-whitespace character - proceed to value
                parser->stage = HTTP1REQUESTPARSER_HEADER_VALUE;
                // Don't break - fall through to process current character as value
                // This handles both "Header: value" and "Header:value"
            }
        case HTTP1REQUESTPARSER_HEADER_VALUE:
            if (ch == '\r') {
                parser->stage = HTTP1REQUESTPARSER_NEWLINE2;

                bufferdata_complete(&parser->buf);
                int r = __set_header_value(parser->request, parser);
                if (r != HTTP1PARSER_CONTINUE)
                    return __clear_and_return(parser, r);

                bufferdata_reset(&parser->buf);

                break;
            }
            else if (httpparser_is_ctl(ch)) {
                return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
            }
            else
            {
                // Ограничение на длину значения заголовка
                if (bufferdata_writed(&parser->buf) >= MAX_HEADER_VALUE_SIZE) {
                    log_error("HTTP error: header value too large (max: %d)\n", MAX_HEADER_VALUE_SIZE);
                    return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
                }
                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1REQUESTPARSER_NEWLINE2:
            if (ch == '\n') {
                parser->stage = HTTP1REQUESTPARSER_HEADER_KEY;
                break;
            }
            else {
                return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
            }
        case HTTP1REQUESTPARSER_NEWLINE3:
            if (ch == '\n') {
                parser->stage = HTTP1REQUESTPARSER_PAYLOAD;

                // RFC 7230: Host header is mandatory for HTTP/1.1
                // For non-SSL connections, host_found is set only when valid Host header is parsed
                // For SSL connections, host_found is initialized to true (SNI available)
                if (parser->request->version == HTTP1_VER_1_1 && !parser->host_header_seen) {
                    log_error("HTTP error: missing required Host header for HTTP/1.1\n");
                    return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
                }

                if (parser->content_length == 0) {
                    // Prevent integer underflow: check if there's data after headers
                    if (parser->pos + 1 < parser->bytes_readed) {
                        parser->pos++;
                        return HTTP1PARSER_HANDLE_AND_CONTINUE;
                    }

                    return HTTP1PARSER_COMPLETE;
                }

                break;
            }
            else {
                return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
            }
        case HTTP1REQUESTPARSER_PAYLOAD:
            return __parse_payload(parser);
        default:
            return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);
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
    parser->content_length_found = 0;
    parser->transfer_encoding_found = 0;
    parser->host_header_seen = 0;
    parser->headers_count = 0;
    parser->content_saved_length = 0;
    parser->request = NULL;
    parser->host_found = parser->connection->ssl != NULL;  // Preserve SSL flag
}

int __parse_payload(httprequestparser_t* parser) {
    httprequest_t* request = parser->request;

    if (!httprequest_allow_payload(request))
        return __clear_and_return(parser, HTTP1PARSER_BAD_REQUEST);

    // Защита от integer underflow
    if (parser->pos > parser->bytes_readed) {
        log_error("HTTP error: parser position exceeds bytes read\n");
        return __clear_and_return(parser, HTTP1PARSER_ERROR);
    }

    size_t string_len = parser->bytes_readed - parser->pos;
    int has_data_for_next_request = 0;

    // Check for integer overflow before addition
    if (string_len > SIZE_MAX - parser->content_saved_length) {
        log_error("HTTP error: integer overflow in payload size calculation\n");
        return __clear_and_return(parser, HTTP1PARSER_ERROR);
    }

    if (string_len + parser->content_saved_length > parser->content_length) {
        // printf("has_data_for_next_request: %ld > %ld\n", string_len + parser->content_saved_length, parser->content_length);
        string_len = parser->content_length - parser->content_saved_length;
        has_data_for_next_request = 1;
    }

    if (parser->content_saved_length + string_len > env()->main.client_max_body_size)
        return __clear_and_return(parser, HTTP1PARSER_PAYLOAD_LARGE);

    if (request->payload_.file.fd < 0) {
        request->payload_.path = create_tmppath(env()->main.tmp);
        if (request->payload_.path == NULL)
            return __clear_and_return(parser, HTTP1PARSER_ERROR);

        request->payload_.file.fd = mkstemp(request->payload_.path);
        if (request->payload_.file.fd == -1)
            return __clear_and_return(parser, HTTP1PARSER_ERROR);
    }

    parser->content_saved_length += string_len;

    if (!request->payload_.file.append_content(&request->payload_.file, &parser->buffer[parser->pos], string_len))
        return __clear_and_return(parser, HTTP1PARSER_ERROR);

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
    size_t len = bufferdata_writed(buf);

    // Проверяем, что длина протокола ровно 8 символов
    if (len != 8) {
        log_error("HTTP error: invalid protocol length %zu\n", len);
        return HTTP1PARSER_BAD_REQUEST;
    }

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
    if (!__header_is_host(header)) return HTTP1PARSER_CONTINUE;

    // Защита от HTTP Request Smuggling: запретить дублирование заголовка Host
    if (parser->host_header_seen) {
        log_error("HTTP error: duplicate Host header detected\n");
        return HTTP1PARSER_BAD_REQUEST;
    }

    parser->host_header_seen = 1;

    // Для SSL соединений Host заголовок опционален (домен из SNI)
    if (parser->host_found) return HTTP1PARSER_CONTINUE;

    const size_t MAX_DOMAIN_LENGTH = 255;
    char domain[MAX_DOMAIN_LENGTH];

    const size_t copy_length = header->value_length < MAX_DOMAIN_LENGTH - 1 ?
        header->value_length :
        MAX_DOMAIN_LENGTH - 1;

    strncpy(domain, header->value, copy_length);
    domain[copy_length] = '\0';  // Гарантируем null-терминацию

    size_t domain_length = 0;

    for (; domain_length < copy_length; domain_length++) {
        if (domain[domain_length] == ':') {
            domain[domain_length] = '\0';
            break;
        }
    }

    int vector[PCRE_VECTOR_SIZE];
    connection_server_ctx_t* ctx = parser->connection->ctx;
    cqueue_item_t* item = cqueue_first(&ctx->listener->servers);
    while (item) {
        server_t* server = item->data;

        if (server->ip == parser->connection->ip && server->port == parser->connection->port) {
            domain_t* server_domain = server->domain;

            while (server_domain) {
                int matches_count = pcre_exec(server_domain->pcre_template, NULL, domain, domain_length, 0, 0, vector, PCRE_VECTOR_SIZE);

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

    for (size_t i = start_position; i < length; i++) {
        long long int end = -1;

        if (isdigit(str[i])) continue;
        else if (str[i] == '-') {
            if (last_range && last_range->end == -1) goto failed;
            if (last_range && last_range->start == -1) goto failed;

            long long int start = -1;

            start_finded = 1;
            if (i > start_position) {
                if (i - start_position > 10) goto failed;

                char* endptr = NULL;
                start = strtoll(&str[start_position], &endptr, 10);
                if (endptr != &str[i]) goto failed;  // Parse error

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

                char* endptr = NULL;
                end = strtoll(&str[start_position], &endptr, 10);
                if (endptr != &str[i]) goto failed;  // Parse error

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
        else if (str[i] == ' ') {
            if (!(i > 0 && str[i - 1] == ',')) goto failed;
            start_position = i + 1;
        }
        else goto failed;
    }

    // Handle the last range after the loop
    if (start_position < length) {
        if (length - start_position > 10) goto failed;

        char* endptr = NULL;
        long long int end = strtoll(&str[start_position], &endptr, 10);
        // endptr should point to end of string or non-digit
        if (endptr == &str[start_position]) goto failed;  // No digits parsed

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

    result = 0;

    failed:

    if (result == -1) {
        http_ranges_free(ranges);
        return NULL;
    }

    return ranges;
}

int __set_header_key(httprequest_t* request, httprequestparser_t* parser, bufferdata_t* buf) {
    // Check header count limit to prevent DoS
    if (parser->headers_count >= MAX_HEADERS_COUNT) {
        log_error("HTTP error: too many headers (max: %d)\n", MAX_HEADERS_COUNT);
        return HTTP1PARSER_BAD_REQUEST;
    }

    char* string = bufferdata_get(buf);
    size_t length = bufferdata_writed(buf);
    http_header_t* header = http_header_create(string, length, NULL, 0);

    if (header == NULL) {
        log_error("HTTP error: can't alloc header memory\n");
        return HTTP1PARSER_OUT_OF_MEMORY;
    }

    if (header->key == NULL) {
        http_header_free(header);
        return HTTP1PARSER_OUT_OF_MEMORY;
    }

    if (request->header_ == NULL)
        request->header_ = header;

    if (request->last_header)
        request->last_header->next = header;

    request->last_header = header;
    parser->headers_count++;

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

    if (__header_is_content_length(request->last_header)) {
        // Защита от дублирования Content-Length
        if (parser->content_length_found) {
            log_error("HTTP error: duplicate Content-Length header\n");
            return HTTP1PARSER_BAD_REQUEST;
        }

        // RFC 7230: Transfer-Encoding и Content-Length вместе - признак атаки Request Smuggling
        if (parser->transfer_encoding_found) {
            log_error("HTTP error: both Transfer-Encoding and Content-Length headers present (Request Smuggling attempt)\n");
            return HTTP1PARSER_BAD_REQUEST;
        }

        size_t validated_length = 0;
        if (!__validate_content_length(request->last_header->value, &validated_length))
            return HTTP1PARSER_BAD_REQUEST;

        parser->content_length = validated_length;
        parser->content_length_found = 1;
    }

    if (__header_is_transfer_encoding(request->last_header)) {
        // RFC 7230: Transfer-Encoding не поддерживается в HTTP/1.0
        if (request->version == HTTP1_VER_1_0) {
            log_error("HTTP error: Transfer-Encoding not allowed in HTTP/1.0\n");
            return HTTP1PARSER_BAD_REQUEST;
        }

        // RFC 7230: Transfer-Encoding и Content-Length вместе - признак атаки Request Smuggling
        if (parser->content_length_found) {
            log_error("HTTP error: both Transfer-Encoding and Content-Length headers present (Request Smuggling attempt)\n");
            return HTTP1PARSER_BAD_REQUEST;
        }

        // Transfer-Encoding: chunked не поддерживается на этапе запроса
        // Отклоняем все запросы с Transfer-Encoding для безопасности
        log_error("HTTP error: Transfer-Encoding not supported in requests\n");
        return HTTP1PARSER_BAD_REQUEST;
    }

    return HTTP1PARSER_CONTINUE;
}

int __header_is_host(http_header_t* header) {
    return cmpstrn_lower(header->key, header->key_length, "host", 4);
}

int __header_is_content_length(http_header_t* header) {
    return cmpstrn_lower(header->key, header->key_length, "content-length", 14);
}

int __header_is_transfer_encoding(http_header_t* header) {
    return cmpstrn_lower(header->key, header->key_length, "transfer-encoding", 17);
}

int __validate_content_length(const char* value, size_t* out_length) {
    if (value == NULL || out_length == NULL) return 0;

    // Проверяем, что строка состоит только из цифр
    size_t i = 0;
    while (value[i] != '\0') {
        if (!isdigit((unsigned char)value[i])) {
            log_error("HTTP error: Content-Length contains non-digit characters: %s\n", value);
            return 0;
        }
        i++;
    }

    // Проверяем, что строка не пустая
    if (i == 0) {
        log_error("HTTP error: Content-Length is empty\n");
        return 0;
    }

    // Используем strtoul для безопасного преобразования
    errno = 0;
    char* endptr = NULL;
    unsigned long long result = strtoull(value, &endptr, 10);

    // Проверяем ошибки преобразования
    if (errno == ERANGE || result > env()->main.client_max_body_size) {
        log_error("HTTP error: Content-Length too large: %s (max: %u)\n", value, env()->main.client_max_body_size);
        return 0;
    }

    if (endptr == value || *endptr != '\0') {
        log_error("HTTP error: Content-Length invalid format: %s\n", value);
        return 0;
    }

    *out_length = (size_t)result;
    return 1;
}