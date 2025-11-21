#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>

#include "httprequest.h"
#include "httpresponse.h"
#include "cookieparser.h"
#include "domain.h"
#include "log.h"
#include "appconfig.h"
#include "httpcommon.h"
#include "httpresponseparser.h"
#include "helpers.h"

int __httpresponseparser_set_protocol(httpresponse_t*, httpresponseparser_t*);
int __httpresponseparser_set_statuscode(httpresponse_t*, httpresponseparser_t*);
int __httpresponseparser_set_header_key(httpresponse_t*, httpresponseparser_t*);
int __httpresponseparser_set_header_value(httpresponse_t*, httpresponseparser_t*);
int __httpresponseparser_parse_payload(httpresponseparser_t*);
void __try_set_keepalive(httpresponseparser_t*);
void __try_set_content_length(httpresponseparser_t*);
void __try_set_transfer_encoding(httpresponseparser_t*);
void __try_set_content_encoding(httpresponseparser_t*);
void __httpresponseparser_flush(httpresponseparser_t*);
int __transfer_decoding(httpresponse_t*, const char*, size_t);


void httpresponseparser_init(httpresponseparser_t* parser) {
    parser->stage = HTTP1RESPONSEPARSER_PROTOCOL;
    parser->bytes_readed = 0;
    parser->pos_start = 0;
    parser->pos = 0;
    parser->buffer = NULL;
    parser->connection = NULL;
    parser->content_length = 0;
    parser->content_saved_length = 0;

    parser->teparser = httpteparser_init();
    if (parser->teparser == NULL) return;

    bufferdata_init(&parser->buf);
    gzip_init(&parser->gzip);
}

void httpresponseparser_set_connection(httpresponseparser_t* parser, connection_t* connection) {
    parser->connection = connection;
    parser->teparser->connection = connection;
}

void httpresponseparser_set_buffer(httpresponseparser_t* parser, char* buffer) {
    parser->buffer = buffer;
}

void httpresponseparser_free(httpresponseparser_t* parser) {
    __httpresponseparser_flush(parser);
    free(parser);
}

void httpresponseparser_reset(httpresponseparser_t* parser) {
    __httpresponseparser_flush(parser);
    httpresponseparser_init(parser);
}

void __httpresponseparser_flush(httpresponseparser_t* parser) {
    if (parser->buf.dynamic_buffer) free(parser->buf.dynamic_buffer);
    parser->buf.dynamic_buffer = NULL;

    httpteparser_free(parser->teparser);
}

int httpresponseparser_run(httpresponseparser_t* parser) {
    connection_client_ctx_t* ctx = parser->connection->ctx;
    httpresponse_t* response = ctx->response;
    httprequest_t* request = ctx->request;
    parser->pos_start = 0;
    parser->pos = 0;

    if (parser->stage == HTTP1RESPONSEPARSER_PAYLOAD)
        return __httpresponseparser_parse_payload(parser);

    for (parser->pos = parser->pos_start; parser->pos < parser->bytes_readed; parser->pos++) {
        char ch = parser->buffer[parser->pos];

        switch (parser->stage)
        {
        case HTTP1RESPONSEPARSER_PROTOCOL:
            if (ch == ' ') {
                parser->stage = HTTP1RESPONSEPARSER_STATUS_CODE;

                bufferdata_complete(&parser->buf);
                if (!__httpresponseparser_set_protocol(response, parser))
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
        case HTTP1RESPONSEPARSER_STATUS_CODE:
            if (ch == ' ') {
                parser->stage = HTTP1RESPONSEPARSER_STATUS_TEXT;

                bufferdata_complete(&parser->buf);
                if (!__httpresponseparser_set_statuscode(response, parser))
                    return HTTP1PARSER_BAD_REQUEST;

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
        case HTTP1RESPONSEPARSER_STATUS_TEXT:
            if (ch == '\r') {
                parser->stage = HTTP1RESPONSEPARSER_NEWLINE1;

                bufferdata_complete(&parser->buf);
                bufferdata_reset(&parser->buf);
            }
            else {
                if (bufferdata_writed(&parser->buf) > 128)
                    return HTTP1PARSER_BAD_REQUEST;

                bufferdata_push(&parser->buf, ch);
            }
            break;
        case HTTP1RESPONSEPARSER_NEWLINE1:
            if (ch == '\n') {
                parser->stage = HTTP1RESPONSEPARSER_HEADER_KEY;
                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1RESPONSEPARSER_HEADER_KEY:
            if (ch == '\r') {
                if (bufferdata_writed(&parser->buf) > 0)
                    return HTTP1PARSER_BAD_REQUEST;

                parser->stage = HTTP1RESPONSEPARSER_NEWLINE3;
                break;
            }
            else if (ch == ':') {
                parser->stage = HTTP1RESPONSEPARSER_HEADER_SPACE;

                bufferdata_complete(&parser->buf);
                if (!__httpresponseparser_set_header_key(response, parser))
                    return HTTP1PARSER_BAD_REQUEST;

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
        case HTTP1RESPONSEPARSER_HEADER_SPACE:
            if (ch == ' ') {
                parser->stage = HTTP1RESPONSEPARSER_HEADER_VALUE;
                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1RESPONSEPARSER_HEADER_VALUE:
            if (ch == '\r') {
                parser->stage = HTTP1RESPONSEPARSER_NEWLINE2;

                bufferdata_complete(&parser->buf);
                if (!__httpresponseparser_set_header_value(response, parser))
                    return HTTP1PARSER_BAD_REQUEST;

                bufferdata_reset(&parser->buf);

                break;
            }
            else if (httpparser_is_ctl(ch))
                return HTTP1PARSER_BAD_REQUEST;
            else
            {
                bufferdata_push(&parser->buf, ch);
                break;
            }
        case HTTP1RESPONSEPARSER_NEWLINE2:
            if (ch == '\n') {
                parser->stage = HTTP1RESPONSEPARSER_HEADER_KEY;
                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1RESPONSEPARSER_NEWLINE3:
            if (ch == '\n') {
                parser->stage = HTTP1RESPONSEPARSER_PAYLOAD;

                if (response->transfer_encoding == TE_NONE && parser->content_length == 0)
                    return HTTP1RESPONSEPARSER_COMPLETE;
                if (request->method == ROUTE_HEAD)
                    return HTTP1RESPONSEPARSER_COMPLETE;

                break;
            }
            else
                return HTTP1PARSER_BAD_REQUEST;
        case HTTP1RESPONSEPARSER_PAYLOAD:
            return __httpresponseparser_parse_payload(parser);
        default:
            return HTTP1PARSER_BAD_REQUEST;
        }
    }

    return HTTP1PARSER_CONTINUE;
}

void httpresponseparser_set_bytes_readed(httpresponseparser_t* parser, int readed) {
    parser->bytes_readed = readed;
}

int __httpresponseparser_set_protocol(httpresponse_t* response, httpresponseparser_t* parser) {
    char* s = bufferdata_get(&parser->buf);

    if (s[0] == 'H' && s[1] == 'T' && s[2] == 'T' && s[3] == 'P' && s[4] == '/'  && s[5] == '1' && s[6] == '.' && s[7] == '1') {
        response->version = HTTP1_VER_1_1;
        return 1;
    }

    return 0;
}

int __httpresponseparser_set_statuscode(httpresponse_t* response, httpresponseparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);
    int status_code = atoi(string);
    if (status_code == 0)
        return 0;

    response->status_code = status_code;

    return 1;
}

int __httpresponseparser_parse_payload(httpresponseparser_t* parser) {
    connection_client_ctx_t* ctx = parser->connection->ctx;
    httpresponse_t* response = ctx->response;

    if (!httpresponse_has_payload(response))
        return HTTP1PARSER_BAD_REQUEST;

    parser->pos_start = parser->pos;
    parser->pos = parser->bytes_readed;

    if (response->payload_.file.fd < 0) {
        response->payload_.path = create_tmppath(env()->main.tmp);
        if (response->payload_.path == NULL)
            return HTTP1PARSER_ERROR;

        response->payload_.file.fd = mkstemp(response->payload_.path);
        if (response->payload_.file.fd == -1)
            return HTTP1PARSER_ERROR;
    }

    const size_t string_len = parser->pos - parser->pos_start;
    const size_t client_max_body_size = env()->main.client_max_body_size;

    if (parser->content_saved_length + string_len > client_max_body_size)
        return HTTP1PARSER_PAYLOAD_LARGE;

    if (response->transfer_encoding == TE_CHUNKED) {
        int ret = __transfer_decoding(response, &parser->buffer[parser->pos_start], string_len);
        switch (ret) {
            case HTTP1TEPARSER_ERROR:
                return HTTP1PARSER_ERROR;
            case HTTP1TEPARSER_CONTINUE:
                break;
            case HTTP1TEPARSER_COMPLETE:
                return HTTP1RESPONSEPARSER_COMPLETE;
        }
    }
    else {
        if (response->content_encoding == CE_GZIP) {
            gzip_t* gzip = &parser->gzip;
            char buffer[GZIP_BUFFER];
            size_t decompressed_total = 0;

            if (!gzip_inflate_init(gzip, &parser->buffer[parser->pos_start], string_len))
                return HTTP1PARSER_ERROR;

            do {
                const size_t writed = gzip_inflate(gzip, buffer, GZIP_BUFFER);
                if (gzip_inflate_has_error(gzip))
                    return HTTP1PARSER_ERROR;

                if (writed > 0) {
                    response->payload_.file.append_content(&response->payload_.file, buffer, writed);
                    decompressed_total += writed;
                }
            } while (gzip_want_continue(gzip));

            if (gzip_is_end(gzip))
                if (!gzip_inflate_free(gzip))
                    return HTTP1PARSER_ERROR;

            parser->content_saved_length += decompressed_total;
        }
        else {
            if (!response->payload_.file.append_content(&response->payload_.file, &parser->buffer[parser->pos_start], string_len))
                return HTTP1PARSER_ERROR;

            parser->content_saved_length += string_len;
        }

        if (parser->content_saved_length >= parser->content_length)
            return HTTP1RESPONSEPARSER_COMPLETE;
    }

    return HTTP1PARSER_CONTINUE;
}

void __try_set_keepalive(httpresponseparser_t* parser) {
    connection_client_ctx_t* ctx = parser->connection->ctx;
    httpresponse_t* response = ctx->response;
    http_header_t* header = response->last_header;

    const char* connection_key = "connection";
    const size_t connection_key_length = 10;
    const char* connection_value = "keep-alive";
    const size_t connection_value_length = 10;

    if (header->key_length != connection_key_length) return;
    if (!cmpstrn_lower(header->key, header->key_length, connection_key, connection_key_length)) return;

    parser->connection->keepalive = cmpstrn_lower(header->value, header->value_length, connection_value, connection_value_length);
}

void __try_set_content_length(httpresponseparser_t* parser) {
    connection_client_ctx_t* ctx = parser->connection->ctx;
    httpresponse_t* response = ctx->response;
    http_header_t* header = response->last_header;

    const char* key = "content-length";
    const size_t key_length = 14;

    if (header->key_length != key_length) return;
    if (!cmpstrn_lower(header->key, header->key_length, key, key_length)) return;

    parser->content_length = atoll(header->value); // TODO: Проверить на переполнение
    response->content_length = parser->content_length;
}

void __try_set_transfer_encoding(httpresponseparser_t* parser) {
    connection_client_ctx_t* ctx = parser->connection->ctx;
    httpresponse_t* response = ctx->response;
    http_header_t* header = response->last_header;

    const char* key = "transfer-encoding";
    const size_t key_length = 17;

    if (header->key_length != key_length) return;
    if (!cmpstrn_lower(header->key, header->key_length, key, key_length)) return;

    const char* value_chunked = "chunked";
    const size_t value_chunked_length = 7;

    const char* value_gzip = "gzip";
    const size_t value_gzip_length = 4;

    if (cmpstrn_lower(header->value, header->value_length, value_chunked, value_chunked_length))
        response->transfer_encoding = TE_CHUNKED;
    else if (cmpstrn_lower(header->value, header->value_length, value_gzip, value_gzip_length))
        response->transfer_encoding = TE_GZIP;
}

void __try_set_content_encoding(httpresponseparser_t* parser) {
    connection_client_ctx_t* ctx = parser->connection->ctx;
    httpresponse_t* response = ctx->response;
    http_header_t* header = response->last_header;

    const char* key = "content-encoding";
    const size_t key_length = 16;

    if (header->key_length != key_length) return;
    if (!cmpstrn_lower(header->key, header->key_length, key, key_length)) return;

    const char* value_gzip = "gzip";
    const size_t value_gzip_length = 4;
    if (cmpstrn_lower(header->value, header->value_length, value_gzip, value_gzip_length))
        response->content_encoding = CE_GZIP;
}

int __httpresponseparser_set_header_key(httpresponse_t* response, httpresponseparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);
    size_t length = bufferdata_writed(&parser->buf);
    http_header_t* header = http_header_create(string, length, NULL, 0);

    if (header == NULL) {
        log_error("HTTP error: can't alloc header memory\n");
        return 0;
    }
    
    if (header->key == NULL)
        return 0;

    if (response->header_ == NULL)
        response->header_ = header;

    if (response->last_header)
        response->last_header->next = header;

    response->last_header = header;

    return 1;
}

int __httpresponseparser_set_header_value(httpresponse_t* response, httpresponseparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);
    size_t length = bufferdata_writed(&parser->buf);

    response->last_header->value = copy_cstringn(string, length);
    response->last_header->value_length = length;

    if (response->last_header->value == NULL)
        return HTTP1PARSER_OUT_OF_MEMORY;

    __try_set_keepalive(parser);
    __try_set_content_length(parser);
    __try_set_transfer_encoding(parser);
    __try_set_content_encoding(parser);

    return HTTP1PARSER_CONTINUE;
}

int __transfer_decoding(httpresponse_t* response, const char* data, size_t size) {
    httpteparser_t* parser = ((httpresponseparser_t*)response->parser)->teparser;
    httpteparser_set_buffer(parser, (char*)data, size);

    return httpteparser_run(parser);
}
