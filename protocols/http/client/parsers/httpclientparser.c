#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "helpers.h"
#include "httpcommon.h"
#include "httpclient.h"
#include "httpclientparser.h"
#include "queryparser.h"

void __httpclientparser_flush(httpclientparser_t* parser);
int __httpclientparser_set_query(httpclientparser_t* parser, const char* string, size_t length, size_t pos);
int __httpclientparser_set_path(httpclientparser_t* parser, const char* string, size_t length);
int __httpclientparser_set_protocol(httpclientparser_t* parser);
int __httpclientparser_set_host(httpclientparser_t* parser);
int __httpclientparser_set_port(httpclientparser_t* parser);
int __httpclientparser_set_uri(httpclientparser_t* parser);

void httpclientparser_init(httpclientparser_t* parser) {
    parser->stage = CLIENTPARSER_PROTOCOL;
    parser->bytes_readed = 0;
    parser->pos_start = 0;
    parser->pos = 0;
    parser->path_length = 0;
    parser->use_ssl = 0;
    parser->port = 0;
    parser->host = NULL;
    parser->uri = NULL;
    parser->path = NULL;
    parser->buffer = NULL;
    parser->query = NULL;
    parser->last_query = NULL;

    bufferdata_init(&parser->buf);
}

int httpclientparser_move_use_ssl(httpclientparser_t* parser) {
    return parser->use_ssl;
}

char* httpclientparser_move_host(httpclientparser_t* parser) {
    char* host = parser->host;
    parser->host = NULL;

    return host;
}

unsigned short httpclientparser_move_port(httpclientparser_t* parser) {
    return parser->port;
}

char* httpclientparser_move_uri(httpclientparser_t* parser) {
    char* uri = parser->uri;
    parser->uri = NULL;

    return uri;
}

char* httpclientparser_move_path(httpclientparser_t* parser) {
    char* path = parser->path;
    parser->path = NULL;

    return path;
}

query_t* httpclientparser_move_query(httpclientparser_t* parser) {
    query_t* query = parser->query;
    parser->query = NULL;

    return query;
}

query_t* httpclientparser_move_last_query(httpclientparser_t* parser) {
    query_t* last_query = parser->last_query;
    parser->last_query = NULL;

    return last_query;
}


void httpclientparser_free(httpclientparser_t* parser) {
    if (parser == NULL) return;

    __httpclientparser_flush(parser);
    free(parser);
}

void httpclientparser_reset(httpclientparser_t* parser) {
    __httpclientparser_flush(parser);
    httpclientparser_init(parser);
}

int httpclientparser_parse(httpclientparser_t* parser, const char* url) {
    if (url == NULL)
        return CLIENTPARSER_BAD_PROTOCOL;

    parser->buffer = (char*)url;
    parser->bytes_readed = strlen(url);
    if (parser->bytes_readed == 0)
        return CLIENTPARSER_BAD_PROTOCOL;

    parser->pos_start = 0;
    parser->pos = 0;

    // Самодостаточность: parse начинает с чистой стадии и буфера, даже без предшествующего reset().
    parser->stage = CLIENTPARSER_PROTOCOL;
    bufferdata_reset(&parser->buf);

    for (parser->pos = parser->pos_start; parser->pos < parser->bytes_readed; parser->pos++) {
        char ch = parser->buffer[parser->pos];
        int end = parser->pos + 1 == parser->bytes_readed;

        switch (parser->stage)
        {
        case CLIENTPARSER_PROTOCOL:
            if (ch == '/') {
                if (bufferdata_writed(&parser->buf) > 0)
                    return CLIENTPARSER_BAD_PROTOCOL;

                parser->stage = CLIENTPARSER_URI;

                if (end || ch == '/')
                    parser->pos--;
                break;
            }
            else if (ch == ':') {
                parser->stage = CLIENTPARSER_PROTOCOL_SLASH1;

                bufferdata_complete(&parser->buf);
                if (!__httpclientparser_set_protocol(parser))
                    return CLIENTPARSER_BAD_PROTOCOL;

                bufferdata_reset(&parser->buf);
                break;
            }
            else if (end)
                return CLIENTPARSER_BAD_PROTOCOL;
            else {
                if (bufferdata_writed(&parser->buf) >= 5)
                    return CLIENTPARSER_BAD_PROTOCOL;

                bufferdata_push(&parser->buf, ch);
                break;
            }
        case CLIENTPARSER_PROTOCOL_SLASH1:
            if (ch == '/') {
                parser->stage = CLIENTPARSER_PROTOCOL_SLASH2;
                break;
            }
            else if (end) 
                return CLIENTPARSER_BAD_PROTOCOL_SEPARATOR;
            else
                return CLIENTPARSER_BAD_PROTOCOL_SEPARATOR;
        case CLIENTPARSER_PROTOCOL_SLASH2:
            if (ch == '/') {
                parser->stage = CLIENTPARSER_HOST;
                break;
            }
            else if (end) 
                return CLIENTPARSER_BAD_PROTOCOL_SEPARATOR;
            else
                return CLIENTPARSER_BAD_PROTOCOL_SEPARATOR;
        case CLIENTPARSER_HOST:
        {
            if (ch == ':')
                parser->stage = CLIENTPARSER_PORT;
            else if (ch == '/' || ch == '?' || ch == '#')
                parser->stage = CLIENTPARSER_URI;
            else if (end) {
                parser->stage = CLIENTPARSER_URI;
                bufferdata_push(&parser->buf, ch);
            }
            else {
                bufferdata_push(&parser->buf, ch);
                break;
            }

            bufferdata_complete(&parser->buf);
            if (!__httpclientparser_set_host(parser))
                return CLIENTPARSER_BAD_HOST;

            bufferdata_reset(&parser->buf);

            if (ch == '/' || ch == '?' || ch == '#') {
                parser->pos--;
                break;
            }
            if (end) {
                ch = '/';
                goto start_uri;
            }
            break;
        }
        case CLIENTPARSER_PORT:
        {
            if (ch == '/' || ch == '?' || ch == '#')
                parser->stage = CLIENTPARSER_URI;
            else if (end) {
                parser->stage = CLIENTPARSER_URI;
                bufferdata_push(&parser->buf, ch);
            }
            else {
                // Ограничиваем длину порта: защищаем и от atoi-подобного переполнения,
                // и от неограниченного роста буфера на гигантских числовых строках.
                if (bufferdata_writed(&parser->buf) >= 5)
                    return CLIENTPARSER_BAD_PORT;

                bufferdata_push(&parser->buf, ch);
                break;
            }

            bufferdata_complete(&parser->buf);
            if (!__httpclientparser_set_port(parser))
                return CLIENTPARSER_BAD_PORT;

            bufferdata_reset(&parser->buf);

            if (ch == '/' || ch == '?' || ch == '#') {
                parser->pos--;
                break;
            }
            if (end) {
                ch = '/';
                goto start_uri;
            }
            break;
        }
        case CLIENTPARSER_URI:
        {
            start_uri:

            bufferdata_push(&parser->buf, ch);
            
            if (!end) break;

            bufferdata_complete(&parser->buf);
            if (!__httpclientparser_set_uri(parser))
                return CLIENTPARSER_BAD_URI;

            bufferdata_reset(&parser->buf);
            break;
        }
        }
    }

    // URL закончился до того, как был сформирован URI. Это неполные абсолютные
    // адреса вида "http:", "http:/", "http://", "http://host:" — стадии-обработчики
    // таких хвостов не имеют явной проверки end, т.к. разделитель (':','//') уже
    // поглощён на предыдущей итерации. Корректный разбор (относительный "/" или
    // абсолютный с host) всегда завершается в стадии URI.
    switch (parser->stage) {
    case CLIENTPARSER_PROTOCOL_SLASH1:
    case CLIENTPARSER_PROTOCOL_SLASH2:
        return CLIENTPARSER_BAD_PROTOCOL_SEPARATOR;
    case CLIENTPARSER_HOST:
        return CLIENTPARSER_BAD_HOST;
    case CLIENTPARSER_PORT:
        return CLIENTPARSER_BAD_PORT;
    default:
        break;
    }

    return CLIENTPARSER_OK;
}

void __httpclientparser_flush(httpclientparser_t* parser) {
    if (parser->buf.dynamic_buffer) free(parser->buf.dynamic_buffer);
    parser->buf.dynamic_buffer = NULL;

    bufferdata_reset(&parser->buf);

    if (parser->host) free(parser->host);
    parser->host = NULL;

    if (parser->uri) free(parser->uri);
    parser->uri = NULL;

    if (parser->path) free(parser->path);
    parser->path = NULL;
    parser->path_length = 0;

    queries_free(parser->query);
    parser->query = NULL;
    parser->last_query = NULL;
}

int __httpclientparser_set_protocol(httpclientparser_t* parser) {
    const char* protocol = bufferdata_get(&parser->buf);

    if (protocol[0] == 'h' && protocol[1] == 't' && protocol[2] == 't' && protocol[3] == 'p' && protocol[4] == 's') {
        parser->use_ssl = 1;
        parser->port = 443;
        return 1;
    }
    else if (protocol[0] == 'h' && protocol[1] == 't' && protocol[2] == 't' && protocol[3] == 'p') {
        // Явно сбрасываем use_ssl: иначе повторное использование парсера для "http://"
        // после "https://" оставляет stale-флаг шифрования от предыдущего разбора.
        parser->use_ssl = 0;
        parser->port = 80;
        return 1;
    }

    return 0;
}

int __httpclientparser_set_host(httpclientparser_t* parser) {
    const size_t length = bufferdata_writed(&parser->buf);

    // Пустая authority ("http://:80", "http://?x", "http://#frag") недопустима.
    if (length == 0) return 0;

    parser->host = malloc(sizeof(char) * (length + 1));
    if (parser->host == NULL) return 0;

    memcpy(parser->host, bufferdata_get(&parser->buf), length);
    parser->host[length] = 0;

    return 1;
}

int __httpclientparser_set_port(httpclientparser_t* parser) {
    const char* port = bufferdata_get(&parser->buf);
    const size_t length = bufferdata_writed(&parser->buf);

    if (length == 0 || strspn(port, "0123456789") != length)
        return 0;

    // strtol с проверкой переполнения/диапазона вместо atoi (atoi даёт UB на больших значениях).
    errno = 0;
    char* end = NULL;
    long port_number = strtol(port, &end, 10);
    if (errno != 0 || end == port || *end != '\0')
        return 0;
    if (port_number <= 0 || port_number > 65535)
        return 0;

    parser->port = (unsigned short)port_number;

    return 1;
}

int __httpclientparser_set_uri(httpclientparser_t* parser) {
    const char* string = bufferdata_get(&parser->buf);
    size_t length = bufferdata_writed(&parser->buf);
    if (length == 0) {
        string = "/";
        length = 1;
    }

    // Путь заканчивается на первом '?' (запускает разбор query) или '#' (фрагмент).
    // (size_t)-1 означает, что разделителя в строке не было.
    size_t path_point_end = (size_t)-1;
    for (size_t pos = 0; pos < length; pos++) {
        switch (string[pos]) {
        case '?':
            path_point_end = pos;

            if (!__httpclientparser_set_query(parser, string, length, pos))
                return 0;

            goto next;
        case '#':
            path_point_end = pos;
            goto next;
        }
    }

    next:

    if (path_point_end == (size_t)-1)
        path_point_end = length;

    // Пустой путь (например "http://host?x=1" или "http://host#frag") нормализуем в "/".
    if (path_point_end == 0) {
        if (!__httpclientparser_set_path(parser, "/", 1))
            return 0;
    }
    else if (!__httpclientparser_set_path(parser, string, path_point_end)) {
        return 0;
    }

    // uri строится из ДЕКОДИРОВАННОГО пути по его реальной длине;
    // иначе для %-encoded путей в uri попадают встроенный '\0' и хвостовой мусор.
    str_t* uri = str_createn(parser->path, parser->path_length);
    if (uri == NULL) return 0;

    query_t* query = parser->query;
    if (query != NULL) str_appendc(uri, '?');

    char* query_str = query_stringify(parser->query);
    if (query_str != NULL) {
        str_append(uri, query_str, strlen(query_str));
        free(query_str);
    }

    parser->uri = str_copy(uri);
    str_free(uri);

    return 1;
}

int __httpclientparser_set_query(httpclientparser_t* parser, const char* string, size_t length, size_t pos) {
    query_t* first_query = NULL;
    query_t* last_query = NULL;

    // Колбэк не нужен: queryparser_parse сам собирает и возвращает голову/хвост списка.
    queryparser_result_t result = queryparser_parse(
        string,
        length,
        pos + 1,  // Start after '?'
        NULL,
        NULL,
        &first_query,
        &last_query
    );

    if (result != QUERYPARSER_OK)
        return 0;

    parser->query = first_query;
    parser->last_query = last_query;

    return 1;
}

int __httpclientparser_set_path(httpclientparser_t* parser, const char* string, size_t length) {
    size_t decoded_length = length;
    parser->path = urldecodel(string, length, &decoded_length);
    if (parser->path == NULL) return 0;

    parser->path_length = decoded_length;

    if (is_path_traversal(parser->path, decoded_length))
        return 0;

    return 1;
}
