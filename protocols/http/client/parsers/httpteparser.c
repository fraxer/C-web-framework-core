#include "httpteparser.h"
#include "helpers.h"

static const long __hextable[] = { 
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1, 0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,-1,10,11,12,13,14,15,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static int __set_chunk_size(httpteparser_t* parser);
static ssize_t __hex_to_dec(const char* data, size_t size);
static int __read_chunk(httpteparser_t* parser);

httpteparser_t* httpteparser_init() {
    httpteparser_t* parser = malloc(sizeof * parser);
    if (parser == NULL) return NULL;

    parser->stage = HTTP1TEPARSER_CHUNKSIZE;
    parser->bytes_readed = 0;
    parser->pos_start = 0;
    parser->pos = 0;
    parser->chunk_size = 0;
    parser->chunk_size_readed = 0;
    parser->buffer = NULL;
    parser->connection = NULL;

    bufferdata_init(&parser->buf);
    gzip_init(&parser->gzip);

    return parser;
}

void httpteparser_free(httpteparser_t* parser) {
    if (parser->buf.dynamic_buffer) free(parser->buf.dynamic_buffer);
    parser->buf.dynamic_buffer = NULL;

    /*
     * inflateInit2() вызывается лениво при первом gzip-чанке, а inflateEnd() —
     * только по достижении Z_STREAM_END. На любом досрочном завершении
     * (ошибка/обрыв соединения) внутренние буферы zlib иначе утекают.
     * gzip_free() безопасна, если inflate уже освобождён (is_deflate_init == -1).
     */
    gzip_free(&parser->gzip);

    free(parser);
}

void httpteparser_set_buffer(httpteparser_t* parser, char* buffer, size_t buffer_size) {
    parser->buffer = buffer;
    parser->bytes_readed = buffer_size;
}

int httpteparser_run(httpteparser_t* parser) {
    parser->pos_start = 0;
    parser->pos = 0;

    for (parser->pos = parser->pos_start; parser->pos < parser->bytes_readed; parser->pos++) {
        char ch = parser->buffer[parser->pos];

        switch (parser->stage)
        {
        case HTTP1TEPARSER_CHUNKSIZE:
            if (ch == '\r') {
                if (bufferdata_writed(&parser->buf) > 8)
                    return HTTP1TEPARSER_ERROR;

                parser->stage = HTTP1TEPARSER_CHUNKSIZE_NEWLINE;

                bufferdata_complete(&parser->buf);
                if (!__set_chunk_size(parser))
                    return HTTP1TEPARSER_ERROR;

                bufferdata_reset(&parser->buf);
            }
            else if (ch == ';') {
                /*
                 * chunk-ext (";token=value..."), RFC 7230 §4.1.1. Hex-размер уже
                 * накоплен — парсим его сейчас, а байты расширения пропускаем до CRLF.
                 */
                bufferdata_complete(&parser->buf);
                if (!__set_chunk_size(parser))
                    return HTTP1TEPARSER_ERROR;

                bufferdata_reset(&parser->buf);
                parser->stage = HTTP1TEPARSER_CHUNKSIZE_EXT;
            }
            else {
                if (bufferdata_writed(&parser->buf) > 8)
                    return HTTP1TEPARSER_ERROR;

                bufferdata_push(&parser->buf, ch);
            }
            break;
        case HTTP1TEPARSER_CHUNKSIZE_NEWLINE:
            if (ch == '\n') {
                /*
                 * Последний чанк (chunk_size == 0): за размерной строкой идёт
                 * trailer-part и финальный CRLF, а не данные чанка.
                 */
                parser->stage = (parser->chunk_size == 0)
                    ? HTTP1TEPARSER_TRAILER
                    : HTTP1TEPARSER_CHUNK;
                break;
            }
            else
                return HTTP1TEPARSER_ERROR;
        case HTTP1TEPARSER_CHUNKSIZE_EXT:
            /* Пропуск байтов chunk-ext до CRLF. */
            if (ch == '\r')
                parser->stage = HTTP1TEPARSER_CHUNKSIZE_NEWLINE;
            break;
        case HTTP1TEPARSER_CHUNK:
            {
                if (!__read_chunk(parser))
                    return HTTP1TEPARSER_ERROR;

                if (parser->chunk_size_readed >= parser->chunk_size
                    && parser->pos < parser->bytes_readed) {
                    /*
                     * '\r', завершающий чанк, может приехать в следующем буфере.
                     * Здесь parser->pos уже сдвинут на temp_chunk_size внутри
                     * __read_chunk; если данные чанка точно заполнили буфер, pos
                     * == bytes_readed и чтение buffer[pos] — out-of-bounds.
                     */
                    ch = parser->buffer[parser->pos];
                    if (ch == '\r')
                        parser->stage = HTTP1TEPARSER_CHUNK_NEWLINE;
                }

                break;
            }
            break;
        case HTTP1TEPARSER_CHUNK_NEWLINE:
            if (ch == '\n') {
                parser->stage = HTTP1TEPARSER_CHUNKSIZE;
                break;
            }
            else
                return HTTP1TEPARSER_ERROR;
        case HTTP1TEPARSER_TRAILER:
            /*
             * trailer-part = *( header-field CRLF ) (RFC 7230 §4.1.2). Пустая
             * строка (текущая строка не содержит байтов) — это финальный CRLF.
             * Содержимое trailer-строк не используем, только отличаем пустую
             * строку от непустой, поэтому копим байты ради счётчика.
             */
            if (ch == '\r') {
                if (bufferdata_writed(&parser->buf) == 0)
                    parser->stage = HTTP1TEPARSER_TRAILER_FINAL_NEWLINE;
                else {
                    bufferdata_reset(&parser->buf);
                    parser->stage = HTTP1TEPARSER_TRAILER_NEWLINE;
                }
            }
            else {
                if (bufferdata_writed(&parser->buf) > 8192)
                    return HTTP1TEPARSER_ERROR;
                bufferdata_push(&parser->buf, ch);
            }
            break;
        case HTTP1TEPARSER_TRAILER_NEWLINE:
            if (ch == '\n') {
                parser->stage = HTTP1TEPARSER_TRAILER;
                break;
            }
            else
                return HTTP1TEPARSER_ERROR;
        case HTTP1TEPARSER_TRAILER_FINAL_NEWLINE:
            if (ch == '\n')
                return HTTP1TEPARSER_COMPLETE;
            else
                return HTTP1TEPARSER_ERROR;
        }
    }

    /*
     * Строгое завершение: финальный CRLF должен быть прочитан, иначе оставшиеся
     * байты терминатора останутся в сокете и испортят следующий ответ на
     * keep-alive соединении. Ждём их в следующем буфере (CONTINUE). Если сервер
     * оборвёт поток без финального CRLF, клиент увидит EOF и использует уже
     * полностью записанное тело — см. http_client_read (case 0).
     */
    return HTTP1TEPARSER_CONTINUE;
}

int __set_chunk_size(httpteparser_t* parser) {
    char* string = bufferdata_get(&parser->buf);
    size_t length = bufferdata_writed(&parser->buf);

    ssize_t result = __hex_to_dec(string, length);
    if (result == -1)
        return 0;

    parser->chunk_size = (size_t)result;
    parser->chunk_size_readed = 0;

    return 1;
}

ssize_t __hex_to_dec(const char* data, size_t size) {
    ssize_t ret = 0;
    for (size_t pos = 0; pos < size && ret >= 0; pos++) {
        unsigned char hex = data[pos];
        ret = (ret << 4) | __hextable[hex];
        if (ret > INT_MAX) return -1;
    }
    return ret; 
}

int __read_chunk(httpteparser_t* parser) {
    size_t temp_chunk_size = parser->chunk_size - parser->chunk_size_readed > parser->bytes_readed - parser->pos
        ? parser->bytes_readed - parser->pos
        : parser->chunk_size - parser->chunk_size_readed;

    /*
     * Чанк уже прочитан целиком в предыдущем буфере (temp_chunk_size == 0):
     * данных для записи нет. Пропускаем append_content/inflate — иначе вызов
     * записи нуля байт трактуется как ошибка (см. __file_append_content).
     */
    if (temp_chunk_size == 0)
        return 1;

    connection_client_ctx_t* ctx = parser->connection->ctx;
    httpresponse_t* response = ctx->response;

    if (response->content_encoding == CE_GZIP) {
        gzip_t* const gzip = &parser->gzip;
        char buffer[GZIP_BUFFER];

        if (!gzip_inflate_init(gzip, &parser->buffer[parser->pos], temp_chunk_size))
            return 0;

        do {
            const size_t writed = gzip_inflate(gzip, buffer, GZIP_BUFFER);
            if (gzip_inflate_has_error(gzip))
                return 0;

            if (writed > 0) {
                if (!response->payload_.file.append_content(&response->payload_.file, buffer, writed))
                    return 0;
            }
        } while (gzip_want_continue(gzip));

        if (gzip_is_end(gzip)) {
            if (!gzip_inflate_free(gzip))
                return 0;
        }
    }
    else {
        if (!response->payload_.file.append_content(&response->payload_.file, &parser->buffer[parser->pos], temp_chunk_size))
            return 0;
    }

    parser->chunk_size_readed += temp_chunk_size;
    parser->pos += temp_chunk_size;

    return 1;
}
