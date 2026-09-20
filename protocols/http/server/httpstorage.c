#include <string.h>
#include <stdio.h>

#include "httpstorage.h"
#include "storages3.h"
#include "appconfig.h"
#include "mimetype.h"
#include "file.h"
#include "log.h"

static void __headers_common(httpresponse_t* response, const s3fetch_t* meta, const char* path);
static int __if_range_matches(httprequest_t* request, const s3fetch_t* meta);
static int __range_bounds(const httprequest_t* request, size_t total, size_t chunk,
                          size_t* start, size_t* end);

void http_storage_respond(httprequest_t* request, httpresponse_t* response,
                          const char* storage_name, const char* path) {
    if (request == NULL || response == NULL) return;
    if (storage_name == NULL || path == NULL) {
        response->send_default(response, 500);
        return;
    }

    http_header_t* if_none_match = request->get_header(request, "If-None-Match");
    http_header_t* if_modified_since = request->get_header(request, "If-Modified-Since");

    s3fetch_t meta;
    storages3_head(storage_name, path,
                   if_none_match != NULL ? if_none_match->value : NULL,
                   if_modified_since != NULL ? if_modified_since->value : NULL,
                   &meta);

    const int head_status = storages3_http_status(meta.status);
    if (head_status == 304) {
        __headers_common(response, &meta, path);
        response->status_code = 304;
        storages3_fetch_free(&meta);
        return;
    }
    if (head_status != 200) {
        storages3_fetch_free(&meta);
        response->send_default(response, head_status);
        return;
    }

    __headers_common(response, &meta, path);

    /* HEAD обслуживается метаданными целиком: тело не скачивается. Длина
     * ставится здесь и через add_headeru, чтобы её же не сосчитала по пустому
     * телу нижняя стадия. */
    if (request->method == ROUTE_HEAD) {
        char length[32];
        const int written = snprintf(length, sizeof(length), "%zu", meta.total_size);
        if (written > 0)
            response->add_headeru(response, "Content-Length", 14, length, (size_t)written);

        response->status_code = 200;
        storages3_fetch_free(&meta);
        return;
    }

    /* Один диапазон обслуживаем; несколько — игнорируем Range целиком и отдаём
     * объект (RFC 9110 §14.2 это разрешает): multipart/byteranges для S3-ветки
     * вне объёма. If-Range сверяется локально с ETag из HEAD — второго запроса
     * для этого не нужно (RFC 9110 §13.1.5). */
    const int single_range = request->ranges != NULL && request->ranges->next == NULL;

    size_t start = 0;
    size_t end = 0;
    int ranged = 0;

    if (single_range && __if_range_matches(request, &meta)) {
        const size_t chunk = storages3_chunk_size(env()->main.client_max_body_size);
        if (!__range_bounds(request, meta.total_size, chunk, &start, &end)) {
            char content_range[64];
            const int written = snprintf(content_range, sizeof(content_range), "bytes */%zu", meta.total_size);
            if (written > 0)
                response->add_headeru(response, "Content-Range", 13, content_range, (size_t)written);

            storages3_fetch_free(&meta);
            response->send_default(response, 416);
            return;
        }

        ranged = 1;
    }

    s3fetch_t body;
    const int ok = ranged
        ? storages3_fetch(storage_name, path, start, end, 0, &body)
        : storages3_fetch(storage_name, path, 0, 0, 1, &body);

    if (!ok) {
        const int status = storages3_http_status(body.status);
        storages3_fetch_free(&body);
        storages3_fetch_free(&meta);
        response->send_default(response, status == 200 ? 502 : status);
        return;
    }

    if (ranged) {
        const size_t total = body.total_size > 0 ? body.total_size : meta.total_size;
        char content_range[96];
        const int written = snprintf(content_range, sizeof(content_range), "bytes %zu-%zu/%zu",
                                     start, end, total);
        if (written > 0)
            response->add_headeru(response, "Content-Range", 13, content_range, (size_t)written);

        response->status_code = 206;
        /* Диапазон вырезал S3: без этого range-фильтр нарежет присланный кусок
         * второй раз, от его собственного нуля. */
        response->range_passthrough = 1;
    }
    else
        response->status_code = 200;

    int attached = 0;
    if (body.file.ok)
        attached = http_response_body_file(response, &body.file);
    else if (body.body != NULL)
        attached = http_response_body_data(response, body.body, body.size);

    storages3_fetch_free(&body);
    storages3_fetch_free(&meta);

    if (!attached)
        response->send_default(response, 500);
}

/* Content-Type — по расширению из таблицы mimetypes, как у остальной статики;
 * заголовок S3 — запасной вариант. Валидаторы берутся из ответа S3: они
 * описывают объект, а mtime временного файла не описывает ничего. */
void __headers_common(httpresponse_t* response, const s3fetch_t* meta, const char* path) {
    response->add_headeru(response, "Accept-Ranges", 13, "bytes", 5);

    if (meta->etag != NULL)
        response->add_headeru(response, "ETag", 4, meta->etag, strlen(meta->etag));
    if (meta->last_modified != NULL)
        response->add_headeru(response, "Last-Modified", 13, meta->last_modified, strlen(meta->last_modified));

    const char* ext = file_extension(path);
    const char* mimetype = NULL;
    if (ext != NULL && appconfig()->mimetype != NULL)
        mimetype = mimetype_find_ext(appconfig()->mimetype, ext);
    if (mimetype == NULL)
        mimetype = meta->content_type;
    if (mimetype == NULL)
        mimetype = "application/octet-stream";

    response->add_headeru(response, "Content-Type", 12, mimetype, strlen(mimetype));
}

int __if_range_matches(httprequest_t* request, const s3fetch_t* meta) {
    http_header_t* if_range = request->get_header(request, "If-Range");
    if (if_range == NULL || if_range->value == NULL) return 1;
    if (meta->etag == NULL) return 0;

    return strcmp(if_range->value, meta->etag) == 0;
}

/* Границы запрошенного диапазона в байтах объекта. 0 — диапазон неудовлетворим.
 *
 * Кодировку задаёт парсер (см. range_resolve): start == -1 — суффиксная форма
 * "bytes=-N", end == -1 — открытый конец "bytes=N-". Открытый конец и слишком
 * широкий диапазон клипуются порцией: RFC 9110 §14.2 разрешает отдать
 * подмножество запрошенного, а плеер продолжит конкретными диапазонами. */
int __range_bounds(const httprequest_t* request, size_t total, size_t chunk,
                   size_t* start, size_t* end) {
    const ssize_t requested_start = request->ranges->start;
    const ssize_t requested_end = request->ranges->end;

    if (total == 0) return 0;

    if (requested_start == -1) {
        const size_t suffix = requested_end > 0 ? (size_t)requested_end : 0;
        if (suffix == 0) return 0;

        *start = suffix >= total ? 0 : total - suffix;
        *end = total - 1;
    }
    else {
        if (requested_start < 0) return 0;
        if ((size_t)requested_start >= total) return 0;

        *start = (size_t)requested_start;
        *end = requested_end == -1 ? total - 1 : (size_t)requested_end;

        if (*end >= total) *end = total - 1;
        if (*end < *start) return 0;
    }

    if (*end - *start + 1 > chunk)
        *end = *start + chunk - 1;

    return 1;
}
