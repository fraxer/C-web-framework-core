#define _GNU_SOURCE
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "appconfig.h"
#include "base64.h"
#include "mailattachment.h"

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

static const char* const MAILATTACHMENT_FALLBACK_TYPE = "application/octet-stream";

const char* mailattachment_content_type(const char* filename) {
    if (filename == NULL) return MAILATTACHMENT_FALLBACK_TYPE;

    const char* dot = strrchr(filename, '.');
    if (dot == NULL || dot[1] == '\0') return MAILATTACHMENT_FALLBACK_TYPE;

    /* Таблица конфигурации хранит расширения в нижнем регистре ("pdf"),
     * а приходит имя как есть (report.PDF) — приводим к ключу таблицы. */
    char ext[32];
    size_t n = 0;
    for (const char* p = dot + 1; *p != '\0' && n < sizeof(ext) - 1; p++)
        ext[n++] = (char)tolower((unsigned char)*p);
    ext[n] = '\0';

    /* mimetype_find_type — функция ext→mimetype (имена find-функций модуля
     * src/mimetype инвертированы: mimetype_find_ext читает таблицу
     * mimetype→ext и возвращает расширение). */
    const char* type = mimetype_find_type(appconfig()->mimetype, ext);
    return type != NULL ? type : MAILATTACHMENT_FALLBACK_TYPE;
}

void mailattachment_ascii_filename(const char* filename, char* out, size_t out_size) {
    if (out == NULL || out_size == 0) return;

    out[0] = '\0';

    const char* base = filename;
    if (base != NULL) {
        const char* slash = strrchr(base, '/');
        const char* bslash = strrchr(base, '\\');
        if (bslash != NULL && (slash == NULL || bslash > slash))
            base = bslash + 1;
        else if (slash != NULL)
            base = slash + 1;
    }
    else {
        base = "";
    }

    size_t n = 0;
    for (const char* p = base; *p != '\0' && n < out_size - 1; p++) {
        const char c = *p;
        const int safe = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                         (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        out[n++] = safe ? c : '_';
    }
    out[n] = '\0';

    if (out[0] == '\0')
        snprintf(out, out_size, "attachment");
}

void mailattachment_percent_encode(const char* value, char* out, size_t out_size) {
    static const char hex[] = "0123456789ABCDEF";

    if (out == NULL || out_size == 0) return;

    size_t n = 0;
    for (const unsigned char* p = (const unsigned char*)(value ? value : ""); *p != '\0'; p++) {
        const unsigned char c = *p;
        const int unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                               (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                               c == '_' || c == '~';
        if (unreserved) {
            if (n + 1 >= out_size) break;
            out[n++] = (char)c;
        }
        else {
            if (n + 3 >= out_size) break;
            out[n++] = '%';
            out[n++] = hex[c >> 4];
            out[n++] = hex[c & 0x0F];
        }
    }
    out[n] = '\0';
}

mail_attachment_part_t mailattachment_part_build(const mail_attachment_t* attachment, const char* boundary) {
    mail_attachment_part_t part = { NULL, 0 };

    if (attachment == NULL || attachment->filename == NULL || attachment->filename[0] == '\0' ||
        attachment->data == NULL || attachment->size == 0)
        return part;

    const char* type = (attachment->content_type != NULL && attachment->content_type[0] != '\0')
        ? attachment->content_type
        : mailattachment_content_type(attachment->filename);

    char ascii[NAME_MAX];
    mailattachment_ascii_filename(attachment->filename, ascii, sizeof(ascii));

    char percent[NAME_MAX * 3];
    mailattachment_percent_encode(attachment->filename, percent, sizeof(percent));

    /* NAME_MAX*3 (percent) + NAME_MAX (ascii ×2) + тип + константы — хватает с запасом */
    char headers[NAME_MAX * 6];
    const int headers_length = snprintf(headers, sizeof(headers),
        "--%s\r\n"
        "Content-Type: %s; name=\"%s\"\r\n"
        "Content-Disposition: attachment; filename=\"%s\";\r\n"
        " filename*=UTF-8''%s\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n",
        boundary, type, ascii, ascii, percent);
    if (headers_length <= 0 || (size_t)headers_length >= sizeof(headers)) return part;

    /* ёмкость: base64_encode_nl_len включает терминатор NUL, поэтому берётся
     * с запасом, а точная длина тела берётся из возврата base64_encode_nl */
    const size_t buffer_length = (size_t)headers_length +
        (size_t)base64_encode_nl_len((int)attachment->size, 76) + 2 /* \r\n */;

    part.data = malloc(buffer_length + 1);
    if (part.data == NULL) return part;

    memcpy(part.data, headers, (size_t)headers_length);
    const size_t encoded_length = (size_t)base64_encode_nl(part.data + headers_length,
        attachment->data, (int)attachment->size, 76);
    memcpy(part.data + headers_length + encoded_length, "\r\n", 2);
    part.size = (size_t)headers_length + encoded_length + 2;
    part.data[part.size] = '\0';

    return part;
}

void mail_attachment_part_free(mail_attachment_part_t* part) {
    if (part == NULL) return;
    free(part->data);
    part->data = NULL;
    part->size = 0;
}
