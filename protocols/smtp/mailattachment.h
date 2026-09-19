#ifndef __MAILATTACHMENT__
#define __MAILATTACHMENT__

#include <stddef.h>

/* Вложение письма. Данные принадлежат вызывающему до возврата send_mail*. */
typedef struct mail_attachment {
    const char* filename;      /* имя для Content-Disposition, UTF-8 */
    const char* content_type;  /* NULL или "" => вывести из расширения */
    const void* data;          /* бинарные данные, НЕ NUL-терминированы */
    size_t size;
} mail_attachment_t;

/* MIME-тип по расширению имени из таблицы mimetypes config.json сайта
 * (config->mimetype). Расширение приводится к нижнему регистру. Промах,
 * имя без точки, NULL или таблица не настроена — application/octet-stream. */
const char* mailattachment_content_type(const char* filename);

/* ASCII-fallback имени для устаревших параметров filename=/name=: последний
 * сегмент пути (по '/' и '\'), символы вне A-Za-z0-9 ._ - заменяются на '_',
 * пустой результат — "attachment". */
void mailattachment_ascii_filename(const char* filename, char* out, size_t out_size);

/* Собранная MIME-часть письма. */
typedef struct mail_attachment_part {
    char* data;   /* malloc-буфер, NUL-терминирован; NULL — ошибка/некорректное вложение */
    size_t size;  /* длина без NUL */
} mail_attachment_part_t;

/* RFC 3986 percent-encoding: незарезервированные байты остаются, прочие — %XX
 * верхним регистром, побайтово (UTF-8 проходит как есть). */
void mailattachment_percent_encode(const char* value, char* out, size_t out_size);

/* boundary — значение ЦЕЛИКОМ, с "=_"-префиксом (как в Content-Type);
 * разделитель части — строка "--" + boundary. */
mail_attachment_part_t mailattachment_part_build(const mail_attachment_t* attachment, const char* boundary);

void mail_attachment_part_free(mail_attachment_part_t* part);

#endif /* __MAILATTACHMENT__ */
