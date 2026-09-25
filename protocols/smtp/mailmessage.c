#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "appconfig.h"
#include "base64.h"
#include "dkim.h"
#include "helpers.h"
#include "mailattachment.h"
#include "mailheader.h"
#include "uuid.h"

#include "mailmessage.h"

static void __mailmessage_string_free(mail_string_t* string);
static int __mailmessage_set_date(mail_message_t* message, time_t* rawtime);
static int __mailmessage_set_message_id(mail_message_t* message, time_t* rawtime);
static int __mailmessage_header_add(mail_message_t* message, const char* key, const char* value);
static size_t __mailmessage_content_length(const mail_message_t* message);
static int __mailmessage_data_append(char* data, size_t* pos, const char* string, const size_t length);
static int __mailmessage_set_dkim_headers(dkim_t* dkim, const mail_message_t* message);
static int __mailmessage_boundary_generate(mail_message_t* message);
static int __mailmessage_attachments_all_inline(const mail_message_t* message);
static int __mailmessage_build_body(mail_message_t* message);
static int __mailmessage_dkim_sign(mail_message_t* message, time_t rawtime, char** sign_out);
static const char* __mailmessage_host(void);

mail_message_t* mail_message_create(void) {
    return calloc(1, sizeof(mail_message_t));
}

void mail_message_free(mail_message_t* message) {
    if (message == NULL) return;

    __mailmessage_string_free(&message->from_with_name);
    __mailmessage_string_free(&message->from);
    __mailmessage_string_free(&message->to);
    __mailmessage_string_free(&message->subject);
    __mailmessage_string_free(&message->date);
    __mailmessage_string_free(&message->message_id);

    mail_header_t* header = message->header;
    while (header != NULL) {
        mail_header_t* next = header->next;
        mail_header_free(header);
        header = next;
    }

    free(message->body_data);
    free(message->data);
    free(message);
}

/* What may stand between < > in From/To -- and after MAIL FROM: and RCPT TO:
 * in mail.c, which prints the same string. A CR or LF there starts a new
 * header or a new SMTP command, so an application mailing an address a user
 * typed relayed to whoever the user appended (found by fuzz_mail_message).
 * Only what breaks the framing is refused: the syntax proper is the caller's
 * business (validate_email), and UTF-8 addresses (RFC 6531) pass. */
static int __mailmessage_address_safe(const char* email) {
    if (email == NULL || email[0] == '\0' || strchr(email, '@') == NULL) return 0;

    for (const unsigned char* p = (const unsigned char*)email; *p; p++)
        if (*p <= 0x20 || *p == 0x7F || *p == '<' || *p == '>') return 0;

    return 1;
}

/* RFC 2047: each encoded-word is self-contained and at most 75 characters.
 * 39 source bytes leave room for "Subject: " on the first line. Keep valid
 * UTF-8 characters together; arbitrary invalid byte strings still make
 * progress and retain their bytes. All storage is on the heap. */
static char* __mailmessage_encoded_words(const char* text) {
    const size_t len = strlen(text);
    if (len > (SIZE_MAX - 16) / 3) return NULL;
    char* out = malloc(len * 3 + 16);
    if (out == NULL) return NULL;

    size_t pos = 0, off = 0;
    do {
        size_t n = len - off < 39 ? len - off : 39;
        if (off + n < len) {
            const size_t original = n;
            while (n > original - 3 && ((unsigned char)text[off + n] & 0xC0) == 0x80) n--;
            if (((unsigned char)text[off + n] & 0xC0) == 0x80) n = original;
        }
        if (off != 0) { memcpy(out + pos, "\r\n ", 3); pos += 3; }
        memcpy(out + pos, "=?UTF-8?B?", 10); pos += 10;
        pos += (size_t)base64_encode(out + pos, text + off, (int)n);
        memcpy(out + pos, "?=", 2); pos += 2;
        off += n;
    } while (off < len);
    out[pos] = '\0';
    return out;
}

int mail_message_set_from(mail_message_t* message, const char* email, const char* sender_name) {
    if (message == NULL) return 0;
    if (!__mailmessage_address_safe(email)) return 0;
    if (sender_name == NULL) return 0;

    char* encoded_sender_name = __mailmessage_encoded_words(sender_name);
    if (encoded_sender_name == NULL) return 0;
    const size_t encoded_sender_name_length = strlen(encoded_sender_name);

    const size_t email_length = strlen(email);
    const char* last = strrchr(encoded_sender_name, '\n');
    const size_t last_line = last != NULL ? strlen(last + 1) : 6 + encoded_sender_name_length;
    const char* separator = last_line + email_length + 3 > 76 ? "\r\n " : " ";
    const char* template = "%s%s<%s>";
    message->from_with_name.length = encoded_sender_name_length + strlen(separator) + email_length + 2;
    message->from_with_name.value = malloc(message->from_with_name.length + 1);
    if (message->from_with_name.value == NULL) {
        free(encoded_sender_name);
        return 0;
    }

    message->from_with_name.length = snprintf(message->from_with_name.value, message->from_with_name.length + 1,
                                            template, encoded_sender_name, separator, email);
    free(encoded_sender_name);
    if (message->from_with_name.length <= 0) return 0;

    template = "<%s>";
    message->from.length = strlen(template) - 2 + email_length;
    message->from.value = malloc(message->from.length + 1);
    if (message->from.value == NULL)
        return 0;

    message->from.length = snprintf(message->from.value, message->from.length + 1, template, email);
    if (message->from.length <= 0) return 0;

    return 1;
}

int mail_message_set_to(mail_message_t* message, const char* email) {
    if (message == NULL) return 0;
    if (!__mailmessage_address_safe(email)) return 0;

    const size_t email_length = strlen(email);
    const char* template = "<%s>";

    message->to.length = strlen(template) - 2 + email_length;
    message->to.value = malloc(message->to.length + 1);
    if (message->to.value == NULL)
        return 0;

    message->to.length = snprintf(message->to.value, message->to.length + 1, template, email);
    if (message->to.length <= 0) return 0;

    return 1;
}

int mail_message_set_subject(mail_message_t* message, const char* subject) {
    if (message == NULL) return 0;
    if (subject == NULL) return 0;

    char* encoded_subject = __mailmessage_encoded_words(subject);
    if (encoded_subject == NULL) return 0;
    message->subject.value = encoded_subject;
    message->subject.length = strlen(encoded_subject);

    return 1;
}

void mail_message_set_body(mail_message_t* message, const char* body) {
    if (message == NULL) return;

    message->body = body;
}

void mail_message_set_attachments(mail_message_t* message, const mail_attachment_t* attachments, size_t count) {
    if (message == NULL) return;

    message->attachments = attachments;
    message->attachments_count = count;
}

int mail_message_build(mail_message_t* message, time_t rawtime) {
    if (message == NULL || message->body == NULL || message->body[0] == '\0') return 0;

    /* Некорректное вложение отвергается до сборки: частично собранного
     * письма не существует */
    for (size_t i = 0; i < message->attachments_count; i++) {
        const mail_attachment_t* a = &message->attachments[i];
        if (a->filename == NULL || a->filename[0] == '\0' ||
            a->data == NULL || a->size == 0)
            return 0;
    }

    /* повторная сборка того же сообщения не течёт (наследие test_mail_set_content_replaces_previous) */
    if (message->data != NULL) { free(message->data); message->data = NULL; message->data_size = 0; }
    if (message->body_data != NULL) { free(message->body_data); message->body_data = NULL; message->body_size = 0; }

    /* заголовки прошлой сборки тоже не живут: иначе повторная сборка
     * дублирует их, а неудачная оставляет цепочку частично заполненной */
    {
        mail_header_t* header = message->header;
        while (header != NULL) {
            mail_header_t* next = header->next;
            mail_header_free(header);
            header = next;
        }
        message->header = NULL;
        message->last_header = NULL;
    }

    int result = 0;
    char* dkim_sign = NULL;

    if (!__mailmessage_build_body(message)) goto failed;
    if (!__mailmessage_set_date(message, &rawtime)) goto failed;
    if (!__mailmessage_set_message_id(message, &rawtime)) goto failed;
    if (!__mailmessage_dkim_sign(message, rawtime, &dkim_sign)) goto failed;

    /* Порядок заголовков — как в сегодняшнем __mail_build_content (mail.c:1624-1632) */
    if (!__mailmessage_header_add(message, "From", message->from_with_name.value)) goto failed;
    if (!__mailmessage_header_add(message, "To", message->to.value)) goto failed;
    if (!__mailmessage_header_add(message, "Subject", message->subject.value)) goto failed;
    if (!__mailmessage_header_add(message, "Date", message->date.value)) goto failed;
    if (!__mailmessage_header_add(message, "Message-Id", message->message_id.value)) goto failed;
    if (dkim_sign != NULL && !__mailmessage_header_add(message, "DKIM-Signature", dkim_sign)) goto failed;
    if (!__mailmessage_header_add(message, "MIME-Version", "1.0")) goto failed;
    if (message->attachments_count > 0) {
        char content_type[128];
        snprintf(content_type, sizeof(content_type),
                 __mailmessage_attachments_all_inline(message)
                     ? "multipart/related; type=\"text/html\"; boundary=\"%s\""
                     : "multipart/mixed; boundary=\"%s\"",
                 message->boundary);
        if (!__mailmessage_header_add(message, "Content-Type", content_type)) goto failed;
    }
    else {
        if (!__mailmessage_header_add(message, "Content-Transfer-Encoding", "base64")) goto failed;
        if (!__mailmessage_header_add(message, "Content-Type", "text/html; charset=utf-8")) goto failed;
    }

    message->data_size = __mailmessage_content_length(message);
    message->data = malloc(message->data_size);
    if (message->data == NULL) goto failed;

    size_t pos = 0;
    for (mail_header_t* header = message->header; header != NULL; header = header->next) {
        if (!__mailmessage_data_append(message->data, &pos, header->key, header->key_length)) goto failed;
        if (!__mailmessage_data_append(message->data, &pos, ": ", 2)) goto failed;
        if (!__mailmessage_data_append(message->data, &pos, header->value, header->value_length)) goto failed;
        if (!__mailmessage_data_append(message->data, &pos, "\r\n", 2)) goto failed;
    }
    if (!__mailmessage_data_append(message->data, &pos, "\r\n", 2)) goto failed;
    if (!__mailmessage_data_append(message->data, &pos, message->body_data, message->body_size)) goto failed;
    if (!__mailmessage_data_append(message->data, &pos, "\r\n.\r\n", 5)) goto failed;

    result = 1;

failed:
    if (result == 0 && message->data != NULL) {
        free(message->data);
        message->data = NULL;
        message->data_size = 0;
    }
    free(dkim_sign);

    return result;
}

/* The domain of the Message-Id: mail.host, with the same "localhost" fallback
 * mail.c makes for its EHLO argument -- an empty argument would be a syntax
 * error, and relay mode often leaves mail.host unset. */
static const char* __mailmessage_host(void) {
    const char* host = env()->mail.host;

    return (host != NULL && host[0] != '\0') ? host : "localhost";
}

static void __mailmessage_string_free(mail_string_t* string) {
    if (string->value != NULL)
        free(string->value);

    string->value = NULL;
    string->length = 0;
}

static int __mailmessage_set_date(mail_message_t* message, time_t* rawtime) {
    if (message == NULL) return 0;
    if (rawtime == NULL) return 0;

    char timezone[7];
    {
        /* timezone_offset() returns a signed hour difference (e.g. -5 for EST).
         * The numeric part must use the absolute value so the sign is emitted
         * only once; otherwise -5 would render as "-0-500" instead of "-0500". */
        const int tz = timezone_offset();
        const int tz_abs = tz < 0 ? -tz : tz;
        const char* sign = tz < 0 ? "-" : "+";
        const char* zero = tz_abs < 10 ? "0" : "";
        const int r = snprintf(timezone, sizeof(timezone), "%s%s%d00", sign, zero, tz_abs);
        if (r <= 0) return 0;
    }

    char template[80];
    const int r = snprintf(template, sizeof(template), "%%a, %%d %%b %%Y %%T %s", timezone);
    if (r <= 0) return 0;

    struct tm* timeinfo = localtime(rawtime);
    if (timeinfo == NULL) return 0;

    message->date.value = malloc(80);
    if (message->date.value == NULL)
        return 0;

    message->date.length = strftime(message->date.value, 80, template, timeinfo);
    if (message->date.length <= 0) return 0;

    return 1;
}

static int __mailmessage_set_message_id(mail_message_t* message, time_t* rawtime) {
    if (message == NULL) return 0;
    if (rawtime == NULL) return 0;

    char template[80];
    const int r = snprintf(template, sizeof(template), "<%%Y%%m%%d%%H%%M%%S@%s>", __mailmessage_host());
    if (r <= 0) return 0;

    struct tm* timeinfo = localtime(rawtime);
    if (timeinfo == NULL) return 0;

    message->message_id.value = malloc(80);
    if (message->message_id.value == NULL)
        return 0;

    message->message_id.length = strftime(message->message_id.value, 80, template, timeinfo);
    if (message->message_id.length <= 0) return 0;

    return 1;
}

/* Картинки тела письма — multipart/related (RFC 2387): части с Content-ID
 * относятся к HTML, а не приложены к нему. Стоит подмешаться обычному
 * вложению — корень остаётся multipart/mixed: вложенный related ради такой
 * смеси не собирается, а cid-ссылки клиенты разбирают и в mixed. */
int __mailmessage_attachments_all_inline(const mail_message_t* message) {
    for (size_t i = 0; i < message->attachments_count; i++) {
        const char* cid = message->attachments[i].cid;
        if (cid == NULL || cid[0] == '\0') return 0;
    }

    return 1;
}

static int __mailmessage_boundary_generate(mail_message_t* message) {
    char uuid[UUID4_SIZE];
    if (uuid4_generate(uuid) != 1) return 0;

    snprintf(message->boundary, sizeof(message->boundary), "=_%.36s", uuid);
    return 1;
}

static int __mailmessage_build_body(mail_message_t* message) {
    /* base64 текстовой части — как раньше (перенос 76) */
    const size_t body_length = strlen(message->body);
    char* encoded = malloc((size_t)base64_encode_nl_len((int)body_length, 76) + 1);
    if (encoded == NULL) return 0;

    const size_t encoded_size = base64_encode_nl(encoded, message->body, (int)body_length, 76);

    if (message->attachments_count == 0) {
        /* Односоставное письмо — байты как раньше */
        message->body_data = encoded;
        message->body_size = encoded_size;
        return 1;
    }

    if (!__mailmessage_boundary_generate(message)) {
        free(encoded);
        return 0;
    }

    /* Текстовая часть: те же заголовки, что были верхними у односоставного
     * письма, теперь внутри части (спека §4) */
    char text_prefix[512];
    const int text_prefix_length = snprintf(text_prefix, sizeof(text_prefix),
        "--%s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n",
        message->boundary);

    char closing[96];
    const int closing_length = snprintf(closing, sizeof(closing), "--%s--\r\n", message->boundary);

    if (text_prefix_length <= 0 || closing_length <= 0) {
        free(encoded);
        return 0;
    }

    /* Части вложений собираются заранее: любая неудача освобождает все
     * предыдущие, и тело не собирается вовсе */
    mail_attachment_part_t* parts = calloc(message->attachments_count, sizeof(mail_attachment_part_t));
    if (parts == NULL) {
        free(encoded);
        return 0;
    }

    size_t total = (size_t)text_prefix_length + encoded_size + 2 + (size_t)closing_length;

    for (size_t i = 0; i < message->attachments_count; i++) {
        parts[i] = mailattachment_part_build(&message->attachments[i], message->boundary);
        if (parts[i].data == NULL) {
            for (size_t j = 0; j < i; j++) mail_attachment_part_free(&parts[j]);
            free(parts);
            free(encoded);
            return 0;
        }
        total += parts[i].size;
    }

    char* body = malloc(total + 1);
    if (body == NULL) {
        for (size_t i = 0; i < message->attachments_count; i++) mail_attachment_part_free(&parts[i]);
        free(parts);
        free(encoded);
        return 0;
    }

    size_t pos = 0;
    memcpy(body + pos, text_prefix, (size_t)text_prefix_length); pos += (size_t)text_prefix_length;
    memcpy(body + pos, encoded, encoded_size); pos += encoded_size;
    memcpy(body + pos, "\r\n", 2); pos += 2;
    for (size_t i = 0; i < message->attachments_count; i++) {
        memcpy(body + pos, parts[i].data, parts[i].size); pos += parts[i].size;
        mail_attachment_part_free(&parts[i]);
    }
    memcpy(body + pos, closing, (size_t)closing_length); pos += (size_t)closing_length;
    body[pos] = '\0';

    free(parts);
    free(encoded);

    message->body_data = body;
    message->body_size = pos;
    return 1;
}

static int __mailmessage_dkim_sign(mail_message_t* message, time_t rawtime, char** sign_out) {
    *sign_out = NULL;

    const char* dkim_private = env()->mail.dkim_private;
    const char* dkim_selector = env()->mail.dkim_selector;

    /* DKIM is optional, which is what config.md has always claimed and what the
     * code did not do: dkim_create_sign() returns NULL on an unset key, and the
     * message was then never sent at all. A configuration with no key now
     * produces an unsigned message and the send goes ahead.
     *
     * A relay makes this the ordinary case rather than the exception -- it
     * signs with its own key and its own domain, and a second signature from
     * the sender is not wanted. The half-configured case (a key without a
     * selector, or the reverse) is rejected at configuration load, so seeing
     * one of them here means both are set. */
    if (dkim_private == NULL || dkim_private[0] == '\0' ||
        dkim_selector == NULL || dkim_selector[0] == '\0')
        return 1;

    dkim_t* dkim = dkim_create();
    if (dkim == NULL) return 0;

    dkim_set_private_key(dkim, dkim_private);
    dkim_set_domain(dkim, env()->mail.host);
    dkim_set_selector(dkim, dkim_selector);
    dkim_set_timestamp(dkim, rawtime);

    int ok = __mailmessage_set_dkim_headers(dkim, message);
    if (ok) *sign_out = dkim_create_sign(dkim, message->body_data);

    dkim_free(dkim);
    return ok && *sign_out != NULL;
}

static int __mailmessage_set_dkim_headers(dkim_t* dkim, const mail_message_t* message) {
    if (!dkim_header_add(dkim, "From", 4, message->from_with_name.value, message->from_with_name.length)) return 0;
    if (!dkim_header_add(dkim, "To", 2, message->to.value, message->to.length)) return 0;
    if (!dkim_header_add(dkim, "Subject", 7, message->subject.value, message->subject.length)) return 0;
    if (!dkim_header_add(dkim, "Date", 4, message->date.value, message->date.length)) return 0;
    if (!dkim_header_add(dkim, "Message-Id", 10, message->message_id.value, message->message_id.length)) return 0;

    return 1;
}

static int __mailmessage_header_add(mail_message_t* message, const char* key, const char* value) {
    if (message == NULL) return 0;
    if (key == NULL) return 0;
    if (value == NULL) return 0;
    if (key[0] == 0) return 0;
    if (value[0] == 0) return 0;

    const size_t key_length = strlen(key);
    const size_t value_length = strlen(value);
    mail_header_t* header = mail_header_create(key, key_length, value, value_length);
    if (header == NULL) return 0;
    if (header->key == NULL || header->value == NULL) {
        mail_header_free(header);
        return 0;
    }

    if (message->header == NULL)
        message->header = header;

    if (message->last_header != NULL)
        message->last_header->next = header;

    message->last_header = header;

    return 1;
}

static size_t __mailmessage_content_length(const mail_message_t* message) {
    mail_header_t* header = message->header;
    size_t size = 0;

    while (header) {
        size += header->key_length;
        size += 2; // ": "
        size += header->value_length;
        size += 2; // "\r\n"

        header = header->next;
    }

    size += 2; // "\r\n"
    size += message->body_size;
    size += 5; // "\r\n.\r\n"

    return size;
}

static int __mailmessage_data_append(char* data, size_t* pos, const char* string, const size_t length) {
    memcpy(&data[*pos], string, length);
    *pos += length;

    return 1;
}
