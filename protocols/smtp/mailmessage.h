#ifndef __MAILMESSAGE__
#define __MAILMESSAGE__

#include <stddef.h>
#include <time.h>

#include "mailattachment.h"
#include "mailheader.h"

typedef struct mail_message {
    mail_string_t from_with_name;
    mail_string_t from;
    mail_string_t to;
    mail_string_t subject;
    mail_string_t date;
    mail_string_t message_id;

    const char* body;                       /* сырой HTML; владение у вызывающего */
    const mail_attachment_t* attachments;   /* владение у вызывающего */
    size_t attachments_count;

    mail_header_t* header;
    mail_header_t* last_header;

    char boundary[64];                      /* "=_<uuid>", multipart-режим */

    char* body_data;                        /* собранное тело провода */
    size_t body_size;

    char* data;                             /* финал: заголовки + тело + "\r\n.\r\n" */
    size_t data_size;
} mail_message_t;

mail_message_t* mail_message_create(void);
void mail_message_free(mail_message_t* message);
int mail_message_set_from(mail_message_t* message, const char* email, const char* sender_name);
int mail_message_set_to(mail_message_t* message, const char* email);
int mail_message_set_subject(mail_message_t* message, const char* subject);
void mail_message_set_body(mail_message_t* message, const char* body);
void mail_message_set_attachments(mail_message_t* message, const mail_attachment_t* attachments, size_t count);

/* Двухпроходная сборка: тело (для bh= DKIM) → заголовки → склейка.
 * rawtime задаёт Date, Message-Id и t= подписи. 1 — успех. */
int mail_message_build(mail_message_t* message, time_t rawtime);

#endif /* __MAILMESSAGE__ */
