#ifndef __MAIL__
#define __MAIL__

#include <arpa/inet.h>

#include "mailheader.h"
#include "openssl.h"
#include "smtprequest.h"
#include "smtpresponse.h"

#define NS_MAXDNAME 1025
#define BUF_SIZE 16384

#define MAIL_IP_LIST_SIZE 5
#define MAIL_RECORDS_SIZE 5

/* Direct delivery talks to an MX on 25; the relay's port comes from the
 * configuration (mail.relay.port). */
#define MAIL_SMTP_PORT 25
#define MAIL_DEFAULT_TIMEOUT 30

/* Upper bound on the cleartext of one AUTH exchange (the NUL-separated
 * user/password of AUTH PLAIN, or either half of AUTH LOGIN) and on its base64,
 * so both live on the stack and can be wiped by explicit_bzero. */
#define MAIL_AUTH_SECRET_MAX 512
#define MAIL_AUTH_SECRET_ENCODED_MAX (((MAIL_AUTH_SECRET_MAX + 2) / 3 * 4) + 1)

typedef struct mail_payload {
    const char* from;
    const char* from_name;
    const char* to;
    const char* subject;
    const char* body;
} mail_payload_t;

typedef struct mail_string {
    char* value;
    size_t length;
} mail_string_t;

typedef struct mail_result {
    int status;
    char error[SMTPRESPONSE_MESSAGE_SIZE];
} mail_result_t;

typedef struct mail {
    int reseted;
    int last_status;
    char last_error[SMTPRESPONSE_MESSAGE_SIZE];
    mail_string_t from_with_name;
    mail_string_t from;
    mail_string_t to;
    mail_string_t subject;
    mail_string_t date;
    mail_string_t message_id;

    connection_t* connection;
    smtprequest_t* request;
    smtprequest_data_t* request_data;
    smtpresponse_t* response;

    char* buffer;
    size_t buffer_size;

    char* data;
    size_t data_size;

    SSL_CTX* ssl_ctx;
    mail_header_t* _header;
    mail_header_t* _last_header;

    int(*connected)(struct mail* instance);
    int(*connect)(struct mail* instance, const char* email);

    int(*read_banner)(struct mail* instance);
    int(*send_hello)(struct mail* instance);
    int(*start_tls)(struct mail* instance);
    /* AUTH against the configured relay. A no-op returning 1 in direct mode and
     * whenever no credentials are configured, so the caller can invoke it
     * unconditionally. */
    int(*auth)(struct mail* instance);
    int(*set_from)(struct mail* instance, const char* email, const char* sender_name);
    int(*set_to)(struct mail* instance, const char* email);
    int(*set_subject)(struct mail* instance, const char* subject);
    int(*set_body)(struct mail* instance, const char* body);

    int(*send_mail)(struct mail* instance);
    int(*send_reset)(struct mail* instance);
    int(*send_quit)(struct mail* instance);

    void(*free)(struct mail* instance);
} mail_t;

typedef struct mail_mx_record {
    int ok;
    int preference;
    char domain[NS_MAXDNAME];
    struct in_addr ip_list[MAIL_IP_LIST_SIZE];
} mail_mx_record_t;

mail_t* mail_create();
int mail_is_real(const char* email);
int send_mail(mail_payload_t* payload);
int send_mail_result(mail_payload_t* payload, mail_result_t* result);
void send_mail_async(mail_payload_t* payload);

void mail_set_error(mail_t* instance, int status, const char* message);

#endif