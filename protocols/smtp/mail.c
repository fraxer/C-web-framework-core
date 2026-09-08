#define _GNU_SOURCE
#include <string.h>
#include <sys/time.h>
#include <idn2.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <openssl/x509v3.h>

#include "log.h"
#include "appconfig.h"
#include "helpers.h"
#include "base64.h"
#include "smtpclienthandlers.h"
#include "dkim.h"
#include "connection_c.h"
#include "mail.h"
#include "taskmanager.h"

void __mail_string_reset(mail_string_t* string);
void __mail_string_free(mail_string_t* string);
int __mail_connected(mail_t* instance);
int __mail_connect(mail_t* instance, const char* email);
connection_t* __mail_connection_create(const int fd, const unsigned short port);
int __mail_connection_setup(mail_t* instance, const int fd, const unsigned short port);
int __mail_socket_create(const int family, const int timeout);
int __mail_connect_mx(const char* email, const unsigned short port, const int timeout);
int __mail_connect_host(const char* host, const unsigned short port, const int timeout);
int __mail_connection_close(connection_t* connection);
void __mail_connection_free(connection_t* connection);
int __mail_read_banner(mail_t* instance);
int __mail_send_hello(mail_t* instance);
int __mail_start_tls(mail_t* instance);
int __mail_auth(mail_t* instance);
int __mail_send_quit(mail_t* instance);
int __mail_set_from(mail_t* instance, const char* email, const char* sender_name);
int __mail_set_to(mail_t* instance, const char* email);
int __mail_set_subject(mail_t* instance, const char* subject);
int __mail_set_date(mail_t* instance, time_t* rawtime);
int __mail_set_message_id(mail_t* instance, time_t* rawtime);
int __mail_set_content(mail_t* instance, const char* body);
int __mail_send_mail(mail_t* instance);
int __mail_send_from(mail_t* instance);
int __mail_send_to(mail_t* instance);
int __mail_send_data(mail_t* instance);
int __mail_send_content(mail_t* instance);
int __mail_send_reset(mail_t* instance);
void __mail_free(mail_t* instance);
const char* __mail_domain_from_email(const char* email);
int __mail_set_conn_timeout(const int fd, const int seconds);
int __mail_get_mx_servers(const char* host, mail_mx_record_t* mx_records);
int __mail_parse_mx_record(unsigned char* buffer, size_t r, ns_sect s, int idx, ns_msg* message, mail_mx_record_t* mx_record);
int __mail_can_interact(mail_t* instance);
int __mail_send_command(mail_t* instance, const char* format, ...);
int __mail_init_tls(mail_t* instance);
int __mail_alloc_ssl(connection_t* connection, const char* hostname, const int verify);
int __mail_handshake(connection_t* connection, const int verify);
int __mail_set_dkim_headers(dkim_t* dkim, mail_t* instance);
int __mail_build_content(mail_t* instance);
int __mail_header_add(mail_t* instance, const char* key, const char* value);
size_t __mail_calc_content_length(mail_t* instance);
int __mail_data_append(char* data, size_t* pos, const char* string, const size_t length);

/* ---------------------------------------------------------------------------
 * Why a session stopped (mail_result_t in mail.h). The reason is recorded on
 * the session that knows it and copied out to the caller's struct at the end;
 * there is no state outside the objects involved.
 * ------------------------------------------------------------------------- */
void mail_set_error(mail_t* instance, int status, const char* message) {
    if (instance == NULL) return;

    instance->last_status = status;

    if (message == NULL) {
        instance->last_error[0] = '\0';
        return;
    }

    const size_t n = sizeof(instance->last_error) - 1;
    strncpy(instance->last_error, message, n);
    instance->last_error[n] = '\0';

    /* SMTP reply text arrives with its CRLF still attached; the stored string
     * is meant to be logged or embedded, so trim it. */
    size_t length = strlen(instance->last_error);
    while (length > 0 && (instance->last_error[length - 1] == '\n' || instance->last_error[length - 1] == '\r'))
        instance->last_error[--length] = '\0';
}

/* Settle on the most specific reason available, in this order:
 *
 *   1. one a step recorded itself -- a refused STARTTLS or a failed handshake
 *      is not described by the reply that happens to be the latest one;
 *   2. the server's own words, which say far more than the step that noticed
 *      them ("550 mailbox unavailable");
 *   3. the name of the step, for failures that happen before any reply exists.
 */
static void __mail_error_settle(mail_t* instance, const char* fallback) {
    if (instance == NULL) return;
    if (instance->last_error[0] != '\0') return;

    if (instance->connection != NULL && instance->connection->ctx != NULL) {
        connection_client_ctx_t* ctx = instance->connection->ctx;
        smtpresponse_t* response = ctx->response;

        if (response != NULL && response->status != 0) {
            mail_set_error(instance, response->status,
                response->message[0] != '\0' ? response->message : fallback);
            return;
        }
    }

    mail_set_error(instance, 0, fallback);
}

/* Hand the reason to the caller. Both arguments are optional: no result struct
 * means the caller did not ask, and no session means the send failed before one
 * existed (a NULL payload, a recipient domain with no MX, an allocation). */
static void __mail_result_fill(mail_result_t* result, const mail_t* instance, int status, const char* message) {
    if (result == NULL) return;

    if (instance != NULL) {
        result->status = instance->last_status;
        memcpy(result->error, instance->last_error, sizeof(result->error));
        return;
    }

    result->status = status;
    result->error[0] = '\0';

    if (message != NULL) {
        const size_t n = sizeof(result->error) - 1;
        strncpy(result->error, message, n);
        result->error[n] = '\0';
    }
}

/* The name this client announces in EHLO and uses for the Message-Id domain.
 * mail.host is optional and, in relay mode, frequently unset -- an empty EHLO
 * argument is a syntax error, so fall back to something a server will accept. */
static const char* __mail_ehlo_host(void) {
    const char* host = env()->mail.host;

    return (host != NULL && host[0] != '\0') ? host : "localhost";
}

/* STARTTLS is unconditional for direct delivery -- that is what this client has
 * always done -- and configuration-driven for a relay. */
static int __mail_starttls_required(void) {
    const env_mail_relay_t* relay = &env()->mail.relay;

    if (!relay->enabled) return 1;

    return relay->security == ENV_MAIL_SECURITY_STARTTLS;
}

mail_t* mail_create() {
    mail_t* instance = malloc(sizeof * instance);
    if (instance == NULL) return NULL;

    instance->reseted = 0;
    instance->last_status = 0;
    instance->last_error[0] = '\0';

    __mail_string_reset(&instance->from_with_name);
    __mail_string_reset(&instance->from);
    __mail_string_reset(&instance->to);
    __mail_string_reset(&instance->subject);
    __mail_string_reset(&instance->date);
    __mail_string_reset(&instance->message_id);

    instance->ssl_ctx = NULL;
    instance->connection = NULL;
    instance->request = NULL;
    instance->request_data = NULL;
    instance->response = NULL;
    instance->buffer_size = BUF_SIZE;
    instance->buffer = malloc(sizeof(char) * instance->buffer_size);
    if (instance->buffer == NULL) {
        free(instance);
        return NULL;
    }

    instance->data_size = 0;
    instance->data = NULL;
    instance->_header = NULL;
    instance->_last_header = NULL;
    instance->connected = __mail_connected;
    instance->connect = __mail_connect;
    instance->read_banner = __mail_read_banner;
    instance->send_hello = __mail_send_hello;
    instance->start_tls = __mail_start_tls;
    instance->auth = __mail_auth;
    instance->set_from = __mail_set_from;
    instance->set_to = __mail_set_to;
    instance->set_subject = __mail_set_subject;
    instance->set_body = __mail_set_content;
    instance->send_mail = __mail_send_mail;
    instance->send_reset = __mail_send_reset;
    instance->send_quit = __mail_send_quit;
    instance->free = __mail_free;

    return instance;
}

int mail_is_real(const char* email) {
    if (email == NULL) return 0;

    const char* domain = __mail_domain_from_email(email);
    if (domain == NULL) {
        log_error("Domain not detected by email: %s\n", email);
        return 0;
    }

    char* punycode_domain = NULL;
    int r = idn2_to_ascii_8z(domain, &punycode_domain, IDN2_NONTRANSITIONAL);
    if (r != IDNA_SUCCESS) {
        log_error("Mail idn2_to_ascii_8z failed (%d): %s\n", r, idn2_strerror(r));
        return 0;
    }

    mail_mx_record_t mx_records[MAIL_RECORDS_SIZE];
    memset(mx_records, 0, sizeof(mail_mx_record_t) * MAIL_RECORDS_SIZE);
    r = __mail_get_mx_servers(punycode_domain, mx_records);

    free(punycode_domain);

    return r > 0;
}

int send_mail(mail_payload_t* payload) {
    return send_mail_result(payload, NULL);
}

int send_mail_result(mail_payload_t* payload, mail_result_t* result) {
    __mail_result_fill(result, NULL, 0, NULL);

    if (payload == NULL) return 0;

    const env_mail_relay_t* relay = &env()->mail.relay;

    /* Only direct delivery needs the recipient's domain to answer for itself:
     * in relay mode the relay does the routing, and an internal domain with no
     * MX at all is a perfectly ordinary recipient. */
    if (!relay->enabled && !mail_is_real(payload->to)) {
        log_error("[send_mail] Recipient domain has no MX records\n");
        __mail_result_fill(result, NULL, 0, "Recipient domain has no MX records");
        return 0;
    }

    mail_t* mail = mail_create();
    if (mail == NULL) {
        log_error("[send_mail] Failed to create mail instance\n");
        __mail_result_fill(result, NULL, 0, "Failed to create mail instance");
        return 0;
    }

    int sent = 0;  // Assume failure
    const char* reason = "Unknown error";

    // Check connection
    if (!mail->connected(mail)) {
        if (!mail->connect(mail, payload->to)) {
            reason = "Failed to connect";
            goto cleanup;
        }

        // Check banner read
        if (!mail->read_banner(mail)) {
            reason = "Failed to read banner";
            goto cleanup;
        }

        // Check EHLO
        if (!mail->send_hello(mail)) {
            reason = "Failed to send EHLO";
            goto cleanup;
        }

        /* STARTTLS upgrades the session in place. Implicit TLS (mail.relay
         * security "tls") has already handshaked inside connect(), and a
         * plaintext relay asked for no TLS at all. */
        if (__mail_starttls_required() && !mail->start_tls(mail)) {
            reason = "Failed to start TLS";
            goto cleanup;
        }

        // AUTH, when the configuration carries relay credentials
        if (!mail->auth(mail)) {
            reason = "Failed to authenticate";
            goto cleanup;
        }
    }

    // Set sender
    if (!mail->set_from(mail, payload->from, payload->from_name)) {
        reason = "Failed to set FROM";
        goto cleanup;
    }

    // Set recipient
    if (!mail->set_to(mail, payload->to)) {
        reason = "Failed to set TO";
        goto cleanup;
    }

    // Set subject
    if (!mail->set_subject(mail, payload->subject)) {
        reason = "Failed to set subject";
        goto cleanup;
    }

    // Set body
    if (!mail->set_body(mail, payload->body)) {
        reason = "Failed to set body";
        goto cleanup;
    }

    // Send mail (MAIL FROM, RCPT TO, DATA, content)
    if (!mail->send_mail(mail)) {
        reason = "Failed to send mail";
        goto cleanup;
    }

    // Send RSET to reset connection
    if (!mail->send_reset(mail)) {
        reason = "Failed to send RSET";
        goto cleanup;
    }

    // Send QUIT to close connection
    if (!mail->send_quit(mail)) {
        reason = "Failed to send QUIT";
        goto cleanup;
    }

    sent = 1;  // Success

cleanup:
    /* One place for the failure report, so what the caller reads back is always
     * the reply the session actually stopped on. */
    if (sent == 0) {
        log_error("[send_mail] %s\n", reason);
        __mail_error_settle(mail, reason);
    }

    __mail_result_fill(result, mail, 0, NULL);

    mail->free(mail);
    return sent;
}

static mail_payload_t* __mail_payload_copy(mail_payload_t* payload) {
    if (payload == NULL) return NULL;

    mail_payload_t* copy = malloc(sizeof * copy);
    if (copy == NULL) return NULL;

    copy->from = payload->from ? strdup(payload->from) : NULL;
    copy->from_name = payload->from_name ? strdup(payload->from_name) : NULL;
    copy->to = payload->to ? strdup(payload->to) : NULL;
    copy->subject = payload->subject ? strdup(payload->subject) : NULL;
    copy->body = payload->body ? strdup(payload->body) : NULL;

    return copy;
}

static void __mail_payload_free(void* data) {
    if (data == NULL) return;

    mail_payload_t* payload = data;

    free((void*)payload->from);
    free((void*)payload->from_name);
    free((void*)payload->to);
    free((void*)payload->subject);
    free((void*)payload->body);
    free(payload);
}

static void __send_mail_task(void* data) {
    send_mail(data);
}

void send_mail_async(mail_payload_t* payload) {
    if (payload == NULL) return;

    mail_payload_t* copy = __mail_payload_copy(payload);
    if (copy == NULL) {
        log_error("[send_mail_async] Failed to copy payload\n");
        return;
    }

    if (!taskmanager_async_with_free(__send_mail_task, copy, __mail_payload_free)) {
        log_error("[send_mail_async] Failed to queue async task\n");
        __mail_payload_free(copy);
    }
}

void __mail_string_reset(mail_string_t* item) {
    if (item == NULL) return;

    item->value = NULL;
    item->length = 0;
}

void __mail_string_free(mail_string_t* string) {
    if (string->value != NULL)
        free(string->value);

    __mail_string_reset(string);
}

int __mail_connected(mail_t* instance) {
    if (instance == NULL) return 0;
    if (instance->connection == NULL) return 0;

    return instance->connection->fd > 0;
}

/* Establish the SMTP session's socket.
 *
 * The two delivery modes differ only here. Direct delivery derives the endpoint
 * from the recipient -- MX lookup, port 25, IPv4 only, because that is what the
 * MX record parser produces. Relay mode takes the endpoint from the
 * configuration and resolves it with getaddrinfo(), so it reaches an IPv6-only
 * relay and asks no MX question at all (nor anything of libidn2).
 *
 * `email` is ignored in relay mode; the argument stays for the callers written
 * against the direct-delivery API. */
int __mail_connect(mail_t* instance, const char* email) {
    if (instance == NULL) return 0;

    const env_mail_relay_t* relay = &env()->mail.relay;
    const int timeout = (relay->enabled && relay->timeout > 0) ? relay->timeout : MAIL_DEFAULT_TIMEOUT;

    unsigned short port = MAIL_SMTP_PORT;
    int fd = -1;

    if (relay->enabled) {
        port = relay->port;
        fd = __mail_connect_host(relay->host, port, timeout);
    }
    else {
        if (email == NULL) return 0;

        fd = __mail_connect_mx(email, port, timeout);
    }

    if (fd < 0) return 0;

    if (!__mail_connection_setup(instance, fd, port)) {
        /* The connection object owns the descriptor once it exists; before that
         * this is the only reference to it. */
        if (instance->connection == NULL) close(fd);
        return 0;
    }

    /* Implicit TLS (submission over 465): the handshake runs before anything is
     * read, so the banner itself arrives encrypted and no STARTTLS is sent. */
    if (relay->enabled && relay->security == ENV_MAIL_SECURITY_TLS) {
        if (!__mail_init_tls(instance)) {
            log_error("[__mail_connect] TLS handshake with %s failed\n", relay->host);
            mail_set_error(instance, 0, "TLS handshake with the relay failed");
            return 0;
        }
    }

    return 1;
}

/* A connected socket to the MX of the recipient's domain, or -1. Records are
 * tried in the order the resolver returned them, each address getting its own
 * descriptor: a socket whose connect() failed cannot be reused for the next
 * attempt. */
int __mail_connect_mx(const char* email, const unsigned short port, const int timeout) {
    const char* domain = __mail_domain_from_email(email);
    if (domain == NULL) {
        log_error("Domain not detected by email: %s\n", email);
        return -1;
    }

    char* punycode_domain = NULL;
    int r = idn2_to_ascii_8z(domain, &punycode_domain, IDN2_NONTRANSITIONAL);
    if (r != IDNA_SUCCESS) {
        log_error("Mail idn2_to_ascii_8z failed (%d): %s\n", r, idn2_strerror(r));
        return -1;
    }

    log_info("Mail domain: %s\n", punycode_domain);

    mail_mx_record_t mx_records[MAIL_RECORDS_SIZE];
    memset(mx_records, 0, sizeof(mail_mx_record_t) * MAIL_RECORDS_SIZE);
    r = __mail_get_mx_servers(punycode_domain, mx_records);

    free(punycode_domain);

    if (!r) {
        log_error("[__mail_connect] Not found servers\n");
        return -1;
    }

    for (int i = 0; i < MAIL_RECORDS_SIZE; i++) {
        mail_mx_record_t* record = &mx_records[i];
        if (!record->ok) continue;

        for (int j = 0; j < MAIL_IP_LIST_SIZE; j++) {
            if (record->ip_list[j].s_addr == 0) continue;

            const int fd = __mail_socket_create(AF_INET, timeout);
            if (fd < 0) return -1;

            struct sockaddr_in sockaddr;
            memset(&sockaddr, 0, sizeof(sockaddr));

            sockaddr.sin_family = AF_INET;
            sockaddr.sin_port = htons(port);
            sockaddr.sin_addr.s_addr = record->ip_list[j].s_addr;

            if (connect(fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1) {
                log_error("[__mail_connect_mx] Error in connect to %s: %s\n", record->domain, strerror(errno));
                close(fd);
                continue;
            }

            return fd;
        }
    }

    return -1;
}

/* A connected socket to a named host, or -1. getaddrinfo() rather than the MX
 * resolver: the relay's name is an A/AAAA record, and going through the generic
 * resolver is what makes an IPv6 relay reachable. Every returned address is
 * tried before giving up. */
int __mail_connect_host(const char* host, const unsigned short port, const int timeout) {
    if (host == NULL || host[0] == '\0') {
        log_error("[__mail_connect_host] Empty relay host\n");
        return -1;
    }

    char service[8];
    if (snprintf(service, sizeof(service), "%u", (unsigned)port) <= 0)
        return -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* addresses = NULL;
    const int r = getaddrinfo(host, service, &hints, &addresses);
    if (r != 0) {
        log_error("[__mail_connect_host] getaddrinfo(%s): %s\n", host, gai_strerror(r));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo* address = addresses; address != NULL; address = address->ai_next) {
        fd = __mail_socket_create(address->ai_family, timeout);
        if (fd < 0) continue;

        if (connect(fd, address->ai_addr, address->ai_addrlen) == 0)
            break;

        log_error("[__mail_connect_host] Error in connect to %s:%u: %s\n", host, (unsigned)port, strerror(errno));

        close(fd);
        fd = -1;
    }

    freeaddrinfo(addresses);

    if (fd < 0)
        log_error("[__mail_connect_host] Failed to connect to %s:%u\n", host, (unsigned)port);

    return fd;
}

int __mail_socket_create(const int family, const int timeout) {
    const int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        log_error("Error mail socket create\n");
        return -1;
    }

    if (!__mail_set_conn_timeout(fd, timeout)) {
        log_error("Error mail set socket timeout\n");
        close(fd);
        return -1;
    }

    return fd;
}

/* Hang the connection object and the SMTP request/response machinery off an
 * already-connected descriptor. Whatever it allocates before a failure is owned
 * by the instance and released by __mail_free. */
int __mail_connection_setup(mail_t* instance, const int fd, const unsigned short port) {
    instance->connection = __mail_connection_create(fd, port);
    if (instance->connection == NULL) {
        log_error("Error mail connection create\n");
        return 0;
    }

    instance->connection->buffer = instance->buffer;
    instance->connection->buffer_size = instance->buffer_size;

    instance->request_data = smtprequest_data_create(instance->connection);
    if (instance->request_data == NULL)
        return 0;

    instance->request = smtprequest_create(instance->connection);
    if (instance->request == NULL)
        return 0;

    connection_client_ctx_t* ctx = instance->connection->ctx;

    ctx->request = instance->request;

    instance->response = smtpresponse_create(instance->connection);
    if (instance->response == NULL)
        return 0;

    ctx->response = instance->response;

    return 1;
}

connection_t* __mail_connection_create(const int fd, const unsigned short port) {
    connection_t* connection = connection_c_create(fd, NULL, port);
    if (connection == NULL) return NULL;

    connection->close = __mail_connection_close;

    set_smtp_client_command(connection);

    return connection;
}

int __mail_connection_close(connection_t* connection) {
    if (connection == NULL) return 0;

    if (connection->fd > 0) {
        close(connection->fd);
        connection->fd = 0;
    }

    return 1;
}

void __mail_connection_free(connection_t* connection) {
    if (connection == NULL) return;

    connection->close(connection);

    if (connection->ssl != NULL) {
        SSL_free(connection->ssl);
        connection->ssl = NULL;
    }

    /* connection_c_create() allocated the client context along with the
     * connection, and nothing was releasing it -- one leak per message sent.
     * The request and response objects hanging off it belong to mail_t (which
     * frees them right after this), so they are detached first: the context's
     * own destructor would otherwise free them a second time. */
    connection_client_ctx_t* ctx = connection->ctx;
    if (ctx != NULL) {
        ctx->request = NULL;
        ctx->response = NULL;
        ctx->base.free(ctx);
        connection->ctx = NULL;
    }

    free(connection);
}

int __mail_read_banner(mail_t* instance) {
    if (!__mail_can_interact(instance)) return 0;

    // Check read return value
    int read_result = instance->connection->read(instance->connection);
    if (!read_result) {
        log_error("[__mail_read_banner] Read failed\n");
        instance->reseted = 1;
        return 0;
    }

    connection_client_ctx_t* ctx = instance->connection->ctx;
    smtpresponse_t* response = ctx->response;
    if (response->status != 220 && response->status != 250) {
        instance->reseted = 1;
        mail_set_error(instance, response->status, response->message);
        log_error("%s\n", response->message);
        return 0;
    }

    return 1;
}

int __mail_send_hello(mail_t* instance) {
    if (!__mail_can_interact(instance)) return 0;

    /* The capability set describes the *current* EHLO and nothing earlier: a
     * server normally announces AUTH only once the session is encrypted, so the
     * post-STARTTLS EHLO must not inherit the pre-STARTTLS answer. */
    connection_client_ctx_t* ctx = instance->connection->ctx;
    smtpresponse_reset_capabilities(ctx->response);

    if (!__mail_send_command(instance, "EHLO %s\r\n", __mail_ehlo_host())) return 0;

    smtpresponse_t* response = ctx->response;
    if (response->status != 250) {
        instance->reseted = 1;
        mail_set_error(instance, response->status, response->message);
        log_error("[__mail_send_hello] %s\n", response->message);
        return 0;
    }

    return 1;
}

int __mail_start_tls(mail_t* instance) {
    if (!__mail_can_interact(instance)) return 0;

    connection_client_ctx_t* ctx = instance->connection->ctx;
    smtpresponse_t* response = ctx->response;

    /* Ask only for what the server announced. Until the EHLO reply was parsed
     * this was decided by the reply code to a STARTTLS sent blind, which reads
     * as a protocol violation to anything strict. */
    if (!(response->extensions & SMTPRESPONSE_EXT_STARTTLS)) {
        log_error("[__mail_start_tls] Server does not offer STARTTLS\n");
        mail_set_error(instance, 0, "Server does not offer STARTTLS");
        return 0;
    }

    if (!__mail_send_command(instance, "STARTTLS\r\n")) return 0;

    if (response->status != 220) {
        mail_set_error(instance, response->status, response->message);
        log_error("[__mail_start_tls] %s\n", response->message);
        return 0;
    }

    if (!__mail_init_tls(instance)) {
        mail_set_error(instance, 0, "TLS handshake failed");
        return 0;
    }

    /* The extension list is re-read here: this second EHLO is the one that
     * carries AUTH. */
    if (!__mail_send_hello(instance)) return 0;

    return 1;
}

/* Human-readable list of the mechanisms a server announced, for the error that
 * says why none of them could be used. */
static void __mail_auth_mechanisms_string(unsigned int mechanisms, char* out, size_t size) {
    const char* plain = (mechanisms & SMTPRESPONSE_AUTH_PLAIN) ? "PLAIN" : "";
    const char* login = (mechanisms & SMTPRESPONSE_AUTH_LOGIN) ? "LOGIN" : "";

    if (plain[0] != '\0' && login[0] != '\0')
        snprintf(out, size, "PLAIN LOGIN");
    else if (plain[0] != '\0' || login[0] != '\0')
        snprintf(out, size, "%s%s", plain, login);
    else
        snprintf(out, size, "none");
}

/* Check the reply to one AUTH step. 535 gets a message of its own: it is the
 * most common way a relay is misconfigured, and "Failed to send mail" says
 * nothing about it. */
static int __mail_auth_expect(mail_t* instance, const int expected) {
    connection_client_ctx_t* ctx = instance->connection->ctx;
    smtpresponse_t* response = ctx->response;

    if (response->status == expected) return 1;

    instance->reseted = 1;
    mail_set_error(instance, response->status, response->message);

    if (response->status == 535)
        log_error("[__mail_auth] 535 authentication failed -- check mail.relay.user and mail.relay.password: %s\n", response->message);
    else
        log_error("[__mail_auth] Unexpected reply %d: %s\n", response->status, response->message);

    return 0;
}

/* AUTH PLAIN (RFC 4616): one command whose argument is
 * base64("\0" user "\0" password) -- NUL-separated, so the cleartext is built
 * and encoded by explicit length rather than as a C string. */
static int __mail_auth_plain(mail_t* instance, const char* user, const char* password) {
    const size_t user_length = strlen(user);
    const size_t password_length = strlen(password);
    const size_t plain_length = user_length + password_length + 2;

    if (plain_length > MAIL_AUTH_SECRET_MAX) {
        log_error("[__mail_auth] Credentials too long for AUTH PLAIN\n");
        return 0;
    }

    char plain[MAIL_AUTH_SECRET_MAX];
    char encoded[MAIL_AUTH_SECRET_ENCODED_MAX];

    plain[0] = '\0';
    memcpy(plain + 1, user, user_length);
    plain[1 + user_length] = '\0';
    memcpy(plain + 2 + user_length, password, password_length);

    base64_encode(encoded, plain, (int)plain_length);
    explicit_bzero(plain, sizeof(plain));

    const int sent = __mail_send_command(instance, "AUTH PLAIN %s\r\n", encoded);
    explicit_bzero(encoded, sizeof(encoded));

    if (!sent) return 0;

    return __mail_auth_expect(instance, 235);
}

/* AUTH LOGIN: the pre-RFC three-step exchange every major relay still speaks --
 * a bare command, then the login, then the password, each base64 on its own
 * line and each answered with a 334 challenge. */
static int __mail_auth_login(mail_t* instance, const char* user, const char* password) {
    const size_t user_length = strlen(user);
    const size_t password_length = strlen(password);

    if (user_length > MAIL_AUTH_SECRET_MAX || password_length > MAIL_AUTH_SECRET_MAX) {
        log_error("[__mail_auth] Credentials too long for AUTH LOGIN\n");
        return 0;
    }

    char encoded[MAIL_AUTH_SECRET_ENCODED_MAX];

    if (!__mail_send_command(instance, "AUTH LOGIN\r\n")) return 0;
    if (!__mail_auth_expect(instance, 334)) return 0;

    base64_encode(encoded, user, (int)user_length);
    const int user_sent = __mail_send_command(instance, "%s\r\n", encoded);
    explicit_bzero(encoded, sizeof(encoded));

    if (!user_sent) return 0;
    if (!__mail_auth_expect(instance, 334)) return 0;

    base64_encode(encoded, password, (int)password_length);
    const int password_sent = __mail_send_command(instance, "%s\r\n", encoded);
    explicit_bzero(encoded, sizeof(encoded));

    if (!password_sent) return 0;

    return __mail_auth_expect(instance, 235);
}

int __mail_auth(mail_t* instance) {
    if (instance == NULL) return 0;

    const env_mail_relay_t* relay = &env()->mail.relay;

    /* Nothing to authenticate against in direct mode, and no credentials is a
     * configuration, not an omission: an internal relay that accepts anything
     * from the local network is exactly the "security: none, no user" case. */
    if (!relay->enabled) return 1;
    if (relay->auth == ENV_MAIL_AUTH_NONE) return 1;
    if (relay->user == NULL || relay->password == NULL) return 1;

    if (!__mail_can_interact(instance)) return 0;

    /* Credentials leave this process in the clear only where that was asked for
     * explicitly -- and the configuration loader has already warned about it. */
    if (instance->connection->ssl == NULL && relay->security != ENV_MAIL_SECURITY_NONE) {
        log_error("[__mail_auth] Refusing to send credentials over an unencrypted connection\n");
        mail_set_error(instance, 0, "Refusing to send credentials over an unencrypted connection");
        return 0;
    }

    connection_client_ctx_t* ctx = instance->connection->ctx;
    smtpresponse_t* response = ctx->response;

    char mechanisms[64];
    __mail_auth_mechanisms_string(response->auth_mechanisms, mechanisms, sizeof(mechanisms));

    if (!(response->extensions & SMTPRESPONSE_EXT_AUTH)) {
        log_error("[__mail_auth] Server %s does not offer AUTH\n", relay->host);
        mail_set_error(instance, 0, "Relay does not offer AUTH");
        return 0;
    }

    env_mail_auth_e mechanism = relay->auth;
    if (mechanism == ENV_MAIL_AUTH_AUTO) {
        if (response->auth_mechanisms & SMTPRESPONSE_AUTH_PLAIN)
            mechanism = ENV_MAIL_AUTH_PLAIN;
        else if (response->auth_mechanisms & SMTPRESPONSE_AUTH_LOGIN)
            mechanism = ENV_MAIL_AUTH_LOGIN;
        else {
            log_error("[__mail_auth] Server %s offers no supported AUTH mechanism (offered: %s)\n", relay->host, mechanisms);
            mail_set_error(instance, 0, "Relay offers no supported AUTH mechanism");
            return 0;
        }
    }
    else if (mechanism == ENV_MAIL_AUTH_PLAIN && !(response->auth_mechanisms & SMTPRESPONSE_AUTH_PLAIN)) {
        log_error("[__mail_auth] mail.relay.auth is \"plain\" but %s offers: %s\n", relay->host, mechanisms);
        mail_set_error(instance, 0, "Relay does not offer AUTH PLAIN");
        return 0;
    }
    else if (mechanism == ENV_MAIL_AUTH_LOGIN && !(response->auth_mechanisms & SMTPRESPONSE_AUTH_LOGIN)) {
        log_error("[__mail_auth] mail.relay.auth is \"login\" but %s offers: %s\n", relay->host, mechanisms);
        mail_set_error(instance, 0, "Relay does not offer AUTH LOGIN");
        return 0;
    }

    const int result = mechanism == ENV_MAIL_AUTH_PLAIN
        ? __mail_auth_plain(instance, relay->user, relay->password)
        : __mail_auth_login(instance, relay->user, relay->password);

    /* The command buffer is reused for every later command, and it just held
     * the base64 of the password. */
    explicit_bzero(instance->request->command, sizeof(instance->request->command));

    return result;
}

int __mail_send_quit(mail_t* instance) {
    if (instance == NULL) return 0;
    if (!__mail_connected(instance)) {
        log_error("[__mail_send_quit] Not connected\n");
        return 0;
    }

    if (!__mail_send_command(instance, "QUIT\r\n")) return 0;

    return 1;
}

int __mail_set_from(mail_t* instance, const char* email, const char* sender_name) {
    if (instance == NULL) return 0;
    if (email == NULL) return 0;
    if (sender_name == NULL) return 0;

    size_t sender_name_length = strlen(sender_name);
    char encoded_sender_name[base64_encode_len(sender_name_length)];
    size_t encoded_sender_name_length = base64_encode(encoded_sender_name, sender_name, sender_name_length);

    const size_t email_length = strlen(email);
    const char* template = "=?UTF-8?B?%s?= <%s>";
    instance->from_with_name.length = strlen(template) - 4 + encoded_sender_name_length + email_length;
    instance->from_with_name.value = malloc(instance->from_with_name.length + 1);
    if (instance->from_with_name.value == NULL)
        return 0;

    instance->from_with_name.length = snprintf(instance->from_with_name.value, instance->from_with_name.length + 1, template, encoded_sender_name, email);
    if (instance->from_with_name.length <= 0) return 0;

    template = "<%s>";
    instance->from.length = strlen(template) - 2 + email_length;
    instance->from.value = malloc(instance->from.length + 1);
    if (instance->from.value == NULL)
        return 0;

    instance->from.length = snprintf(instance->from.value, instance->from.length + 1, template, email);
    if (instance->from.length <= 0) return 0;

    return 1;
}

int __mail_set_to(mail_t* instance, const char* email) {
    if (instance == NULL) return 0;
    if (email == NULL) return 0;

    const size_t email_length = strlen(email);
    const char* template = "<%s>";

    instance->to.length = strlen(template) - 2 + email_length;
    instance->to.value = malloc(instance->to.length + 1);
    if (instance->to.value == NULL)
        return 0;

    instance->to.length = snprintf(instance->to.value, instance->to.length + 1, template, email);
    if (instance->to.length <= 0) return 0;

    return 1;
}

int __mail_set_subject(mail_t* instance, const char* subject) {
    if (instance == NULL) return 0;
    if (subject == NULL) return 0;

    size_t subject_length = strlen(subject);
    char encoded_subject[base64_encode_len(subject_length)];
    const size_t encoded_subject_length = base64_encode(encoded_subject, subject, subject_length);

    const char* template = "=?UTF-8?B?%s?=";
    instance->subject.length = strlen(template) - 2 + encoded_subject_length;
    instance->subject.value = malloc(instance->subject.length + 1);
    if (instance->subject.value == NULL)
        return 0;

    instance->subject.length = snprintf(instance->subject.value, instance->subject.length + 1, template, encoded_subject);
    if (instance->subject.length <= 0) return 0;

    return 1;
}

int __mail_set_date(mail_t* instance, time_t* rawtime) {
    if (instance == NULL) return 0;
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

    instance->date.value = malloc(80);
    if (instance->date.value == NULL)
        return 0;

    instance->date.length = strftime(instance->date.value, 80, template, timeinfo);
    if (instance->date.length <= 0) return 0;

    return 1;
}

int __mail_set_message_id(mail_t* instance, time_t* rawtime) {
    if (instance == NULL) return 0;
    if (rawtime == NULL) return 0;

    char template[80];
    const int r = snprintf(template, sizeof(template), "<%%Y%%m%%d%%H%%M%%S@%s>", __mail_ehlo_host());
    if (r <= 0) return 0;

    struct tm* timeinfo = localtime(rawtime);
    if (timeinfo == NULL) return 0;

    instance->message_id.value = malloc(80);
    if (instance->message_id.value == NULL)
        return 0;

    instance->message_id.length = strftime(instance->message_id.value, 80, template, timeinfo);
    if (instance->message_id.length <= 0) return 0;

    return 1;
}

int __mail_set_content(mail_t* instance, const char* body) {
    if (instance == NULL) return 0;
    if (body == NULL) return 0;
    if (instance->data != NULL)
        free(instance->data);

    const int wrap = 76;
    size_t body_length = strlen(body);
    instance->data = malloc(base64_encode_nl_len(body_length, wrap));
    if (instance->data == NULL) return 0;

    instance->data_size = base64_encode_nl(instance->data, body, body_length, wrap);

    return 1;
}

int __mail_send_mail(mail_t* instance) {
    if (instance == NULL) return 0;
    
    if (!__mail_send_from(instance))
        return 0;
    if (!__mail_send_to(instance))
        return 0;
    if (!__mail_send_data(instance))
        return 0;
    if (!__mail_build_content(instance))
        return 0;
    if (!__mail_send_content(instance))
        return 0;

    return 1;
}

int __mail_send_from(mail_t* instance) {
    if (!__mail_can_interact(instance)) return 0;
    if (instance->from.length == 0) return 0;
    if (!__mail_send_command(instance, "MAIL FROM: %s\r\n", instance->from.value)) return 0;

    connection_client_ctx_t* ctx = instance->connection->ctx;
    smtpresponse_t* response = ctx->response;
    if (response->status != 250) {
        instance->reseted = 1;
        mail_set_error(instance, response->status, response->message);
        log_error("%s\n", response->message);
        return 0;
    }

    return 1;
}

int __mail_send_to(mail_t* instance) {
    if (!__mail_can_interact(instance)) return 0;
    if (instance->to.length == 0) return 0;
    if (!__mail_send_command(instance, "RCPT TO: %s\r\n", instance->to.value)) return 0;

    connection_client_ctx_t* ctx = instance->connection->ctx;
    smtpresponse_t* response = ctx->response;
    if (response->status != 250) {
        instance->reseted = 1;
        mail_set_error(instance, response->status, response->message);
        log_error("%s\n", response->message);
        return 0;
    }

    return 1;
}

int __mail_send_data(mail_t* instance) {
    if (!__mail_can_interact(instance)) return 0;
    if (!__mail_send_command(instance, "DATA\r\n")) return 0;

    connection_client_ctx_t* ctx = instance->connection->ctx;
    smtpresponse_t* response = ctx->response;
    if (response->status != 354) {
        instance->reseted = 1;
        mail_set_error(instance, response->status, response->message);
        log_error("%s\n", response->message);
        return 0;
    }

    set_smtp_client_content(instance->connection);
    ctx->request = instance->request_data;

    return 1;
}

int __mail_send_content(mail_t* instance) {
    if (!__mail_can_interact(instance)) return 0;
    if (instance->data_size == 0) return 0;

    // Check write return value
    int write_result = instance->connection->write(instance->connection);
    if (!write_result) {
        log_error("[__mail_send_content] Write failed\n");
        instance->reseted = 1;
        return 0;
    }

    // Check read return value
    int read_result = instance->connection->read(instance->connection);
    if (!read_result) {
        log_error("[__mail_send_content] Read failed\n");
        instance->reseted = 1;
        return 0;
    }

    connection_client_ctx_t* ctx = instance->connection->ctx;
    smtpresponse_t* response = ctx->response;
    if (response->status != 250) {
        instance->reseted = 1;
        mail_set_error(instance, response->status, response->message);
        log_error("%s\n", response->message);
        return 0;
    }

    set_smtp_client_command(instance->connection);
    ctx->request = instance->request;

    return 1;
}

int __mail_send_reset(mail_t* instance) {
    if (!__mail_can_interact(instance)) return 0;
    if (!__mail_send_command(instance, "RSET\r\n")) return 0;

    instance->reseted = 1;

    return 1;
}

void __mail_free(mail_t* instance) {
    if (instance == NULL) return;

    __mail_string_free(&instance->from_with_name);
    __mail_string_free(&instance->from);
    __mail_string_free(&instance->to);
    __mail_string_free(&instance->subject);
    __mail_string_free(&instance->date);
    __mail_string_free(&instance->message_id);
    
    if (instance->ssl_ctx != NULL) {
        SSL_CTX_free(instance->ssl_ctx);
        instance->ssl_ctx = NULL;
    }
    if (instance->connection != NULL) {
        __mail_connection_free(instance->connection);
        instance->connection = NULL;
    }
    if (instance->request != NULL) {
        instance->request->base.free(instance->request);
        instance->request = NULL;
    }
    if (instance->request_data != NULL) {
        instance->request_data->base.free(instance->request_data);
        instance->request_data = NULL;
    }
    if (instance->response != NULL) {
        instance->response->base.free(instance->response);
        instance->response = NULL;
    }
    if (instance->buffer != NULL) {
        free(instance->buffer);
        instance->buffer = NULL;
    }
    if (instance->data != NULL) {
        free(instance->data);
        instance->data = NULL;
    }

    instance->buffer_size = 0;
    instance->data_size = 0;

    mail_header_t* header = instance->_header;
    while (header) {
        mail_header_t* next = header->next;
        mail_header_free(header);
        header = next;
    }

    free(instance);
}

const char* __mail_domain_from_email(const char* email) {
    if (email == NULL) return NULL;

    const char* domain = strchr(email, '@');
    if (domain == NULL)
        return NULL;

    domain++;

    return domain;
}

int __mail_set_conn_timeout(const int fd, const int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds > 0 ? seconds : MAIL_DEFAULT_TIMEOUT;
    timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
        log_error("Error mail setsockopt SO_RCVTIMEO: %d\n", errno);
        return 0;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
        log_error("Error mail setsockopt SO_SNDTIMEO: %d\n", errno);
        return 0;
    }

    return 1;
}

int __mail_get_mx_servers(const char* host, mail_mx_record_t* mx_records) {
    union {
        HEADER hdr;
        unsigned char buf[NS_PACKETSZ];
    } buffer;

    const int buffer_size = res_query(host, ns_c_in, ns_t_mx, (unsigned char*)&buffer, sizeof(buffer));
    if (buffer_size == -1) {
        log_error("[getMXServers] Empty buffer: %s\n", strerror(errno));
        return 0;
    }

    if (buffer.hdr.rcode != NOERROR) {
        switch (buffer.hdr.rcode) {
            case FORMERR:
                log_error("[getMXServers] Buffer error: Format error\n");
                break;
            case SERVFAIL:
                log_error("[getMXServers] Buffer error: Server failure\n");
                break;
            case NXDOMAIN:
                log_error("[getMXServers] Buffer error: Name error\n");
                break;
            case NOTIMP:
                log_error("[getMXServers] Buffer error: Not implemented\n");
                break;
            case REFUSED:
                log_error("[getMXServers] Buffer error: Refused\n");
                break;
            default:
                log_error("[getMXServers] Buffer error: Unknown error\n");
        }

        return 0;
    }

    ns_msg message;
    if (ns_initparse(buffer.buf, buffer_size, &message) == -1) {
        log_error("[getMXServers] Can't init parse ns: %s\n", strerror(errno));
        return 0;
    }

    ns_rr resource_record;
    if (ns_parserr(&message, ns_s_qd, 0, &resource_record) == -1) {
        log_error("[getMXServers] Can't parse question section: %s\n", strerror(errno));
        return 0;
    }

    int result = 0;
    int answers = ntohs(buffer.hdr.ancount);
    answers = answers > MAIL_RECORDS_SIZE ? MAIL_RECORDS_SIZE : answers;
    for (int i = 0; i < answers; ++i)
        if (__mail_parse_mx_record(buffer.buf, buffer_size, ns_s_an, i, &message, &mx_records[i]))
            result = 1;

    return result;
}

int __mail_parse_mx_record(unsigned char* buffer, size_t r, ns_sect s, int idx, ns_msg* message, mail_mx_record_t* mx_record) {
    ns_rr resource_record;
    if (ns_parserr(message, s, idx, &resource_record) == -1) {
        log_error("[parseMxRecord] Can't parse answer section: %s\n", strerror(errno));
        return 0;
    }

    if (ns_rr_type(resource_record) != ns_t_mx)
        return 0;

    const unsigned char* data = ns_rr_rdata(resource_record);
    mx_record->preference = ns_get16(data);

    {
        unsigned char tmpname[NS_MAXDNAME];
        ns_name_unpack(buffer, buffer + r, data + sizeof(u_int16_t), tmpname, NS_MAXDNAME);
        ns_name_ntop(tmpname, mx_record->domain, NS_MAXDNAME);
    }

    struct hostent* he = gethostbyname(mx_record->domain);
    if (he == NULL) {
        log_error("[parseMxRecord] Error get host by name\n");
        return 0;
    }

    mx_record->ok = 1;

    struct in_addr** addr_list = (struct in_addr**)he->h_addr_list;
    for (int i = 0; addr_list[i] != NULL && i < MAIL_IP_LIST_SIZE; i++) {
        log_info("%d\n", *addr_list[i]);

        memcpy(&mx_record->ip_list[i], addr_list[i], sizeof(struct in_addr));
    }

    log_info("[parseMxRecord] pref: %d, host name: %s\n", mx_record->preference, mx_record->domain);

    return 1;
}

int __mail_can_interact(mail_t* instance) {
    if (instance == NULL) return 0;

    if (!__mail_connected(instance)) {
        log_error("[__mail_can_interact] Not connected\n");
        return 0;
    }

    if (instance->reseted) {
        log_error("[__mail_can_interact] Reseted\n");
        return 0;
    }

    return 1;
}

int __mail_send_command(mail_t* instance, const char* format, ...) {
    if (instance == NULL) return 0;
    if (format == NULL) return 0;

    va_list args;
    va_start(args, format);
    size_t size = vsnprintf(instance->request->command, sizeof(instance->request->command), format, args);
    va_end(args);

    // Check for buffer truncation
    if (size >= sizeof(instance->request->command)) {
        log_error("[__mail_send_command] Command truncated\n");
        instance->reseted = 1;
        return 0;
    }

    if (size <= 2) return 0;

    // Fix CRLF validation: should use OR (||) not AND (&&)
    if (instance->request->command[size - 2] != '\r' || instance->request->command[size - 1] != '\n') {
        log_error("[__mail_send_command] Invalid CRLF termination\n");
        instance->reseted = 1;
        return 0;
    }

    // Check write return value
    int write_result = instance->connection->write(instance->connection);
    if (!write_result) {
        log_error("[__mail_send_command] Write failed\n");
        instance->reseted = 1;
        return 0;
    }

    // Check read return value
    int read_result = instance->connection->read(instance->connection);
    if (!read_result) {
        log_error("[__mail_send_command] Read failed\n");
        instance->reseted = 1;
        return 0;
    }

    return 1;
}

/* A hostname that is really an address literal: SNI must not carry one, and
 * neither IPv4 dotted-quad nor an IPv6 literal is a name to verify against. */
static int __mail_host_is_address(const char* host) {
    if (strchr(host, ':') != NULL) return 1;

    for (const char* p = host; *p != '\0'; p++)
        if ((*p < '0' || *p > '9') && *p != '.')
            return 0;

    return 1;
}

int __mail_init_tls(mail_t* instance) {
    if (instance == NULL) return 0;

    const env_mail_relay_t* relay = &env()->mail.relay;

    /* Certificate verification is for the relay, and only for it.
     *
     * Delivery straight to a stranger's MX is opportunistic TLS (RFC 7435):
     * those certificates routinely fail to match the MX name, nobody publishes
     * a way to know which ones should, and refusing them means not delivering
     * at all -- so that leg stays unauthenticated, exactly as before. A relay is
     * the opposite case: a host named in our own configuration, and the one the
     * password is about to travel to. */
    const int verify = relay->enabled && relay->verify;
    const char* hostname = relay->enabled ? relay->host : NULL;

    int result = 0;

    instance->ssl_ctx = SSL_CTX_new(TLS_method());
    if (instance->ssl_ctx == NULL) goto failed;

    if (verify) {
        if (!SSL_CTX_set_default_verify_paths(instance->ssl_ctx)) {
            log_error("[__mail_init_tls] Failed to load the trusted CA store\n");
            goto failed;
        }

        SSL_CTX_set_verify(instance->ssl_ctx, SSL_VERIFY_PEER, NULL);
    }

    instance->connection->ssl_ctx = instance->ssl_ctx;

    if (!__mail_alloc_ssl(instance->connection, hostname, verify))
        goto failed;

    if (!__mail_handshake(instance->connection, verify))
        goto failed;

    result = 1;

    failed:

    return result;
}

int __mail_alloc_ssl(connection_t* connection, const char* hostname, const int verify) {
    if (connection->ssl != NULL) return 1;

    int result = 0;

    connection->ssl = SSL_new(connection->ssl_ctx);
    if (connection->ssl == NULL)
        goto failed;

    if (hostname != NULL && !__mail_host_is_address(hostname)) {
        /* Without SNI a relay behind a shared front end answers with some other
         * tenant's certificate, and then hostname verification fails on a
         * perfectly correct configuration. */
        SSL_set_tlsext_host_name(connection->ssl, hostname);

        if (verify) {
            SSL_set_hostflags(connection->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

            if (!SSL_set1_host(connection->ssl, hostname))
                goto failed;
        }
    }

    if (!SSL_set_fd(connection->ssl, connection->fd))
        goto failed;

    SSL_set_connect_state(connection->ssl);

    result = 1;

    failed:

    if (result == 0) {
        if (connection->ssl) {
            SSL_free(connection->ssl);
            connection->ssl = NULL;
        }
    }

    return result;
}

int __mail_handshake(connection_t* connection, const int verify) {
    if (connection == NULL) return 0;

    set_smtp_client_tls(connection);

    // Check write return value during TLS handshake
    int write_result = connection->write(connection);
    if (!write_result) {
        if (verify) {
            const long verify_result = SSL_get_verify_result(connection->ssl);
            if (verify_result != X509_V_OK) {
                log_error("[__mail_handshake] Certificate verification failed: %s\n",
                    X509_verify_cert_error_string(verify_result));
                return 0;
            }
        }

        log_error("[__mail_handshake] Write failed during TLS handshake\n");
        return 0;
    }

    connection_client_ctx_t* ctx = connection->ctx;
    if (ctx->request == NULL || connection->fd == 0) {
        log_error("[__mail_handshake] Invalid context or disconnected\n");
        return 0;
    }

    /* connection->write() reports success for the "would block" SSL states too,
     * and on this blocking socket that means the handshake ran out its timeout.
     * Left unchecked, the session would go on to write SMTP commands into a
     * socket that never became TLS. */
    if (!SSL_is_init_finished(connection->ssl)) {
        log_error("[__mail_handshake] TLS handshake did not complete\n");
        return 0;
    }

    return 1;
}

int __mail_set_dkim_headers(dkim_t* dkim, mail_t* instance) {
    if (!dkim_header_add(dkim, "From", 4, instance->from_with_name.value, instance->from_with_name.length)) return 0;
    if (!dkim_header_add(dkim, "To", 2, instance->to.value, instance->to.length)) return 0;
    if (!dkim_header_add(dkim, "Subject", 7, instance->subject.value, instance->subject.length)) return 0;
    if (!dkim_header_add(dkim, "Date", 4, instance->date.value, instance->date.length)) return 0;
    if (!dkim_header_add(dkim, "Message-Id", 10, instance->message_id.value, instance->message_id.length)) return 0;

    return 1;
}

int __mail_build_content(mail_t* instance) {
    if (instance == NULL) return 0;

    int result = 0;
    time_t rawtime = time(0);
    dkim_t* dkim = NULL;
    char* dkim_sign = NULL;

    if (!__mail_set_date(instance, &rawtime))
        goto failed;
    if (!__mail_set_message_id(instance, &rawtime))
        goto failed;

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
    const char* dkim_private = env()->mail.dkim_private;
    const char* dkim_selector = env()->mail.dkim_selector;

    if (dkim_private != NULL && dkim_private[0] != '\0' &&
        dkim_selector != NULL && dkim_selector[0] != '\0') {
        dkim = dkim_create();
        if (dkim == NULL)
            goto failed;

        dkim_set_private_key(dkim, dkim_private);
        dkim_set_domain(dkim, env()->mail.host);
        dkim_set_selector(dkim, dkim_selector);
        dkim_set_timestamp(dkim, rawtime);

        if (!__mail_set_dkim_headers(dkim, instance))
            goto failed;

        dkim_sign = dkim_create_sign(dkim, instance->data);
        if (dkim_sign == NULL)
            goto failed;
    }

    if (!__mail_header_add(instance, "From", instance->from_with_name.value)) goto failed;
    if (!__mail_header_add(instance, "To", instance->to.value)) goto failed;
    if (!__mail_header_add(instance, "Subject", instance->subject.value)) goto failed;
    if (!__mail_header_add(instance, "Date", instance->date.value)) goto failed;
    if (!__mail_header_add(instance, "Message-Id", instance->message_id.value)) goto failed;
    if (dkim_sign != NULL && !__mail_header_add(instance, "DKIM-Signature", dkim_sign)) goto failed;
    if (!__mail_header_add(instance, "MIME-Version", "1.0")) goto failed;
    if (!__mail_header_add(instance, "Content-Transfer-Encoding", "base64")) goto failed;
    if (!__mail_header_add(instance, "Content-Type", "text/html; charset=utf-8")) goto failed;

    instance->request_data->content_size = __mail_calc_content_length(instance);
    instance->request_data->content = malloc(sizeof(char) * instance->request_data->content_size);
    if (instance->request_data->content == NULL)
        goto failed;

    size_t pos = 0;
    mail_header_t* header = instance->_header;
    while (header) {
        if (!__mail_data_append(instance->request_data->content, &pos, header->key, header->key_length)) goto failed;
        if (!__mail_data_append(instance->request_data->content, &pos, ": ", 2)) goto failed;
        if (!__mail_data_append(instance->request_data->content, &pos, header->value, header->value_length)) goto failed;
        if (!__mail_data_append(instance->request_data->content, &pos, "\r\n", 2)) goto failed;

        header = header->next;
    }

    if (!__mail_data_append(instance->request_data->content, &pos, "\r\n", 2)) goto failed;
    if (!__mail_data_append(instance->request_data->content, &pos, instance->data, instance->data_size)) goto failed;
    if (!__mail_data_append(instance->request_data->content, &pos, "\r\n.\r\n", 5)) goto failed;

    result = 1;

    failed:

    if (result == 0) {
        instance->reseted = 1;
    }

    if (dkim != NULL) dkim_free(dkim);
    if (dkim_sign != NULL) free(dkim_sign);

    return result;
}

int __mail_header_add(mail_t* instance, const char* key, const char* value) {
    if (instance == NULL) return 0;
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

    if (instance->_header == NULL)
        instance->_header = header;

    if (instance->_last_header != NULL)
        instance->_last_header->next = header;

    instance->_last_header = header;

    return 1;
}

size_t __mail_calc_content_length(mail_t* instance) {
    mail_header_t* header = instance->_header;
    size_t size = 0;

    while (header) {
        size += header->key_length;
        size += 2; // ": "
        size += header->value_length;
        size += 2; // "\r\n"

        header = header->next;
    }

    size += 2; // "\r\n"
    size += instance->data_size;
    size += 5; // "\r\n.\r\n"

    return size;
}

int __mail_data_append(char* data, size_t* pos, const char* string, const size_t length) {
    memcpy(&data[*pos], string, length);
    *pos += length;

    return 1;
}
