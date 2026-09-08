#ifndef __SMTPRESPONSE__
#define __SMTPRESPONSE__

#include "connection.h"
#include "response.h"

#define SMTPRESPONSE_MESSAGE_SIZE 1024

/* Extensions announced in a multi-line EHLO reply. Only the ones the client can
 * act on are kept -- a fixed set of flags rather than a list of arbitrary
 * keywords, because nothing here ever asks "what else did the server offer?".
 *
 * The reply is accumulated as it is parsed, so the flags describe the *last*
 * EHLO: __mail_send_hello clears them before writing the command, which matters
 * because a server typically announces AUTH only after STARTTLS. */
#define SMTPRESPONSE_EXT_STARTTLS  (1u << 0)
#define SMTPRESPONSE_EXT_AUTH      (1u << 1)
#define SMTPRESPONSE_EXT_SIZE      (1u << 2)
#define SMTPRESPONSE_EXT_PIPELINING (1u << 3)

/* AUTH mechanisms, from the argument list of the AUTH keyword. */
#define SMTPRESPONSE_AUTH_PLAIN    (1u << 0)
#define SMTPRESPONSE_AUTH_LOGIN    (1u << 1)

typedef struct smtpresponse {
    response_t base;

    int status;
    char message[SMTPRESPONSE_MESSAGE_SIZE];
    void* parser;

    unsigned int extensions;       /* SMTPRESPONSE_EXT_* */
    unsigned int auth_mechanisms;  /* SMTPRESPONSE_AUTH_* */
    size_t size_limit;             /* the SIZE argument, 0 when unannounced */

    connection_t* connection;
} smtpresponse_t;

/* Forget every capability of the previous EHLO. Called before each EHLO is
 * written, since a reply is parsed line by line into the same response. */
void smtpresponse_reset_capabilities(smtpresponse_t* response);

/* Read one line of an EHLO reply (with its "250-"/"250 " prefix, with or
 * without the trailing CRLF) and record what it announces. Exposed for the
 * response parser and the unit tests. */
void smtpresponse_parse_capability(smtpresponse_t* response, const char* line, size_t length);

smtpresponse_t* smtpresponse_create(connection_t*);

#endif
