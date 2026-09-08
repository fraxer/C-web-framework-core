#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include "smtpresponse.h"
#include "smtpresponseparser.h"

void __smtpresponse_reset(void*);
void __smtpresponse_free(void*);
int __smtpresponse_init_parser(smtpresponse_t*);

smtpresponse_t* smtpresponse_create(connection_t* connection) {
    smtpresponse_t* response = malloc(sizeof * response);
    if (response == NULL) return NULL;

    response->status = 0;
    response->connection = connection;
    memset(response->message, 0, SMTPRESPONSE_MESSAGE_SIZE);
    smtpresponse_reset_capabilities(response);
    response->base.reset = __smtpresponse_reset;
    response->base.free = __smtpresponse_free;

    if (!__smtpresponse_init_parser(response)) {
        free(response);
        return NULL;
    }

    return response;
}

void __smtpresponse_reset(void* arg) {
    if (arg == NULL) return;

    smtpresponse_t* response = (smtpresponse_t*)arg;

    response->status = 0;
    memset(response->message, 0, SMTPRESPONSE_MESSAGE_SIZE);
    smtpresponse_reset_capabilities(response);

    smtpresponseparser_reset(response->parser);
}

void __smtpresponse_free(void* arg) {
    if (arg == NULL) return;

    smtpresponse_t* response = (smtpresponse_t*)arg;

    __smtpresponse_reset(response);
    smtpresponseparser_free(response->parser);

    free(response);
}

void smtpresponse_reset_capabilities(smtpresponse_t* response) {
    if (response == NULL) return;

    response->extensions = 0;
    response->auth_mechanisms = 0;
    response->size_limit = 0;
}

/* Case-insensitive comparison of the keyword at the head of `line` against
 * `keyword`, requiring a word boundary after it (end of line or a space): the
 * EHLO keyword "SIZE" must not match a hypothetical "SIZEX". */
static int __smtpresponse_keyword_is(const char* line, size_t length, const char* keyword) {
    const size_t keyword_length = strlen(keyword);
    if (length < keyword_length) return 0;

    for (size_t i = 0; i < keyword_length; i++)
        if (toupper((unsigned char)line[i]) != (unsigned char)keyword[i])
            return 0;

    /* '=' as well as a space: some servers still announce "AUTH=PLAIN LOGIN"
     * alongside (or instead of) the RFC 4954 spelling. */
    return length == keyword_length ||
           line[keyword_length] == ' ' ||
           line[keyword_length] == '=';
}

/* The AUTH keyword's argument list: "AUTH PLAIN LOGIN", and on some servers the
 * historical "AUTH=PLAIN LOGIN" form, hence both separators. */
static void __smtpresponse_parse_auth(smtpresponse_t* response, const char* args, size_t length) {
    size_t i = 0;
    while (i < length) {
        while (i < length && (args[i] == ' ' || args[i] == '=')) i++;

        size_t start = i;
        while (i < length && args[i] != ' ' && args[i] != '=') i++;

        const size_t token_length = i - start;
        if (token_length == 0) continue;

        if (__smtpresponse_keyword_is(&args[start], token_length, "PLAIN"))
            response->auth_mechanisms |= SMTPRESPONSE_AUTH_PLAIN;
        else if (__smtpresponse_keyword_is(&args[start], token_length, "LOGIN"))
            response->auth_mechanisms |= SMTPRESPONSE_AUTH_LOGIN;
    }
}

void smtpresponse_parse_capability(smtpresponse_t* response, const char* line, size_t length) {
    if (response == NULL || line == NULL) return;

    /* Strip the line terminator, then the three-digit code and its separator.
     * Anything shorter than "NNN-" carries no keyword. */
    while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r'))
        length--;

    if (length < 4) return;
    if (line[3] != ' ' && line[3] != '-') return;

    /* Only a 250 reply lists extensions; a 5xx EHLO rejection has a free-text
     * body that must not be mined for keywords. */
    if (line[0] != '2' || line[1] != '5' || line[2] != '0') return;

    line += 4;
    length -= 4;

    while (length > 0 && *line == ' ') { line++; length--; }
    if (length == 0) return;

    if (__smtpresponse_keyword_is(line, length, "STARTTLS")) {
        response->extensions |= SMTPRESPONSE_EXT_STARTTLS;
        return;
    }

    if (__smtpresponse_keyword_is(line, length, "PIPELINING")) {
        response->extensions |= SMTPRESPONSE_EXT_PIPELINING;
        return;
    }

    if (__smtpresponse_keyword_is(line, length, "SIZE")) {
        response->extensions |= SMTPRESPONSE_EXT_SIZE;

        size_t i = 4;
        while (i < length && line[i] == ' ') i++;

        size_t limit = 0;
        int digits = 0;
        while (i < length && line[i] >= '0' && line[i] <= '9') {
            limit = limit * 10 + (size_t)(line[i] - '0');
            digits++;
            i++;
        }

        if (digits > 0)
            response->size_limit = limit;

        return;
    }

    if (__smtpresponse_keyword_is(line, length, "AUTH")) {
        response->extensions |= SMTPRESPONSE_EXT_AUTH;
        __smtpresponse_parse_auth(response, line + 4, length - 4);
        return;
    }
}

int __smtpresponse_init_parser(smtpresponse_t* response) {
    if (response == NULL) return 0;

    response->parser = malloc(sizeof(smtpresponseparser_t));
    if (response->parser == NULL) return 0;

    smtpresponseparser_init(response->parser);

    return 1;
}