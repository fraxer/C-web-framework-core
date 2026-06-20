#include <stdlib.h>

#include "dkimcanonparser.h"

dkimcanonparser_t* dkimcanonparser_alloc() {
    return malloc(sizeof(dkimcanonparser_t));
}

void dkimcanonparser_init(dkimcanonparser_t* parser) {
    parser->stage = DKIMCANONPARSER_SYMBOL;
    parser->buffer_size = 0;
    parser->pos_start = 0;
    parser->pos = 0;
    parser->buffer = NULL;

    bufferdata_init(&parser->buf);
}

void dkimcanonparser_set_buffer(dkimcanonparser_t* parser, const char* buffer, const size_t buffer_size) {
    parser->buffer = buffer;
    parser->buffer_size = buffer_size;
}

void dkimcanonparser_flush(dkimcanonparser_t* parser) {
    if (parser->buf.dynamic_buffer) free(parser->buf.dynamic_buffer);
    parser->buf.dynamic_buffer = NULL;
}

void dkimcanonparser_free(dkimcanonparser_t* parser) {
    dkimcanonparser_flush(parser);
    free(parser);
}

int dkimcanonparser_run(dkimcanonparser_t* parser) {
    /* run() resets its own cursors, so reset the output buffer and stage too;
     * otherwise a second run() on the same parser accumulates onto the previous
     * canonical form. bufferdata_reset() keeps any dynamic allocation for reuse
     * and is freed by dkimcanonparser_free(). */
    parser->stage = DKIMCANONPARSER_SYMBOL;
    parser->pos_start = 0;
    parser->pos = 0;
    bufferdata_reset(&parser->buf);

    for (parser->pos = parser->pos_start; parser->pos < parser->buffer_size; parser->pos++) {
        char ch = parser->buffer[parser->pos];

        switch (ch)
        {
        case '\t':
        case ' ':
        {
            if (parser->stage != DKIMCANONPARSER_SPACE)
                bufferdata_push(&parser->buf, ' ');

            parser->stage = DKIMCANONPARSER_SPACE;

            break;
        }
        case '\n':
        {
            parser->stage = DKIMCANONPARSER_SYMBOL;

            bufferdata_complete(&parser->buf);

            while (1) {
                char c = bufferdata_back(&parser->buf);

                /* Strip trailing WSP on the line (RFC 6376 §3.4.4(b)) and also a
                 * preceding '\r', so a CRLF-terminated input line does not end up
                 * as "\r\r\n" — the '\r' is re-added by the push below. */
                if (c == ' ' || c == '\t' || c == '\r')
                    bufferdata_pop_back(&parser->buf);
                else
                    break;
            }

            bufferdata_push(&parser->buf, '\r');
            bufferdata_push(&parser->buf, '\n');

            break;
        }
        default:
            parser->stage = DKIMCANONPARSER_SYMBOL;
            bufferdata_push(&parser->buf, ch);
        }
    }

    while (1) {
        char c = bufferdata_back(&parser->buf);

        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            bufferdata_pop_back(&parser->buf);
        else
            break;
    }

    /* RFC 6376 §3.4.4: a CRLF is appended only when the body is non-empty.
     * An empty body, or one made up solely of blank/WSP lines, canonicalizes
     * to a zero-length string — not to "\r\n". */
    if (bufferdata_writed(&parser->buf) > 0) {
        bufferdata_push(&parser->buf, '\r');
        bufferdata_push(&parser->buf, '\n');
    }
    bufferdata_complete(&parser->buf);

    return 1;
}

char* dkimcanonparser_get_content(dkimcanonparser_t* parser) {
    return bufferdata_copy(&parser->buf);
}
