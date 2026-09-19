#ifndef CWFR_CSTR_INTERNAL_H
#define CWFR_CSTR_INTERNAL_H

#include <stdint.h>

/* Shared between cstr.c and validation.c -- both inside this library, so no
 * dependency cycle. Never installed: cmake/install.cmake drops every
 * *_internal.h from the public headers.
 *
 * The name carries the module prefix rather than the leading underscores the
 * original used: identifiers starting with two underscores are reserved for
 * the implementation by the C standard.
 *
 * The UTF-8 decoder these two also share lives in utf8.h instead: utf8_strlen
 * needs it as well, and misc cannot depend on this library. */

/* C0 except tab, newline and carriage return, DEL, C1, and the invisible
 * characters: BOM, zero-width, the bidirectional marks. The last ones matter
 * for more than tidiness -- an RLO reverses how a line is shown and passes one
 * string off as another in a letter a human reads. */
int cstr_is_control_codepoint(uint32_t codepoint);

#endif
