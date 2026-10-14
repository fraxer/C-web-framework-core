#ifndef __VIEWMODIFIER__
#define __VIEWMODIFIER__

#include <stddef.h>

#include "arena.h"
#include "bufferdata.h"
#include "viewexpr.h"

#define VIEWMODIFIER_MAX_ARGS VIEWEXPR_MAX_ARGS

// How the value of a {{ }} tag reaches the output.
typedef enum {
    VIEW_ESCAPE = 0, // HTML-escape & < > " '
    VIEW_RAW         // write as is
} view_escape_e;

typedef enum {
    VIEWMOD_VALUE = 0, // transforms a value, the tag output is then escaped
    VIEWMOD_RAW,       // disables the final escaping; root of a {{ }} tag only
    VIEWMOD_SAFE       // escapes the input itself and writes fixed markup; root of a {{ }} tag only
} viewmodifier_kind_e;

typedef struct viewmodifier {
    const char* name;
    unsigned char min_args;
    unsigned char max_args;
    viewmodifier_kind_e kind;

    // VIEWMOD_VALUE: the transformed value; new strings are allocated in the
    // arena, a NULL arena makes such modifiers return null. NULL otherwise.
    viewexpr_value_t (*apply)(arena_t* arena, const viewexpr_value_t* input,
                              const viewexpr_value_t* args, size_t argc);

    // VIEWMOD_SAFE: writes the input to the output in the given mode. NULL otherwise.
    void (*output)(bufferdata_t* buf, const viewexpr_value_t* input, view_escape_e escape);
} viewmodifier_t;

const viewmodifier_t* viewmodifier_find(const char* name, size_t length);

// Writes `length` bytes of text: & < > " ' as HTML entities in VIEW_ESCAPE
// mode, NUL bytes as U+FFFD in both modes.
void viewmodifier_write_text(bufferdata_t* buf, const char* text, size_t length, view_escape_e escape);

#endif
