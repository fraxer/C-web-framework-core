#ifndef __HTTP1FORMDATAPARSER__
#define __HTTP1FORMDATAPARSER__

#include <stdlib.h>
#include <stddef.h>

#include "str.h"

#define FORMDATABUFSIZ 1024
#define FORMDATAKEY 1
#define FORMDATAVALUE 2

typedef enum formdataparser_stage {
    FORMDATA_SEMICOLON = 0,
    FORMDATA_SKIP,
    FORMDATA_KEY,
    FORMDATA_EQUAL,
    FORMDATA_VALUE,
    FORMDATA_AFTER_VALUE
} formdataparser_stage_e;

typedef struct formdatalocation {
    int ok;
    size_t offset;
    size_t size;
} formdatalocation_t;

typedef struct formdatafield {
    str_t key;
    str_t value;
    struct formdatafield* next;
} formdatafield_t;

typedef struct formdataparser {
    char buffer[FORMDATABUFSIZ];
    const char* error;
    const char* disposition_type;
    formdatafield_t* field;
    formdatafield_t* last_field;
    size_t size;
    formdataparser_stage_e stage;
    unsigned int quote : 1;
} formdataparser_t;

int formdataparser_init(formdataparser_t* parser, const char* disposition_type);

void formdataparser_clear(formdataparser_t* parser);

int formdataparser_parse(formdataparser_t* parser, const char* buffer, size_t buffer_size);

const char* formdataparser_find_field(formdataparser_t* parser, const char* field);

formdatafield_t* formdataparser_first_field(formdataparser_t* parser);

#endif