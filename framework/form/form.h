#ifndef CWFR_FORM_H
#define CWFR_FORM_H

#include <stddef.h>
#include <stdint.h>

typedef struct form form_t;

typedef enum {
    FORM_VALID = 0,
    FORM_REQUIRED,
    FORM_MIN_LENGTH,
    FORM_MAX_LENGTH,
    FORM_MIN_VALUE,
    FORM_MAX_VALUE,
    FORM_INVALID,
    FORM_REGEX,
    FORM_MAX_SIZE,
    FORM_EMPTY_FILE,
    FORM_INVALID_CHOICE
} form_error_t;

typedef enum {
    FORM_FIELD_UNSPECIFIED,
    FORM_FIELD_TEXT,
    FORM_FIELD_INTEGER,
    FORM_FIELD_DECIMAL,
    FORM_FIELD_BOOLEAN,
    FORM_FIELD_OBJECT,
    FORM_FIELD_CUSTOM,
    FORM_FIELD_DATE,
    FORM_FIELD_TIME,
    FORM_FIELD_DATETIME,
    FORM_FIELD_UUID,
    FORM_FIELD_JSON,
    FORM_FIELD_CHOICE,
    FORM_FIELD_FILEPATH,
    FORM_FIELD_FILE,
    FORM_FIELD_MULTIPLE_CHOICE
} form_field_kind_t;

typedef enum { FORM_INPUT_TEXT, FORM_INPUT_OBJECT, FORM_INPUT_TEXT_LIST } form_input_kind_t;

typedef struct {
    char** items;
    size_t count;
} form_input_text_list_t;

typedef struct {
    const char* const* items;
    size_t count;
} form_value_text_list_t;

typedef struct {
    int year, month, day;
} form_date_t;

typedef struct {
    int hour, minute, second, microsecond;
} form_time_t;

typedef struct {
    form_date_t date;
    form_time_t time;
    int offset_minutes;
    int has_offset;
} form_datetime_t;

typedef struct {
    uint8_t bytes[16];
} form_uuid_t;

/* Text buffers and text lists (array plus each string) are owned by the form.
 * Objects are released by destroy, if set. The input array may be on stack. */
typedef struct {
    form_input_kind_t kind;
    union {
        char* text;
        void* object;
        form_input_text_list_t text_list;
    } data;
    void (*destroy)(void* object);
} form_input_t;

typedef enum {
    FORM_VALUE_EMPTY,
    FORM_VALUE_TEXT,
    FORM_VALUE_INTEGER,
    FORM_VALUE_DECIMAL,
    FORM_VALUE_BOOLEAN,
    FORM_VALUE_OBJECT,
    FORM_VALUE_DATE,
    FORM_VALUE_TIME,
    FORM_VALUE_DATETIME,
    FORM_VALUE_UUID,
    FORM_VALUE_TEXT_LIST
} form_value_kind_t;

/* Text and text-list values borrow the input. A separately allocated object
 * may be owned by the form through destroy; it is freed before its input.
 * A parser returning the input object must leave destroy unset. */
typedef struct {
    form_value_kind_t kind;
    union {
        const char* text;
        int64_t integer;
        long double decimal;
        int boolean;
        void* object;
        form_date_t date;
        form_time_t time;
        form_datetime_t datetime;
        form_uuid_t uuid;
        form_value_text_list_t text_list;
    } data;
    void (*destroy)(void* object); /* Only for FORM_VALUE_OBJECT. */
} form_value_t;

typedef int (*form_parse_fn)(const form_input_t* input, form_value_t* value, void* context);
typedef int (*form_validator_fn)(const form_value_t* value, void* context);

typedef struct {
    form_validator_fn check;
    void* context;
    const char* message;
} form_validator_t;

/* Shared properties of all field types. Contexts are borrowed. */
typedef struct {
    const char* name;
    int required;
    void* context;
    const form_validator_t* validators;
    size_t validators_count;
    const char* required_message;
    const char* invalid_message;
} form_field_common_t;

/* Zero disables a text length boundary. */
typedef struct {
    form_field_common_t common;
    int clean_flags;
    const char* default_value; /* Borrowed; NULL means no default. */
    size_t min_length;
    size_t max_length;
    /* PCRE2 UTF-8 search pattern; use \A and \z for a full-string match.
     * NULL disables the rule. Borrowed for the form lifetime. */
    const char* regex;
    const char* min_length_message;
    const char* max_length_message;
    const char* regex_message;
} form_text_field_t;

/* Explicit has_* flags allow zero as a numeric boundary. */
typedef struct {
    form_field_common_t common;
    int clean_flags;
    int has_default;
    int64_t default_value;
    int has_min_value;
    int64_t min_value;
    int has_max_value;
    int64_t max_value;
    const char* min_value_message;
    const char* max_value_message;
} form_integer_field_t;

typedef struct {
    form_field_common_t common;
    int clean_flags;
    int has_default;
    long double default_value;
    int has_min_value;
    long double min_value;
    int has_max_value;
    long double max_value;
    const char* min_value_message;
    const char* max_value_message;
} form_decimal_field_t;

typedef struct {
    form_field_common_t common;
    int clean_flags;
    int has_default;
    int default_value;
} form_boolean_field_t;

typedef struct {
    form_field_common_t common;
    void* default_value; /* Borrowed; NULL means no default. */
} form_object_field_t;

typedef struct {
    form_field_common_t common;
    int clean_flags;
    const form_value_t* default_value; /* Borrowed. */
    form_parse_fn parse;
} form_custom_field_t;

typedef struct {
    form_field_common_t common;
    int clean_flags;
    int has_default;
    form_date_t default_value;
} form_date_field_t;

typedef struct {
    form_field_common_t common;
    int clean_flags;
    int has_default;
    form_time_t default_value;
} form_time_field_t;

typedef struct {
    form_field_common_t common;
    int clean_flags;
    int has_default;
    form_datetime_t default_value;
} form_datetime_field_t;

typedef struct {
    form_field_common_t common;
    int clean_flags;
    int has_default;
    form_uuid_t default_value;
} form_uuid_field_t;

/* JSON values are json_doc_t* in FORM_VALUE_OBJECT. Parsed documents belong
 * to the form; defaults are borrowed. */
typedef struct {
    form_field_common_t common;
    int clean_flags;
    void* default_value; /* Borrowed json_doc_t*. */
} form_json_field_t;

typedef struct {
    form_field_common_t common;
    int clean_flags;
    const char* default_value;
    const char* const* choices;
    size_t choices_count;
    const char* invalid_choice_message;
} form_choice_field_t;

/* Input and returned value are a single name inside directory of the storage
 * (a storage name from config.json). Symlinks are rejected. Set at least one of
 * allow_files/allow_directories. On S3 a directory is a prefix holding at least
 * one object, and every check is a request to the storage. */
typedef struct {
    form_field_common_t common;
    int clean_flags;
    const char* default_value;
    const char* storage;
    const char* directory; /* Inside the storage; NULL or "" is its root. */
    int allow_files;
    int allow_directories;
    const char* invalid_choice_message;
} form_filepath_field_t;

/* Input is a file_content_t* in FORM_INPUT_OBJECT. The request owns its fd;
 * the input destroy callback only releases the wrapper, if needed. */
typedef struct {
    form_field_common_t common;
    void* default_value; /* Borrowed file_content_t*. */
    size_t max_size;
    size_t max_filename_length;
    int allow_empty_file;
    const char* max_size_message;
    const char* max_filename_length_message;
    const char* empty_file_message;
} form_file_field_t;

/* FORM_INPUT_TEXT_LIST owns its array and every string. Cleaned values borrow
 * them until form_free(). Empty lists are valid when required is false.
 * clean_flags are applied to every item, as for a single choice. */
typedef struct {
    form_field_common_t common;
    int clean_flags;
    const char* const* choices;
    size_t choices_count;
    const char* const* default_values; /* Borrowed; NULL means empty list. */
    size_t default_values_count;
    const char* invalid_choice_message;
} form_multiple_choice_field_t;

typedef struct {
    form_field_kind_t kind;
    union {
        form_text_field_t text;
        form_integer_field_t integer;
        form_decimal_field_t decimal;
        form_boolean_field_t boolean;
        form_object_field_t object;
        form_custom_field_t custom;
        form_date_field_t date;
        form_time_field_t time;
        form_datetime_field_t datetime;
        form_uuid_field_t uuid;
        form_json_field_t json;
        form_choice_field_t choice;
        form_filepath_field_t filepath;
        form_file_field_t file;
        form_multiple_choice_field_t multiple_choice;
    };
} form_field_spec_t;

/* clean() edits a text buffer in place and returns a pointer into it.
 * length() is required if a text field has a length rule. validate() runs after
 * field checks and may add field or non-field errors. The schema, validator
 * arrays, defaults and their contexts must outlive the form. */
typedef struct {
    const form_field_spec_t* fields;
    size_t fields_count;
    char* (*clean)(char* text, int flags);
    size_t (*length)(const char* text);
    void (*validate)(form_t* form, void* context);
    void* context;
} form_schema_t;

/* Consumes every input for a non-NULL schema with fields_count > 0 and a
 * non-NULL input array, including when schema validation or allocation fails.
 * A NULL schema, zero fields or NULL inputs are programmer errors. */
form_t* form_create(const form_schema_t* schema, const form_input_t inputs[]);

/* Runs once, then caches the result and errors. */
int form_is_valid(form_t* form);

/* A field value is available after field validation, including inside the
 * form-wide callback. It is NULL if that field failed. cleaned_data requires
 * the entire form to be valid. Both pointers are borrowed until form_free(). */
const form_value_t* form_field_value(const form_t* form, size_t index);
const form_value_t* form_cleaned_data(const form_t* form, size_t index);

/* Only callable from schema.validate(). The first error per field wins. */
int form_add_error(form_t* form, size_t index, form_error_t code, const char* message);
int form_add_non_field_error(form_t* form, const char* message);

/* Errors are available after form_is_valid(). */
form_error_t form_error_code(const form_t* form, size_t index);
const char* form_error_message(const form_t* form, size_t index);
const char* form_non_field_error(const form_t* form);
const char* form_field_name(const form_t* form, size_t index);
size_t form_fields_count(const form_t* form);

/* Built-in parsers; applications may provide their own. */
int form_parse_integer(const form_input_t* input, form_value_t* value, void* context);
int form_parse_boolean(const form_input_t* input, form_value_t* value, void* context);
int form_parse_decimal(const form_input_t* input, form_value_t* value, void* context);

void form_free(form_t* form);

#endif
