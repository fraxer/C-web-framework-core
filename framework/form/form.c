#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <pcre2.h>

#include "form.h"
#include "cstr.h"
#include "file.h"
#include "helpers.h"
#include "json.h"
#include "storage.h"
#include "utf8.h"

typedef struct {
    form_input_t input;
    form_value_t value;
    form_error_t error;
    const char* message;
    pcre2_code* regex;
    char** cleaned_items; /* Cleaned list items; point into input strings. */
} form_field_t;

struct form {
    const form_schema_t* schema;
    form_field_t* fields;
    const char* non_field_error;
    int fields_validated;
    int validating_form;
    int validated;
    int valid;
};

static void json_value_free(void* value) {
    json_free(value);
}

static int fixed_number(const char** cursor, int count, int* result) {
    int number = 0;
    for (int i = 0; i < count; i++) {
        if (!isdigit((unsigned char)(*cursor)[i])) return 0;
        number = number * 10 + (*cursor)[i] - '0';
    }

    *cursor += count;
    *result = number;

    return 1;
}

static int valid_date(form_date_t date) {
    static const int days[] = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    if (date.year < 1 || date.year > 9999 || date.month < 1 || date.month > 12)
        return 0;

    int max_day = days[date.month];
    if (date.month == 2 && date.year % 4 == 0 &&
        (date.year % 100 != 0 || date.year % 400 == 0)) max_day++;

    return date.day >= 1 && date.day <= max_day;
}

static int parse_date_text(const char** cursor, form_date_t* date) {
    const char* p = *cursor;
    if (!fixed_number(&p, 4, &date->year) || *p++ != '-' ||
        !fixed_number(&p, 2, &date->month) || *p++ != '-' ||
        !fixed_number(&p, 2, &date->day) || !valid_date(*date)) return 0;

    *cursor = p;

    return 1;
}

static int valid_time(form_time_t time) {
    return time.hour >= 0 && time.hour < 24 && time.minute >= 0 &&
           time.minute < 60 && time.second >= 0 && time.second < 60 &&
           time.microsecond >= 0 && time.microsecond < 1000000;
}

static int valid_datetime(form_datetime_t datetime) {
    return valid_date(datetime.date) && valid_time(datetime.time) &&
           (datetime.has_offset
            ? (datetime.offset_minutes >= -1439 && datetime.offset_minutes <= 1439)
            : datetime.offset_minutes == 0);
}

static int parse_time_text(const char** cursor, form_time_t* time) {
    const char* p = *cursor;
    *time = (form_time_t){0};

    if (!fixed_number(&p, 2, &time->hour) || *p++ != ':' ||
        !fixed_number(&p, 2, &time->minute))
        return 0;

    if (*p == ':') {
        p++;
        if (!fixed_number(&p, 2, &time->second)) return 0;
    }

    if (*p == '.') {
        int digits = 0;
        p++;
        while (isdigit((unsigned char)*p) && digits < 6) {
            time->microsecond = time->microsecond * 10 + *p++ - '0';
            digits++;
        }

        if (digits == 0 || isdigit((unsigned char)*p))
            return 0;
    
        while (digits++ < 6)
            time->microsecond *= 10;
    }

    if (!valid_time(*time))
        return 0;

    *cursor = p;

    return 1;
}

static int parse_temporal(const form_input_t* input, form_value_t* value, form_field_kind_t kind) {
    if (input->kind != FORM_INPUT_TEXT || input->data.text == NULL)
        return 0;

    const char* p = input->data.text;
    if (kind == FORM_FIELD_DATE) {
        form_date_t date;
        if (!parse_date_text(&p, &date) || *p)
            return 0;

        *value = (form_value_t){
            .kind = FORM_VALUE_DATE,
            .data.date = date
        };
    } else if (kind == FORM_FIELD_TIME) {
        form_time_t time;
        if (!parse_time_text(&p, &time) || *p)
            return 0;

        *value = (form_value_t){
            .kind = FORM_VALUE_TIME,
            .data.time = time
        };
    } else {
        form_datetime_t datetime = {0};
        if (!parse_date_text(&p, &datetime.date) || (*p != 'T' && *p != ' '))
            return 0;

        p++;

        if (!parse_time_text(&p, &datetime.time))
            return 0;

        if (*p == 'Z') {
            datetime.has_offset = 1;
            p++;
        }
        else if (*p == '+' || *p == '-') {
            int sign = *p++ == '+' ? 1 : -1;
            int hours, minutes;
            if (!fixed_number(&p, 2, &hours) || *p++ != ':' ||
                !fixed_number(&p, 2, &minutes) || hours > 23 || minutes > 59)
                return 0;

            datetime.has_offset = 1;
            datetime.offset_minutes = sign * (hours * 60 + minutes);
        }

        if (*p)
            return 0;

        *value = (form_value_t){
            .kind = FORM_VALUE_DATETIME,
            .data.datetime = datetime
        };
    }

    return 1;
}

static int parse_uuid(const form_input_t* input, form_value_t* value) {
    if (input->kind != FORM_INPUT_TEXT || input->data.text == NULL)
        return 0;

    const char* p = input->data.text;
    size_t length = strlen(p);
    if (length != 36 && length != 32)
        return 0;

    form_uuid_t uuid;
    for (size_t i = 0; i < 16; i++) {
        if (length == 36 && (i == 4 || i == 6 || i == 8 || i == 10)) {
            if (*p++ != '-')
                return 0;
        }

        int hi = hex_char_to_int(*p++);
        int lo = hex_char_to_int(*p++);
        if (hi < 0 || lo < 0)
            return 0;

        uuid.bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    *value = (form_value_t){
        .kind = FORM_VALUE_UUID,
        .data.uuid = uuid
    };

    return 1;
}

static int in_choices(const char* text, const char* const* choices, size_t count) {
    for (size_t i = 0; i < count; i++)
        if (strcmp(text, choices[i]) == 0)
            return 1;

    return 0;
}

static int filepath_valid(const form_filepath_field_t* spec, const char* name) {
    /* Only a single name inside directory. '*' is rejected because
     * storage_file_get treats it as a glob pattern on a filesystem storage. */
    if (*name == 0 || strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        strchr(name, '/') != NULL || strchr(name, '*') != NULL)
        return 0;

    const char* directory = spec->directory != NULL ? spec->directory : "";
    size_t directory_length = strlen(directory);
    while (directory_length > 0 && directory[directory_length - 1] == '/')
        directory_length--;

    /* storage builds the path in a PATH_MAX buffer: a truncated path could
     * name a different entry. */
    if (directory_length + 1 + strlen(name) >= PATH_MAX)
        return 0;

    storage_entry_e type = directory_length > 0
        ? storage_entry_type(spec->storage, "%.*s/%s", (int)directory_length, directory, name)
        : storage_entry_type(spec->storage, "%s", name);

    return (spec->allow_files && type == STORAGE_ENTRY_FILE) ||
           (spec->allow_directories && type == STORAGE_ENTRY_DIRECTORY);
}

static void input_free(form_input_t* input) {
    if (input->kind == FORM_INPUT_TEXT)
        free(input->data.text);
    else if (input->kind == FORM_INPUT_OBJECT && input->destroy != NULL && input->data.object != NULL)
        input->destroy(input->data.object);
    else if (input->kind == FORM_INPUT_TEXT_LIST) {
        if (input->data.text_list.items != NULL)
            for (size_t i = 0; i < input->data.text_list.count; i++)
                free(input->data.text_list.items[i]);

        free(input->data.text_list.items);
    }
}

static void inputs_free(const form_input_t inputs[], size_t count) {
    for (size_t i = 0; i < count; i++) {
        form_input_t input = inputs[i];
        input_free(&input);
    }
}

static const form_field_common_t* field_common(const form_field_spec_t* spec) {
    switch (spec->kind) {
    case FORM_FIELD_TEXT: return &spec->text.common;
    case FORM_FIELD_INTEGER: return &spec->integer.common;
    case FORM_FIELD_DECIMAL: return &spec->decimal.common;
    case FORM_FIELD_BOOLEAN: return &spec->boolean.common;
    case FORM_FIELD_OBJECT: return &spec->object.common;
    case FORM_FIELD_CUSTOM: return &spec->custom.common;
    case FORM_FIELD_DATE: return &spec->date.common;
    case FORM_FIELD_TIME: return &spec->time.common;
    case FORM_FIELD_DATETIME: return &spec->datetime.common;
    case FORM_FIELD_UUID: return &spec->uuid.common;
    case FORM_FIELD_JSON: return &spec->json.common;
    case FORM_FIELD_CHOICE: return &spec->choice.common;
    case FORM_FIELD_FILEPATH: return &spec->filepath.common;
    case FORM_FIELD_FILE: return &spec->file.common;
    case FORM_FIELD_MULTIPLE_CHOICE: return &spec->multiple_choice.common;
    default: return NULL;
    }
}

static int field_clean_flags(const form_field_spec_t* spec) {
    switch (spec->kind) {
    case FORM_FIELD_TEXT: return spec->text.clean_flags;
    case FORM_FIELD_INTEGER: return spec->integer.clean_flags;
    case FORM_FIELD_DECIMAL: return spec->decimal.clean_flags;
    case FORM_FIELD_BOOLEAN: return spec->boolean.clean_flags;
    case FORM_FIELD_CUSTOM: return spec->custom.clean_flags;
    case FORM_FIELD_DATE: return spec->date.clean_flags;
    case FORM_FIELD_TIME: return spec->time.clean_flags;
    case FORM_FIELD_DATETIME: return spec->datetime.clean_flags;
    case FORM_FIELD_UUID: return spec->uuid.clean_flags;
    case FORM_FIELD_JSON: return spec->json.clean_flags;
    case FORM_FIELD_CHOICE: return spec->choice.clean_flags;
    case FORM_FIELD_FILEPATH: return spec->filepath.clean_flags;
    case FORM_FIELD_MULTIPLE_CHOICE: return spec->multiple_choice.clean_flags;
    default: return 0;
    }
}

static int field_default(const form_field_spec_t* spec, form_value_t* value) {
    switch (spec->kind) {
    case FORM_FIELD_TEXT:
        if (spec->text.default_value == NULL)
            return 0;

        *value = (form_value_t){
            .kind = FORM_VALUE_TEXT,
            .data.text = spec->text.default_value
        };
        return 1;
    case FORM_FIELD_INTEGER:
        if (!spec->integer.has_default)
            return 0;

        *value = (form_value_t){
            .kind = FORM_VALUE_INTEGER,
            .data.integer = spec->integer.default_value
        };
        return 1;
    case FORM_FIELD_DECIMAL:
        if (!spec->decimal.has_default)
            return 0;

        *value = (form_value_t){
            .kind = FORM_VALUE_DECIMAL,
            .data.decimal = spec->decimal.default_value
        };
        return 1;
    case FORM_FIELD_BOOLEAN:
        if (!spec->boolean.has_default)
            return 0;

        *value = (form_value_t){
            .kind = FORM_VALUE_BOOLEAN,
            .data.boolean = spec->boolean.default_value
        };
        return 1;
    case FORM_FIELD_OBJECT:
        if (spec->object.default_value == NULL)
            return 0;

        *value = (form_value_t){
            .kind = FORM_VALUE_OBJECT,
            .data.object = spec->object.default_value
        };
        return 1;
    case FORM_FIELD_CUSTOM:
        if (spec->custom.default_value == NULL)
            return 0;

        *value = *spec->custom.default_value;
        value->destroy = NULL;
        return 1;
    case FORM_FIELD_DATE:
        if (!spec->date.has_default) return 0;
        *value = (form_value_t){
            .kind = FORM_VALUE_DATE,
            .data.date = spec->date.default_value
        };
        return 1;
    case FORM_FIELD_TIME:
        if (!spec->time.has_default) return 0;
        *value = (form_value_t){
            .kind = FORM_VALUE_TIME,
            .data.time = spec->time.default_value
        };
        return 1;
    case FORM_FIELD_DATETIME:
        if (!spec->datetime.has_default) return 0;
        *value = (form_value_t){
            .kind = FORM_VALUE_DATETIME,
            .data.datetime = spec->datetime.default_value
        };
        return 1;
    case FORM_FIELD_UUID:
        if (!spec->uuid.has_default) return 0;
        *value = (form_value_t){
            .kind = FORM_VALUE_UUID,
            .data.uuid = spec->uuid.default_value
        };
        return 1;
    case FORM_FIELD_JSON:
        if (spec->json.default_value == NULL) return 0;
        *value = (form_value_t){
            .kind = FORM_VALUE_OBJECT,
            .data.object = spec->json.default_value
        };
        return 1;
    case FORM_FIELD_CHOICE:
        if (spec->choice.default_value == NULL) return 0;
        *value = (form_value_t){
            .kind = FORM_VALUE_TEXT,
            .data.text = spec->choice.default_value
        };
        return 1;
    case FORM_FIELD_FILEPATH:
        if (spec->filepath.default_value == NULL) return 0;
        *value = (form_value_t){
            .kind = FORM_VALUE_TEXT,
            .data.text = spec->filepath.default_value
        };
        return 1;
    case FORM_FIELD_FILE:
        if (spec->file.default_value == NULL) return 0;
        *value = (form_value_t){
            .kind = FORM_VALUE_OBJECT,
            .data.object = spec->file.default_value
        };
        return 1;
    case FORM_FIELD_MULTIPLE_CHOICE:
        *value = (form_value_t){
            .kind = FORM_VALUE_TEXT_LIST,
            .data.text_list = {
                spec->multiple_choice.default_values,
                spec->multiple_choice.default_values_count
            }
        };
        return 1;
    default:
        return 0;
    }
}

static int spec_valid(const form_schema_t* schema, const form_field_spec_t* spec) {
    const form_field_common_t* common = field_common(spec);

    if (common == NULL || common->name == NULL ||
        (common->validators_count > 0 && common->validators == NULL))
        return 0;

    switch (spec->kind) {
    case FORM_FIELD_TEXT:
        return spec->text.max_length == 0 ||
               spec->text.min_length <= spec->text.max_length;
    case FORM_FIELD_INTEGER:
        return !spec->integer.has_min_value ||
               !spec->integer.has_max_value ||
               spec->integer.min_value <= spec->integer.max_value;
    case FORM_FIELD_DECIMAL:
        return (!spec->decimal.has_default ||
                isfinite(spec->decimal.default_value)) &&
               (!spec->decimal.has_min_value ||
                isfinite(spec->decimal.min_value)) &&
               (!spec->decimal.has_max_value ||
                isfinite(spec->decimal.max_value)) &&
               (!spec->decimal.has_min_value ||
                !spec->decimal.has_max_value ||
                spec->decimal.min_value <= spec->decimal.max_value);
    case FORM_FIELD_BOOLEAN:
        return !spec->boolean.has_default ||
               spec->boolean.default_value == 0 ||
               spec->boolean.default_value == 1;
    case FORM_FIELD_OBJECT:
        return 1;
    case FORM_FIELD_CUSTOM:
        return spec->custom.parse != NULL;
    case FORM_FIELD_DATE:
        return !spec->date.has_default || valid_date(spec->date.default_value);
    case FORM_FIELD_TIME:
        return !spec->time.has_default || valid_time(spec->time.default_value);
    case FORM_FIELD_DATETIME:
        return !spec->datetime.has_default ||
               valid_datetime(spec->datetime.default_value);
    case FORM_FIELD_UUID:
    case FORM_FIELD_JSON:
        return 1;
    case FORM_FIELD_CHOICE:
        if (spec->choice.choices_count && !spec->choice.choices)
            return 0;

        for (size_t i = 0; i < spec->choice.choices_count; i++)
            if (!spec->choice.choices[i])
                return 0;

        return 1;
    case FORM_FIELD_FILEPATH:
        return spec->filepath.storage != NULL &&
               (spec->filepath.allow_files || spec->filepath.allow_directories);
    case FORM_FIELD_FILE:
        return 1;
    case FORM_FIELD_MULTIPLE_CHOICE:
        if (spec->multiple_choice.choices_count && !spec->multiple_choice.choices)
            return 0;

        for (size_t i = 0; i < spec->multiple_choice.choices_count; i++)
            if (!spec->multiple_choice.choices[i])
                return 0;

        if (spec->multiple_choice.default_values_count && !spec->multiple_choice.default_values)
            return 0;

        for (size_t i = 0; i < spec->multiple_choice.default_values_count; i++)
            if (!spec->multiple_choice.default_values[i])
                return 0;

        return 1;
    default:
        return 0;
    }
}

form_t* form_create(const form_schema_t* schema, const form_input_t inputs[]) {
    if (schema == NULL || schema->fields_count == 0 || inputs == NULL)
        return NULL;

    if (schema->fields == NULL)
        goto invalid_schema;

    for (size_t i = 0; i < schema->fields_count; i++) {
        const form_field_spec_t* spec = &schema->fields[i];
        if (!spec_valid(schema, spec))
            goto invalid_schema;

        const form_field_common_t* common = field_common(spec);
        for (size_t j = 0; j < common->validators_count; j++)
            if (common->validators[j].check == NULL)
                goto invalid_schema;
    }

    form_t* form = calloc(1, sizeof * form);
    form_field_t* fields = calloc(schema->fields_count, sizeof *fields);
    if (form == NULL || fields == NULL) {
        free(form);
        free(fields);
        goto invalid_schema;
    }

    form->schema = schema;
    form->fields = fields;
    for (size_t i = 0; i < schema->fields_count; i++)
        fields[i].input = inputs[i];

    for (size_t i = 0; i < schema->fields_count; i++) {
        const form_field_spec_t* spec = &schema->fields[i];
        if (spec->kind != FORM_FIELD_TEXT || spec->text.regex == NULL)
            continue;

        int error_code;
        PCRE2_SIZE error_offset;
        fields[i].regex = pcre2_compile((PCRE2_SPTR)spec->text.regex,
                                        PCRE2_ZERO_TERMINATED,
                                        PCRE2_UTF | PCRE2_UCP,
                                        &error_code, &error_offset, NULL);

        if (fields[i].regex == NULL) {
            form_free(form);
            return NULL;
        }
    }

    return form;

    invalid_schema:

    inputs_free(inputs, schema->fields_count);

    return NULL;
}

static int input_empty(const form_input_t* input) {
    if (input->kind == FORM_INPUT_TEXT)
        return input->data.text == NULL || *input->data.text == 0;

    if (input->kind == FORM_INPUT_TEXT_LIST)
        return input->data.text_list.count == 0;

    return input->kind == FORM_INPUT_OBJECT && input->data.object == NULL;
}

/* A schema that sets neither hook gets the core implementation: cstr_clean
 * gives clean_flags their meaning, and utf8_strlen counts the characters a
 * length rule is written in. A schema may still override either one. */
static char* schema_clean(const form_schema_t* schema, char* text, int flags) {
    return (schema->clean != NULL ? schema->clean : cstr_clean)(text, flags);
}

static size_t schema_length(const form_schema_t* schema, const char* text) {
    return (schema->length != NULL ? schema->length : utf8_strlen)(text);
}

static form_error_t value_error(const form_schema_t* schema, const form_field_spec_t* spec, const form_value_t* value, const form_field_t* field) {
    const form_field_common_t* common = field_common(spec);

    switch (spec->kind) {
    case FORM_FIELD_TEXT: {
        if (value->kind != FORM_VALUE_TEXT)
            return FORM_INVALID;

        if (spec->text.min_length > 0 || spec->text.max_length > 0) {
            size_t length = schema_length(schema, value->data.text);
            if (spec->text.min_length > 0 && length < spec->text.min_length)
                return FORM_MIN_LENGTH;
            if (spec->text.max_length > 0 && length > spec->text.max_length)
                return FORM_MAX_LENGTH;
        }
        if (field->regex != NULL) {
            pcre2_match_data* match_data = pcre2_match_data_create_from_pattern(field->regex, NULL);
            if (match_data == NULL)
                return FORM_INVALID;

            int result = pcre2_match(field->regex,
                                     (PCRE2_SPTR)value->data.text,
                                     strlen(value->data.text), 0, 0,
                                     match_data, NULL);
            pcre2_match_data_free(match_data);
            if (result == PCRE2_ERROR_NOMATCH)
                return FORM_REGEX;
            if (result < 0)
                return FORM_INVALID;
        }
        return FORM_VALID;
    }
    case FORM_FIELD_INTEGER:
        if (value->kind != FORM_VALUE_INTEGER)
            return FORM_INVALID;

        if (spec->integer.has_min_value && value->data.integer < spec->integer.min_value)
            return FORM_MIN_VALUE;

        if (spec->integer.has_max_value && value->data.integer > spec->integer.max_value)
            return FORM_MAX_VALUE;

        return FORM_VALID;
    case FORM_FIELD_DECIMAL:
        if (value->kind != FORM_VALUE_DECIMAL || !isfinite(value->data.decimal))
            return FORM_INVALID;

        if (spec->decimal.has_min_value && value->data.decimal < spec->decimal.min_value)
            return FORM_MIN_VALUE;

        if (spec->decimal.has_max_value && value->data.decimal > spec->decimal.max_value)
            return FORM_MAX_VALUE;

        return FORM_VALID;
    case FORM_FIELD_BOOLEAN:
        if (value->kind != FORM_VALUE_BOOLEAN)
            return FORM_INVALID;

        return common->required && !value->data.boolean ? FORM_REQUIRED : FORM_VALID;
    case FORM_FIELD_OBJECT:
        return value->kind == FORM_VALUE_OBJECT ? FORM_VALID : FORM_INVALID;
    case FORM_FIELD_CUSTOM:
        return FORM_VALID;
    case FORM_FIELD_DATE:
        return value->kind == FORM_VALUE_DATE && valid_date(value->data.date) ? FORM_VALID : FORM_INVALID;
    case FORM_FIELD_TIME:
        return value->kind == FORM_VALUE_TIME && valid_time(value->data.time) ? FORM_VALID : FORM_INVALID;
    case FORM_FIELD_DATETIME:
        return value->kind == FORM_VALUE_DATETIME && valid_datetime(value->data.datetime) ? FORM_VALID : FORM_INVALID;
    case FORM_FIELD_UUID:
        return value->kind == FORM_VALUE_UUID ? FORM_VALID : FORM_INVALID;
    case FORM_FIELD_JSON:
        return value->kind == FORM_VALUE_OBJECT && value->data.object != NULL ? FORM_VALID : FORM_INVALID;
    case FORM_FIELD_CHOICE:
        if (value->kind != FORM_VALUE_TEXT)
            return FORM_INVALID;

        return in_choices(value->data.text, spec->choice.choices, spec->choice.choices_count) ? FORM_VALID : FORM_INVALID_CHOICE;
    case FORM_FIELD_FILEPATH:
        if (value->kind != FORM_VALUE_TEXT)
            return FORM_INVALID;

        return filepath_valid(&spec->filepath, value->data.text) ? FORM_VALID : FORM_INVALID_CHOICE;
    case FORM_FIELD_FILE: {
        if (value->kind != FORM_VALUE_OBJECT || value->data.object == NULL)
            return FORM_INVALID;

        const file_content_t* file = value->data.object;
        struct stat st;
        if (!file->ok || file->fd < 0 || file->offset < 0 ||
            !memchr(file->filename, 0, sizeof file->filename) ||
            file->filename[0] == 0 || strchr(file->filename, '/') ||
            strchr(file->filename, '\\') ||
            fstat(file->fd, &st) != 0 || !S_ISREG(st.st_mode) ||
            file->offset > st.st_size ||
            file->size > (uintmax_t)(st.st_size - file->offset))
            return FORM_INVALID;

        if (!spec->file.allow_empty_file && file->size == 0)
            return FORM_EMPTY_FILE;
        if (spec->file.max_size && file->size > spec->file.max_size)
            return FORM_MAX_SIZE;
        if (spec->file.max_filename_length && strlen(file->filename) > spec->file.max_filename_length)
            return FORM_MAX_LENGTH;

        return FORM_VALID;
    }
    case FORM_FIELD_MULTIPLE_CHOICE:
        if (value->kind != FORM_VALUE_TEXT_LIST)
            return FORM_INVALID;

        if (value->data.text_list.count && !value->data.text_list.items)
            return FORM_INVALID;

        for (size_t i = 0; i < value->data.text_list.count; i++) {
            const char* item = value->data.text_list.items[i];
            if (!item || !in_choices(item, spec->multiple_choice.choices, spec->multiple_choice.choices_count))
                return FORM_INVALID_CHOICE;
        }

        return FORM_VALID;
    default:
        return FORM_INVALID;
    }
}

static void field_validate(form_t* form, size_t index) {
    const form_field_spec_t* spec = &form->schema->fields[index];
    const form_field_common_t* common = field_common(spec);
    form_field_t* field = &form->fields[index];
    form_input_t cleaned = field->input;

    if (cleaned.kind != FORM_INPUT_TEXT && cleaned.kind != FORM_INPUT_OBJECT && cleaned.kind != FORM_INPUT_TEXT_LIST) {
        field->error = FORM_INVALID;
        return;
    }

    if (cleaned.kind == FORM_INPUT_TEXT)
        cleaned.data.text = schema_clean(form->schema, cleaned.data.text, field_clean_flags(spec));

    /* clean() may return a pointer past the start of the buffer, while input
     * must keep the original pointers for free(): clean into a separate array. */
    if (cleaned.kind == FORM_INPUT_TEXT_LIST &&
        cleaned.data.text_list.count > 0 && cleaned.data.text_list.items != NULL) {
        size_t count = cleaned.data.text_list.count;
        char** items = realloc(field->cleaned_items, count * sizeof *items);
        if (items == NULL) {
            field->error = FORM_INVALID;
            return;
        }
        field->cleaned_items = items;
        int flags = field_clean_flags(spec);
        for (size_t i = 0; i < count; i++) {
            char* item = cleaned.data.text_list.items[i];
            items[i] = item != NULL ? schema_clean(form->schema, item, flags) : NULL;
        }
        cleaned.data.text_list.items = items;
    }

    if (input_empty(&cleaned)) {
        if (common->required) {
            field->error = FORM_REQUIRED;
            return;
        }
        if (!field_default(spec, &field->value))
            return;

        field->error = value_error(form->schema, spec, &field->value, field);
        if (field->error != FORM_VALID)
            return;

        goto validate_value;
    }

    form_parse_fn parse = NULL;
    switch (spec->kind) {
    case FORM_FIELD_TEXT:
        if (cleaned.kind != FORM_INPUT_TEXT)
            goto invalid;
    
        field->value = (form_value_t){
            .kind = FORM_VALUE_TEXT,
            .data.text = cleaned.data.text
        };
        break;
    case FORM_FIELD_INTEGER: parse = form_parse_integer; break;
    case FORM_FIELD_DECIMAL: parse = form_parse_decimal; break;
    case FORM_FIELD_BOOLEAN: parse = form_parse_boolean; break;
    case FORM_FIELD_OBJECT:
        if (cleaned.kind != FORM_INPUT_OBJECT)
            goto invalid;

        field->value = (form_value_t){
            .kind = FORM_VALUE_OBJECT,
            .data.object = cleaned.data.object
        };
        break;
    case FORM_FIELD_CUSTOM: parse = spec->custom.parse; break;
    case FORM_FIELD_DATE:
    case FORM_FIELD_TIME:
    case FORM_FIELD_DATETIME:
        if (!parse_temporal(&cleaned, &field->value, spec->kind))
            goto invalid;
        break;
    case FORM_FIELD_UUID:
        if (!parse_uuid(&cleaned, &field->value))
            goto invalid;
        break;
    case FORM_FIELD_JSON: {
        if (cleaned.kind != FORM_INPUT_TEXT)
            goto invalid;

        json_doc_t* doc = json_parse(cleaned.data.text);
        if (doc == NULL)
            goto invalid;

        if (json_root(doc) == NULL) {
            json_free(doc);
            goto invalid;
        }
        field->value = (form_value_t){
            .kind = FORM_VALUE_OBJECT,
            .data.object = doc,
            .destroy = json_value_free
        };
        break;
    }
    case FORM_FIELD_CHOICE:
    case FORM_FIELD_FILEPATH:
        if (cleaned.kind != FORM_INPUT_TEXT)
            goto invalid;

        field->value = (form_value_t){
            .kind = FORM_VALUE_TEXT,
            .data.text = cleaned.data.text
        };
        break;
    case FORM_FIELD_FILE:
        if (cleaned.kind != FORM_INPUT_OBJECT)
            goto invalid;

        field->value = (form_value_t){
            .kind = FORM_VALUE_OBJECT,
            .data.object = cleaned.data.object
        };
        break;
    case FORM_FIELD_MULTIPLE_CHOICE:
        if (cleaned.kind != FORM_INPUT_TEXT_LIST)
            goto invalid;

        field->value = (form_value_t){
            .kind = FORM_VALUE_TEXT_LIST,
            .data.text_list = {
                (const char* const*)cleaned.data.text_list.items,
                cleaned.data.text_list.count
            }
        };
        break;
    default: goto invalid;
    }
    if (parse != NULL) {
        if (!parse(&cleaned, &field->value, common->context)) {
            if (field->value.kind == FORM_VALUE_OBJECT && field->value.destroy != NULL)
                field->value.destroy(field->value.data.object);

            field->value = (form_value_t){0};
            goto invalid;
        }
    }
    field->error = value_error(form->schema, spec, &field->value, field);
    if (field->error != FORM_VALID)
        return;

    validate_value:

    for (size_t i = 0; i < common->validators_count; i++) {
        const form_validator_t* validator = &common->validators[i];
        if (!validator->check(&field->value, validator->context)) {
            field->error = FORM_INVALID;
            field->message = validator->message;
            return;
        }
    }

    return;

    invalid:

    field->error = FORM_INVALID;
}

int form_is_valid(form_t* form) {
    if (form == NULL) return 0;
    if (form->validated) return form->valid;
    if (form->validating_form) return 0;

    for (size_t i = 0; i < form->schema->fields_count; i++)
        field_validate(form, i);

    form->fields_validated = 1;
    form->validating_form = 1;
    if (form->schema->validate != NULL)
        form->schema->validate(form, form->schema->context);

    form->validating_form = 0;

    form->valid = form->non_field_error == NULL;
    for (size_t i = 0; i < form->schema->fields_count; i++)
        if (form->fields[i].error != FORM_VALID)
            form->valid = 0;

    form->validated = 1;

    return form->valid;
}

const form_value_t* form_field_value(const form_t* form, size_t index) {
    if (form == NULL || !form->fields_validated || index >= form->schema->fields_count ||
        form->fields[index].error != FORM_VALID)
        return NULL;

    return &form->fields[index].value;
}

const form_value_t* form_cleaned_data(const form_t* form, size_t index) {
    if (form == NULL || !form->validated || !form->valid)
        return NULL;

    return form_field_value(form, index);
}

int form_add_error(form_t* form, size_t index, form_error_t code, const char* message) {
    if (form == NULL || !form->validating_form || code == FORM_VALID ||
        index >= form->schema->fields_count ||
        form->fields[index].error != FORM_VALID)
        return 0;

    form->fields[index].error = code;
    form->fields[index].message = message;
    return 1;
}

int form_add_non_field_error(form_t* form, const char* message) {
    if (form == NULL || !form->validating_form || message == NULL || form->non_field_error != NULL)
        return 0;

    form->non_field_error = message;
    return 1;
}

form_error_t form_error_code(const form_t* form, size_t index) {
    if (form == NULL || !form->validated || index >= form->schema->fields_count)
        return FORM_VALID;

    return form->fields[index].error;
}

const char* form_error_message(const form_t* form, size_t index) {
    if (form == NULL || !form->validated || index >= form->schema->fields_count)
        return NULL;

    const form_field_t* field = &form->fields[index];
    if (field->message != NULL)
        return field->message;

    const form_field_spec_t* spec = &form->schema->fields[index];
    const form_field_common_t* common = field_common(spec);
    switch (field->error) {
    case FORM_REQUIRED: return common->required_message;
    case FORM_MIN_LENGTH:
        return spec->kind == FORM_FIELD_TEXT ? spec->text.min_length_message : NULL;
    case FORM_MAX_LENGTH:
        if (spec->kind == FORM_FIELD_TEXT) return spec->text.max_length_message;
        if (spec->kind == FORM_FIELD_FILE) return spec->file.max_filename_length_message;
        return NULL;
    case FORM_REGEX:
        return spec->kind == FORM_FIELD_TEXT ? spec->text.regex_message : NULL;
    case FORM_MIN_VALUE:
        if (spec->kind == FORM_FIELD_INTEGER)
            return spec->integer.min_value_message;
        if (spec->kind == FORM_FIELD_DECIMAL)
            return spec->decimal.min_value_message;
        return NULL;
    case FORM_MAX_VALUE:
        if (spec->kind == FORM_FIELD_INTEGER)
            return spec->integer.max_value_message;
        if (spec->kind == FORM_FIELD_DECIMAL)
            return spec->decimal.max_value_message;
        return NULL;
    case FORM_INVALID: return common->invalid_message;
    case FORM_INVALID_CHOICE:
        if (spec->kind == FORM_FIELD_CHOICE) return spec->choice.invalid_choice_message;
        if (spec->kind == FORM_FIELD_FILEPATH) return spec->filepath.invalid_choice_message;
        if (spec->kind == FORM_FIELD_MULTIPLE_CHOICE)
            return spec->multiple_choice.invalid_choice_message;
        return NULL;
    case FORM_MAX_SIZE:
        return spec->kind == FORM_FIELD_FILE ? spec->file.max_size_message : NULL;
    case FORM_EMPTY_FILE:
        return spec->kind == FORM_FIELD_FILE ? spec->file.empty_file_message : NULL;
    default: return NULL;
    }
}

const char* form_non_field_error(const form_t* form) {
    return form != NULL && form->validated ? form->non_field_error : NULL;
}

const char* form_field_name(const form_t* form, size_t index) {
    if (form == NULL || index >= form->schema->fields_count)
        return NULL;

    return field_common(&form->schema->fields[index])->name;
}

size_t form_fields_count(const form_t* form) {
    return form != NULL ? form->schema->fields_count : 0;
}

int form_parse_integer(const form_input_t* input, form_value_t* value, void* context) {
    (void)context;

    if (input == NULL || value == NULL || input->kind != FORM_INPUT_TEXT || input->data.text == NULL || *input->data.text == 0)
        return 0;

    errno = 0;
    char* end = NULL;
    long long number = strtoll(input->data.text, &end, 10);
    if (errno == ERANGE || end == input->data.text || *end != 0 || number < INT64_MIN || number > INT64_MAX)
        return 0;

    *value = (form_value_t){
        .kind = FORM_VALUE_INTEGER,
        .data.integer = (int64_t)number
    };
    return 1;
}

int form_parse_boolean(const form_input_t* input, form_value_t* value, void* context) {
    (void)context;

    if (input == NULL || value == NULL || input->kind != FORM_INPUT_TEXT || input->data.text == NULL)
        return 0;

    const char* text = input->data.text;
    int boolean = 0;
    if (strcmp(text, "true") == 0 || strcmp(text, "1") == 0)
        boolean = 1;
    else if (strcmp(text, "false") == 0 || strcmp(text, "0") == 0)
        boolean = 0;
    else
        return 0;

    *value = (form_value_t){
        .kind = FORM_VALUE_BOOLEAN,
        .data.boolean = boolean
    };
    return 1;
}

int form_parse_decimal(const form_input_t* input, form_value_t* value, void* context) {
    (void)context;

    if (input == NULL || value == NULL || input->kind != FORM_INPUT_TEXT ||
        input->data.text == NULL || *input->data.text == 0)
        return 0;

    errno = 0;
    char* end = NULL;
    long double number = strtold(input->data.text, &end);
    if (errno == ERANGE || end == input->data.text || *end != 0 || !isfinite(number))
        return 0;

    *value = (form_value_t){
        .kind = FORM_VALUE_DECIMAL,
        .data.decimal = number
    };
    return 1;
}

void form_free(form_t* form) {
    if (form == NULL) return;

    for (size_t i = 0; i < form->schema->fields_count; i++) {
        form_field_t* field = &form->fields[i];
        if (field->regex != NULL)
            pcre2_code_free(field->regex);

        if (field->value.kind == FORM_VALUE_OBJECT && field->value.destroy != NULL)
            field->value.destroy(field->value.data.object);

        input_free(&field->input);
        free(field->cleaned_items);
    }
    free(form->fields);
    free(form);
}
