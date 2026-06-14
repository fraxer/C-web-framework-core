#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <locale.h>
#include <pthread.h>

#include "db.h"
#include "log.h"
#include "array.h"
#include "appconfig.h"
#include "model.h"

static void __model_value_clear(mvalue_t* value, mtype_e type);
static void __model_value_free(mvalue_t* value, mtype_e type);
static int __model_fill(const int row, const int fields_count, mfield_t* first_field, dbresult_t* result);
static int __model_set_binary(mfield_t* field, const char* value, const size_t size);
static int __model_set_date(mfield_t* field, tm_t* value);
static int __model_allow_field_in_json(const char* field_name, char** display_fields);
static mfield_t __model_tmpfield_create(mfield_t* source_field);
static int __str_modify_add_symbols_before(str_t* str, char add_symbol, char before_symbol);
static json_token_t* __model_json_object_fields(mfield_t* first_field, int fields_count, char** display_fields);
static json_token_t* __json_clone(const json_token_t* src);
static json_token_t* __model_array_to_json(array_t* array);
static void __model_cell_init(mfield_t* cell, const mcolumn_t* col);
static void* __model_fill_one(void*(create_instance)(void), dbresult_t* result);
static array_t* __model_fill_array(void*(create_instance)(void), dbresult_t* result);

/* ---------------------------------------------------------------------------
 * Error contract (R7): thread-local "last status" + DB error text.
 *
 * Each public model operation resets the status to MODEL_OK on entry and sets
 * it at the point of failure. State is per-thread and lives only until the next
 * model operation in that thread, mirroring errno semantics.
 * ------------------------------------------------------------------------- */
static __thread model_status_e __model_status = MODEL_OK;
static __thread char __model_error[512];

static void __model_set_status(model_status_e status) {
    __model_status = status;
    if (status != MODEL_ERR_DB)
        __model_error[0] = '\0';
}

/* Record a DB failure together with the driver's error text (if any). */
static void __model_set_db_error(dbresult_t* result) {
    __model_status = MODEL_ERR_DB;

    const char* msg = dbresult_error(result);
    if (msg == NULL) {
        __model_error[0] = '\0';
        return;
    }

    const size_t n = sizeof(__model_error) - 1;
    strncpy(__model_error, msg, n);
    __model_error[n] = '\0';
}

model_status_e model_last_status(void) {
    return __model_status;
}

const char* model_last_error(void) {
    if (__model_status == MODEL_ERR_DB && __model_error[0] != '\0')
        return __model_error;

    return NULL;
}

/* Locale-independent numeric formatting.
   Numeric SQL literals and JSON numbers must always use '.' as the decimal
   separator. Under a locale such as ru_RU (LC_NUMERIC with ',') snprintf("%f")
   would emit a comma and corrupt both SQL and JSON. We format in a private
   "C" locale via uselocale(), which is thread-local and so safe under the
   framework's worker threads. */
static locale_t __c_locale = (locale_t)0;
static pthread_once_t __c_locale_once = PTHREAD_ONCE_INIT;

static void __c_locale_init(void) {
    __c_locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
}

static ssize_t __snprintf_c(char* buf, size_t n, const char* fmt, ...) {
    pthread_once(&__c_locale_once, __c_locale_init);

    locale_t old = (locale_t)0;
    if (__c_locale != (locale_t)0)
        old = uselocale(__c_locale);

    va_list args;
    va_start(args, fmt);
    ssize_t size = vsnprintf(buf, n, fmt, args);
    va_end(args);

    if (old != (locale_t)0)
        uselocale(old);

    return size;
}

/* Convert tm_t to struct tm for strftime/strptime calls */
struct tm tm_to_strtm(const tm_t* src) {
    struct tm dst = {
        .tm_sec = src->tm_sec, .tm_min = src->tm_min,
        .tm_hour = src->tm_hour, .tm_mday = src->tm_mday,
        .tm_mon = src->tm_mon, .tm_year = src->tm_year,
        .tm_wday = src->tm_wday, .tm_yday = src->tm_yday,
        .tm_isdst = src->tm_isdst,
        .tm_gmtoff = src->tm_gmtoff, .tm_zone = src->tm_zone
    };
    return dst;
}

/* Convert struct tm (from strptime) to tm_t, initializing tm_usec to 0 */
void strtm_to_tm(const struct tm* src, tm_t* dst) {
    dst->tm_sec = src->tm_sec; dst->tm_min = src->tm_min;
    dst->tm_hour = src->tm_hour; dst->tm_mday = src->tm_mday;
    dst->tm_mon = src->tm_mon; dst->tm_year = src->tm_year;
    dst->tm_wday = src->tm_wday; dst->tm_yday = src->tm_yday;
    dst->tm_isdst = src->tm_isdst;
    dst->tm_gmtoff = src->tm_gmtoff; dst->tm_zone = src->tm_zone;
    dst->tm_usec = 0;
}

int parse_usec(const char* str, const char** end) {
    long usec = 0;
    int digits = 0;

    while (*str >= '0' && *str <= '9' && digits < 6) {
        usec = usec * 10 + (*str - '0');
        digits++;
        str++;
    }
    while (digits < 6) {
        usec *= 10;
        digits++;
    }
    if (end)
        *end = str;

    return (int)usec;
}

int parse_tz_offset(const char* str, long* gmtoff) {
    if (*str == 'Z') { *gmtoff = 0; return 1; }
    if (*str != '+' && *str != '-') return 0;

    int sign = (*str == '-') ? -1 : 1;
    int hours = 0;
    int mins = 0;

    str++;

    if (sscanf(str, "%d:%d", &hours, &mins) >= 1) {
        *gmtoff = sign * (hours * 3600 + mins * 60);
        return 1;
    }

    return 0;
}

const char* strptime_flex(const char* value, struct tm* stm) {
    const char* r = strptime(value, "%Y-%m-%d %H:%M:%S", stm);
    if (r == NULL)
        r = strptime(value, "%Y-%m-%dT%H:%M:%S", stm);
    return r;
}

/* Parse datetime from strptime result, extract microseconds, return pointer past them */
const char* parse_datetime_rest(const char* rest, tm_t* tm) {
    while (*rest && *rest != '.' && *rest != '+' && *rest != '-' && *rest != 'Z')
        rest++;

    if (*rest == '.') {
        rest++;
        tm->tm_usec = parse_usec(rest, &rest);
    }

    return rest;
}

// Numeric types
void* field_create_bool(const char* field_name, short value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_BOOL;
    field->name = field_name;
    field->dirty = 0;
    field->value._short = value;
    field->value._string = NULL;
    field->oldvalue._short = 0;
    field->oldvalue._string = NULL;
    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 0;

    return field;
}

void* field_create_smallint(const char* field_name, short value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_SMALLINT;
    field->name = field_name;
    field->dirty = 0;
    field->value._short = value;
    field->value._string = NULL;
    field->oldvalue._short = 0;
    field->oldvalue._string = NULL;
    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 0;

    return field;
}

void* field_create_int(const char* field_name, int value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_INT;
    field->name = field_name;
    field->dirty = 0;
    field->value._int = value;
    field->value._string = NULL;
    field->oldvalue._int = 0;
    field->oldvalue._string = NULL;
    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 0;

    return field;
}

void* field_create_bigint(const char* field_name, long long value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_BIGINT;
    field->name = field_name;
    field->dirty = 0;
    field->value._bigint = value;
    field->value._string = NULL;
    field->oldvalue._bigint = 0;
    field->oldvalue._string = NULL;
    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 0;

    return field;
}

void* field_create_float(const char* field_name, float value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_FLOAT;
    field->name = field_name;
    field->dirty = 0;
    field->value._float = value;
    field->value._string = NULL;
    field->oldvalue._float = 0;
    field->oldvalue._string = NULL;
    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 0;

    return field;
}

void* field_create_double(const char* field_name, double value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_DOUBLE;
    field->name = field_name;
    field->dirty = 0;
    field->value._double = value;
    field->value._string = NULL;
    field->oldvalue._double = 0;
    field->oldvalue._string = NULL;
    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 0;

    return field;
}

void* field_create_decimal(const char* field_name, long double value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_DECIMAL;
    field->name = field_name;
    field->dirty = 0;
    field->value._ldouble = value;
    field->value._string = NULL;
    field->oldvalue._ldouble = 0;
    field->oldvalue._string = NULL;
    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 0;

    return field;
}

void* field_create_money(const char* field_name, double value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_MONEY;
    field->name = field_name;
    field->dirty = 0;
    field->value._double = value;
    field->value._string = NULL;
    field->oldvalue._double = 0;
    field->oldvalue._string = NULL;
    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 0;

    return field;
}

// Date/Time types
void* field_create_date(const char* field_name, tm_t* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_DATE;
    field->name = field_name;
    field->dirty = 0;
    if (value == NULL)
        memset(&field->value._tm, 0, sizeof(tm_t));
    else
        memcpy(&field->value._tm, value, sizeof(tm_t));
    field->value._string = NULL;
    field->oldvalue._tm = (tm_t){0};
    field->oldvalue._string = NULL;
    field->is_null = value == NULL ? 1 : 0;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

void* field_create_time(const char* field_name, tm_t* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_TIME;
    field->name = field_name;
    field->dirty = 0;
    if (value == NULL)
        memset(&field->value._tm, 0, sizeof(tm_t));
    else
        memcpy(&field->value._tm, value, sizeof(tm_t));
    field->value._string = NULL;
    field->oldvalue._tm = (tm_t){0};
    field->oldvalue._string = NULL;
    field->is_null = value == NULL ? 1 : 0;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

void* field_create_timetz(const char* field_name, tm_t* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_TIMETZ;
    field->name = field_name;
    field->dirty = 0;
    if (value == NULL)
        memset(&field->value._tm, 0, sizeof(tm_t));
    else
        memcpy(&field->value._tm, value, sizeof(tm_t));
    field->value._string = NULL;
    field->oldvalue._tm = (tm_t){0};
    field->oldvalue._string = NULL;
    field->is_null = value == NULL ? 1 : 0;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

void* field_create_timestamp(const char* field_name, tm_t* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_TIMESTAMP;
    field->name = field_name;
    field->dirty = 0;
    if (value == NULL)
        memset(&field->value._tm, 0, sizeof(tm_t));
    else
        memcpy(&field->value._tm, value, sizeof(tm_t));
    field->value._string = NULL;
    field->oldvalue._tm = (tm_t){0};
    field->oldvalue._string = NULL;
    field->is_null = value == NULL ? 1 : 0;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

void* field_create_timestamptz(const char* field_name, tm_t* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_TIMESTAMPTZ;
    field->name = field_name;
    field->dirty = 0;
    if (value == NULL)
        memset(&field->value._tm, 0, sizeof(tm_t));
    else
        memcpy(&field->value._tm, value, sizeof(tm_t));
    field->value._string = NULL;
    field->oldvalue._tm = (tm_t){0};
    field->oldvalue._string = NULL;
    field->is_null = value == NULL ? 1 : 0;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

// JSON
void* field_create_json(const char* field_name, json_doc_t* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_JSON;
    field->name = field_name;
    field->dirty = 0;
    field->value._jsondoc = value;
    field->value._string = NULL;
    field->oldvalue._jsondoc = NULL;
    field->oldvalue._string = NULL;
    field->is_null = value == NULL ? 1 : 0;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

// String types
void* field_create_binary(const char* field_name, const char* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_BINARY;
    field->name = field_name;
    field->dirty = 0;
    field->value._string = str_create(value != NULL ? value : "");
    if (field->value._string == NULL) {
        free(field);
        return NULL;
    }
    field->value._short = 0;
    field->oldvalue._short = 0;
    field->oldvalue._string = NULL;
    field->is_null = value == NULL ? 1 : 0;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

void* field_create_varchar(const char* field_name, const char* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_VARCHAR;
    field->name = field_name;
    field->dirty = 0;
    field->value._string = str_create(value != NULL ? value : "");
    if (field->value._string == NULL) {
        free(field);
        return NULL;
    }
    field->value._short = 0;
    field->oldvalue._short = 0;
    field->oldvalue._string = NULL;
    field->is_null = value == NULL ? 1 : 0;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

void* field_create_char(const char* field_name, const char* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_CHAR;
    field->name = field_name;
    field->dirty = 0;
    field->value._string = str_create(value != NULL ? value : "");
    if (field->value._string == NULL) {
        free(field);
        return NULL;
    }
    field->value._short = 0;
    field->oldvalue._short = 0;
    field->oldvalue._string = NULL;
    field->is_null = value == NULL ? 1 : 0;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

void* field_create_text(const char* field_name, const char* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_TEXT;
    field->name = field_name;
    field->dirty = 0;
    field->value._string = str_create(value != NULL ? value : "");
    if (field->value._string == NULL) {
        free(field);
        return NULL;
    }
    field->value._short = 0;
    field->oldvalue._short = 0;
    field->oldvalue._string = NULL;
    field->is_null = value != NULL ? 0 : 1;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

// Enum
void* field_create_enum(const char* field_name, const char* default_value, char** values, int count) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    // Create enums structure
    enums_t* enums = enums_create(values, count);
    if (enums == NULL) {
        free(field);
        return NULL;
    }

    field->type = MODEL_ENUM;
    field->name = field_name;
    field->dirty = 0;
    field->value._enum = enums;
    field->value._string = str_create(default_value != NULL ? default_value : "");
    if (field->value._string == NULL) {
        enums_free(enums);
        free(field);
        return NULL;
    }
    field->oldvalue._enum = NULL;
    field->oldvalue._string = NULL;
    field->is_null = default_value == NULL ? 1 : 0;
    field->use_raw_sql = default_value == NULL ? 1 : 0;

    return field;
}

// Array
void* field_create_array(const char* field_name, array_t* value) {
    mfield_t* field = malloc(sizeof * field);
    if (field == NULL) return NULL;

    field->type = MODEL_ARRAY;
    field->name = field_name;
    field->dirty = 0;
    field->value._array = value;
    field->value._string = NULL;
    field->oldvalue._array = NULL;
    field->oldvalue._string = NULL;
    field->is_null = value == NULL ? 1 : 0;
    field->use_raw_sql = value == NULL ? 1 : 0;

    return field;
}

short model_bool(mfield_t* field) {
    if (field == NULL) return 0;
    if (field->type != MODEL_BOOL) return 0;

    return field->value._short;
}

short model_smallint(mfield_t* field) {
    if (field == NULL) return 0;
    if (field->type != MODEL_SMALLINT) return 0;

    return field->value._short;
}

int model_int(mfield_t* field) {
    if (field == NULL) return 0;
    if (field->type != MODEL_INT) return 0;

    return field->value._int;
}

long long int model_bigint(mfield_t* field) {
    if (field == NULL) return 0;
    if (field->type != MODEL_BIGINT) return 0;

    return field->value._bigint;
}

float model_float(mfield_t* field) {
    if (field == NULL) return 0.0;
    if (field->type != MODEL_FLOAT) return 0.0;

    return field->value._float;
}

double model_double(mfield_t* field) {
    if (field == NULL) return 0.0;
    if (field->type != MODEL_DOUBLE) return 0.0;

    return field->value._double;
}

long double model_decimal(mfield_t* field) {
    if (field == NULL) return 0.0;
    if (field->type != MODEL_DECIMAL) return 0.0;

    return field->value._ldouble;
}

double model_money(mfield_t* field) {
    if (field == NULL) return 0.0;
    if (field->type != MODEL_MONEY) return 0.0;

    return field->value._double;
}

tm_t model_timestamp(mfield_t* field) {
    if (field == NULL) return (tm_t){0};
    if (field->type != MODEL_TIMESTAMP) return (tm_t){0};

    return field->value._tm;
}

tm_t model_timestamptz(mfield_t* field) {
    if (field == NULL) return(tm_t){0};
    if (field->type != MODEL_TIMESTAMPTZ) return (tm_t){0};

    return field->value._tm;
}

tm_t model_date(mfield_t* field) {
    if (field == NULL) return (tm_t){0};
    if (field->type != MODEL_DATE) return (tm_t){0};

    return field->value._tm;
}

tm_t model_time(mfield_t* field) {
    if (field == NULL) return (tm_t){0};
    if (field->type != MODEL_TIME) return (tm_t){0};

    return field->value._tm;
}

tm_t model_timetz(mfield_t* field) {
    if (field == NULL) return (tm_t){0};
    if (field->type != MODEL_TIMETZ) return (tm_t){0};

    return field->value._tm;
}

json_doc_t* model_json(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_JSON) return NULL;

    return field->value._jsondoc;
}

str_t* model_binary(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_BINARY) return NULL;

    return field->value._string;
}

str_t* model_varchar(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_VARCHAR) return NULL;

    return field->value._string;
}

str_t* model_char(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_CHAR) return NULL;

    return field->value._string;
}

str_t* model_text(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_TEXT) return NULL;

    return field->value._string;
}

str_t* model_enum(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_ENUM) return NULL;

    return field->value._string;
}

array_t* model_array(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_ARRAY) return NULL;

    return field->value._array;
}

int model_set_bool(mfield_t* field, short value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_BOOL) return 0;

    if (!field->dirty) {
        field->oldvalue._short = field->value._short;
        field->dirty = 1;
    }

    field->value._short = value;
    field->is_null = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

int model_set_smallint(mfield_t* field, short value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_SMALLINT) return 0;

    if (!field->dirty) {
        field->oldvalue._short = field->value._short;
        field->dirty = 1;
    }

    field->value._short = value;
    field->is_null = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

int model_set_int(mfield_t* field, int value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_INT) return 0;

    if (!field->dirty) {
        field->oldvalue._int = field->value._int;
        field->dirty = 1;
    }

    field->value._int = value;
    field->is_null = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

int model_set_bigint(mfield_t* field, long long int value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_BIGINT) return 0;

    if (!field->dirty) {
        field->oldvalue._bigint = field->value._bigint;
        field->dirty = 1;
    }

    field->value._bigint = value;
    field->is_null = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

int model_set_float(mfield_t* field, float value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_FLOAT) return 0;

    if (!field->dirty) {
        field->oldvalue._float = field->value._float;
        field->dirty = 1;
    }

    field->value._float = value;
    field->is_null = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

int model_set_double(mfield_t* field, double value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_DOUBLE) return 0;

    if (!field->dirty) {
        field->oldvalue._double = field->value._double;
        field->dirty = 1;
    }

    field->value._double = value;
    field->is_null = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

int model_set_decimal(mfield_t* field, long double value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_DECIMAL) return 0;

    if (!field->dirty) {
        field->oldvalue._ldouble = field->value._ldouble;
        field->dirty = 1;
    }

    field->value._ldouble = value;
    field->is_null = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

int model_set_money(mfield_t* field, double value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_MONEY) return 0;

    if (!field->dirty) {
        field->oldvalue._double = field->value._double;
        field->dirty = 1;
    }

    field->value._double = value;
    field->is_null = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

int model_set_timestamp(mfield_t* field, tm_t* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TIMESTAMP) return 0;

    return __model_set_date(field, value);
}

int model_set_timestamp_now(mfield_t* field) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TIMESTAMP) return 0;

    if (!field->dirty) {
        field->oldvalue._tm = field->value._tm;
        field->dirty = 1;
    }

    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 1;

    if (field->value._string == NULL)
        field->value._string = str_createn("NOW()", 5);
    else
        str_assign(field->value._string, "NOW()", 5);

    return field->value._string != NULL;
}

int model_set_timestamptz(mfield_t* field, tm_t* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TIMESTAMPTZ) return 0;

    return __model_set_date(field, value);
}

int model_set_timestamptz_now(mfield_t* field) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TIMESTAMPTZ) return 0;

    if (!field->dirty) {
        field->oldvalue._tm = field->value._tm;
        field->dirty = 1;
    }

    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 1;

    if (field->value._string == NULL)
        field->value._string = str_createn("NOW()", 5);
    else
        str_assign(field->value._string, "NOW()", 5);

    return field->value._string != NULL;
}

int model_set_date(mfield_t* field, tm_t* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_DATE) return 0;

    return __model_set_date(field, value);
}

int model_set_time(mfield_t* field, tm_t* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TIME) return 0;

    return __model_set_date(field, value);
}

int model_set_timetz(mfield_t* field, tm_t* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TIMETZ) return 0;

    return __model_set_date(field, value);
}

int model_set_json(mfield_t* field, json_doc_t* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_JSON) return 0;

    if (!field->dirty) {
        field->oldvalue._jsondoc = field->value._jsondoc;
        field->value._jsondoc = NULL;
        field->dirty = 1;
    }

    if (value == NULL) {
        field->is_null = 1;
        return 1;
    }

    json_free(field->value._jsondoc);

    json_doc_t* document = json_create_empty();
    if (document == NULL) return 0;

    if (!json_copy(value, document)) {
        json_free(document);
        return 0;
    }

    field->value._jsondoc = document;
    field->is_null = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

int model_set_binary(mfield_t* field, const char* value, const size_t size) {
    return model_set_binary_from_str(field, value, size);
}

int model_set_varchar(mfield_t* field, const char* value) {
    return model_set_varchar_from_str(field, value, value ? strlen(value) : 0);
}

int model_set_char(mfield_t* field, const char* value) {
    return model_set_char_from_str(field, value, value ? strlen(value) : 0);
}

int model_set_text(mfield_t* field, const char* value) {
    return model_set_text_from_str(field, value, value ? strlen(value) : 0);
}

int model_set_enum(mfield_t* field, const char* value) {
    return model_set_enum_from_str(field, value, value ? strlen(value) : 0);
}

int model_set_array(mfield_t* field, array_t* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_ARRAY) return 0;

    if (!field->dirty) {
        field->oldvalue._array = field->value._array;
        field->value._array = NULL;
        field->dirty = 1;
    }

    if (value == NULL) {
        field->is_null = 1;
        return 1;
    }

    field->value._array = value;
    field->is_null = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

int __model_set_binary(mfield_t* field, const char* value, const size_t size) {
    if (field == NULL) return 0;

    if (!field->dirty) {
        if (field->oldvalue._string == NULL)
            field->oldvalue._string = str_create_empty(256);

        if (field->oldvalue._string == NULL)
            return 0;

        str_move(field->value._string, field->oldvalue._string);
        field->dirty = 1;
    }

    if (!str_reset(field->value._string))
        return 0;

    if (value == NULL) {
        field->is_null = 1;
        return 1;
    }

    field->is_null = 0;
    field->use_raw_sql = 0;

    return str_assign(field->value._string, value, size);
}

int __model_set_date(mfield_t* field, tm_t* value) {
    if (field == NULL) return 0;

    if (!field->dirty) {
        field->oldvalue._tm = field->value._tm;
        field->dirty = 1;
    }

    if (value == NULL) {
        field->is_null = 1;
        return 1;
    }

    memcpy(&field->value._tm, value, sizeof(tm_t));
    field->is_null = 0;
    field->use_default = 0;
    field->use_raw_sql = 0;

    str_clear(field->value._string);

    return 1;
}

str_t* model_field_to_string(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->is_null) {
        field->use_raw_sql = 1;

        if (field->value._string == NULL)
            field->value._string = str_createn("NULL", 4);
        else
            str_assign(field->value._string, "NULL", 4);

        return field->value._string;
    }

    switch (field->type) {
    case MODEL_BOOL:
        return model_bool_to_str(field);
    case MODEL_SMALLINT:
        return model_smallint_to_str(field);
    case MODEL_INT:
        return model_int_to_str(field);
    case MODEL_BIGINT:
        return model_bigint_to_str(field);
    case MODEL_FLOAT:
        return model_float_to_str(field);
    case MODEL_DOUBLE:
        return model_double_to_str(field);
    case MODEL_DECIMAL:
        return model_decimal_to_str(field);
    case MODEL_MONEY:
        return model_money_to_str(field);
    case MODEL_DATE:
        return model_date_to_str(field);
    case MODEL_TIME:
        return model_time_to_str(field);
    case MODEL_TIMETZ:
        return model_timetz_to_str(field);
    case MODEL_TIMESTAMP:
        return model_timestamp_to_str(field);
    case MODEL_TIMESTAMPTZ:
        return model_timestamptz_to_str(field);
    case MODEL_JSON:
        return model_json_to_str(field);
    case MODEL_BINARY:
        return model_binary(field);
    case MODEL_VARCHAR:
        return model_varchar(field);
    case MODEL_CHAR:
        return model_char(field);
    case MODEL_TEXT:
        return model_text(field);
    case MODEL_ENUM:
        return model_enum(field);
    case MODEL_ARRAY:
        return model_array_to_str(field);
    }

    return NULL;
}

void __model_value_clear(mvalue_t* value, mtype_e type) {
    if (value == NULL) return;

    switch (type) {
    case MODEL_BOOL:
    case MODEL_SMALLINT:
    case MODEL_INT:
    case MODEL_BIGINT:
    case MODEL_FLOAT:
    case MODEL_DOUBLE:
    case MODEL_DECIMAL:
    case MODEL_MONEY:
        value->_short = 0;
        break;

    case MODEL_DATE:
    case MODEL_TIME:
    case MODEL_TIMETZ:
    case MODEL_TIMESTAMP:
    case MODEL_TIMESTAMPTZ:
        memset(&value->_tm, 0, sizeof(tm_t));
        break;

    case MODEL_JSON:
        json_clear(value->_jsondoc);
        break;

    case MODEL_ARRAY:
        break;

    default:
        break;
    }

    str_clear(value->_string);
}

void __model_value_free(mvalue_t* value, mtype_e type) {
    if (value == NULL) return;

    switch (type) {
    case MODEL_BOOL:
    case MODEL_SMALLINT:
    case MODEL_INT:
    case MODEL_BIGINT:
    case MODEL_FLOAT:
    case MODEL_DOUBLE:
    case MODEL_DECIMAL:
    case MODEL_MONEY:
        break;

    case MODEL_DATE:
    case MODEL_TIME:
    case MODEL_TIMETZ:
    case MODEL_TIMESTAMP:
    case MODEL_TIMESTAMPTZ:
        break;

    case MODEL_JSON:
        json_free(value->_jsondoc);
        break;

    case MODEL_ENUM:
        enums_free(value->_enum);
        break;

    case MODEL_ARRAY:
        array_free(value->_array);
        break;

    default:
        break;
    }

    str_free(value->_string);
    explicit_bzero(value, sizeof(mvalue_t));
}

int __model_fill(const int row, const int fields_count, mfield_t* first_field, dbresult_t* result) {
    for (int col = 0; col < dbresult_query_cols(result); col++) {
        const db_table_cell_t* field = dbresult_cell(result, row, col);

        for (int i = 0; i < fields_count; i++) {
            mfield_t* modelfield = first_field + i;
            if (modelfield == NULL)
                return 0;

            if (strcmp(modelfield->name, result->current->fields[col].value) == 0) {
                switch (modelfield->type) {
                case MODEL_BOOL:
                    if (!model_set_bool_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_SMALLINT:
                    if (!model_set_smallint_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_INT:
                    if (!model_set_int_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_BIGINT:
                    if (!model_set_bigint_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_FLOAT:
                    if (!model_set_float_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_DOUBLE:
                    if (!model_set_double_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_DECIMAL:
                    if (!model_set_decimal_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_MONEY:
                    if (!model_set_money_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_DATE:
                    if (!model_set_date_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_TIME:
                    if (!model_set_time_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_TIMETZ:
                    if (!model_set_timetz_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_TIMESTAMP:
                    if (!model_set_timestamp_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_TIMESTAMPTZ:
                    if (!model_set_timestamptz_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_JSON:
                    if (!model_set_json_from_str(modelfield, field->value))
                        return 0;
                    break;
                case MODEL_BINARY:
                    if (!model_set_binary_from_str(modelfield, field->value, field->length))
                        return 0;
                    break;
                case MODEL_VARCHAR:
                    if (!model_set_varchar_from_str(modelfield, field->value, field->length))
                        return 0;
                    break;
                case MODEL_CHAR:
                    if (!model_set_char_from_str(modelfield, field->value, field->length))
                        return 0;
                    break;
                case MODEL_TEXT:
                    if (!model_set_text_from_str(modelfield, field->value, field->length))
                        return 0;
                    break;
                case MODEL_ENUM:
                    if (!model_set_enum_from_str(modelfield, field->value, field->length))
                        return 0;
                    break;
                case MODEL_ARRAY:
                    if (!model_set_array_from_str(modelfield, field->value))
                        return 0;
                    break;
                default:
                    return 0;
                }

                modelfield->dirty = 0;
                
                break;
            }
        }
    }

    return 1;
}

int model_set_bool_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_BOOL) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }

    if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 || strcmp(value, "t") == 0)
        return model_set_bool(field, 1);
    else if (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 || strcmp(value, "f") == 0)
        return model_set_bool(field, 0);

    return 0;
}

int model_set_smallint_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }
    return model_set_smallint(field, (short)atoi(value));
}

int model_set_int_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }
    return model_set_int(field, atoi(value));
}

int model_set_bigint_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }
    return model_set_bigint(field, atoll(value));
}

int model_set_float_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }
    return model_set_float(field, (float)atof(value));
}

int model_set_double_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }
    return model_set_double(field, atof(value));
}

int model_set_decimal_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }
    return model_set_decimal(field, strtold(value, NULL));
}

int model_set_money_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }
    return model_set_money(field, atof(value));
}

int model_set_timestamp_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TIMESTAMP) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }

    struct tm stm = {0};
    const char* rest = strptime_flex(value, &stm);
    if (rest == NULL) return 0;

    tm_t tm = {0};
    strtm_to_tm(&stm, &tm);
    parse_datetime_rest(rest, &tm);

    return model_set_timestamp(field, &tm);
}

int model_set_timestamptz_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TIMESTAMPTZ) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }

    struct tm stm = {0};
    const char* rest = strptime_flex(value, &stm);
    if (rest == NULL) return 0;

    tm_t tm = {0};
    strtm_to_tm(&stm, &tm);
    tm.tm_isdst = 0;
    rest = parse_datetime_rest(rest, &tm);

    if (*rest == '+' || *rest == '-' || *rest == 'Z')
        parse_tz_offset(rest, &tm.tm_gmtoff);

    return model_set_timestamptz(field, &tm);
}

int model_set_date_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_DATE) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }

    struct tm stm = {0};
    if (strlen(value) > 0 && strptime(value, "%Y-%m-%d %H:%M:%S", &stm) == NULL)
        return 0;

    tm_t tm = {0};
    strtm_to_tm(&stm, &tm);

    return model_set_date(field, &tm);
}

int model_set_time_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TIME) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }

    struct tm stm = {0};
    const char* rest = strptime(value, "%H:%M:%S", &stm);
    if (rest == NULL) return 0;

    tm_t tm = {0};
    strtm_to_tm(&stm, &tm);
    parse_datetime_rest(rest, &tm);

    return model_set_time(field, &tm);
}

int model_set_timetz_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TIMETZ) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }

    struct tm stm = {0};
    const char* rest = strptime(value, "%H:%M:%S", &stm);
    if (rest == NULL) return 0;

    tm_t tm = {0};
    strtm_to_tm(&stm, &tm);
    tm.tm_isdst = 0;
    rest = parse_datetime_rest(rest, &tm);

    if (*rest == '+' || *rest == '-' || *rest == 'Z')
        parse_tz_offset(rest, &tm.tm_gmtoff);

    return model_set_timetz(field, &tm);
}

int model_set_json_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (field->type != MODEL_JSON) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }

    json_doc_t* document = json_parse(value);
    if (document == NULL) return 0;

    json_free(field->value._jsondoc);
    field->value._jsondoc = document;
    field->is_null = 0;
    field->use_raw_sql = 0;
    str_clear(field->value._string);

    return 1;
}

int model_set_binary_from_str(mfield_t* field, const char* value, size_t size) {
    if (field == NULL) return 0;
    if (field->type != MODEL_BINARY) return 0;

    return __model_set_binary(field, value, size);
}

int model_set_varchar_from_str(mfield_t* field, const char* value, size_t size) {
    if (field == NULL) return 0;
    if (field->type != MODEL_VARCHAR) return 0;

    return __model_set_binary(field, value, size);
}

int model_set_char_from_str(mfield_t* field, const char* value, size_t size) {
    if (field == NULL) return 0;
    if (field->type != MODEL_CHAR) return 0;

    return __model_set_binary(field, value, size);
}

int model_set_text_from_str(mfield_t* field, const char* value, size_t size) {
    if (field == NULL) return 0;
    if (field->type != MODEL_TEXT) return 0;

    return __model_set_binary(field, value, size);
}

int model_set_enum_from_str(mfield_t* field, const char* value, size_t size) {
    if (field == NULL) return 0;
    if (field->type != MODEL_ENUM) return 0;

    if (size == 0)
        return __model_set_binary(field, value, size);

    for (short i = 0; i < field->value._enum->count; i++)
        if (strcmp(field->value._enum->values[i], value) == 0)
            return __model_set_binary(field, value, size);

    return 0;
}

int model_set_array_from_str(mfield_t* field, const char* value) {
    if (field == NULL) return 0;
    if (value == NULL) { field->is_null = 1; return 1; }

    json_doc_t* document = json_parse(value);
    if (document == NULL) return 0;

    const json_token_t* token_array = json_root(document);
    if (!json_is_array(token_array)) {
        json_free(document);
        return 0;
    }

    array_t* array = array_create();
    if (array == NULL) {
        json_free(document);
        return 0;
    }

    for (json_it_t it_array = json_init_it(token_array); !json_end_it(&it_array); json_next_it(&it_array)) {
        json_token_t* token_value = json_it_value(&it_array);
        if (json_is_string(token_value)) {
            array_push_back(array, array_create_string(json_string(token_value)));
        } else if (json_is_number(token_value)) {
            array_push_back(array, array_create_ldouble(json_ldouble(token_value)));
        } else if (json_is_bool(token_value)) {
            array_push_back(array, array_create_ldouble(json_bool(token_value)));
        } else if (json_is_null(token_value)) {
            array_push_back(array, array_create_ldouble(0));
        }
        else {
            json_free(document);
            array_free(array);
            return 0;
        }
    }

    array_free(field->value._array);
    field->value._array = array;
    field->is_null = 0;
    field->use_raw_sql = 0;
    str_clear(field->value._string);

    json_free(document);

    return 1;
}

str_t* model_bool_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_BOOL) return NULL;

    char str[2] = {0};
    ssize_t size = snprintf(str, sizeof(str), "%d", model_bool(field));
    if (size < 0) return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(str, size);
    else
        str_assign(field->value._string, str, size);

    return field->value._string;
}

str_t* model_smallint_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_SMALLINT) return NULL;

    char str[7] = {0};
    ssize_t size = snprintf(str, sizeof(str), "%d", model_smallint(field));
    if (size < 0) return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(str, size);
    else
        str_assign(field->value._string, str, size);

    return field->value._string;
}

str_t* model_int_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_INT) return NULL;

    char str[12] = {0};
    ssize_t size = snprintf(str, sizeof(str), "%d", model_int(field));
    if (size < 0) return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(str, size);
    else
        str_assign(field->value._string, str, size);

    return field->value._string;
}

str_t* model_bigint_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_BIGINT) return NULL;

    char str[21] = {0};
    ssize_t size = snprintf(str, sizeof(str), "%lld", model_bigint(field));
    if (size < 0) return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(str, size);
    else
        str_assign(field->value._string, str, size);

    return field->value._string;
}

str_t* model_float_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_FLOAT) return NULL;

    char str[64] = {0};
    ssize_t size = __snprintf_c(str, sizeof(str), "%.6f", model_float(field));
    if (size < 0) return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(str, size);
    else
        str_assign(field->value._string, str, size);

    return field->value._string;
}

str_t* model_double_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_DOUBLE) return NULL;

    char str[375] = {0};
    ssize_t size = __snprintf_c(str, sizeof(str), "%.12f", model_double(field));
    if (size < 0) return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(str, size);
    else
        str_assign(field->value._string, str, size);

    return field->value._string;
}

str_t* model_decimal_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_DECIMAL) return NULL;

    char str[512] = {0};
    ssize_t size = __snprintf_c(str, sizeof(str), "%.12Lf", model_decimal(field));
    if (size < 0) return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(str, size);
    else
        str_assign(field->value._string, str, size);

    return field->value._string;
}

str_t* model_money_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_MONEY) return NULL;

    char str[375] = {0};
    ssize_t size = __snprintf_c(str, sizeof(str), "%.12f", model_money(field));
    if (size < 0) return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(str, size);
    else
        str_assign(field->value._string, str, size);

    return field->value._string;
}

str_t* model_timestamp_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_TIMESTAMP) return NULL;

    // Return raw SQL value if already set (e.g., NOW())
    if (field->value._string != NULL && str_size(field->value._string) > 0)
        return field->value._string;

    char value[64] = {0};
    size_t size = 0;

    if (field->value._tm.tm_year == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);

        size = strftime(value, sizeof(value), "%Y-%m-%dT%H:%M:%S", gmtime(&ts.tv_sec));
        size += sprintf(value + size, ".%06ld", ts.tv_nsec / 1000);
    }
    else {
        struct tm stm = tm_to_strtm(&field->value._tm);
        size = strftime(value, sizeof(value), "%Y-%m-%d %H:%M:%S", &stm);
        if (field->value._tm.tm_usec != 0)
            size += sprintf(value + size, ".%06d", field->value._tm.tm_usec);
    }

    if (size == 0)
        return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(value, size);
    else
        str_assign(field->value._string, value, size);

    return field->value._string;
}

str_t* model_timestamptz_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_TIMESTAMPTZ) return NULL;

    // Return raw SQL value if already set (e.g., NOW())
    if (field->value._string != NULL && str_size(field->value._string) > 0)
        return field->value._string;

    struct tm stm = tm_to_strtm(&field->value._tm);
    char value[48] = {0};
    size_t size = strftime(value, sizeof(value), "%Y-%m-%d %H:%M:%S", &stm);

    if (field->value._tm.tm_usec != 0)
        size += sprintf(value + size, ".%06d", field->value._tm.tm_usec);

    size += strftime(value + size, sizeof(value) - size, "%z", &stm);

    if (size == 0)
        return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(value, size);
    else
        str_assign(field->value._string, value, size);

    return field->value._string;
}

str_t* model_date_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_DATE) return NULL;

    struct tm stm = tm_to_strtm(&field->value._tm);
    char value[32] = {0};
    const size_t size = strftime(value, sizeof(value), "%Y-%m-%d %H:%M:%S", &stm);
    if (size == 0)
        return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(value, size);
    else
        str_assign(field->value._string, value, size);

    return field->value._string;
}

str_t* model_time_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_TIME) return NULL;

    struct tm stm = tm_to_strtm(&field->value._tm);
    char value[20] = {0};
    size_t size = strftime(value, sizeof(value), "%H:%M:%S", &stm);
    if (field->value._tm.tm_usec != 0)
        size += sprintf(value + size, ".%06d", field->value._tm.tm_usec);

    if (size == 0)
        return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(value, size);
    else
        str_assign(field->value._string, value, size);

    return field->value._string;
}

str_t* model_timetz_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_TIMETZ) return NULL;

    struct tm stm = tm_to_strtm(&field->value._tm);
    char value[32] = {0};
    size_t size = strftime(value, sizeof(value), "%H:%M:%S", &stm);

    if (field->value._tm.tm_usec != 0)
        size += sprintf(value + size, ".%06d", field->value._tm.tm_usec);

    size += strftime(value + size, sizeof(value) - size, "%z", &stm);

    if (size == 0)
        return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(value, size);
    else
        str_assign(field->value._string, value, size);

    return field->value._string;
}

str_t* model_json_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_JSON) return NULL;

    char* data = json_stringify_detach(field->value._jsondoc);
    if (data == NULL) return NULL;

    if (field->value._string == NULL)
        field->value._string = str_createn(data, strlen(data));
    else
        str_assign(field->value._string, data, strlen(data));

    free(data);

    return field->value._string;
}

str_t* model_array_to_str(mfield_t* field) {
    if (field == NULL) return NULL;
    if (field->type != MODEL_ARRAY) return NULL;

    array_t* array = field->value._array;
    str_t* string = str_create_empty(256);
    if (string == NULL) return NULL;

    str_appendc(string, '[');

    for (size_t i = 0; i < array_size(array); i++) {
        avalue_t* item = &array->elements[i];
        if (item->type == ARRAY_POINTER) continue;

        str_t* str = array_item_to_string(array, i);
        if (str == NULL) {
            str_free(string);
            return NULL;
        }

        if (i > 0)
            str_appendc(string, ',');

        __str_modify_add_symbols_before(str, '\\', '"');
        str_appendc(string, '\"');
        str_append(string, str_get(str), str_size(str));
        str_appendc(string, '\"');
        str_free(str);
    }

    str_appendc(string, ']');

    if (field->value._string == NULL)
        field->value._string = string;
    else {
        str_assign(field->value._string, str_get(string), str_size(string));
        str_free(string);
    }

    return field->value._string;
}

void model_param_clear(void* field) {
    mfield_t* _field = field;

    __model_value_free(&_field->value, _field->type);
    __model_value_free(&_field->oldvalue, _field->type);
}

void model_param_free(void* field) {
    model_param_clear(field);
    free(field);
}

void model_params_clear(void* params, const size_t size) {
    const size_t count_fields = size / sizeof(mfield_t);

    mfield_t* fields = params;
    for (size_t i = 0; i < count_fields; i++)
        model_param_clear(fields + i);
}

void model_params_free(void* params, const size_t size) {
    model_params_clear(params, size);
    free(params);
}

json_token_t* model_json_create_object(void* arg, char** display_fields) {
    return model_to_json(arg, display_fields);
}

/* Рекурсивный клон токена в standalone-токены (не привязанные к документу).
   Нужен потому, что токены json_parse-документа принадлежат memory-block
   аллокатору своего документа: их нельзя переподвесить в родительский объект
   модели (двойное освобождение / висячие ссылки при json_free документа). */
static json_token_t* __json_clone(const json_token_t* src) {
    if (src == NULL) return json_create_null();

    if (json_is_object(src)) {
        json_token_t* object = json_create_object();
        if (object == NULL) return NULL;

        for (json_it_t it = json_init_it(src); !json_end_it(&it); json_next_it(&it)) {
            const char* key = json_it_key(&it);
            json_token_t* value = __json_clone(json_it_value(&it));
            if (value == NULL || !json_object_set(object, key, value)) {
                json_token_free_tree(value);
                json_token_free_tree(object);
                return NULL;
            }
        }

        return object;
    }

    if (json_is_array(src)) {
        json_token_t* array = json_create_array();
        if (array == NULL) return NULL;

        for (json_it_t it = json_init_it(src); !json_end_it(&it); json_next_it(&it)) {
            json_token_t* value = __json_clone(json_it_value(&it));
            if (value == NULL || !json_array_append(array, value)) {
                json_token_free_tree(value);
                json_token_free_tree(array);
                return NULL;
            }
        }

        return array;
    }

    if (json_is_string(src))
        return json_create_string(json_string(src));
    if (json_is_number(src))
        return json_create_number(json_ldouble(src));
    if (json_is_bool(src))
        return json_create_bool(json_bool(src));

    return json_create_null();
}

/* Нативная JSON-сериализация массива модели: числа отдаются числами, строки —
   строками, без обёртывания всех элементов в кавычки (как делает model_array_to_str). */
static json_token_t* __model_array_to_json(array_t* array) {
    json_token_t* token_array = json_create_array();
    if (token_array == NULL) return NULL;

    if (array == NULL) return token_array;

    for (size_t i = 0; i < array_size(array); i++) {
        avalue_t* item = &array->elements[i];

        json_token_t* value = NULL;
        switch (item->type) {
        case ARRAY_INT:
            value = json_create_number(item->_int);
            break;
        case ARRAY_DOUBLE:
            value = json_create_number(item->_double);
            break;
        case ARRAY_LONGDOUBLE:
            value = json_create_number(item->_ldouble);
            break;
        case ARRAY_STRING:
            value = json_create_string(item->_string ? item->_string : "");
            break;
        case ARRAY_POINTER:
            continue;
        }

        if (value == NULL || !json_array_append(token_array, value)) {
            json_token_free_tree(value);
            json_token_free_tree(token_array);
            return NULL;
        }
    }

    return token_array;
}

static json_token_t* __model_json_object_fields(mfield_t* first_field, int fields_count, char** display_fields) {
    int result = 0;
    json_token_t* object = json_create_object();
    if (object == NULL) return NULL;

    for (int i = 0; i < fields_count; i++) {
        mfield_t* field = first_field + i;

        if (!__model_allow_field_in_json(field->name, display_fields))
            continue;

        json_token_t* token_value = NULL;

        if (field->is_null)
            token_value = json_create_null();
        else switch (field->type) {
        case MODEL_BOOL:
            token_value = json_create_bool(model_bool(field));
            break;
        case MODEL_SMALLINT:
            token_value = json_create_number(model_smallint(field));
            break;
        case MODEL_INT:
            token_value = json_create_number(model_int(field));
            break;
        case MODEL_BIGINT:
            token_value = json_create_number(model_bigint(field));
            break;
        case MODEL_FLOAT:
            token_value = json_create_number(model_float(field));
            break;
        case MODEL_DOUBLE:
            token_value = json_create_number(model_double(field));
            break;
        case MODEL_DECIMAL:
            token_value = json_create_number(model_decimal(field));
            break;
        case MODEL_MONEY:
            token_value = json_create_number(model_double(field));
            break;
        case MODEL_DATE:
            token_value = json_create_string(str_get(model_date_to_str(field)));
            break;
        case MODEL_TIME:
            token_value = json_create_string(str_get(model_time_to_str(field)));
            break;
        case MODEL_TIMETZ:
            token_value = json_create_string(str_get(model_timetz_to_str(field)));
            break;
        case MODEL_TIMESTAMP:
            token_value = json_create_string(str_get(model_timestamp_to_str(field)));
            break;
        case MODEL_TIMESTAMPTZ:
            token_value = json_create_string(str_get(model_timestamptz_to_str(field)));
            break;
        case MODEL_JSON:
            token_value = field->value._jsondoc != NULL
                ? __json_clone(json_root(field->value._jsondoc))
                : json_create_null();
            break;
        case MODEL_BINARY:
            token_value = json_create_string(str_get(model_binary(field)));
            break;
        case MODEL_VARCHAR:
            token_value = json_create_string(str_get(model_varchar(field)));
            break;
        case MODEL_CHAR:
            token_value = json_create_string(str_get(model_char(field)));
            break;
        case MODEL_TEXT:
            token_value = json_create_string(str_get(model_text(field)));
            break;
        case MODEL_ENUM:
            token_value = json_create_string(str_get(model_enum(field)));
            break;
        case MODEL_ARRAY:
            token_value = __model_array_to_json(field->value._array);
            break;
        }

        if (token_value == NULL) goto failed;

        json_object_set(object, field->name, token_value);
    }

    result = 1;

    failed:

    if (result == 0) {
        json_token_free_tree(object);
        return NULL;
    }

    return object;
}

int __model_allow_field_in_json(const char* field_name, char** display_fields) {
    if (display_fields == NULL) return 1;

    while (*display_fields != NULL) {
        if (strcmp(*display_fields, field_name) == 0)
            return 1;

        display_fields++;
    }

    return 0;
}

mfield_t __model_tmpfield_create(mfield_t* source_field) {
    mfield_t tmpfield = {
        .type = source_field->type,
        .dirty = source_field->dirty,
        .name = source_field->name,
        .value = source_field->value,
        .oldvalue = source_field->oldvalue
    };

    return tmpfield;
}

int __str_modify_add_symbols_before(str_t* str, char add_symbol, char before_symbol) {
    if (str == NULL) return 0;

    size_t i = 0;
    while (i < str->size) {
        // Get fresh pointer on each iteration (realloc may change buffer address)
        char* buffer = str_get(str);

        if (buffer[i] == before_symbol) {
            // Insert symbol before current position
            if (!str_insertc(str, add_symbol, i)) {
                return 0;
            }
            // Skip the inserted symbol
            i++;
        }
        i++;
    }

    return 1;
}

/* =========================================================================
 * Parameterized CRUD value binding (R2)
 *
 * Values are never interpolated into SQL text. A field carrying `use_raw_sql`
 * (NULL, NOW(), ...) is inlined as a trusted framework fragment; every other
 * value is emitted as a positional placeholder ($N) and the field is appended
 * to an ordered bind array consumed by dbquery_params -> execute_params. Only
 * identifiers (table/column names from the compile-time schema) reach the SQL
 * text directly.
 * ========================================================================= */

// Append a bound value to `sql`: either inline a trusted raw fragment, or emit
// "$N[::cast]" and push `field` onto `params`. *idx is the running placeholder
// counter, incremented only when a placeholder is emitted.
// Returns 1 on success, 0 on conversion failure.
static int __model_append_bind(dbconnection_t* conn, str_t* sql, mfield_t* field, array_t* params, int* idx) {
    str_t* value = model_field_to_string(field);
    if (value == NULL) return 0;

    // model_field_to_string sets use_raw_sql for is_null fields ("NULL"), so the
    // raw branch also covers NULLs and SQL functions — inline, never bound.
    if (field->use_raw_sql) {
        str_append(sql, str_get(value), str_size(value));
        return 1;
    }

    (*idx)++;

    char placeholder[16];
    const int n = snprintf(placeholder, sizeof(placeholder), "$%d", *idx);
    str_append(sql, placeholder, n);

    const char* suffix = conn->type_cast(field->type);
    if (suffix != NULL && suffix[0] != '\0')
        str_append(sql, suffix, strlen(suffix));

    array_push_back(params, array_create_pointer(field, array_nocopy, array_nofree));

    return 1;
}

// Clone a field carrying `srcval`, owning a fresh string slot so that binding it
// neither mutates nor frees the source field's buffers. Used to bind the OLD
// primary-key value in UPDATE ... WHERE when the key itself changed (the source
// field is bound separately in SET with its new value).
static mfield_t* __model_bind_clone(const mfield_t* field, mvalue_t srcval) {
    mfield_t* f = malloc(sizeof(*f));
    if (f == NULL) return NULL;

    *f = *field;
    f->value = srcval;
    f->value._string = NULL;
    f->is_null = 0;
    f->use_raw_sql = 0;
    f->dirty = 0;

    // String-backed types keep their data in _string; copy it so the clone owns
    // an independent buffer. Scalars carry their value in the union and format
    // lazily into a freshly allocated _string.
    if (srcval._string != NULL) {
        f->value._string = str_createn(str_get(srcval._string), str_size(srcval._string));
        if (f->value._string == NULL) {
            free(f);
            return NULL;
        }
    }

    return f;
}

static void __model_bind_clone_free(void* p) {
    mfield_t* f = p;
    if (f == NULL) return;
    if (f->value._string != NULL) str_free(f->value._string);
    free(f);
}

/* =========================================================================
 * Schema/record model (R1)
 *
 * Generic CRUD/serialization over a shared `const mschema_t*` and a heap cell
 * array, reusing every per-field helper (model_set_*, model_field_to_string,
 * __model_fill, __model_value_*). Coexists with the legacy model_t/vtable path
 * during the staged migration.
 * ========================================================================= */

static void __model_cell_init(mfield_t* cell, const mcolumn_t* col) {
    memset(cell, 0, sizeof(*cell));
    cell->name = col->name;
    cell->type = col->type;

    switch (col->type) {
    case MODEL_BINARY:
    case MODEL_VARCHAR:
    case MODEL_CHAR:
    case MODEL_TEXT:
        cell->value._string = str_create_empty(64);
        cell->is_null = 1;
        cell->use_raw_sql = 1;
        break;
    case MODEL_ENUM:
        cell->value._enum = enums_create((char**)col->enum_values, col->enum_count);
        cell->value._string = str_create_empty(64);
        cell->is_null = 1;
        cell->use_raw_sql = 1;
        break;
    case MODEL_JSON:
        cell->is_null = 1;
        cell->use_raw_sql = 1;
        break;
    case MODEL_ARRAY:
        cell->is_null = 1;
        cell->use_raw_sql = 1;
        break;
    default:
        /* numeric and temporal: zeroed value, not null */
        cell->is_null = 0;
        break;
    }

    /* Column with a DB-side default: leave it out of INSERT until explicitly
       set (mirrors legacy mfield_timestamp(x, NOW)). */
    if (col->has_default) {
        cell->is_null = 1;
        cell->use_default = 1;
        cell->use_raw_sql = 0;
    }
    /* Numeric/temporal column that starts NULL (mirrors mfield_x(name, NULL)):
       inserted as an explicit NULL until set. */
    else if (col->nullable) {
        cell->is_null = 1;
    }
}

int model_init(model_t* record, const mschema_t* schema) {
    if (record == NULL || schema == NULL) return 0;

    record->schema = schema;
    record->table = schema->table;
    record->fields = calloc(schema->columns_count, sizeof(mfield_t));
    if (record->fields == NULL) return 0;

    for (int i = 0; i < schema->columns_count; i++)
        __model_cell_init(&record->fields[i], &schema->columns[i]);

    return 1;
}

mfield_t* model_field(void* arg, int index) {
    model_t* record = arg;
    if (record == NULL || record->fields == NULL) return NULL;
    if (index < 0 || index >= record->schema->columns_count) return NULL;

    return &record->fields[index];
}

void model_free(void* arg) {
    model_t* record = arg;
    if (record == NULL) return;

    if (record->fields != NULL) {
        const int count = record->schema->columns_count;
        for (int i = 0; i < count; i++) {
            __model_value_free(&record->fields[i].value, record->fields[i].type);
            __model_value_free(&record->fields[i].oldvalue, record->fields[i].type);
        }
        explicit_bzero(record->fields, count * sizeof(mfield_t));
        free(record->fields);
    }

    /* record is the first member of the concrete model struct */
    free(record);
}

void* model_get(const char* dbid, void*(create_instance)(void), array_t* params) {
    __model_set_status(MODEL_OK);

    if (create_instance == NULL) {
        __model_set_status(MODEL_ERR_PARAM);
        return NULL;
    }

    model_t* record = create_instance();
    if (record == NULL) {
        __model_set_status(MODEL_ERR_ALLOC);
        return NULL;
    }

    const mschema_t* schema = record->schema;

    dbinstance_t* dbinst = dbinstance(dbid);
    if (dbinst == NULL) {
        __model_set_status(MODEL_ERR_DB);
        model_free(record);
        return NULL;
    }

    dbconnection_t* conn = dbinst->connection;
    dbinstance_free(dbinst);

    str_t* fields = str_create_empty(256);
    str_t* sql = str_create_empty(256);
    array_t* bind = array_create();
    dbresult_t* result = NULL;
    void* res = NULL;

    if (fields == NULL || sql == NULL || bind == NULL) {
        __model_set_status(MODEL_ERR_ALLOC);
        goto failed;
    }

    for (int i = 0; i < schema->columns_count; i++) {
        if (i > 0)
            str_appendc(fields, ',');

        str_t* escaped = conn->escape_identifier(conn, schema->columns[i].name);
        if (escaped == NULL) {
            __model_set_status(MODEL_ERR_ALLOC);
            goto failed;
        }

        str_append(fields, str_get(escaped), str_size(escaped));
        str_free(escaped);
    }

    str_append(sql, "SELECT ", 7);
    str_append(sql, str_get(fields), str_size(fields));
    str_append(sql, " FROM ", 6);
    str_append(sql, record->table, strlen(record->table));
    str_append(sql, " WHERE ", 7);

    int idx = 0;
    for (size_t i = 0; i < array_size(params); i++) {
        mfield_t* param = array_get(params, i);

        if (i > 0)
            str_append(sql, " AND ", 5);

        str_append(sql, param->name, strlen(param->name));

        if (param->is_null) {
            str_append(sql, " IS NULL", 8);
        } else {
            str_appendc(sql, '=');
            if (!__model_append_bind(conn, sql, param, bind, &idx)) {
                __model_set_status(MODEL_ERR_ALLOC);
                goto failed;
            }
        }
    }

    str_append(sql, " LIMIT 1 ", 9);

    result = dbquery_params(dbid, str_get(sql), bind);

    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }
    if (dbresult_query_rows(result) == 0) {
        __model_set_status(MODEL_ERR_NOTFOUND);
        goto failed;
    }

    if (!__model_fill(0, schema->columns_count, record->fields, result)) {
        __model_set_status(MODEL_ERR_ALLOC);
        goto failed;
    }

    res = record;

    failed:

    if (res == NULL)
        model_free(record);

    str_free(fields);
    str_free(sql);
    array_free(bind);
    dbresult_free(result);

    return res;
}

int model_create(const char* dbid, void* arg) {
    __model_set_status(MODEL_OK);

    if (dbid == NULL || arg == NULL) {
        __model_set_status(MODEL_ERR_PARAM);
        return 0;
    }

    model_t* record = arg;
    const mschema_t* schema = record->schema;
    if (schema->columns_count == 0) {
        __model_set_status(MODEL_ERR_PARAM);
        return 0;
    }

    dbinstance_t* dbinst = dbinstance(dbid);
    if (dbinst == NULL) {
        __model_set_status(MODEL_ERR_DB);
        return 0;
    }

    dbconnection_t* conn = dbinst->connection;
    dbinstance_free(dbinst);

    int res = 0;
    dbresult_t* result = NULL;
    str_t* columns = str_create_empty(256);
    str_t* values = str_create_empty(256);
    str_t* sql = str_create_empty(256);
    array_t* bind = array_create();

    if (columns == NULL || values == NULL || sql == NULL || bind == NULL) {
        __model_set_status(MODEL_ERR_ALLOC);
        goto failed;
    }

    int idx = 0;
    int written = 0;
    for (int i = 0; i < schema->columns_count; i++) {
        mfield_t* field = &record->fields[i];

        if (schema->columns[i].is_primary && !field->dirty)
            continue;
        if (field->use_default)
            continue;

        if (written > 0) {
            str_appendc(columns, ',');
            str_appendc(values, ',');
        }

        str_t* escaped = conn->escape_identifier(conn, field->name);
        if (escaped == NULL) {
            __model_set_status(MODEL_ERR_ALLOC);
            goto failed;
        }

        str_append(columns, str_get(escaped), str_size(escaped));
        str_free(escaped);

        if (!__model_append_bind(conn, values, field, bind, &idx)) {
            __model_set_status(MODEL_ERR_ALLOC);
            goto failed;
        }

        written++;
    }

    if (written == 0) {
        __model_set_status(MODEL_ERR_PARAM);
        goto failed;
    }

    str_append(sql, "INSERT INTO ", 12);
    str_append(sql, record->table, strlen(record->table));
    str_append(sql, " (", 2);
    str_append(sql, str_get(columns), str_size(columns));
    str_append(sql, ") VALUES (", 10);
    str_append(sql, str_get(values), str_size(values));
    str_appendc(sql, ')');

    result = dbquery_params(dbid, str_get(sql), bind);
    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }

    res = 1;

    failed:

    str_free(columns);
    str_free(values);
    str_free(sql);
    array_free(bind);
    dbresult_free(result);

    return res;
}

int model_update(const char* dbid, void* arg) {
    __model_set_status(MODEL_OK);

    if (arg == NULL) {
        __model_set_status(MODEL_ERR_PARAM);
        return 0;
    }

    model_t* record = arg;
    const mschema_t* schema = record->schema;

    dbinstance_t* dbinst = dbinstance(dbid);
    if (dbinst == NULL) {
        __model_set_status(MODEL_ERR_DB);
        return 0;
    }

    dbconnection_t* conn = dbinst->connection;
    dbinstance_free(dbinst);

    int res = 0;
    dbresult_t* result = NULL;
    str_t* set_params = str_create_empty(256);
    str_t* where_params = str_create_empty(256);
    str_t* sql = str_create_empty(256);
    array_t* bind = array_create();
    // Owns the heap clones used to bind the OLD primary-key value (dirty PK case).
    array_t* clones = array_create();

    if (set_params == NULL || where_params == NULL || sql == NULL || bind == NULL || clones == NULL) {
        __model_set_status(MODEL_ERR_ALLOC);
        goto failed;
    }

    // Placeholder numbering follows SQL text order: SET ($1..) precedes WHERE,
    // so SET is built before WHERE and they share a single running counter.
    int idx = 0;

    // Pass 1 — SET clause: every dirty field bound with its (new) value.
    for (int i = 0, iter_set = 0; i < schema->columns_count; i++) {
        mfield_t* field = &record->fields[i];

        if (!field->dirty)
            continue;

        if (iter_set > 0)
            str_appendc(set_params, ',');

        str_append(set_params, field->name, strlen(field->name));
        str_appendc(set_params, '=');

        if (!__model_append_bind(conn, set_params, field, bind, &idx)) {
            __model_set_status(MODEL_ERR_ALLOC);
            goto failed;
        }

        iter_set++;
    }

    // Pass 2 — WHERE clause: locate the row by primary key. A dirty key is bound
    // by its OLD value (the SET above already bound its new value).
    for (int i = 0, iter_where = 0; i < schema->columns_count; i++) {
        if (!schema->columns[i].is_primary)
            continue;

        mfield_t* field = &record->fields[i];

        if (iter_where > 0)
            str_append(where_params, " AND ", 5);

        str_append(where_params, field->name, strlen(field->name));
        str_appendc(where_params, '=');

        if (field->dirty) {
            mfield_t* clone = __model_bind_clone(field, field->oldvalue);
            if (clone == NULL) {
                __model_set_status(MODEL_ERR_ALLOC);
                goto failed;
            }

            array_push_back(clones, array_create_pointer(clone, array_nocopy, __model_bind_clone_free));

            if (!__model_append_bind(conn, where_params, clone, bind, &idx)) {
                __model_set_status(MODEL_ERR_ALLOC);
                goto failed;
            }
        } else {
            if (!__model_append_bind(conn, where_params, field, bind, &idx)) {
                __model_set_status(MODEL_ERR_ALLOC);
                goto failed;
            }
        }

        iter_where++;
    }

    str_append(sql, "UPDATE ", 7);
    str_append(sql, record->table, strlen(record->table));
    str_append(sql, " SET ", 5);
    str_append(sql, str_get(set_params), str_size(set_params));
    str_append(sql, " WHERE ", 7);
    str_append(sql, str_get(where_params), str_size(where_params));

    result = dbquery_params(dbid, str_get(sql), bind);

    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }

    res = 1;

    for (int i = 0; i < schema->columns_count; i++) {
        mfield_t* field = &record->fields[i];
        field->dirty = 0;
        __model_value_clear(&field->oldvalue, field->type);
    }

    failed:

    str_free(set_params);
    str_free(where_params);
    str_free(sql);
    array_free(bind);
    array_free(clones);
    dbresult_free(result);

    return res;
}

int model_delete(const char* dbid, void* arg) {
    __model_set_status(MODEL_OK);

    if (dbid == NULL || arg == NULL) {
        __model_set_status(MODEL_ERR_PARAM);
        return 0;
    }

    model_t* record = arg;
    const mschema_t* schema = record->schema;
    if (schema->columns_count == 0) {
        __model_set_status(MODEL_ERR_PARAM);
        return 0;
    }

    dbinstance_t* dbinst = dbinstance(dbid);
    if (dbinst == NULL) {
        __model_set_status(MODEL_ERR_DB);
        return 0;
    }

    dbconnection_t* conn = dbinst->connection;
    dbinstance_free(dbinst);

    int res = 0;
    dbresult_t* result = NULL;
    str_t* where_params = str_create_empty(256);
    str_t* sql = str_create_empty(256);
    array_t* bind = array_create();

    if (where_params == NULL || sql == NULL || bind == NULL) {
        __model_set_status(MODEL_ERR_ALLOC);
        goto failed;
    }

    int idx = 0;
    for (int i = 0, iter_where = 0; i < schema->columns_count; i++) {
        if (!schema->columns[i].is_primary)
            continue;

        mfield_t* field = &record->fields[i];

        if (iter_where > 0)
            str_append(where_params, " AND ", 5);

        str_append(where_params, field->name, strlen(field->name));
        str_appendc(where_params, '=');

        if (!__model_append_bind(conn, where_params, field, bind, &idx)) {
            __model_set_status(MODEL_ERR_ALLOC);
            goto failed;
        }

        iter_where++;
    }

    str_append(sql, "DELETE FROM ", 12);
    str_append(sql, record->table, strlen(record->table));
    str_append(sql, " WHERE ", 7);
    str_append(sql, str_get(where_params), str_size(where_params));

    result = dbquery_params(dbid, str_get(sql), bind);

    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }

    res = 1;

    failed:

    str_free(where_params);
    str_free(sql);
    array_free(bind);
    dbresult_free(result);

    return res;
}

int model_delete_by_params(const char* dbid, void* arg, array_t* params) {
    __model_set_status(MODEL_OK);

    if (dbid == NULL || arg == NULL) {
        __model_set_status(MODEL_ERR_PARAM);
        return 0;
    }
    if (params == NULL || array_size(params) == 0) {
        __model_set_status(MODEL_ERR_PARAM);
        return 0;
    }

    model_t* record = arg;
    const mschema_t* schema = record->schema;
    if (schema->columns_count == 0) {
        __model_set_status(MODEL_ERR_PARAM);
        return 0;
    }

    dbinstance_t* dbinst = dbinstance(dbid);
    if (dbinst == NULL) {
        __model_set_status(MODEL_ERR_DB);
        return 0;
    }

    dbconnection_t* conn = dbinst->connection;
    dbinstance_free(dbinst);

    int res = 0;
    dbresult_t* result = NULL;
    str_t* where_params = str_create_empty(256);
    str_t* sql = str_create_empty(256);
    array_t* bind = array_create();

    if (where_params == NULL || sql == NULL || bind == NULL) {
        __model_set_status(MODEL_ERR_ALLOC);
        goto failed;
    }

    int idx = 0;
    for (size_t i = 0, iter_where = 0; i < array_size(params); i++) {
        const char* param_name = array_get(params, i);

        for (int j = 0; j < schema->columns_count; j++) {
            mfield_t* field = &record->fields[j];
            if (strcmp(param_name, field->name) != 0)
                continue;

            if (iter_where > 0)
                str_append(where_params, " AND ", 5);

            str_append(where_params, field->name, strlen(field->name));

            if (field->is_null) {
                str_append(where_params, " IS NULL", 8);
            } else {
                str_appendc(where_params, '=');
                if (!__model_append_bind(conn, where_params, field, bind, &idx)) {
                    __model_set_status(MODEL_ERR_ALLOC);
                    goto failed;
                }
            }

            iter_where++;
            break;
        }
    }

    str_append(sql, "DELETE FROM ", 12);
    str_append(sql, record->table, strlen(record->table));
    str_append(sql, " WHERE ", 7);
    str_append(sql, str_get(where_params), str_size(where_params));

    result = dbquery_params(dbid, str_get(sql), bind);

    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }

    res = 1;

    failed:

    str_free(where_params);
    str_free(sql);
    array_free(bind);
    dbresult_free(result);

    return res;
}

/* =========================================================================
 * Typed query builder (R4)
 *
 * Builds a parameterized SELECT from an mquery_t. Identifiers (table, column
 * names) are taken from the compile-time schema by index and escaped; every
 * condition value is bound via __model_append_bind ($N + ordered bind array),
 * exactly like the R2 CRUD path. LIMIT/OFFSET are framework-controlled ints,
 * inlined directly — an int carries no injection surface.
 *
 * v1 supports a flat AND of conditions, one ORDER BY column, and LIMIT/OFFSET.
 * ========================================================================= */

// Append the escaped name of schema column `column` to `sql`.
// Returns 1 on success, 0 on bad index or allocation failure.
static int __model_append_column(dbconnection_t* conn, str_t* sql, const mschema_t* schema, int column) {
    if (column < 0 || column >= schema->columns_count)
        return 0;

    str_t* escaped = conn->escape_identifier(conn, schema->columns[column].name);
    if (escaped == NULL)
        return 0;

    str_append(sql, str_get(escaped), str_size(escaped));
    str_free(escaped);

    return 1;
}

// Render a single condition ("<col> <op> <bound>") into `sql`.
// Returns 1 on success, 0 on invalid condition or allocation failure.
static int __model_append_cond(dbconnection_t* conn, str_t* sql, const mschema_t* schema, const mcond_t* cond, array_t* bind, int* idx) {
    if (!__model_append_column(conn, sql, schema, cond->column))
        return 0;

    switch (cond->op) {
    case MOP_EQ:   str_appendc(sql, '='); break;
    case MOP_NE:   str_append(sql, "<>", 2); break;
    case MOP_LT:   str_appendc(sql, '<'); break;
    case MOP_LE:   str_append(sql, "<=", 2); break;
    case MOP_GT:   str_appendc(sql, '>'); break;
    case MOP_GE:   str_append(sql, ">=", 2); break;
    case MOP_LIKE: str_append(sql, " LIKE ", 6); break;
    case MOP_IS_NULL:  str_append(sql, " IS NULL", 8); return 1;
    case MOP_NOT_NULL: str_append(sql, " IS NOT NULL", 12); return 1;
    case MOP_IN: {
        str_append(sql, " IN (", 5);
        const int count = cond->value_count > 0 ? cond->value_count : 1;
        for (int i = 0; i < count; i++) {
            if (i > 0)
                str_appendc(sql, ',');
            if (!__model_append_bind(conn, sql, &cond->value[i], bind, idx))
                return 0;
        }
        str_appendc(sql, ')');
        return 1;
    }
    default:
        return 0;
    }

    return __model_append_bind(conn, sql, cond->value, bind, idx);
}

// Build the full parameterized SELECT for `query` into `sql`, pushing bound
// condition values onto `bind`. When force_limit_one is set, a "LIMIT 1" is
// emitted regardless of query->limit (used by model_find_one).
// Returns 1 on success, 0 on invalid query or allocation failure.
static int __model_build_find(dbconnection_t* conn, const mschema_t* schema, const char* table, const mquery_t* query, str_t* sql, array_t* bind, int force_limit_one) {
    str_append(sql, "SELECT ", 7);
    for (int i = 0; i < schema->columns_count; i++) {
        if (i > 0)
            str_appendc(sql, ',');
        if (!__model_append_column(conn, sql, schema, i))
            return 0;
    }

    str_append(sql, " FROM ", 6);
    str_append(sql, table, strlen(table));

    if (query->conds_count > 0) {
        str_append(sql, " WHERE ", 7);

        int idx = 0;
        for (int i = 0; i < query->conds_count; i++) {
            if (i > 0)
                str_append(sql, " AND ", 5);
            if (!__model_append_cond(conn, sql, schema, &query->conds[i], bind, &idx))
                return 0;
        }
    }

    if (query->order_column >= 0) {
        str_append(sql, " ORDER BY ", 10);
        if (!__model_append_column(conn, sql, schema, query->order_column))
            return 0;
        str_append(sql, query->order_dir == MORDER_DESC ? " DESC" : " ASC",
                   query->order_dir == MORDER_DESC ? 5 : 4);
    }

    char buf[32];
    if (force_limit_one) {
        str_append(sql, " LIMIT 1", 8);
    } else if (query->limit >= 0) {
        const int n = snprintf(buf, sizeof(buf), " LIMIT %d", query->limit);
        str_append(sql, buf, n);
    }

    if (query->offset >= 0) {
        const int n = snprintf(buf, sizeof(buf), " OFFSET %d", query->offset);
        str_append(sql, buf, n);
    }

    return 1;
}

void* model_find_one(const char* dbid, void*(create_instance)(void), const mquery_t* query) {
    __model_set_status(MODEL_OK);

    if (dbid == NULL || create_instance == NULL || query == NULL) {
        __model_set_status(MODEL_ERR_PARAM);
        return NULL;
    }

    model_t* record = create_instance();
    if (record == NULL) {
        __model_set_status(MODEL_ERR_ALLOC);
        return NULL;
    }

    const mschema_t* schema = record->schema;

    dbinstance_t* dbinst = dbinstance(dbid);
    if (dbinst == NULL) {
        __model_set_status(MODEL_ERR_DB);
        model_free(record);
        return NULL;
    }

    dbconnection_t* conn = dbinst->connection;
    dbinstance_free(dbinst);

    str_t* sql = str_create_empty(256);
    array_t* bind = array_create();
    dbresult_t* result = NULL;
    void* res = NULL;

    if (sql == NULL || bind == NULL) {
        __model_set_status(MODEL_ERR_ALLOC);
        goto failed;
    }

    if (!__model_build_find(conn, schema, record->table, query, sql, bind, 1)) {
        __model_set_status(MODEL_ERR_PARAM);
        goto failed;
    }

    result = dbquery_params(dbid, str_get(sql), bind);
    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }
    if (dbresult_query_rows(result) == 0) {
        __model_set_status(MODEL_ERR_NOTFOUND);
        goto failed;
    }

    if (!__model_fill(0, schema->columns_count, record->fields, result)) {
        __model_set_status(MODEL_ERR_ALLOC);
        goto failed;
    }

    res = record;

    failed:

    if (res == NULL)
        model_free(record);

    str_free(sql);
    array_free(bind);
    dbresult_free(result);

    return res;
}

array_t* model_find_list(const char* dbid, void*(create_instance)(void), const mquery_t* query) {
    __model_set_status(MODEL_OK);

    if (dbid == NULL || create_instance == NULL || query == NULL) {
        __model_set_status(MODEL_ERR_PARAM);
        return NULL;
    }

    // A throwaway instance gives us the schema and effective table without
    // duplicating per-model knowledge here; the rows are filled into fresh
    // instances by __model_fill_array.
    model_t* probe = create_instance();
    if (probe == NULL) {
        __model_set_status(MODEL_ERR_ALLOC);
        return NULL;
    }

    const mschema_t* schema = probe->schema;

    dbinstance_t* dbinst = dbinstance(dbid);
    if (dbinst == NULL) {
        __model_set_status(MODEL_ERR_DB);
        model_free(probe);
        return NULL;
    }

    dbconnection_t* conn = dbinst->connection;
    dbinstance_free(dbinst);

    str_t* sql = str_create_empty(256);
    array_t* bind = array_create();
    dbresult_t* result = NULL;
    array_t* array = NULL;

    if (sql == NULL || bind == NULL) {
        __model_set_status(MODEL_ERR_ALLOC);
        goto failed;
    }

    if (!__model_build_find(conn, schema, probe->table, query, sql, bind, 0)) {
        __model_set_status(MODEL_ERR_PARAM);
        goto failed;
    }

    result = dbquery_params(dbid, str_get(sql), bind);
    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }
    if (dbresult_query_rows(result) == 0) {
        __model_set_status(MODEL_ERR_NOTFOUND);
        goto failed;
    }

    array = __model_fill_array(create_instance, result);
    if (array == NULL)
        __model_set_status(MODEL_ERR_ALLOC);

    failed:

    model_free(probe);
    str_free(sql);
    array_free(bind);
    dbresult_free(result);

    return array;
}

static void* __model_fill_one(void*(create_instance)(void), dbresult_t* result) {
    if (result == NULL) return NULL;

    model_t* record = create_instance();
    if (record == NULL) return NULL;

    if (!__model_fill(0, record->schema->columns_count, record->fields, result)) {
        model_free(record);
        return NULL;
    }

    return record;
}

static array_t* __model_fill_array(void*(create_instance)(void), dbresult_t* result) {
    if (result == NULL) return NULL;

    array_t* array = array_create();
    if (array == NULL) return NULL;

    for (int row = 0; row < dbresult_query_rows(result); row++) {
        model_t* record = create_instance();
        if (record == NULL) goto failed;

        if (!__model_fill(row, record->schema->columns_count, record->fields, result)) {
            model_free(record);
            goto failed;
        }

        array_push_back(array, array_create_pointer(record, array_nocopy, model_free));
    }

    failed:

    return array;
}

void* model_one(const char* dbid, void*(create_instance)(void), const char* format, array_t* params) {
    __model_set_status(MODEL_OK);

    void* record = NULL;
    dbresult_t* result = dbquery(dbid, format, params);
    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }

    if (dbresult_query_rows(result) == 0) {
        __model_set_status(MODEL_ERR_NOTFOUND);
        goto failed;
    }

    record = __model_fill_one(create_instance, result);
    if (record == NULL)
        __model_set_status(MODEL_ERR_ALLOC);

    failed:

    dbresult_free(result);

    return record;
}

array_t* model_list(const char* dbid, void*(create_instance)(void), const char* format, array_t* params) {
    __model_set_status(MODEL_OK);

    array_t* array = NULL;
    dbresult_t* result = dbquery(dbid, format, params);
    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }

    if (dbresult_query_rows(result) == 0) {
        __model_set_status(MODEL_ERR_NOTFOUND);
        goto failed;
    }

    array = __model_fill_array(create_instance, result);
    if (array == NULL)
        __model_set_status(MODEL_ERR_ALLOC);

    failed:

    dbresult_free(result);

    return array;
}

void* model_prepared_one(const char* dbid, void*(create_instance)(void), const char* stat_name, const char* sql, array_t* params) {
    __model_set_status(MODEL_OK);

    void* record = NULL;
    dbresult_t* result = dbprepared(dbid, stat_name, sql, params);
    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }

    if (dbresult_query_rows(result) == 0) {
        __model_set_status(MODEL_ERR_NOTFOUND);
        goto failed;
    }

    record = __model_fill_one(create_instance, result);
    if (record == NULL)
        __model_set_status(MODEL_ERR_ALLOC);

    failed:

    dbresult_free(result);

    return record;
}

array_t* model_prepared_list(const char* dbid, void*(create_instance)(void), const char* stat_name, const char* sql, array_t* params) {
    __model_set_status(MODEL_OK);

    array_t* array = NULL;
    dbresult_t* result = dbprepared(dbid, stat_name, sql, params);
    if (!dbresult_ok(result)) {
        __model_set_db_error(result);
        goto failed;
    }

    if (dbresult_query_rows(result) == 0) {
        __model_set_status(MODEL_ERR_NOTFOUND);
        goto failed;
    }

    array = __model_fill_array(create_instance, result);
    if (array == NULL)
        __model_set_status(MODEL_ERR_ALLOC);

    failed:

    dbresult_free(result);

    return array;
}

json_token_t* model_to_json(void* arg, char** display_fields) {
    model_t* record = arg;
    if (record == NULL) return NULL;

    return __model_json_object_fields(record->fields, record->schema->columns_count, display_fields);
}

char* model_stringify(void* arg, char** display_fields) {
    if (arg == NULL) return NULL;

    json_doc_t* doc = json_create_empty();
    if (!doc) return NULL;

    json_token_t* object = model_to_json(arg, display_fields);
    if (object == NULL) {
        json_free(doc);
        return NULL;
    }

    json_set_root(doc, object);

    char* data = json_stringify_detach(doc);

    json_free(doc);

    return data;
}

char* model_list_stringify(array_t* array) {
    if (array == NULL) return NULL;

    json_doc_t* doc = json_root_create_array();
    if (!doc) return NULL;

    json_token_t* json_array = json_root(doc);
    char* data = NULL;

    for (size_t i = 0; i < array_size(array); i++) {
        avalue_t* item = &array->elements[i];
        if (item->type != ARRAY_POINTER) goto failed;

        model_t* record = item->_pointer;
        if (record == NULL) goto failed;

        json_array_append(json_array, model_to_json(record, NULL));
    }

    data = json_stringify_detach(doc);

    failed:

    json_free(doc);

    return data;
}

