#ifndef __MFIELD__
#define __MFIELD__

#include <stddef.h>
#include <string.h>
#include <time.h>

#include "database.h"
#include "json.h"
#include "array.h"
#include "str.h"
#include "enums.h"
#include "macros.h"

/* ---------------------------------------------------------------------------
 * mfield.h — base layer
 *
 * Core value/field types, the per-type constructor macros (legacy field
 * initializers + param builders), and the per-type accessor declarations
 * (get / set / set_from_str / to_str). No dependency on schema, query or
 * CRUD layers; mschema.h, mquery.h and model.h build on top of this.
 * ------------------------------------------------------------------------- */

#define mparam_bool(NAME, VALUE) field_create_bool(#NAME, VALUE)
#define mparam_smallint(NAME, VALUE) field_create_smallint(#NAME, VALUE)
#define mparam_int(NAME, VALUE) field_create_int(#NAME, VALUE)
#define mparam_bigint(NAME, VALUE) field_create_bigint(#NAME, VALUE)
#define mparam_float(NAME, VALUE) field_create_float(#NAME, VALUE)
#define mparam_double(NAME, VALUE) field_create_double(#NAME, VALUE)
#define mparam_decimal(NAME, VALUE) field_create_decimal(#NAME, VALUE)
#define mparam_money(NAME, VALUE) field_create_double(#NAME, VALUE)
#define mparam_date(NAME, VALUE) field_create_date(#NAME, VALUE)
#define mparam_time(NAME, VALUE) field_create_time(#NAME, VALUE)
#define mparam_timetz(NAME, VALUE) field_create_timetz(#NAME, VALUE)
#define mparam_timestamp(NAME, VALUE) field_create_timestamp(#NAME, VALUE)
#define mparam_timestamptz(NAME, VALUE) field_create_timestamptz(#NAME, VALUE)
#define mparam_json(NAME, VALUE) field_create_json(#NAME, VALUE)
#define mparam_binary(NAME, VALUE) field_create_binary(#NAME, VALUE)
#define mparam_varchar(NAME, VALUE) field_create_varchar(#NAME, VALUE)
#define mparam_char(NAME, VALUE) field_create_char(#NAME, VALUE)
#define mparam_text(NAME, VALUE) field_create_text(#NAME, VALUE)
#define mparam_enum(NAME, VALUE, ...) field_create_enum(#NAME, VALUE, args_str(VALUE, __VA_ARGS__))
#define mparam_array(NAME, VALUE) field_create_array(#NAME, VALUE)


#define mnfields(TYPE, FIELD, NAME, VALUE, ISNULL) \
    .type = TYPE,\
    .name = #NAME,\
    .dirty = 0,\
    .is_null = ISNULL,\
    .value.FIELD = VALUE,\
    .value._string = NULL,\
    .oldvalue._short = 0,\
    .oldvalue._string = NULL

#define mdfields(TYPE, NAME, VALUE, ISNULL) \
    .type = TYPE,\
    .name = #NAME,\
    .dirty = 0,\
    .is_null = ISNULL,\
    .value._tm = VALUE,\
    .value._string = NULL,\
    .oldvalue._tm = (tm_t){0},\
    .oldvalue._string = NULL

#define msfields(TYPE, NAME, VALUE) \
    .type = TYPE,\
    .name = #NAME,\
    .dirty = 0,\
    .is_null = ((VALUE) == NULL ? 1 : 0),\
    .value._short = 0,\
    .value._string = str_create(VALUE),\
    .oldvalue._short = 0,\
    .oldvalue._string = NULL

#define NOW NULL

#define mf_is_null(VALUE) _Generic((VALUE), void*: 1, default: 0)
#define mf_num_val(VALUE, DEFVAL) _Generic((VALUE), void*: DEFVAL, default: (VALUE))
#define mf_tm_val(VALUE) _Generic((VALUE), void*: (tm_t){0}, default: (VALUE))

#define mfield_bool(NAME, VALUE) .NAME = { \
    .type = MODEL_BOOL, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._short = mf_num_val(VALUE, 0), .value._string = NULL, \
    .oldvalue._short = 0, .oldvalue._string = NULL }
#define mfield_smallint(NAME, VALUE) .NAME = { \
    .type = MODEL_SMALLINT, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._short = mf_num_val(VALUE, 0), .value._string = NULL, \
    .oldvalue._short = 0, .oldvalue._string = NULL }
#define mfield_int(NAME, VALUE) .NAME = { \
    .type = MODEL_INT, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._int = mf_num_val(VALUE, 0), .value._string = NULL, \
    .oldvalue._short = 0, .oldvalue._string = NULL }
#define mfield_bigint(NAME, VALUE) .NAME = { \
    .type = MODEL_BIGINT, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._bigint = mf_num_val(VALUE, 0), .value._string = NULL, \
    .oldvalue._short = 0, .oldvalue._string = NULL }
#define mfield_float(NAME, VALUE) .NAME = { \
    .type = MODEL_FLOAT, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._float = mf_num_val(VALUE, 0), .value._string = NULL, \
    .oldvalue._short = 0, .oldvalue._string = NULL }
#define mfield_double(NAME, VALUE) .NAME = { \
    .type = MODEL_DOUBLE, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._double = mf_num_val(VALUE, 0), .value._string = NULL, \
    .oldvalue._short = 0, .oldvalue._string = NULL }
#define mfield_decimal(NAME, VALUE) .NAME = { \
    .type = MODEL_DECIMAL, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._ldouble = mf_num_val(VALUE, 0), .value._string = NULL, \
    .oldvalue._short = 0, .oldvalue._string = NULL }
#define mfield_money(NAME, VALUE) .NAME = { \
    .type = MODEL_MONEY, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._double = mf_num_val(VALUE, 0), .value._string = NULL, \
    .oldvalue._short = 0, .oldvalue._string = NULL }
#define mfield_date(NAME, VALUE) .NAME = { \
    .type = MODEL_DATE, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._tm = mf_tm_val(VALUE), .value._string = NULL, \
    .oldvalue._tm = (tm_t){0}, .oldvalue._string = NULL }
#define mfield_time(NAME, VALUE) .NAME = { \
    .type = MODEL_TIME, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._tm = mf_tm_val(VALUE), .value._string = NULL, \
    .oldvalue._tm = (tm_t){0}, .oldvalue._string = NULL }
#define mfield_timetz(NAME, VALUE) .NAME = { \
    .type = MODEL_TIMETZ, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), \
    .value._tm = mf_tm_val(VALUE), .value._string = NULL, \
    .oldvalue._tm = (tm_t){0}, .oldvalue._string = NULL }
#define mfield_timestamp(NAME, VALUE) .NAME = { \
    .type = MODEL_TIMESTAMP, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), .use_default = mf_is_null(VALUE), \
    .value._tm = mf_tm_val(VALUE), .value._string = NULL, \
    .oldvalue._tm = (tm_t){0}, .oldvalue._string = NULL }
#define mfield_timestamptz(NAME, VALUE) .NAME = { \
    .type = MODEL_TIMESTAMPTZ, .name = #NAME, .dirty = 0, \
    .is_null = mf_is_null(VALUE), .use_default = mf_is_null(VALUE), \
    .value._tm = mf_tm_val(VALUE), .value._string = NULL, \
    .oldvalue._tm = (tm_t){0}, .oldvalue._string = NULL }
#define mfield_json(NAME, VALUE) .NAME = {\
        .type = MODEL_JSON,\
        .name = #NAME,\
        .dirty = 0,\
        .is_null = ((VALUE) == NULL ? 1 : 0),\
        .value._jsondoc = VALUE,\
        .value._string = NULL,\
        .oldvalue._jsondoc = NULL,\
        .oldvalue._string = NULL\
    }
#define mfield_binary(NAME, VALUE) .NAME = { msfields(MODEL_BINARY, NAME, VALUE) }
#define mfield_varchar(NAME, VALUE) .NAME = { msfields(MODEL_VARCHAR, NAME, VALUE) }
#define mfield_char(NAME, VALUE) .NAME = { msfields(MODEL_CHAR, NAME, VALUE) }
#define mfield_text(NAME, VALUE) .NAME = { msfields(MODEL_TEXT, NAME, VALUE) }
#define mfield_enum(NAME, VALUE, ...) .NAME = {\
        .type = MODEL_ENUM,\
        .name = #NAME,\
        .dirty = 0,\
        .is_null = ((VALUE) == NULL ? 1 : 0),\
        .value._enum = enums_create(args_str(__VA_ARGS__)),\
        .value._string = str_create(VALUE),\
        .oldvalue._enum = NULL,\
        .oldvalue._string = NULL\
    }

// For prepare statement definition
#define mfield_def_bool(NAME) mparam_bool(NAME, 0)
#define mfield_def_smallint(NAME) mparam_smallint(NAME, 0)
#define mfield_def_int(NAME) mparam_int(NAME, 0)
#define mfield_def_bigint(NAME) mparam_bigint(NAME, 0)
#define mfield_def_float(NAME) mparam_float(NAME, 0)
#define mfield_def_double(NAME) mparam_double(NAME, 0)
#define mfield_def_decimal(NAME) mparam_decimal(NAME, 0)
#define mfield_def_money(NAME) mparam_money(NAME, 0)
#define mfield_def_date(NAME) mparam_date(NAME, 0)
#define mfield_def_time(NAME) mparam_time(NAME, 0)
#define mfield_def_timetz(NAME) mparam_timetz(NAME, 0)
#define mfield_def_timestamp(NAME) mparam_timestamp(NAME, 0)
#define mfield_def_timestamptz(NAME) mparam_timestamptz(NAME, 0)
#define mfield_def_json(NAME) mparam_json(NAME, 0)
#define mfield_def_binary(NAME) mparam_binary(NAME, 0)
#define mfield_def_varchar(NAME) mparam_varchar(NAME, 0)
#define mfield_def_char(NAME) mparam_char(NAME, 0)
#define mfield_def_text(NAME) mparam_text(NAME, 0)
#define mfield_def_enum(NAME, VALUE, ...) mparam_enum(NAME, VALUE, __VA_ARGS__)
#define mfield_def_array(NAME, VALUE) mparam_array(NAME, VALUE)

typedef struct {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long tm_gmtoff;
    const char* tm_zone;
    int tm_usec;
} tm_t;

static inline void tm_from_time(tm_t* dst, time_t t) {
    struct tm stm;
    localtime_r(&t, &stm);
    dst->tm_sec = stm.tm_sec; dst->tm_min = stm.tm_min;
    dst->tm_hour = stm.tm_hour; dst->tm_mday = stm.tm_mday;
    dst->tm_mon = stm.tm_mon; dst->tm_year = stm.tm_year;
    dst->tm_wday = stm.tm_wday; dst->tm_yday = stm.tm_yday;
    dst->tm_isdst = stm.tm_isdst;
    dst->tm_gmtoff = stm.tm_gmtoff; dst->tm_zone = stm.tm_zone;
    dst->tm_usec = 0;
}

static inline time_t tm_to_time(const tm_t* src) {
    struct tm stm = {
        .tm_sec = src->tm_sec, .tm_min = src->tm_min,
        .tm_hour = src->tm_hour, .tm_mday = src->tm_mday,
        .tm_mon = src->tm_mon, .tm_year = src->tm_year,
        .tm_wday = src->tm_wday, .tm_yday = src->tm_yday,
        .tm_isdst = src->tm_isdst,
        .tm_gmtoff = src->tm_gmtoff, .tm_zone = src->tm_zone
    };
    return mktime(&stm);
}

typedef enum {
    MODEL_BOOL = 0,

    MODEL_SMALLINT,
    MODEL_INT,
    MODEL_BIGINT,
    MODEL_FLOAT,
    MODEL_DOUBLE,
    MODEL_DECIMAL,
    MODEL_MONEY,

    MODEL_DATE,
    MODEL_TIME,
    MODEL_TIMETZ,
    MODEL_TIMESTAMP,
    MODEL_TIMESTAMPTZ,

    MODEL_JSON,

    MODEL_BINARY,
    MODEL_VARCHAR,
    MODEL_CHAR,
    MODEL_TEXT,
    MODEL_ENUM,
    MODEL_ARRAY,

    MTYPE_COUNT,   /* sentinel: number of model types, for dispatch tables */
} mtype_e;

typedef struct {
    union {
        short _short;
        int _int;
        long long _bigint;
        float _float;
        double _double;
        long double _ldouble;
        tm_t _tm;
        json_doc_t* _jsondoc;
        enums_t* _enum;
        array_t* _array;
    };
    str_t* _string;
} mvalue_t;

typedef struct mfield {
    const char* name;
    mvalue_t value;
    mvalue_t oldvalue;
    mtype_e type;
    unsigned dirty : 1;
    unsigned is_null : 1;
    unsigned use_default : 1;
    unsigned use_raw_sql : 1;
} mfield_t;

// Specialized field creation functions
void* field_create_bool(const char* field_name, short value);
void* field_create_smallint(const char* field_name, short value);
void* field_create_int(const char* field_name, int value);
void* field_create_bigint(const char* field_name, long long value);
void* field_create_float(const char* field_name, float value);
void* field_create_double(const char* field_name, double value);
void* field_create_decimal(const char* field_name, long double value);
void* field_create_money(const char* field_name, double value);

void* field_create_date(const char* field_name, tm_t* value);
void* field_create_time(const char* field_name, tm_t* value);
void* field_create_timetz(const char* field_name, tm_t* value);
void* field_create_timestamp(const char* field_name, tm_t* value);
void* field_create_timestamptz(const char* field_name, tm_t* value);

void* field_create_json(const char* field_name, json_doc_t* value);

void* field_create_binary(const char* field_name, const char* value);
void* field_create_varchar(const char* field_name, const char* value);
void* field_create_char(const char* field_name, const char* value);
void* field_create_text(const char* field_name, const char* value);

void* field_create_enum(const char* field_name, const char* default_value, char** values, int count);
void* field_create_array(const char* field_name, array_t* value);

short model_bool(mfield_t* field);
short model_smallint(mfield_t* field);
int model_int(mfield_t* field);
long long int model_bigint(mfield_t* field);
float model_float(mfield_t* field);
double model_double(mfield_t* field);
long double model_decimal(mfield_t* field);
double model_money(mfield_t* field);

tm_t model_timestamp(mfield_t* field);
tm_t model_timestamptz(mfield_t* field);
tm_t model_date(mfield_t* field);
tm_t model_time(mfield_t* field);
tm_t model_timetz(mfield_t* field);

json_doc_t* model_json(mfield_t* field);

str_t* model_binary(mfield_t* field);
str_t* model_varchar(mfield_t* field);
str_t* model_char(mfield_t* field);
str_t* model_text(mfield_t* field);
str_t* model_enum(mfield_t* field);

array_t* model_array(mfield_t* field);

int model_set_bool(mfield_t* field, short value);
int model_set_smallint(mfield_t* field, short value);
int model_set_int(mfield_t* field, int value);
int model_set_bigint(mfield_t* field, long long int value);
int model_set_float(mfield_t* field, float value);
int model_set_double(mfield_t* field, double value);
int model_set_decimal(mfield_t* field, long double value);
int model_set_money(mfield_t* field, double value);

int model_set_timestamp(mfield_t* field, tm_t* value);
int model_set_timestamp_now(mfield_t* field);
int model_set_timestamptz(mfield_t* field, tm_t* value);
int model_set_timestamptz_now(mfield_t* field);
int model_set_date(mfield_t* field, tm_t* value);
int model_set_time(mfield_t* field, tm_t* value);
int model_set_timetz(mfield_t* field, tm_t* value);

int model_set_json(mfield_t* field, json_doc_t* value);

int model_set_binary(mfield_t* field, const char* value, const size_t size);
int model_set_varchar(mfield_t* field, const char* value);
int model_set_char(mfield_t* field, const char* value);
int model_set_text(mfield_t* field, const char* value);
int model_set_enum(mfield_t* field, const char* value);

int model_set_array(mfield_t* field, array_t* value);

int model_set_bool_from_str(mfield_t* field, const char* value);
int model_set_smallint_from_str(mfield_t* field, const char* value);
int model_set_int_from_str(mfield_t* field, const char* value);
int model_set_bigint_from_str(mfield_t* field, const char* value);
int model_set_float_from_str(mfield_t* field, const char* value);
int model_set_double_from_str(mfield_t* field, const char* value);
int model_set_decimal_from_str(mfield_t* field, const char* value);
int model_set_money_from_str(mfield_t* field, const char* value);

int model_set_timestamp_from_str(mfield_t* field, const char* value);
int model_set_timestamptz_from_str(mfield_t* field, const char* value);
int model_set_date_from_str(mfield_t* field, const char* value);
int model_set_time_from_str(mfield_t* field, const char* value);
int model_set_timetz_from_str(mfield_t* field, const char* value);

int model_set_json_from_str(mfield_t* field, const char* value);

int model_set_binary_from_str(mfield_t* field, const char* value, size_t size);
int model_set_varchar_from_str(mfield_t* field, const char* value, size_t size);
int model_set_char_from_str(mfield_t* field, const char* value, size_t size);
int model_set_text_from_str(mfield_t* field, const char* value, size_t size);
int model_set_enum_from_str(mfield_t* field, const char* value, size_t size);

int model_set_array_from_str(mfield_t* field, const char* value);

str_t* model_bool_to_str(mfield_t* field);
str_t* model_smallint_to_str(mfield_t* field);
str_t* model_int_to_str(mfield_t* field);
str_t* model_bigint_to_str(mfield_t* field);
str_t* model_float_to_str(mfield_t* field);
str_t* model_double_to_str(mfield_t* field);
str_t* model_decimal_to_str(mfield_t* field);
str_t* model_money_to_str(mfield_t* field);

str_t* model_timestamp_to_str(mfield_t* field);
str_t* model_timestamptz_to_str(mfield_t* field);
str_t* model_date_to_str(mfield_t* field);
str_t* model_time_to_str(mfield_t* field);
str_t* model_timetz_to_str(mfield_t* field);

str_t* model_json_to_str(mfield_t* field);
str_t* model_array_to_str(mfield_t* field);

str_t* model_field_to_string(mfield_t* field);

void model_param_clear(void* field);
void model_param_free(void* field);
void model_params_clear(void* params, const size_t size);
void model_params_free(void* params, const size_t size);

json_token_t* model_json_create_object(void* arg, char** display_fields);

#endif /* __MFIELD__ */
