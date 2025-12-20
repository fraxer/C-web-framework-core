#ifndef __MODEL__
#define __MODEL__

#include <stddef.h>
#include <string.h>
#include <time.h>

#include "database.h"
#include "json.h"
#include "array.h"
#include "str.h"
#include "enums.h"
#include "macros.h"



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









#define MDL_ARRAY_APPEND(ARRAY, NAME) array_push_back(ARRAY, array_create_pointer(NAME, NULL, model_param_free));

#define MDL_VA_NARGS_REVERSE_(_101,_100,_99,_98,_97,_96,_95,_94,_93,_92,_91,_90,_89,_88,_87,_86,_85,_84,_83,_82,_81,_80,_79,_78,_77,_76,_75,_74,_73,_72,_71,_70,_69,_68,_67,_66,_65,_64,_63,_62,_61,_60,_59,_58,_57,_56,_55,_54,_53,_52,_51,_50,_49,_48,_47,_46,_45,_44,_43,_42,_41,_40,_39,_38,_37,_36,_35,_34,_33,_32,_31,_30,_29,_28,_27,_26,_25,_24,_23,_22,_21,_20,_19,_18,_17,_16,_15,_14,_13,_12,_11,_10,_9,_8,_7,_6,_5,_4,_3,_2,_1,N,...) N
#define MDL_VA_NARGS(...) MDL_VA_NARGS_REVERSE_(__VA_ARGS__, 101,100,99,98,97,96,95,94,93,92,91,90,89,88,87,86,85,84,83,82,81,80,79,78,77,76,75,74,73,72,71,70,69,68,67,66,65,64,63,62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0)

#define MDL_ITEM_CONCAT(A, B) A##B
#define MDL_ITEM(ARRAY, N, ...) MDL_ITEM_CONCAT(MDL_ITEM_, N)(ARRAY, __VA_ARGS__)
#define MDL_ITEM_1(ARRAY, FIELD) MDL_ARRAY_APPEND(ARRAY, FIELD)
#define MDL_ITEM_2(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_1(ARRAY, __VA_ARGS__)
#define MDL_ITEM_3(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_2(ARRAY, __VA_ARGS__)
#define MDL_ITEM_4(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_3(ARRAY, __VA_ARGS__)
#define MDL_ITEM_5(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_4(ARRAY, __VA_ARGS__)
#define MDL_ITEM_6(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_5(ARRAY, __VA_ARGS__)
#define MDL_ITEM_7(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_6(ARRAY, __VA_ARGS__)
#define MDL_ITEM_8(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_7(ARRAY, __VA_ARGS__)
#define MDL_ITEM_9(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_8(ARRAY, __VA_ARGS__)
#define MDL_ITEM_10(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_9(ARRAY, __VA_ARGS__)
#define MDL_ITEM_11(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_10(ARRAY, __VA_ARGS__)
#define MDL_ITEM_12(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_11(ARRAY, __VA_ARGS__)
#define MDL_ITEM_13(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_12(ARRAY, __VA_ARGS__)
#define MDL_ITEM_14(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_13(ARRAY, __VA_ARGS__)
#define MDL_ITEM_15(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_14(ARRAY, __VA_ARGS__)
#define MDL_ITEM_16(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_15(ARRAY, __VA_ARGS__)
#define MDL_ITEM_17(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_16(ARRAY, __VA_ARGS__)
#define MDL_ITEM_18(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_17(ARRAY, __VA_ARGS__)
#define MDL_ITEM_19(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_18(ARRAY, __VA_ARGS__)
#define MDL_ITEM_20(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_19(ARRAY, __VA_ARGS__)
#define MDL_ITEM_21(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_20(ARRAY, __VA_ARGS__)
#define MDL_ITEM_22(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_21(ARRAY, __VA_ARGS__)
#define MDL_ITEM_23(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_22(ARRAY, __VA_ARGS__)
#define MDL_ITEM_24(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_23(ARRAY, __VA_ARGS__)
#define MDL_ITEM_25(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_24(ARRAY, __VA_ARGS__)
#define MDL_ITEM_26(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_25(ARRAY, __VA_ARGS__)
#define MDL_ITEM_27(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_26(ARRAY, __VA_ARGS__)
#define MDL_ITEM_28(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_27(ARRAY, __VA_ARGS__)
#define MDL_ITEM_29(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_28(ARRAY, __VA_ARGS__)
#define MDL_ITEM_30(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_29(ARRAY, __VA_ARGS__)
#define MDL_ITEM_31(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_30(ARRAY, __VA_ARGS__)
#define MDL_ITEM_32(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_31(ARRAY, __VA_ARGS__)
#define MDL_ITEM_33(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_32(ARRAY, __VA_ARGS__)
#define MDL_ITEM_34(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_33(ARRAY, __VA_ARGS__)
#define MDL_ITEM_35(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_34(ARRAY, __VA_ARGS__)
#define MDL_ITEM_36(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_35(ARRAY, __VA_ARGS__)
#define MDL_ITEM_37(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_36(ARRAY, __VA_ARGS__)
#define MDL_ITEM_38(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_37(ARRAY, __VA_ARGS__)
#define MDL_ITEM_39(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_38(ARRAY, __VA_ARGS__)
#define MDL_ITEM_40(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_39(ARRAY, __VA_ARGS__)
#define MDL_ITEM_41(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_40(ARRAY, __VA_ARGS__)
#define MDL_ITEM_42(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_41(ARRAY, __VA_ARGS__)
#define MDL_ITEM_43(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_42(ARRAY, __VA_ARGS__)
#define MDL_ITEM_44(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_43(ARRAY, __VA_ARGS__)
#define MDL_ITEM_45(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_44(ARRAY, __VA_ARGS__)
#define MDL_ITEM_46(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_45(ARRAY, __VA_ARGS__)
#define MDL_ITEM_47(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_46(ARRAY, __VA_ARGS__)
#define MDL_ITEM_48(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_47(ARRAY, __VA_ARGS__)
#define MDL_ITEM_49(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_48(ARRAY, __VA_ARGS__)
#define MDL_ITEM_50(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_49(ARRAY, __VA_ARGS__)
#define MDL_ITEM_51(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_50(ARRAY, __VA_ARGS__)
#define MDL_ITEM_52(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_51(ARRAY, __VA_ARGS__)
#define MDL_ITEM_53(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_52(ARRAY, __VA_ARGS__)
#define MDL_ITEM_54(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_53(ARRAY, __VA_ARGS__)
#define MDL_ITEM_55(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_54(ARRAY, __VA_ARGS__)
#define MDL_ITEM_56(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_55(ARRAY, __VA_ARGS__)
#define MDL_ITEM_57(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_56(ARRAY, __VA_ARGS__)
#define MDL_ITEM_58(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_57(ARRAY, __VA_ARGS__)
#define MDL_ITEM_59(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_58(ARRAY, __VA_ARGS__)
#define MDL_ITEM_60(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_59(ARRAY, __VA_ARGS__)
#define MDL_ITEM_61(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_60(ARRAY, __VA_ARGS__)
#define MDL_ITEM_62(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_61(ARRAY, __VA_ARGS__)
#define MDL_ITEM_63(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_62(ARRAY, __VA_ARGS__)
#define MDL_ITEM_64(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_63(ARRAY, __VA_ARGS__)
#define MDL_ITEM_65(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_64(ARRAY, __VA_ARGS__)
#define MDL_ITEM_66(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_65(ARRAY, __VA_ARGS__)
#define MDL_ITEM_67(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_66(ARRAY, __VA_ARGS__)
#define MDL_ITEM_68(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_67(ARRAY, __VA_ARGS__)
#define MDL_ITEM_69(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_68(ARRAY, __VA_ARGS__)
#define MDL_ITEM_70(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_69(ARRAY, __VA_ARGS__)
#define MDL_ITEM_71(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_70(ARRAY, __VA_ARGS__)
#define MDL_ITEM_72(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_71(ARRAY, __VA_ARGS__)
#define MDL_ITEM_73(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_72(ARRAY, __VA_ARGS__)
#define MDL_ITEM_74(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_73(ARRAY, __VA_ARGS__)
#define MDL_ITEM_75(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_74(ARRAY, __VA_ARGS__)
#define MDL_ITEM_76(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_75(ARRAY, __VA_ARGS__)
#define MDL_ITEM_77(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_76(ARRAY, __VA_ARGS__)
#define MDL_ITEM_78(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_77(ARRAY, __VA_ARGS__)
#define MDL_ITEM_79(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_78(ARRAY, __VA_ARGS__)
#define MDL_ITEM_80(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_79(ARRAY, __VA_ARGS__)
#define MDL_ITEM_81(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_80(ARRAY, __VA_ARGS__)
#define MDL_ITEM_82(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_81(ARRAY, __VA_ARGS__)
#define MDL_ITEM_83(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_82(ARRAY, __VA_ARGS__)
#define MDL_ITEM_84(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_83(ARRAY, __VA_ARGS__)
#define MDL_ITEM_85(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_84(ARRAY, __VA_ARGS__)
#define MDL_ITEM_86(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_85(ARRAY, __VA_ARGS__)
#define MDL_ITEM_87(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_86(ARRAY, __VA_ARGS__)
#define MDL_ITEM_88(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_87(ARRAY, __VA_ARGS__)
#define MDL_ITEM_89(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_88(ARRAY, __VA_ARGS__)
#define MDL_ITEM_90(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_89(ARRAY, __VA_ARGS__)
#define MDL_ITEM_91(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_90(ARRAY, __VA_ARGS__)
#define MDL_ITEM_92(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_91(ARRAY, __VA_ARGS__)
#define MDL_ITEM_93(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_92(ARRAY, __VA_ARGS__)
#define MDL_ITEM_94(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_93(ARRAY, __VA_ARGS__)
#define MDL_ITEM_95(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_94(ARRAY, __VA_ARGS__)
#define MDL_ITEM_96(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_95(ARRAY, __VA_ARGS__)
#define MDL_ITEM_97(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_96(ARRAY, __VA_ARGS__)
#define MDL_ITEM_98(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_97(ARRAY, __VA_ARGS__)
#define MDL_ITEM_99(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_98(ARRAY, __VA_ARGS__)
#define MDL_ITEM_100(ARRAY, NAME, ...) MDL_ARRAY_APPEND(ARRAY, NAME) MDL_ITEM_99(ARRAY, __VA_ARGS__)

#define mparams_fill_array(ARRAY, ...) MDL_ITEM(ARRAY, MDL_VA_NARGS(__VA_ARGS__), __VA_ARGS__)

#define MDL_NSEQ() 64,MW_NSEQ()
#define display_fields(...) (char*[NARG_(__VA_ARGS__,MDL_NSEQ())]){__VA_ARGS__, NULL}

typedef struct tm tm_t;

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
    char name[128];
    mvalue_t value;
    mvalue_t oldvalue;
    mtype_e type;
    unsigned dirty : 1;
    unsigned is_null : 1;
    unsigned use_default : 1;
    unsigned use_raw_sql : 1;
} mfield_t;

typedef struct model {
    mfield_t*(*first_field)(void* arg);
    int(*fields_count)(void* arg);
    const char*(*table)(void* arg);
    const char**(*primary_key)(void* arg);
    int(*primary_key_count)(void* arg);
} model_t;

typedef struct modelview {
    mfield_t*(*first_field)(void* arg);
    int(*fields_count)(void* arg);
} modelview_t;

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

void* model_get(const char* dbid, void*(create_instance)(void), array_t* params);
int model_create(const char* dbid, void* arg);
int model_update(const char* dbid, void* arg);
int model_delete(const char* dbid, void* arg);
void* model_one(const char* dbid, void*(create_instance)(void), const char* format, array_t* params);
array_t* model_list(const char* dbid, void*(create_instance)(void), const char* format, array_t* params);
void* model_prepared_one(const char* dbid, void*(create_instance)(void), const char* stat_name, array_t* params);
array_t* model_prepared_list(const char* dbid, void*(create_instance)(void), const char* stat_name, array_t* params);

json_token_t* model_to_json(void* arg, char** display_fields);
char* model_stringify(void* arg, char** display_fields);
char* model_list_stringify(array_t* array);
void model_free(void* arg);




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

#endif
