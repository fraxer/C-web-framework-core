#ifndef __MODEL_LEGACY__
#define __MODEL_LEGACY__

#include "mfield.h"

/* ---------------------------------------------------------------------------
 * model_legacy.h — params-path helpers
 *
 * mparams_fill_array pushes each named parameter (produced by the mparam_*
 * macros, which expand to field_create_* calls) into an array_t*, wrapping
 * every entry so model_param_free runs when the array is freed. It serves the
 * remaining params-path callers: dbquery(:name) raw-SQL parameters and
 * model_delete_by_params.
 *
 * The argument count is resolved at runtime via a stack array + loop, so there
 * is no fixed ceiling and no per-N overload enumeration.
 * ------------------------------------------------------------------------- */

#define mparams_fill_array(ARRAY, ...) do { \
    void* __mdl_fields[] = { __VA_ARGS__ }; \
    for (size_t __mdl_i = 0; __mdl_i < sizeof(__mdl_fields) / sizeof(__mdl_fields[0]); __mdl_i++) \
        array_push_back(ARRAY, array_create_pointer(__mdl_fields[__mdl_i], NULL, model_param_free)); \
} while (0);

/* Build a NULL-terminated char*[] of field names for model_to_json /
   model_stringify / send_model. The array size is deduced from the
   initializer, so no argument-counting macro is needed. */
#define display_fields(...) (char*[]){ __VA_ARGS__, NULL }

#endif /* __MODEL_LEGACY__ */
