#ifndef __MPARAMS__
#define __MPARAMS__

#include "mfield.h"

/* ---------------------------------------------------------------------------
 * mparams.h — params-path helpers
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
    void* __mp_fields[] = { __VA_ARGS__ }; \
    for (size_t __mp_i = 0; __mp_i < sizeof(__mp_fields) / sizeof(__mp_fields[0]); __mp_i++) \
        array_push_back(ARRAY, array_create_pointer(__mp_fields[__mp_i], NULL, model_param_free)); \
} while (0);

/* Build a NULL-terminated char*[] of field names for model_to_json /
   model_stringify / send_model. The array size is deduced from the
   initializer, so no argument-counting macro is needed. */
#define display_fields(...) (char*[]){ __VA_ARGS__, NULL }

#endif /* __MPARAMS__ */
