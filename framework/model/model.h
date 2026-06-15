#ifndef __MODEL__
#define __MODEL__

#include "mfield.h"
#include "mschema.h"
#include "mquery.h"
#include "model_legacy.h"

/* ---------------------------------------------------------------------------
 * model.h — umbrella header for the model framework
 *
 * Pulls in the four layers (mfield / mschema / mquery / legacy) plus the
 * public CRUD and error contract. Existing `#include "model.h"` sites keep
 * working unchanged; new code may include the specific layer it needs.
 * ------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * Error contract (R7)
 *
 * The CRUD/query functions keep their existing returns (NULL / 0/1): a NULL
 * object or a 0 still means "did not succeed". To let a caller tell *why*
 * without changing signatures, each public model operation also records a
 * thread-local status (errno-style). Read it right after the call:
 *
 *   user_t* u = user_get(params);
 *   if (u == NULL) {
 *       if (model_last_status() == MODEL_ERR_NOTFOUND) send_default(404);
 *       else send_default(500); // log model_last_error()
 *   }
 *
 * The status and error text are valid only until the next model operation in
 * the same thread.
 * ------------------------------------------------------------------------- */
typedef enum {
    MODEL_OK = 0,
    MODEL_ERR_NOTFOUND,   /* query ran, returned 0 rows */
    MODEL_ERR_DB,         /* driver/query error (see model_last_error) */
    MODEL_ERR_PARAM,      /* invalid arguments (NULL dbid/arg, empty params) */
    MODEL_ERR_ALLOC       /* out of memory / value conversion failure */
} model_status_e;

model_status_e model_last_status(void);  /* status of the last op in this thread */
const char*    model_last_error(void);   /* DB error text for MODEL_ERR_DB, else NULL */

void* model_get(const char* dbid, void*(create_instance)(void), array_t* params);
int model_create(const char* dbid, void* arg);
int model_update(const char* dbid, void* arg);
int model_delete(const char* dbid, void* arg);
int model_delete_by_params(const char* dbid, void* arg, array_t* params);
void* model_one(const char* dbid, void*(create_instance)(void), const char* format, array_t* params);
array_t* model_list(const char* dbid, void*(create_instance)(void), const char* format, array_t* params);
void* model_prepared_one(const char* dbid, void*(create_instance)(void), const char* stat_name, const char* sql, array_t* params);
array_t* model_prepared_list(const char* dbid, void*(create_instance)(void), const char* stat_name, const char* sql, array_t* params);
json_token_t* model_to_json(void* arg, char** display_fields);
char* model_stringify(void* arg, char** display_fields);
char* model_list_stringify(array_t* array);
void model_free(void* arg);

#endif /* __MODEL__ */
