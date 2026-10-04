#ifndef __POSTGRESQL_VIEW_INTERNAL__
#define __POSTGRESQL_VIEW_INTERNAL__

#include "dbresult_view_internal.h"

/* Driver dispatch without extending the published dbconnection_t layout. */
int postgresql_view_supported(const dbconnection_t*);
void postgresql_execute_params_view(dbconnection_t*, const char*, array_t*, dbresult_view_t*);
/* Consumes the entire pending protocol; also used by driver integration tests. */
void postgresql_process_result_view(dbconnection_t*, dbresult_view_t*);

#endif
