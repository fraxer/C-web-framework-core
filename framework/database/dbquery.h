#ifndef __DBQUERY__
#define __DBQUERY__

#include "array.h"
#include "database.h"
#include "str.h"
#include "model.h"

dbinstance_t* dbinstance(const char* dbid);
void dbinstance_free(dbinstance_t* instance);
dbresult_t* dbqueryf(const char* dbid, const char*, ...);
dbresult_t* dbquery(const char* dbid, const char* format, array_t* params);
dbresult_t* dbprepared_query(const char* dbid, const char* stmt_name, array_t* params);
dbresult_t* dbtable_exist(const char* dbid, const char* table);
dbresult_t* dbtable_migration_create(const char* dbid, const char* table);
dbresult_t* dbbegin(const char* dbid, transaction_level_e level);
dbresult_t* dbcommit(const char* dbid);
dbresult_t* dbrollback(const char* dbid);
dbresult_t* dbinsert(const char* dbid, const char* table, array_t* params);
dbresult_t* dbupdate(const char* dbid, const char* table, array_t* set, array_t* where);
dbresult_t* dbdelete(const char* dbid, const char* table, array_t* where);
dbresult_t* dbselect(const char* dbid, const char* table, array_t* columns, array_t* where);
int dbexec(const char* dbid, const char* format, array_t* params);
int dbprepared_exec(const char* dbid, const char* stmt_name, array_t* params);


/**
 * Check if a string starts with a given substring
 *
 * @param string The string to check (must not be NULL)
 * @param substring The substring to search for (must not be NULL)
 * @return 1 if string starts with substring, 0 otherwise (also returns 0 if either parameter is NULL)
 *
 * Security note: NULL parameters are safely handled and return 0 (false)
 */
int starts_with_substr(const char* string, const char* substring);
int process_value(dbconnection_t* connection, char parameter_type, str_t* string, str_t* value);
int ispunct_custom(int c);

/**
 * Callback function type for processing SQL parameters
 * Called for each found parameter during SQL parsing
 *
 * @param connection DB connection
 * @param parameter_type ':' for prepared statements or '@' for immediate substitution
 * @param param_name Parameter name (without ':' or '@' prefix, without 'list__' prefix if is_in=1)
 * @param field Found model field
 * @param is_in 1 if this is a list__ array parameter, 0 otherwise
 * @param result_sql Result string where processor should append processed content
 * @param user_data User-defined data (e.g., param_order array for prepared statements)
 * @return 1 if successful, 0 on error (will trigger cleanup and return NULL)
 */
typedef int (*sql_param_processor_t)(
    void* connection,
    char parameter_type,
    const char* param_name,
    mfield_t* field,
    str_t* result_sql,
    void* user_data
);

/**
 * Common SQL parameter parsing function
 * Parses SQL string and calls processor callback for each found parameter
 * Handles string literals, comments, and parameter detection
 *
 * @param connection DB connection
 * @param query SQL query string
 * @param query_size Length of query
 * @param params Array of model fields (parameters)
 * @param processor Callback function to handle each found parameter
 * @param user_data User data passed to processor callback
 * @return Processed SQL string or NULL on error
 */
str_t* parse_sql_parameters(
    void* connection,
    const char* query,
    size_t query_size,
    array_t* params,
    sql_param_processor_t processor,
    void* user_data
);

#endif