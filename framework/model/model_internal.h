#ifndef __MODEL_INTERNAL__
#define __MODEL_INTERNAL__

#include "model.h"

/* Convert tm_t to struct tm for strftime/strptime calls */
struct tm tm_to_strtm(const tm_t* src);

/* Convert struct tm (from strptime) to tm_t, initializing tm_usec to 0 */
void strtm_to_tm(const struct tm* src, tm_t* dst);

/* Parse fractional seconds (1-6 digits), pad with trailing zeros to 6.
   If end is not NULL, sets it to the first non-digit character. */
int parse_usec(const char* str, const char** end);

/* Parse timezone offset: +HH:MM, +HHMM, Z. Returns 1 on success. */
int parse_tz_offset(const char* str, long* gmtoff);

/* Try strptime with both space and T separator */
const char* strptime_flex(const char* value, struct tm* stm);

/* Skip past non-usec/tz characters, parse microseconds, return pointer past them */
const char* parse_datetime_rest(const char* rest, tm_t* tm);

#endif /* __MODEL_INTERNAL__ */
