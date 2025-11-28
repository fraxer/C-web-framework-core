#ifndef __LOG__
#define __LOG__

#include <stdarg.h>

void log_init();

void log_close();

void log_reinit();

void log_emerg(const char*, ...);

void log_alert(const char*, ...);

void log_crit(const char*, ...);

void log_error(const char*, ...);

void log_warning(const char*, ...);

void log_notice(const char*, ...);

void log_info(const char*, ...);

void log_debug(const char*, ...);

#endif