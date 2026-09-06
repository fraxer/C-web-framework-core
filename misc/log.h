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

/**
 * An error that must reach the operator: written to stderr as well as to the log.
 *
 * log_error() alone can come to nothing. It is dropped entirely while env() is
 * NULL -- which is the case for everything that runs before appconfig_set()
 * publishes a parsed configuration: config validation, application modules,
 * app_init(), middleware registration, the context destructor hooks. And even
 * when it is delivered, vsyslog() reaches the journal, never the terminal, so an
 * operator watching a foreground process sees nothing.
 *
 * Use it where losing the message would leave a failure with no explanation --
 * typically anything that refuses to start or refuses to reload. Ordinary
 * runtime errors belong in log_error(): stderr does not scale to per-request
 * volume, and a daemonised server has nowhere to put it.
 */
void log_error_stderr(const char*, ...);

#endif