#include <stdio.h>
#include <syslog.h>

#include "log.h"
#include "appconfig.h"

void log_init() {
    openlog(NULL, LOG_CONS | LOG_NDELAY, LOG_USER);
}

void log_close() {
    closelog();
}

void log_reinit() {
    log_close();
    log_init();
}

static void log_message(int priority, const char* format, va_list args) {
    env_t* environment = env();
    if (environment == NULL) return;

    if (!environment->main.log.enabled) return;

    if (priority > environment->main.log.level) return;

    vsyslog(priority, format, args);
}

void log_emerg(const char* format, ...) {
    va_list args;

    va_start(args, format);

    log_message(LOG_EMERG, format, args);

    va_end(args);
}

void log_alert(const char* format, ...) {
    va_list args;

    va_start(args, format);

    log_message(LOG_ALERT, format, args);

    va_end(args);
}

void log_crit(const char* format, ...) {
    va_list args;

    va_start(args, format);

    log_message(LOG_CRIT, format, args);

    va_end(args);
}

void log_error(const char* format, ...) {
    va_list args;

    va_start(args, format);

    log_message(LOG_ERR, format, args);

    va_end(args);
}

void log_warning(const char* format, ...) {
    va_list args;

    va_start(args, format);

    log_message(LOG_WARNING, format, args);

    va_end(args);
}

void log_notice(const char* format, ...) {
    va_list args;

    va_start(args, format);

    log_message(LOG_NOTICE, format, args);

    va_end(args);
}

void log_info(const char* format, ...) {
    va_list args;

    va_start(args, format);

    log_message(LOG_INFO, format, args);

    va_end(args);
}

void log_debug(const char* format, ...) {
    va_list args;

    va_start(args, format);

    log_message(LOG_DEBUG, format, args);

    va_end(args);
}
