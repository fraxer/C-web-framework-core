#include "appconfig.h"

#include <stdlib.h>

/* The broad runner happens to gets these from an HTTP/1 parser test.  The
 * protocol-only runner must not depend on another suite's link side effects. */
static appconfig_t* test_appconfig;

static void ensure_config(void) {
    if (test_appconfig != NULL) return;
    test_appconfig = calloc(1, sizeof *test_appconfig);
    if (test_appconfig != NULL) {
        test_appconfig->env.main.tmp = "/tmp";
        test_appconfig->env.main.client_max_body_size = 1024 * 1024;
    }
}

appconfig_t* appconfig(void) {
    ensure_config();
    return test_appconfig;
}

env_t* env(void) {
    ensure_config();
    return test_appconfig != NULL ? &test_appconfig->env : NULL;
}

void appconfig_set(appconfig_t* config) {
    test_appconfig = config;
}
