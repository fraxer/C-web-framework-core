#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <linux/limits.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "appconfig.h"
#include "moduleloader.h"
#include "log.h"
#include "signal/signal.h"

int main(int argc, char* argv[]) {
    int result = EXIT_FAILURE;

    if (!appconfig_init(argc, argv))
        goto failed;

    log_init();
    signal_init();

    if (strcmp(CMAKE_BUILD_TYPE, "Release") == 0 || strcmp(CMAKE_BUILD_TYPE, "RelWithDebInfo") == 0)
        if (daemon(1, 1) < 0) goto failed;

    if (!module_loader_init(appconfig()))
        goto failed;

    result = EXIT_SUCCESS;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    int sig;
    sigwait(&mask, &sig);

    failed:

    signal_before_terminate(0);

    return result;
}