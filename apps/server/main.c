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

    /* Phase 5 — graceful drain. SIGTERM/SIGINT no longer hard-exit: the app is
     * marked for shutdown, handler threads are released from the queue condvar,
     * and workers are given a best-effort window. On their next timer tick
     * (~500 ms) each worker sends GOAWAY(NO_ERROR) to its h2 peers and lets
     * in-flight streams finish (h2_on_headers refuses new streams once the
     * GOAWAY is out). Workers and handlers decrement appconfig->threads_count
     * as they exit; once it reaches zero — or the grace window elapses — we
     * fall through to the existing terminate. Bounded by design: a slow client
     * cannot stall shutdown indefinitely. */
    {
        appconfig_t* cfg = appconfig();
        const int grace_ms = env_get_int("http2_shutdown_grace_sec", 5) * 1000;
        log_info("shutdown: signal %d received, draining (grace %d ms)\n", sig, grace_ms);
        atomic_store(&cfg->shutdown, 1);
        module_loader_wakeup_all_threads();

        for (int ms = 0; ms < grace_ms; ms += 100) {
            if (atomic_load(&cfg->threads_count) == 0)
                break;
            usleep(100000);
        }
    }

    failed:

    signal_before_terminate(0);

    return result;
}