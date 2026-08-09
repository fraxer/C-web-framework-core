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

    if (!appconfig_foreground() &&
        (strcmp(CMAKE_BUILD_TYPE, "Release") == 0 ||
         strcmp(CMAKE_BUILD_TYPE, "RelWithDebInfo") == 0))
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
        /* Before the flag the workers watch: they read both in the same pass,
         * and a worker that saw `shutdown` without `terminating` would take the
         * reload path and leave its listeners open. */
        appconfig_set_terminating();
        atomic_store(&cfg->shutdown, 1);
        module_loader_wakeup_all_threads();

        /* Poll appconfig_threads_alive(), not cfg->threads_count: the thread that
         * takes the count to zero frees cfg on its way out, so reading the
         * in-config counter here is a use-after-free. */
        for (int ms = 0; ms < grace_ms; ms += 100) {
            if (appconfig_threads_alive() == 0)
                break;
            usleep(100000);
        }

        /* A thread that outlived the grace window is still inside library code.
         * The ThreadSanitizer report that prompted this shows a worker in
         * OpenSSL -- freeing a connection's TLS state -- while this thread tears
         * OpenSSL down: exit() runs OPENSSL_cleanup from an atexit handler, and
         * every other destructor with it.
         *
         * _exit() runs none of them, and that is the only safe answer here. The
         * threads cannot be joined (they are detached), and killing them
         * mid-work would be worse than letting them run. Nothing is lost by
         * skipping the teardown: the process is ending, and the kernel reclaims
         * everything a destructor would have freed. The clean path below still
         * goes through exit(), so a leak checker's report survives on the only
         * path where it means anything.
         *
         * Reaching this is normal today rather than exceptional -- see the note
         * on the drain below -- which is why it must be correct and not merely
         * defensive. */
        const int alive = appconfig_threads_alive();
        if (alive != 0) {
            log_error("shutdown: %d thread(s) still running after the %d ms grace "
                      "window; exiting without running destructors\n", alive, grace_ms);
            fflush(NULL);
            _exit(result);
        }

        /* Every thread has gone, and the last one out freed the configuration
         * (appconfg_threads_decrement). The global env() hands out still points
         * at it, and everything that logs reads env() -- so the teardown below
         * would log through freed memory. ASan reported exactly that the moment
         * the drain started completing; while it never did, nothing freed the
         * config and the bug stayed hidden.
         *
         * Cleared here rather than inside appconfig_free: this thread is the
         * only one left, so there is nobody to race with, and the reload path --
         * where the global already points at the replacement config -- is not
         * touched at all. The cost is the final log line, which env() now
         * refuses to emit; everything worth saying was said above. */
        appconfig_set(NULL);
    }

    failed:

    signal_before_terminate(0);

    return result;
}