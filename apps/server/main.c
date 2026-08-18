#define _GNU_SOURCE
#include <errno.h>
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

/* Detach from the terminal, but keep the caller's exit status honest.
 *
 * `daemon(1, 1)` was the whole of this, and it made a Release build report
 * success for a configuration it had not read yet: the parent returned the
 * moment it forked, while the child went on to parse the config, fail, print
 * the reason and exit 1 where nobody was looking. `cwfr -c broken.json` printed
 * an error and exited 0, so every wrapper that tests `$?` -- a service unit, a
 * deploy script, `&&` in a shell -- treated a server that never started as a
 * server that had.
 *
 * So the parent does not exit on the fork; it waits to be told. The child writes
 * one byte once the configuration has been applied *and every worker is
 * listening* -- the second half being the startup barrier in appconfig.h, without
 * which this would still have reported success for a server whose sockets failed
 * to bind. Nothing is written on a failure path: the child's exit closes the
 * descriptor, and the read ends in EOF, which is the same answer without a single
 * error path having to remember to report itself.
 *
 * Deliberately unbounded. A timeout would have to choose between calling a slow
 * but successful start a failure and calling a hung one a success, and both are
 * the lie this exists to remove. The child cannot hang silently: if it dies, the
 * descriptor closes.
 *
 * Returns the descriptor the child must signal readiness on, or -1 when there is
 * nothing to signal (foreground, or a build that does not daemonise). */
static int __daemonize(void) {
    if (appconfig_foreground() ||
        (strcmp(CMAKE_BUILD_TYPE, "Release") != 0 &&
         strcmp(CMAKE_BUILD_TYPE, "RelWithDebInfo") != 0))
        return -1;

    int ready[2];
    if (pipe(ready) == -1) {
        log_error("daemonize: cannot create the readiness pipe (errno %d)\n", errno);
        _exit(EXIT_FAILURE);
    }

    const pid_t pid = fork();
    if (pid == -1) {
        log_error("daemonize: fork failed (errno %d)\n", errno);
        _exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        close(ready[1]);

        char byte = 0;
        ssize_t n;
        do {
            n = read(ready[0], &byte, 1);
        } while (n == -1 && errno == EINTR);

        close(ready[0]);

        /* _exit, not exit: the child inherited this process's stdio buffers, so
         * flushing them here would print whatever was buffered a second time,
         * from the other process. */
        _exit(n == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    close(ready[0]);

    /* Same as daemon(1, 1) did: a new session, and the standard descriptors left
     * alone so that a configuration error still reaches the terminal the server
     * was started from. */
    if (setsid() == -1)
        log_error("daemonize: setsid failed (errno %d)\n", errno);

    return ready[1];
}

int main(int argc, char* argv[]) {
    int result = EXIT_FAILURE;

    if (!appconfig_init(argc, argv))
        goto failed;

    log_init();
    signal_init();

    const int ready_fd = __daemonize();

    /* Block control signals before module_loader_init creates any threads.
     * They inherit this mask, leaving the main thread's sigwait() as the sole
     * consumer. In particular, reload no longer parses JSON, allocates memory
     * or starts workers from an asynchronous signal handler. */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0)
        goto failed;

    if (!module_loader_init(appconfig()))
        goto failed;

    /* module_loader_init returns as soon as the workers have been created, and
     * each worker binds its own listening sockets afterwards -- so this is where
     * "the server started" actually becomes true or false (appconfig.h).
     *
     * _exit rather than the failed label: the other workers are being shut down
     * by the one that failed, so threads are still live, and exit() would run
     * OPENSSL_cleanup and every other destructor underneath them -- the hazard
     * the drain below documents. Nothing is lost by skipping the teardown of a
     * process that is refusing to start, and the closed readiness descriptor is
     * what the waiting parent turns into its own non-zero status. */
    if (!appconfig_wait_workers()) {
        log_error("startup: a worker could not start; the server is not listening\n");
        fflush(NULL);
        _exit(EXIT_FAILURE);
    }

    result = EXIT_SUCCESS;

    /* Configuration applied and every worker listening: the parent may stop
     * waiting, and its exit status now means what a caller reads it to mean. */
    if (ready_fd != -1) {
        const char byte = 1;
        ssize_t n;
        do {
            n = write(ready_fd, &byte, 1);
        } while (n == -1 && errno == EINTR);

        close(ready_fd);
    }

    int sig;
    for (;;) {
        if (sigwait(&mask, &sig) != 0)
            continue;

        if (sig == SIGUSR1) {
            signal_reload();
            continue;
        }

        break;
    }

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

    signal_before_terminate(result);

    return result;
}
