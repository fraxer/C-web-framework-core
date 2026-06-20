/* Stub for taskmanager_async_with_free, referenced by mail.c's send_mail_async.
 *
 * The unit-test runner links the calc-only taskmanager_calc.c (which provides
 * the scheduling-math helpers but not the async dispatch path). send_mail_async
 * itself is not exercised by the mail unit tests — it needs a live task manager
 * and network — so a minimal stub satisfies the linker without pulling in the
 * full taskmanager.c (which would duplicate symbols with taskmanager_calc.c).
 *
 * Returns 0 ("not queued"): callers that use the real function treat failure as
 * "clean up the payload yourself", which is the correct outcome for an untested
 * path. No test invokes it. */
#include <sys/types.h> /* ssize_t, pulled in transitively everywhere except this isolated TU */

#include "taskmanager.h"

int taskmanager_async_with_free(task_fn_t run, void* data, task_free_fn_t free_fn) {
    (void)run;
    (void)data;
    (void)free_fn;
    return 0;
}
