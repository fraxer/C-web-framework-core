#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

/* Test-only preload: fail one selected creation, after earlier threads really
 * started. This exercises rollback of async, scheduler, worker and handler
 * reservations without exhausting the host's thread limit. */
int pthread_create(pthread_t* thread, const pthread_attr_t* attr,
                   void* (*start)(void*), void* arg) {
    static int calls;
    const char* fail_at = getenv("CWFR_TEST_THREAD_FAIL_AT");
    if (fail_at != NULL && calls++ == atoi(fail_at))
        return EAGAIN;

    int (*real_create)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
    *(void**)(&real_create) = dlsym(RTLD_NEXT, "pthread_create");
    return real_create(thread, attr, start, arg);
}
