#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log.h"
#include "shadowload.h"

#define SHADOW_PREFIX ".cwfr-shadow-"
#define SHADOW_COPY_BUFFER 65536

/* What the file at `path` looked like when this last decided how to load it,
 * and the copy it decided on -- NULL when the answer was "straight from
 * `path`". The four stat fields together are what "the same file" means here: a
 * rebuild changes the inode, a `cp` over the path keeps it and changes mtime
 * and size.
 *
 * `copy` is what makes the decision stable across repeated loads of one file
 * state, and that matters because a reload loads everything twice: once in
 * module_loader_config_correct(), to find out whether the configuration is
 * usable at all, and once for real. The first pass throws its generation away,
 * dlclose included -- so without remembering the copy, the second pass would
 * see a file it had already accounted for and hand back the *old* object.
 * Reusing the copy also means an unchanged file costs nothing on later reloads:
 * dlopen of the same copy is the same object with one more reference, which is
 * exactly how two generations come to share a library. */
typedef struct shadow_entry {
    char* path;
    char* copy;
    dev_t dev;
    ino_t ino;
    time_t mtime;
    long mtime_nsec;
    off_t size;
    struct shadow_entry* next;
} shadow_entry_t;

typedef struct shadow_name {
    char* path;
    struct shadow_name* next;
} shadow_name_t;

static shadow_entry_t* __entries = NULL;
/* Copies made by this process, unlinked by shadow_cleanup() on the way out. */
static shadow_name_t* __copies = NULL;
/* Directories already swept for other processes' leftovers -- once each. */
static shadow_name_t* __swept = NULL;
static unsigned long __sequence = 0;
static char __error[1024] = {0};

static shadow_entry_t* __shadow_entry_find(const char* path) {
    for (shadow_entry_t* entry = __entries; entry != NULL; entry = entry->next)
        if (strcmp(entry->path, path) == 0)
            return entry;

    return NULL;
}

static int __shadow_changed(const shadow_entry_t* entry, const struct stat* st) {
    return entry->dev != st->st_dev
        || entry->ino != st->st_ino
        || entry->mtime != st->st_mtim.tv_sec
        || entry->mtime_nsec != st->st_mtim.tv_nsec
        || entry->size != st->st_size;
}

static void __shadow_entry_store(shadow_entry_t* entry, const struct stat* st) {
    entry->dev = st->st_dev;
    entry->ino = st->st_ino;
    entry->mtime = st->st_mtim.tv_sec;
    entry->mtime_nsec = st->st_mtim.tv_nsec;
    entry->size = st->st_size;
}

/* Remembering the file is best effort: failing to allocate here costs the next
 * reload a change it will not notice, which is the behaviour this whole file
 * replaces -- not a reason to refuse a load that has already succeeded. */
static void __shadow_entry_update(const char* path, const struct stat* st, const char* copy) {
    shadow_entry_t* entry = __shadow_entry_find(path);

    if (entry == NULL) {
        entry = malloc(sizeof * entry);
        if (entry == NULL) return;

        entry->path = strdup(path);
        if (entry->path == NULL) {
            free(entry);
            return;
        }

        entry->copy = NULL;
        entry->next = __entries;
        __entries = entry;
    }

    free(entry->copy);
    entry->copy = copy == NULL ? NULL : strdup(copy);

    __shadow_entry_store(entry, st);
}

static int __shadow_name_remember(shadow_name_t** list, const char* path) {
    shadow_name_t* name = malloc(sizeof * name);
    if (name == NULL) return 0;

    name->path = strdup(path);
    if (name->path == NULL) {
        free(name);
        return 0;
    }

    name->next = *list;
    *list = name;

    return 1;
}

static int __shadow_name_known(shadow_name_t* list, const char* path) {
    for (; list != NULL; list = list->next)
        if (strcmp(list->path, path) == 0)
            return 1;

    return 0;
}

static void __shadow_name_free(shadow_name_t** list) {
    shadow_name_t* name = *list;

    while (name != NULL) {
        shadow_name_t* next = name->next;

        free(name->path);
        free(name);

        name = next;
    }

    *list = NULL;
}

/* Directory of `path` without its trailing slash, "." when it has none. */
static int __shadow_dirname(const char* path, char* buffer, size_t size) {
    const char* slash = strrchr(path, '/');

    if (slash == NULL) {
        if (size < 2) return 0;
        buffer[0] = '.';
        buffer[1] = 0;
        return 1;
    }

    /* "/lib.so" -- the directory is the root slash itself. */
    size_t length = (slash == path) ? 1 : (size_t)(slash - path);
    if (length + 1 > size) return 0;

    memcpy(buffer, path, length);
    buffer[length] = 0;

    return 1;
}

static const char* __shadow_basename(const char* path) {
    const char* slash = strrchr(path, '/');

    return slash == NULL ? path : slash + 1;
}

/* Store `message` with every mention of the copy replaced by the real path:
 * dlerror() names the file the loader opened, and that name means nothing to
 * whoever wrote the config. Both may be NULL, for the plain-dlopen path. */
static void __shadow_error_set(const char* message, const char* copy, const char* real) {
    if (message == NULL) {
        __error[0] = 0;
        return;
    }

    if (copy == NULL || real == NULL) {
        snprintf(__error, sizeof __error, "%s", message);
        return;
    }

    const size_t copy_length = strlen(copy);
    size_t out = 0;

    for (const char* in = message; *in != 0 && out + 1 < sizeof __error; ) {
        if (strncmp(in, copy, copy_length) == 0) {
            const int written = snprintf(__error + out, sizeof __error - out, "%s", real);
            if (written < 0) break;
            out += (size_t)written;
            if (out + 1 >= sizeof __error) break;
            in += copy_length;
            continue;
        }

        __error[out++] = *in++;
    }

    __error[out < sizeof __error ? out : sizeof __error - 1] = 0;
}

static void __shadow_error_setf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(__error, sizeof __error, format, args);
    va_end(args);
}

static int __shadow_pid_alive(pid_t pid) {
    if (kill(pid, 0) == 0) return 1;

    /* EPERM is a live process owned by somebody else -- as good a reason to
     * leave its file alone as EACCES would be a reason not to touch it. */
    return errno != ESRCH;
}

/* Drop `.cwfr-shadow-*` files left by processes that are gone: a kill -9 or a
 * crash never reaches shadow_cleanup(). Once per directory per process, which
 * in practice means once at startup for each directory handlers are loaded
 * from, and nothing on a reload. */
static void __shadow_sweep(const char* dir) {
    if (dir == NULL || __shadow_name_known(__swept, dir)) return;

    /* Remembered before the sweep, not after: a directory that cannot be read
     * should not be re-opened on every single load either. */
    __shadow_name_remember(&__swept, dir);

    DIR* handle = opendir(dir);
    if (handle == NULL) return;

    const pid_t self = getpid();
    const size_t prefix_length = strlen(SHADOW_PREFIX);
    struct dirent* item = NULL;

    while ((item = readdir(handle)) != NULL) {
        if (strncmp(item->d_name, SHADOW_PREFIX, prefix_length) != 0) continue;

        const char* digits = item->d_name + prefix_length;
        if (!isdigit((unsigned char)*digits)) continue;

        const pid_t owner = (pid_t)strtol(digits, NULL, 10);
        if (owner == self || __shadow_pid_alive(owner)) continue;

        char path[PATH_MAX];
        if (snprintf(path, sizeof path, "%s/%s", dir, item->d_name) >= (int)sizeof path)
            continue;

        if (unlink(path) == 0)
            log_info("shadow_dlopen: removed a stale copy %s left by pid %d\n", path, (int)owner);
    }

    closedir(handle);
}

static int __shadow_copy_bytes(const char* source, const char* destination) {
    const int in = open(source, O_RDONLY | O_CLOEXEC);
    if (in == -1) return 0;

    /* O_EXCL: the name carries this pid and a counter, so an existing file is
     * somebody else's or a leftover, and either way not ours to overwrite.
     * 0700 -- a debugger reads it through /proc/PID/maps as the owner, and
     * dlopen needs no execute bit on the file itself. */
    const int out = open(destination, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    if (out == -1) {
        const int saved = errno;
        close(in);
        errno = saved;
        return 0;
    }

    char buffer[SHADOW_COPY_BUFFER];
    int result = 1;

    for (;;) {
        const ssize_t got = read(in, buffer, sizeof buffer);
        if (got == 0) break;
        if (got == -1) {
            if (errno == EINTR) continue;
            result = 0;
            break;
        }

        ssize_t written = 0;
        while (written < got) {
            const ssize_t n = write(out, buffer + written, (size_t)(got - written));
            if (n == -1) {
                if (errno == EINTR) continue;
                result = 0;
                break;
            }
            written += n;
        }

        if (!result) break;
    }

    int saved = errno;

    if (close(out) == -1) {
        result = 0;
        saved = errno;
    }
    close(in);

    if (!result) {
        unlink(destination);
        errno = saved;
    }

    return result;
}

static int __shadow_copy_name(const char* dir, const char* source, char* buffer, size_t size) {
    const int written = snprintf(buffer, size, "%s/%s%d-%lu-%s",
                                 dir, SHADOW_PREFIX, (int)getpid(), __sequence,
                                 __shadow_basename(source));

    return written > 0 && (size_t)written < size;
}

static int __shadow_copy_into(const char* dir, const char* path, char* buffer, size_t size) {
    /* Retried on a name that is taken, which only a leftover from a dead process
     * that once had this pid can be -- the sweep leaves this process's own files
     * alone. Rare, and not worth losing $ORIGIN over. */
    for (int attempt = 0; attempt < 32; attempt++) {
        __sequence++;

        if (!__shadow_copy_name(dir, path, buffer, size))
            return 0;
        if (__shadow_copy_bytes(path, buffer))
            return 1;
        if (errno != EEXIST)
            return 0;
    }

    return 0;
}

/* Next to the original first -- that is what keeps $ORIGIN in the object's
 * RPATH pointing at the directory its private dependencies live in. `tmpdir` is
 * the answer for a read-only /opt, and costs exactly that: dependencies looked
 * up through $ORIGIN are no longer found, so it is said out loud. */
static int __shadow_make_copy(const char* path, const char* dir, const char* tmpdir,
                              char* buffer, size_t size) {
    if (__shadow_copy_into(dir, path, buffer, size))
        return 1;

    const int reason = errno;
    if (tmpdir == NULL || strcmp(tmpdir, dir) == 0) {
        __shadow_error_setf("cannot write a shadow copy of %s into %s: %s",
                            path, dir, strerror(reason));
        return 0;
    }

    __shadow_sweep(tmpdir);

    if (!__shadow_copy_into(tmpdir, path, buffer, size)) {
        __shadow_error_setf("cannot write a shadow copy of %s into %s (%s) or into %s: %s",
                            path, dir, strerror(reason), tmpdir, strerror(errno));
        return 0;
    }

    log_error_stderr("shadow_dlopen: %s is not writable, so the reloaded copy of %s went to "
                     "%s -- $ORIGIN in its RPATH now points there, and private libraries "
                     "next to the original will not be found\n", dir, path, tmpdir);

    return 1;
}

void* shadow_dlopen(const char* path, int flags, const char* tmpdir) {
    __error[0] = 0;

    if (path == NULL) {
        __shadow_error_setf("shadow_dlopen: path is NULL");
        return NULL;
    }

    char dir[PATH_MAX];
    if (__shadow_dirname(path, dir, sizeof dir))
        __shadow_sweep(dir);

    struct stat st;
    if (stat(path, &st) != 0) {
        /* Let dlopen produce the canonical "no such file" for the real path. */
        void* handle = dlopen(path, flags);
        if (handle == NULL) __shadow_error_set(dlerror(), NULL, NULL);
        return handle;
    }

    shadow_entry_t* entry = __shadow_entry_find(path);

    /* A file whose state this has already decided about: repeat the decision,
     * straight from the path or from the copy made for exactly this file -- see
     * shadow_entry_t on why repeating matters. The one exception is a copy that
     * has since been removed from disk: making a new one is right, and quietly
     * falling back to `path` would hand back the old object. */
    const int repeatable = entry != NULL && !__shadow_changed(entry, &st)
        && (entry->copy == NULL || access(entry->copy, R_OK) == 0);

    if (repeatable) {
        const char* target = entry->copy == NULL ? path : entry->copy;

        void* handle = dlopen(target, flags);
        if (handle == NULL)
            __shadow_error_set(dlerror(), entry->copy, entry->copy == NULL ? NULL : path);

        return handle;
    }

    /* Both conditions, in this order (docs/hotreload/00-shadow-copy.md §3.1):
     * the file changed, and the path is still loaded in this process. When
     * nothing holds the old object any more -- its generation has been freed --
     * a plain dlopen reads the new file, and copying would be pure cost. */
    int loaded = 0;
    if (entry != NULL) {
        void* probe = dlopen(path, RTLD_LAZY | RTLD_NOLOAD);
        if (probe != NULL) {
            /* RTLD_NOLOAD hands out a reference like any other dlopen. */
            dlclose(probe);
            loaded = 1;
        }
    }

    if (!loaded) {
        void* handle = dlopen(path, flags);
        if (handle == NULL) {
            __shadow_error_set(dlerror(), NULL, NULL);
            return NULL;
        }

        __shadow_entry_update(path, &st, NULL);

        return handle;
    }

    char copy[PATH_MAX];
    if (!__shadow_make_copy(path, dir, tmpdir, copy, sizeof copy))
        return NULL;

    void* handle = dlopen(copy, flags);
    if (handle == NULL) {
        /* Most likely the copy was taken while the linker was still writing the
         * file: it unlinks and re-creates, so between O_TRUNC and the last byte
         * the path holds a truncated ELF (§7). Refusing the load is the right
         * answer -- the caller keeps the old configuration -- and the next
         * reload sees a different stat and copies the finished file. */
        __shadow_error_set(dlerror(), copy, path);
        unlink(copy);
        return NULL;
    }

    __shadow_entry_update(path, &st, copy);

    if (!__shadow_name_remember(&__copies, copy)) {
        /* Nothing is broken, the file just has nobody to remove it at exit. */
        log_error("shadow_dlopen: out of memory recording the copy %s; it will be left "
                  "behind and removed by the next start\n", copy);
    }

    log_info("shadow_dlopen: %s was rebuilt; loaded it through %s\n", path, copy);

    return handle;
}

const char* shadow_dlerror(void) {
    return __error[0] == 0 ? NULL : __error;
}

void shadow_cleanup(void) {
    for (shadow_name_t* copy = __copies; copy != NULL; copy = copy->next)
        unlink(copy->path);

    __shadow_name_free(&__copies);
    __shadow_name_free(&__swept);

    shadow_entry_t* entry = __entries;
    while (entry != NULL) {
        shadow_entry_t* next = entry->next;

        free(entry->path);
        free(entry->copy);
        free(entry);

        entry = next;
    }

    __entries = NULL;
}
