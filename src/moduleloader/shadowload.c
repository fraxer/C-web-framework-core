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
#include "elfsoname.h"
#include "shadowload.h"

#define SHADOW_PREFIX ".cwfr-shadow-"
#define SHADOW_COPY_BUFFER 65536
/* Renames that apply to one file, as text. Long enough for any realistic
 * application: truncation would only cost an extra copy, never a wrong load. */
#define SHADOW_STAMP_MAX 1024
#define SHADOW_TAG_ALPHABET "0123456789abcdefghijklmnopqrstuvwxyz"
#define SHADOW_TAG_BASE 36

/* What the file at `path` looked like when this last decided how to load it,
 * the copy it decided on -- NULL when the answer was "straight from `path`" --
 * and the renames that copy carries. The four stat fields together are what
 * "the same file" means here: a rebuild changes the inode, a `cp` over the path
 * keeps it and changes mtime and size.
 *
 * `copy` and `stamp` are what make the decision stable across repeated loads of
 * one file state, and that matters because a reload loads everything twice:
 * once in module_loader_config_correct(), to find out whether the configuration
 * is usable at all, and once for real. The first pass throws its generation
 * away, dlclose included -- so without remembering, the second pass would see a
 * file it had already accounted for and hand back the *old* object. Reusing the
 * copy also means an unchanged file costs nothing on later reloads: dlopen of
 * the same copy is the same object with one more reference, which is exactly how
 * two generations come to share a library. */
typedef struct shadow_entry {
    char* path;
    char* copy;
    char* stamp;
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

typedef struct shadow_soname {
    char* original;
    char* tagged;
    struct shadow_soname* next;
} shadow_soname_t;

struct shadow_sonames {
    shadow_soname_t* first;
};

static shadow_entry_t* __entries = NULL;
/* Copies made by this process, unlinked by shadow_cleanup() on the way out. */
static shadow_name_t* __copies = NULL;
/* Directories already swept for other processes' leftovers -- once each. */
static shadow_name_t* __swept = NULL;
static unsigned long __sequence = 0;
static char __error[1024] = {0};
/* The last load failed because a copy could not be retagged, and renaming has
 * been turned off for the rest of this process, respectively. */
static int __retag_refused = 0;
static int __retag_disabled = 0;

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
static void __shadow_entry_update(const char* path, const struct stat* st,
                                  const char* copy, const char* stamp) {
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
        entry->stamp = NULL;
        entry->next = __entries;
        __entries = entry;
    }

    free(entry->copy);
    entry->copy = copy == NULL ? NULL : strdup(copy);

    free(entry->stamp);
    entry->stamp = strdup(stamp);

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

/* ---- SONAME renames --------------------------------------------------- */

shadow_sonames_t* shadow_sonames_create(void) {
    shadow_sonames_t* map = malloc(sizeof * map);
    if (map == NULL) return NULL;

    map->first = NULL;

    return map;
}

void shadow_sonames_free(shadow_sonames_t* map) {
    if (map == NULL) return;

    shadow_soname_t* item = map->first;
    while (item != NULL) {
        shadow_soname_t* next = item->next;

        free(item->original);
        free(item->tagged);
        free(item);

        item = next;
    }

    free(map);
}

int shadow_sonames_empty(const shadow_sonames_t* map) {
    return map == NULL || map->first == NULL;
}

static const char* __shadow_sonames_lookup(const char* name, void* arg) {
    const shadow_sonames_t* map = arg;
    if (map == NULL) return NULL;

    for (const shadow_soname_t* item = map->first; item != NULL; item = item->next)
        if (strcmp(item->original, name) == 0)
            return item->tagged;

    return NULL;
}

/* Is any library already loaded under this name? The loader is the authority and
 * needs no help from us: a tag is in use exactly while a generation holding it
 * is alive, and it is released by the dlclose that unloads that generation -- on
 * a worker thread, where bookkeeping of our own would have needed a lock. */
static int __shadow_soname_taken(const shadow_sonames_t* map, const char* candidate) {
    for (const shadow_soname_t* item = map->first; item != NULL; item = item->next)
        if (strcmp(item->original, candidate) == 0 || strcmp(item->tagged, candidate) == 0)
            return 1;

    void* handle = dlopen(candidate, RTLD_LAZY | RTLD_NOLOAD);
    if (handle == NULL) return 0;

    dlclose(handle);

    return 1;
}

const char* shadow_sonames_tagged(const shadow_sonames_t* map, const char* soname) {
    return __shadow_sonames_lookup(soname, (void*)map);
}

static int __shadow_sonames_put(shadow_sonames_t* map, const char* original,
                                const char* tagged, char* reason, size_t reason_size) {
    shadow_soname_t* item = malloc(sizeof * item);
    if (item == NULL) {
        snprintf(reason, reason_size, "memory alloc error for the SONAME map");
        return 0;
    }

    item->original = strdup(original);
    item->tagged = strdup(tagged);
    if (item->original == NULL || item->tagged == NULL) {
        free(item->original);
        free(item->tagged);
        free(item);
        snprintf(reason, reason_size, "memory alloc error for the SONAME map");
        return 0;
    }

    item->next = map->first;
    map->first = item;

    return 1;
}

int shadow_sonames_add(shadow_sonames_t* map, const char* soname,
                       char* reason, size_t reason_size) {
    if (map == NULL || soname == NULL) return 0;

    if (__retag_disabled) {
        snprintf(reason, reason_size,
                 "renaming is switched off for this process -- an earlier copy could not "
                 "be retagged");
        return 0;
    }

    for (const shadow_soname_t* item = map->first; item != NULL; item = item->next)
        if (strcmp(item->original, soname) == 0)
            return 1;

    const size_t length = strlen(soname);
    if (length < 3) {
        snprintf(reason, reason_size,
                 "SONAME \"%s\" is too short to carry a generation tag", soname);
        return 0;
    }

    char candidate[PATH_MAX];
    if (length + 1 > sizeof candidate) {
        snprintf(reason, reason_size, "SONAME \"%s\" is too long", soname);
        return 0;
    }

    memcpy(candidate, soname, length + 1);

    int found = 0;
    for (int tag = 0; tag < SHADOW_TAG_BASE * SHADOW_TAG_BASE && !found; tag++) {
        candidate[length - 2] = SHADOW_TAG_ALPHABET[tag / SHADOW_TAG_BASE];
        candidate[length - 1] = SHADOW_TAG_ALPHABET[tag % SHADOW_TAG_BASE];

        if (!__shadow_soname_taken(map, candidate))
            found = 1;
    }

    if (!found) {
        snprintf(reason, reason_size,
                 "every generation tag for SONAME \"%s\" is in use", soname);
        return 0;
    }

    return __shadow_sonames_put(map, soname, candidate, reason, reason_size);
}

/* ---- what a file declares --------------------------------------------- */

typedef struct {
    const shadow_sonames_t* map;
    char* stamp;
    size_t size;
    size_t used;
} shadow_stamp_state_t;

static int __shadow_stamp_visit(const char* name, int is_soname, void* arg) {
    (void)is_soname;

    shadow_stamp_state_t* state = arg;
    const char* tagged = __shadow_sonames_lookup(name, (void*)state->map);
    if (tagged == NULL) return 1;

    const int written = snprintf(state->stamp + state->used, state->size - state->used,
                                 "%s>%s;", name, tagged);
    if (written > 0 && (size_t)written < state->size - state->used)
        state->used += (size_t)written;

    return 1;
}

/* The renames from `map` this file is subject to, as text -- the empty string
 * when it neither declares nor needs anything the map mentions. Compared against
 * what a previous load recorded, so that one file state loaded twice under the
 * same renames reuses one copy (see shadow_entry_t). */
static void __shadow_stamp(const char* path, const shadow_sonames_t* map,
                           char* buffer, size_t size) {
    buffer[0] = 0;

    if (shadow_sonames_empty(map) || __retag_disabled) return;

    shadow_stamp_state_t state = { .map = map, .stamp = buffer, .size = size, .used = 0 };

    elf_dynamic_names(path, __shadow_stamp_visit, &state);
}

typedef struct {
    char* buffer;
    size_t size;
    int found;
} shadow_soname_read_t;

static int __shadow_soname_visit(const char* name, int is_soname, void* arg) {
    if (!is_soname) return 1;

    shadow_soname_read_t* state = arg;
    const size_t length = strlen(name);
    if (length + 1 > state->size) return 0;

    memcpy(state->buffer, name, length + 1);
    state->found = 1;

    return 0;
}

int shadow_read_soname(const char* path, char* buffer, size_t size) {
    shadow_soname_read_t state = { .buffer = buffer, .size = size, .found = 0 };

    elf_dynamic_names(path, __shadow_soname_visit, &state);

    return state.found;
}

/* ---- loading ----------------------------------------------------------- */

/* Is the object registered at this path still in this process? RTLD_NOLOAD
 * hands out a reference like any other dlopen, so it is given straight back. */
static int __shadow_path_loaded(const char* path) {
    void* handle = dlopen(path, RTLD_LAZY | RTLD_NOLOAD);
    if (handle == NULL) return 0;

    dlclose(handle);

    return 1;
}

/* Is the object registered at `path` a different build from the file there now?
 *
 * Two ways it can be. The file changed since this last looked -- a rebuild. Or
 * the last decision for this path was already a copy, which says the object at
 * `path` did not match the file even then, and an object never changes once it
 * is loaded. The second case is the one a validation pass leaves behind: it
 * records the rebuild, so the real pass that follows would otherwise see nothing
 * to do (docs/hotreload/01-soname-per-generation.md §3.6). */
static int __shadow_path_stale(const shadow_entry_t* entry, const struct stat* st) {
    return entry != NULL && (__shadow_changed(entry, st) || entry->copy != NULL);
}

int shadow_needs_copy(const char* path) {
    struct stat st;
    if (path == NULL || stat(path, &st) != 0) return 0;

    if (!__shadow_path_stale(__shadow_entry_find(path), &st)) return 0;

    return __shadow_path_loaded(path);
}

/* The name this path's current copy carries for its own SONAME, dug out of the
 * stamp that copy was made under -- entries are "<original>><tagged>;". */
static int __shadow_entry_tag(const shadow_entry_t* entry, const char* soname,
                              char* buffer, size_t size) {
    if (entry == NULL || entry->stamp == NULL) return 0;

    const size_t length = strlen(soname);

    for (const char* at = entry->stamp; (at = strstr(at, soname)) != NULL; at++) {
        if (at != entry->stamp && at[-1] != ';') continue;
        if (at[length] != '>') continue;

        const char* value = at + length + 1;
        const char* end = strchr(value, ';');
        if (end == NULL) return 0;

        const size_t tagged = (size_t)(end - value);
        if (tagged + 1 > size) return 0;

        memcpy(buffer, value, tagged);
        buffer[tagged] = 0;

        return 1;
    }

    return 0;
}

int shadow_sonames_reserve(shadow_sonames_t* map, const char* path,
                           char* reason, size_t reason_size) {
    struct stat st;
    if (map == NULL || path == NULL || stat(path, &st) != 0) return 1;

    const shadow_entry_t* entry = __shadow_entry_find(path);

    /* The object at this path *is* this file -- a first load, or nothing has
     * happened to it. It keeps the name it was built with, because there is
     * nothing for it to be confused with. */
    if (!__shadow_path_stale(entry, &st)) return 1;

    char soname[256];
    if (!shadow_read_soname(path, soname, sizeof soname)) {
        snprintf(reason, reason_size, "it declares no SONAME");
        return 0;
    }

    /* A copy that is still valid keeps its name: the new generation then loads
     * the very same library as the one that made it, one more reference and not
     * one more instance. This is what makes a reload with nothing rebuilt free,
     * and what lets the real pass reuse the validation pass's copies. */
    char existing[256];
    if (!__shadow_changed(entry, &st) && entry->copy != NULL
        && access(entry->copy, R_OK) == 0
        && __shadow_entry_tag(entry, soname, existing, sizeof existing))
        return __shadow_sonames_put(map, soname, existing, reason, reason_size);

    return shadow_sonames_add(map, soname, reason, reason_size);
}

int shadow_retag_refused(void) {
    return __retag_refused;
}

void shadow_retag_disable(void) {
    __retag_disabled = 1;
}

void* shadow_dlopen_ex(const char* path, int flags, const char* tmpdir,
                       const shadow_sonames_t* map) {
    __error[0] = 0;
    __retag_refused = 0;

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

    char stamp[SHADOW_STAMP_MAX];
    __shadow_stamp(path, map, stamp, sizeof stamp);

    shadow_entry_t* entry = __shadow_entry_find(path);

    /* A file whose state this has already decided about, under the same renames:
     * repeat the decision, straight from the path or from the copy made for
     * exactly this file -- see shadow_entry_t on why repeating matters. The one
     * exception is a copy that has since been removed from disk: making a new one
     * is right, and quietly falling back to `path` would hand back the old
     * object. */
    const int repeatable = entry != NULL
        && !__shadow_changed(entry, &st)
        && strcmp(entry->stamp, stamp) == 0
        && (entry->copy == NULL || access(entry->copy, R_OK) == 0);

    if (repeatable) {
        const char* target = entry->copy == NULL ? path : entry->copy;

        void* handle = dlopen(target, flags);
        if (handle == NULL)
            __shadow_error_set(dlerror(), entry->copy, entry->copy == NULL ? NULL : path);

        return handle;
    }

    /* A plain dlopen is right only when it would read the file as it is now --
     * that is, when nothing is loaded at this path -- and when the object needs
     * no renaming, because a rename is done to a copy and never to the original
     * (docs/hotreload/01-soname-per-generation.md §3.1). */
    if (stamp[0] == 0 && (entry == NULL || !__shadow_path_loaded(path))) {
        void* handle = dlopen(path, flags);
        if (handle == NULL) {
            __shadow_error_set(dlerror(), NULL, NULL);
            return NULL;
        }

        __shadow_entry_update(path, &st, NULL, stamp);

        return handle;
    }

    char copy[PATH_MAX];
    if (!__shadow_make_copy(path, dir, tmpdir, copy, sizeof copy))
        return NULL;

    if (stamp[0] != 0) {
        char reason[512];

        if (!elf_rename_sonames(copy, __shadow_sonames_lookup, (void*)map,
                                reason, sizeof reason)) {
            __shadow_error_setf("%s", reason);
            __retag_refused = 1;
            unlink(copy);
            return NULL;
        }
    }

    void* handle = dlopen(copy, flags);
    if (handle == NULL) {
        /* Most likely the copy was taken while the linker was still writing the
         * file: it unlinks and re-creates, so between O_TRUNC and the last byte
         * the path holds a truncated ELF (00 §7). Refusing the load is the right
         * answer -- the caller keeps the old configuration -- and the next
         * reload sees a different stat and copies the finished file. */
        __shadow_error_set(dlerror(), copy, path);
        unlink(copy);
        return NULL;
    }

    __shadow_entry_update(path, &st, copy, stamp);

    if (!__shadow_name_remember(&__copies, copy)) {
        /* Nothing is broken, the file just has nobody to remove it at exit. */
        log_error("shadow_dlopen: out of memory recording the copy %s; it will be left "
                  "behind and removed by the next start\n", copy);
    }

    if (stamp[0] != 0)
        log_info("shadow_dlopen: loaded %s through %s, renaming %s\n", path, copy, stamp);
    else
        log_info("shadow_dlopen: %s was rebuilt; loaded it through %s\n", path, copy);

    return handle;
}

void* shadow_dlopen(const char* path, int flags, const char* tmpdir) {
    return shadow_dlopen_ex(path, flags, tmpdir, NULL);
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
        free(entry->stamp);
        free(entry);

        entry = next;
    }

    __entries = NULL;
}
