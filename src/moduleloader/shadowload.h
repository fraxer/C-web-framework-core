#ifndef __SHADOWLOAD__
#define __SHADOWLOAD__

#include <stddef.h>

/**
 * dlopen() that picks up a shared object rebuilt in place.
 *
 * dlopen() refuses to load a path it has already loaded, and it decides that
 * twice: first by comparing the string against the names of the loaded objects,
 * before the file is even opened, and then by (st_dev, st_ino) once it is. So a
 * rebuilt .so at the same path returns the old object with the old code, and
 * neither a symlink, a hard link nor a fresh inode at the same path changes
 * that -- only a new name AND a new inode together do.
 *
 * Hence a copy: `<directory of the original>/.cwfr-shadow-<pid>-<seq>-<name>`.
 * Next to the original rather than in a temporary directory, so that $ORIGIN in
 * the object's RPATH still resolves to the directory its private dependencies
 * live in. A copy rather than memfd_create(), because a memfd-loaded library
 * shows up in ASan reports, gdb and perf as `/proc/self/fd/N+0x127c` with no
 * function, file or line -- and restoring those from the on-disk file with
 * addr2line is exactly wrong in the one case that matters, where the file has
 * been rebuilt and no longer describes the loaded code.
 *
 * See docs/hotreload/00-shadow-copy.md for the measurements behind all of this.
 */

/**
 * The SONAME a configuration generation loads its application modules under.
 *
 * A copy answers dlopen(), but it does not answer the *other* way a library is
 * reached: a handler records its module's SONAME in DT_NEEDED, and the loader
 * satisfies that from the first already-loaded object carrying that name --
 * before any file is opened, so a new inode is never even looked at. Two
 * generations of a module therefore share one SONAME, the older always wins,
 * and the new generation's handlers call the old build
 * (docs/hotreload/01-soname-per-generation.md §1).
 *
 * The fix is to give each generation its own name: the module's copy gets a
 * tagged DT_SONAME, and the copies of everything that needs it get the same tag
 * in their DT_NEEDED. This map is that generation's set of renames; it belongs
 * to the appconfig_t being built, and every load of that generation is handed
 * it.
 */
typedef struct shadow_sonames shadow_sonames_t;

shadow_sonames_t* shadow_sonames_create(void);
void shadow_sonames_free(shadow_sonames_t* map);
int shadow_sonames_empty(const shadow_sonames_t* map);

/**
 * Reserve a tag for `soname` and record the rename.
 *
 * The tag is the last two bytes of the name, in base36 -- `libapp.so` becomes
 * `libapp.0f`. Free tags are found by asking the loader itself: a tag is taken
 * exactly while some live generation still has a library loaded under it, which
 * dlopen(name, RTLD_NOLOAD) answers without any bookkeeping of ours and without
 * a lock -- and a generation is released on a worker thread, so bookkeeping
 * would have needed one.
 *
 * Fails, with `reason` filled in, for a SONAME too short to hold a tag, for a
 * name that would collide with another module of the same generation once
 * tagged, and when every tag is in use.
 *
 * @return 1 when the rename was recorded (or was already there), 0 otherwise.
 */
int shadow_sonames_add(shadow_sonames_t* map, const char* soname,
                       char* reason, size_t reason_size);

/** The tag reserved for `soname`, or NULL when it has none. */
const char* shadow_sonames_tagged(const shadow_sonames_t* map, const char* soname);

/**
 * Record whatever rename the module at `path` needs for this generation, if any.
 *
 * Nothing when the object at that path is the file that is there now -- it keeps
 * its own name. The name its existing copy already carries, when that copy is
 * still valid, so a reload with nothing rebuilt shares one library instead of
 * making a second instance. A fresh tag when the file has genuinely been rebuilt
 * under a live generation.
 *
 * @return 1 including "nothing to do", 0 with `reason` when a rename is needed
 *         and cannot be arranged.
 */
int shadow_sonames_reserve(shadow_sonames_t* map, const char* path,
                           char* reason, size_t reason_size);

/**
 * Load `path`, transparently going through a copy when it is needed -- because
 * the path is already loaded in this process and the file on disk has changed
 * since, or because `map` renames a library this object declares or needs. An
 * ordinary first load with an empty map is a plain dlopen(), so startup behaves
 * exactly as it did before any of this existed and leaves nothing on disk.
 *
 * `tmpdir` is the fallback directory for the copy when the original's directory
 * is not writable (`/opt`, a read-only image). Loading still succeeds, but
 * $ORIGIN then points at the wrong place, so the fallback is logged. NULL means
 * "no fallback": the load fails instead.
 *
 * Copies are NOT unlinked when the library is unloaded -- see shadow_cleanup().
 *
 * Not thread safe, and does not need to be: every caller runs while the
 * configuration is being parsed, which is single-threaded at startup and holds
 * module_loader_signal_lock() on a reload.
 *
 * @return the library handle, or NULL -- with shadow_dlerror() explaining why.
 */
void* shadow_dlopen_ex(const char* path, int flags, const char* tmpdir,
                       const shadow_sonames_t* map);

/** shadow_dlopen_ex() with no renames. */
void* shadow_dlopen(const char* path, int flags, const char* tmpdir);

/**
 * The error from the last failed shadow_dlopen(), or NULL if it succeeded.
 *
 * dlerror()'s message names the file the loader actually opened, which for a
 * copy is a `.cwfr-shadow-*` path the operator has never heard of. This is the
 * same message with the real path put back, and it is why callers should use it
 * instead of dlerror().
 *
 * Valid until the next shadow_dlopen().
 */
const char* shadow_dlerror(void);

/**
 * Would loading `path` right now go through a copy, renames aside?
 *
 * Which is the same question as "is a rebuilt file being held open by a live
 * generation" -- and therefore "does this module need a tag of its own". Asked
 * before anything of the new generation is loaded, so that the tags exist by the
 * time the modules themselves are.
 */
int shadow_needs_copy(const char* path);

/** The object's own DT_SONAME, or 0 when it declares none. */
int shadow_read_soname(const char* path, char* buffer, size_t size);

/**
 * Did the last failed load fail *because* a copy could not be retagged?
 *
 * A library whose linker merged its dependency names cannot have one of them
 * rewritten in place (elfsoname.h), and that is not a broken configuration --
 * it only means this application cannot swap its module without a restart. The
 * validation pass asks this, turns renaming off for the process and tries once
 * more, so the rest of the reload still happens.
 */
int shadow_retag_refused(void);
void shadow_retag_disable(void);

/**
 * Unlink every copy this process made, and release the bookkeeping.
 *
 * Called once, when the process is on its way out. Deliberately not on unload:
 * a copy has to outlive the library it carried, or a core dump taken after a
 * reload cannot symbolise the frames of the generation that has already gone --
 * which is the whole reason this is a file on disk and not a memfd. The cost is
 * one file per rebuild for the lifetime of the process; the mapping itself goes
 * with the dlclose(), so nothing accumulates in memory.
 *
 * Copies left behind by a process that was killed rather than shut down are
 * removed by the next start: shadow_dlopen() sweeps each directory it loads
 * from once, dropping `.cwfr-shadow-*` files whose pid is no longer alive.
 */
void shadow_cleanup(void);

#endif
