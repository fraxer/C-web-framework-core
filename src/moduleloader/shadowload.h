#ifndef __SHADOWLOAD__
#define __SHADOWLOAD__

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
 * Load `path`, transparently going through a copy when -- and only when -- the
 * path is already loaded in this process AND the file on disk has changed since
 * this loaded it. An ordinary first load is a plain dlopen(), so startup
 * behaves exactly as it did before this existed and leaves nothing on disk.
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
