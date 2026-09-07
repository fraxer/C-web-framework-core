#ifndef __ELFSONAME__
#define __ELFSONAME__

#include <stddef.h>

/**
 * Reading and rewriting the library names inside a shared object.
 *
 * A library declares its own name in DT_SONAME and names its dependencies in
 * DT_NEEDED, and it is those strings -- not file names -- that the dynamic
 * loader matches when it resolves a dependency. Two objects carrying the same
 * SONAME are therefore interchangeable to it, and the first one loaded wins
 * every lookup: which is why a second, rebuilt copy of an application module is
 * invisible to the handlers that need it (docs/hotreload/01-soname-per-generation.md §1).
 *
 * Giving each configuration generation its own SONAME is what breaks that tie,
 * and this is the piece that does it -- on a private copy of the file, never on
 * the original.
 */

/**
 * Visit DT_SONAME and every DT_NEEDED of `path`.
 *
 * `is_soname` is 1 for the object's own name, 0 for a dependency. Returning 0
 * from `visit` stops the walk.
 *
 * @return 1 when the file was read and understood, 0 otherwise -- a file that is
 *         not an ELF shared object, or is truncated, is simply "no names".
 */
int elf_dynamic_names(const char* path,
                      int (*visit)(const char* name, int is_soname, void* arg),
                      void* arg);

/**
 * Rename DT_SONAME, DT_NEEDED and the `.gnu.version_r` file names of `path` in
 * place, according to `rename` -- which returns the replacement for a name, or
 * NULL to leave it alone.
 *
 * The replacement must be **exactly as long** as the name it replaces: the
 * string is overwritten where it lies in `.dynstr`, so nothing in the file
 * moves and no offset, size or hash has to be recomputed.
 *
 * Refused, with `reason` filled in, when a name cannot be rewritten safely --
 * see the string-sharing note in the implementation. A refusal changes nothing:
 * either every rename lands or none does.
 *
 * @return 1 on success (including "nothing matched"), 0 on refusal.
 */
int elf_rename_sonames(const char* path,
                       const char* (*rename)(const char* name, void* arg),
                       void* arg,
                       char* reason, size_t reason_size);

#endif
