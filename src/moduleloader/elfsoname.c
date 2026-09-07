#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "elfsoname.h"

/* Names are read out of PT_DYNAMIC rather than out of the section headers: a
 * stripped library keeps its program headers -- the loader needs them -- and may
 * have no section headers at all. Both ELF classes and both byte orders are
 * handled, because the file is read, not run, and refusing one would be an
 * arbitrary limit rather than a safe one. */

#define ELF_MAX_REFERENCES 256

typedef struct {
    unsigned char* data;
    size_t size;
    int is64;
    int msb;
} elf_image_t;

/* One place that names a library: either a .dynamic entry (DT_SONAME/DT_NEEDED)
 * or a `vn_file` field in .gnu.version_r. `offset` is where the string lives in
 * .dynstr -- several references may share one string. */
typedef struct {
    size_t offset;
    int is_soname;
} elf_reference_t;

static int __elf_read(const char* path, elf_image_t* elf);
static void __elf_release(elf_image_t* elf);
static int __elf_references(const elf_image_t* elf, size_t* strtab,
                            elf_reference_t* refs, size_t capacity, size_t* count);

static uint16_t __elf_u16(const elf_image_t* elf, size_t offset) {
    if (offset + 2 > elf->size) return 0;

    const unsigned char* p = elf->data + offset;

    return elf->msb ? (uint16_t)((p[0] << 8) | p[1])
                    : (uint16_t)((p[1] << 8) | p[0]);
}

static uint32_t __elf_u32(const elf_image_t* elf, size_t offset) {
    if (offset + 4 > elf->size) return 0;

    const unsigned char* p = elf->data + offset;

    return elf->msb ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]
                    : ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | p[0];
}

static uint64_t __elf_u64(const elf_image_t* elf, size_t offset) {
    if (offset + 8 > elf->size) return 0;

    const uint64_t low = __elf_u32(elf, elf->msb ? offset + 4 : offset);
    const uint64_t high = __elf_u32(elf, elf->msb ? offset : offset + 4);

    return (high << 32) | low;
}

/* An address- or offset-sized field: 8 bytes in ELF64, 4 in ELF32. */
static uint64_t __elf_word(const elf_image_t* elf, size_t offset) {
    return elf->is64 ? __elf_u64(elf, offset) : __elf_u32(elf, offset);
}

static int __elf_read(const char* path, elf_image_t* elf) {
    memset(elf, 0, sizeof * elf);

    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return 0;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < EI_NIDENT) {
        close(fd);
        return 0;
    }

    elf->size = (size_t)st.st_size;
    elf->data = malloc(elf->size);
    if (elf->data == NULL) {
        close(fd);
        return 0;
    }

    size_t got = 0;
    while (got < elf->size) {
        const ssize_t n = read(fd, elf->data + got, elf->size - got);
        if (n == 0) break;
        if (n == -1) {
            if (errno == EINTR) continue;
            break;
        }
        got += (size_t)n;
    }

    close(fd);

    if (got != elf->size || memcmp(elf->data, ELFMAG, SELFMAG) != 0) {
        __elf_release(elf);
        return 0;
    }

    const unsigned char class = elf->data[EI_CLASS];
    const unsigned char data = elf->data[EI_DATA];
    if ((class != ELFCLASS32 && class != ELFCLASS64) ||
        (data != ELFDATA2LSB && data != ELFDATA2MSB)) {
        __elf_release(elf);
        return 0;
    }

    elf->is64 = class == ELFCLASS64;
    elf->msb = data == ELFDATA2MSB;

    return 1;
}

static void __elf_release(elf_image_t* elf) {
    free(elf->data);
    elf->data = NULL;
    elf->size = 0;
}

/* A virtual address as a file offset, through the PT_LOAD that covers it. */
static int __elf_vaddr_to_offset(const elf_image_t* elf, uint64_t vaddr, size_t* offset) {
    const size_t phoff = (size_t)__elf_word(elf, elf->is64 ? 0x20 : 0x1c);
    const size_t phentsize = __elf_u16(elf, elf->is64 ? 0x36 : 0x2a);
    const size_t phnum = __elf_u16(elf, elf->is64 ? 0x38 : 0x2c);

    for (size_t i = 0; i < phnum; i++) {
        const size_t ph = phoff + i * phentsize;
        if (ph + phentsize > elf->size) return 0;

        if (__elf_u32(elf, ph) != PT_LOAD) continue;

        const uint64_t p_offset = elf->is64 ? __elf_u64(elf, ph + 0x08) : __elf_u32(elf, ph + 0x04);
        const uint64_t p_vaddr = elf->is64 ? __elf_u64(elf, ph + 0x10) : __elf_u32(elf, ph + 0x08);
        const uint64_t p_filesz = elf->is64 ? __elf_u64(elf, ph + 0x20) : __elf_u32(elf, ph + 0x10);

        if (vaddr < p_vaddr || vaddr >= p_vaddr + p_filesz) continue;

        const uint64_t result = p_offset + (vaddr - p_vaddr);
        if (result >= elf->size) return 0;

        *offset = (size_t)result;

        return 1;
    }

    return 0;
}

static int __elf_dynamic_segment(const elf_image_t* elf, size_t* offset, size_t* size) {
    const size_t phoff = (size_t)__elf_word(elf, elf->is64 ? 0x20 : 0x1c);
    const size_t phentsize = __elf_u16(elf, elf->is64 ? 0x36 : 0x2a);
    const size_t phnum = __elf_u16(elf, elf->is64 ? 0x38 : 0x2c);

    for (size_t i = 0; i < phnum; i++) {
        const size_t ph = phoff + i * phentsize;
        if (ph + phentsize > elf->size) return 0;

        if (__elf_u32(elf, ph) != PT_DYNAMIC) continue;

        const uint64_t p_offset = elf->is64 ? __elf_u64(elf, ph + 0x08) : __elf_u32(elf, ph + 0x04);
        const uint64_t p_filesz = elf->is64 ? __elf_u64(elf, ph + 0x20) : __elf_u32(elf, ph + 0x10);

        if (p_offset + p_filesz > elf->size) return 0;

        *offset = (size_t)p_offset;
        *size = (size_t)p_filesz;

        return 1;
    }

    return 0;
}

/* Every string in .dynstr that names a library, with the offset it lives at.
 * Collected in one pass because both callers need the whole set: the walk hands
 * them out, and the rename has to know them all before it writes anything. */
static int __elf_references(const elf_image_t* elf, size_t* strtab,
                            elf_reference_t* refs, size_t capacity, size_t* count) {
    size_t dynamic = 0, dynamic_size = 0;
    if (!__elf_dynamic_segment(elf, &dynamic, &dynamic_size)) return 0;

    const size_t entry_size = elf->is64 ? 16 : 8;
    const size_t value_at = elf->is64 ? 8 : 4;

    uint64_t strtab_vaddr = 0, verneed_vaddr = 0, verneed_count = 0;
    int has_strtab = 0;

    for (size_t o = dynamic; o + entry_size <= dynamic + dynamic_size; o += entry_size) {
        const uint64_t tag = __elf_word(elf, o);
        const uint64_t value = __elf_word(elf, o + value_at);

        if (tag == DT_NULL) break;
        if (tag == DT_STRTAB) { strtab_vaddr = value; has_strtab = 1; }
        if (tag == DT_VERNEED) verneed_vaddr = value;
        if (tag == DT_VERNEEDNUM) verneed_count = value;
    }

    if (!has_strtab || !__elf_vaddr_to_offset(elf, strtab_vaddr, strtab)) return 0;

    *count = 0;

    for (size_t o = dynamic; o + entry_size <= dynamic + dynamic_size; o += entry_size) {
        const uint64_t tag = __elf_word(elf, o);
        if (tag == DT_NULL) break;
        if (tag != DT_NEEDED && tag != DT_SONAME) continue;
        if (*count >= capacity) return 0;

        refs[*count].offset = (size_t)__elf_word(elf, o + value_at);
        refs[*count].is_soname = tag == DT_SONAME;
        (*count)++;
    }

    /* .gnu.version_r names the libraries that provide the symbol versions this
     * object needs -- by the same string. A module with versioned symbols would
     * otherwise keep a stale name here after its SONAME was rewritten. */
    if (verneed_vaddr != 0 && verneed_count != 0) {
        size_t vn = 0;
        if (!__elf_vaddr_to_offset(elf, verneed_vaddr, &vn)) return 1;

        for (uint64_t i = 0; i < verneed_count; i++) {
            if (vn + 16 > elf->size) break;

            if (*count >= capacity) return 0;

            refs[*count].offset = __elf_u32(elf, vn + 4);   /* vn_file */
            refs[*count].is_soname = 0;
            (*count)++;

            const uint32_t next = __elf_u32(elf, vn + 12);  /* vn_next */
            if (next == 0) break;
            vn += next;
        }
    }

    return 1;
}

static const char* __elf_string(const elf_image_t* elf, size_t strtab, size_t offset) {
    const size_t at = strtab + offset;
    if (at >= elf->size) return NULL;

    /* The table has to be NUL-terminated for the name to be a string at all. */
    if (memchr(elf->data + at, 0, elf->size - at) == NULL) return NULL;

    return (const char*)elf->data + at;
}

int elf_dynamic_names(const char* path,
                      int (*visit)(const char* name, int is_soname, void* arg),
                      void* arg) {
    elf_image_t elf;
    if (!__elf_read(path, &elf)) return 0;

    elf_reference_t refs[ELF_MAX_REFERENCES];
    size_t strtab = 0, count = 0;
    int result = 0;

    if (!__elf_references(&elf, &strtab, refs, ELF_MAX_REFERENCES, &count))
        goto done;

    result = 1;

    for (size_t i = 0; i < count; i++) {
        const char* name = __elf_string(&elf, strtab, refs[i].offset);
        if (name == NULL) continue;

        if (!visit(name, refs[i].is_soname, arg))
            break;
    }

    done:

    __elf_release(&elf);

    return result;
}

int elf_rename_sonames(const char* path,
                       const char* (*rename)(const char* name, void* arg),
                       void* arg,
                       char* reason, size_t reason_size) {
    /* One buffer to write into keeps every failure path a plain snprintf. */
    char discarded[1];
    if (reason == NULL || reason_size == 0) {
        reason = discarded;
        reason_size = sizeof discarded;
    }
    reason[0] = 0;

    elf_image_t elf;
    if (!__elf_read(path, &elf)) {
        snprintf(reason, reason_size, "%s is not an ELF object this can read", path);
        return 0;
    }

    elf_reference_t refs[ELF_MAX_REFERENCES];
    size_t strtab = 0, count = 0;
    int result = 0;

    if (!__elf_references(&elf, &strtab, refs, ELF_MAX_REFERENCES, &count)) {
        snprintf(reason, reason_size, "%s has no readable .dynamic/.dynstr", path);
        goto done;
    }

    /* Two passes: nothing is written until every rename is known to be safe, so
     * a refusal leaves the file exactly as it was. */
    for (size_t i = 0; i < count; i++) {
        const char* name = __elf_string(&elf, strtab, refs[i].offset);
        if (name == NULL) continue;

        const char* replacement = rename(name, arg);
        if (replacement == NULL) continue;

        if (strlen(replacement) != strlen(name)) {
            snprintf(reason, reason_size,
                     "%s: cannot rename %s to %s, the string is overwritten where it "
                     "lies and the lengths differ", path, name, replacement);
            goto done;
        }

        /* The one way a name can be unsafe to overwrite: a linker that merges
         * suffixes stores "libapp.so" as the tail of "mylibapp.so" and points
         * this entry two bytes into that string. Writing here would rewrite the
         * other name as well.
         *
         * A NUL immediately before the string rules that out completely, and it
         * is the only check needed. The other direction is impossible: a string
         * starting inside ours would have to begin right after a NUL, and there
         * is no NUL inside a single C string. */
        const size_t at = strtab + refs[i].offset;
        if (at > 0 && elf.data[at - 1] != 0) {
            snprintf(reason, reason_size,
                     "%s: %s shares its storage with a longer library name -- the "
                     "linker merged the strings, so it cannot be renamed in place",
                     path, name);
            goto done;
        }
    }

    const int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) {
        snprintf(reason, reason_size, "%s cannot be opened for writing", path);
        goto done;
    }

    result = 1;

    for (size_t i = 0; i < count && result; i++) {
        const char* name = __elf_string(&elf, strtab, refs[i].offset);
        if (name == NULL) continue;

        const char* replacement = rename(name, arg);
        if (replacement == NULL) continue;

        const size_t at = strtab + refs[i].offset;
        const size_t length = strlen(replacement);

        /* Several references may share one string; writing it twice is the same
         * bytes twice, so no attempt is made to deduplicate. */
        if (pwrite(fd, replacement, length, (off_t)at) != (ssize_t)length) {
            snprintf(reason, reason_size, "%s: writing %s failed", path, replacement);
            result = 0;
        }
    }

    if (close(fd) == -1 && result) {
        snprintf(reason, reason_size, "%s: closing after the rename failed", path);
        result = 0;
    }

    done:

    __elf_release(&elf);

    return result;
}
