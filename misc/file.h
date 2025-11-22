#ifndef __CFILE__
#define __CFILE__

#include <sys/types.h>
#include <libgen.h>
#include <fcntl.h>
#include <linux/limits.h>

/**
 * File handle structure.
 * Provides an object-oriented interface for file operations.
 */
typedef struct file {
    /* 8-byte aligned fields */

    /** File size in bytes */
    size_t size;

    /**
     * Sets the file name.
     * @param file  Pointer to file structure
     * @param name  File name (basename will be extracted, leading "/" is ignored)
     * @return 1 on success, 0 on error
     */
    int(*set_name)(struct file* file, const char* name);

    /**
     * Reads and returns file content.
     * @param file  Pointer to file structure
     * @return Pointer to buffer with content (must be freed with free()),
     *         NULL on error
     */
    char*(*content)(struct file* file);

    /**
     * Writes data to file, overwriting existing content.
     * File position is reset to the beginning after write.
     * @param file  Pointer to file structure
     * @param data  Data to write
     * @param size  Data size in bytes
     * @return Number of bytes written, 0 on error
     */
    int(*set_content)(struct file* file, const char* data, const size_t size);

    /**
     * Appends data to the end of file.
     * @param file  Pointer to file structure
     * @param data  Data to append
     * @param size  Data size in bytes
     * @return 1 on success, 0 on error
     */
    int(*append_content)(struct file* file, const char* data, const size_t size);

    /**
     * Closes file and releases resources.
     * If file is temporary (tmp=1), it will be deleted from disk.
     * @param file  Pointer to file structure
     * @return 1 on success, 0 on error
     */
    int(*close)(struct file* file);

    /**
     * Truncates file to specified size.
     * @param file    Pointer to file structure
     * @param offset  New file size in bytes
     * @return 1 on success, 0 on error
     */
    int(*truncate)(struct file* file, const off_t offset);

    /* 4-byte aligned fields */

    /** File descriptor (-1 if file is not open) */
    int fd;

    /** Temporary file flag: 1 = file will be deleted on close() */
    unsigned tmp;

    /** Success flag: 1 = file was opened/created successfully */
    unsigned ok;

    /* 1-byte aligned fields */

    /** File name (without path) */
    char name[NAME_MAX];
} file_t;

/**
 * File content structure for working with data from an external source.
 * Used to extract a portion of data from one file descriptor
 * and create a new file (e.g., when processing multipart form data).
 */
typedef struct file_content {
    /* 8-byte aligned fields */

    /** Offset in source file where content starts */
    off_t offset;

    /** Content size in bytes */
    size_t size;

    /**
     * Sets the file name.
     * @param file_content  Pointer to file_content structure
     * @param filename      File name
     * @return 1 on success, 0 on error
     */
    int(*set_filename)(struct file_content* file_content, const char* filename);

    /**
     * Creates a file on disk and copies content into it.
     * @param file_content  Pointer to file_content structure
     * @param filepath      Directory path where to create the file
     * @param filename      File name (NULL = use file_content->filename)
     * @return file_t structure with open file (check ok field for success)
     */
    file_t(*make_file)(struct file_content* file_content, const char* filepath, const char* filename);

    /**
     * Creates a temporary file and copies content into it.
     * File will be deleted when close() is called.
     * @param file_content  Pointer to file_content structure
     * @return file_t structure with open temporary file
     */
    file_t(*make_tmpfile)(struct file_content* file_content);

    /**
     * Reads content into memory.
     * @param file_content  Pointer to file_content structure
     * @return Pointer to buffer with data (must be freed with free()),
     *         NULL on error
     */
    char*(*content)(struct file_content* file_content);

    /* 4-byte aligned fields */

    /** Source file descriptor from which data is read */
    int fd;

    /** Success flag: 1 = structure is valid */
    int ok;

    /* 1-byte aligned fields */

    /** Name for the file to be created */
    char filename[NAME_MAX];
} file_content_t;

/**
 * Creates an empty file_t structure with initialized methods.
 * @return file_t structure (ok=0, fd=-1)
 */
file_t file_alloc();

/**
 * Creates a temporary file.
 * File is created in the directory specified in config (env()->main.tmp).
 * @param filename  File name (used only for the name field)
 * @return file_t structure (check ok field for success)
 */
file_t file_create_tmp(const char* filename);

/**
 * Opens an existing file or creates a new one.
 * @param path   Full path to the file
 * @param flags  Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
 * @return file_t structure (check ok field for success)
 */
file_t file_open(const char* path, const int flags);

/**
 * Creates a file_content structure for working with a portion of data from a file descriptor.
 * @param fd        Source file descriptor
 * @param filename  Name for the file to be created
 * @param offset    Offset in source where data starts
 * @param size      Data size in bytes
 * @return file_content_t structure with initialized methods
 */
file_content_t file_content_create(const int fd, const char* filename, const off_t offset, const size_t size);

#endif
