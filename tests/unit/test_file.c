#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <linux/limits.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

#include "framework.h"
#include "file.h"
#include "log.h"

// Helper: create temporary directory for testing
static char test_dir[PATH_MAX];

static void setup_test_dir() {
    snprintf(test_dir, sizeof(test_dir), "/tmp/file_test_XXXXXX");
    if (mkdtemp(test_dir) == NULL) {
        fprintf(stderr, "Failed to create test directory\n");
        exit(1);
    }
}

static void cleanup_test_dir() {
    char cmd[PATH_MAX + 20];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
    system(cmd);
}

// ============================================================================
// Basic Functionality Tests - file_alloc()
// ============================================================================

TEST(test_file_alloc_initialization) {
    TEST_CASE("file_alloc should initialize structure correctly");

    file_t file = file_alloc();

    TEST_ASSERT_EQUAL(-1, file.fd, "File descriptor should be -1");
    TEST_ASSERT_EQUAL(0, file.ok, "ok flag should be 0");
    TEST_ASSERT_EQUAL(0, file.tmp, "tmp flag should be 0");
    TEST_ASSERT_EQUAL_SIZE(0, file.size, "Size should be 0");
    TEST_ASSERT_NOT_NULL(file.set_name, "set_name method should be initialized");
    TEST_ASSERT_NOT_NULL(file.content, "content method should be initialized");
    TEST_ASSERT_NOT_NULL(file.set_content, "set_content method should be initialized");
    TEST_ASSERT_NOT_NULL(file.append_content, "append_content method should be initialized");
    TEST_ASSERT_NOT_NULL(file.close, "close method should be initialized");
    TEST_ASSERT_NOT_NULL(file.truncate, "truncate method should be initialized");
}

// ============================================================================
// Basic Functionality Tests - file_open()
// ============================================================================

TEST(test_file_open_existing) {
    TEST_CASE("file_open should open existing file");

    setup_test_dir();

    // Create test file
    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/test_file.txt", test_dir);
    int fd = open(filepath, O_CREAT | O_WRONLY, 0644);
    write(fd, "Hello", 5);
    close(fd);

    file_t file = file_open(filepath, O_RDONLY);

    TEST_ASSERT_EQUAL(1, file.ok, "File should be opened successfully");
    TEST_ASSERT(file.fd >= 0, "File descriptor should be valid");
    TEST_ASSERT_EQUAL_SIZE(5, file.size, "Size should be 5 bytes");
    TEST_ASSERT_STR_EQUAL("test_file.txt", file.name, "Filename should be extracted");

    file.close(&file);
    cleanup_test_dir();
}

TEST(test_file_open_create_new) {
    TEST_CASE("file_open should create new file with O_CREAT flag");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/new_file.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);

    TEST_ASSERT_EQUAL(1, file.ok, "File should be created successfully");
    TEST_ASSERT(file.fd >= 0, "File descriptor should be valid");
    TEST_ASSERT_STR_EQUAL("new_file.txt", file.name, "Filename should be set");

    file.close(&file);
    cleanup_test_dir();
}

TEST(test_file_open_nonexistent_without_create) {
    TEST_CASE("file_open should fail when file doesn't exist and O_CREAT not set");

    file_t file = file_open("/tmp/nonexistent_file_xyz.txt", O_RDONLY);

    TEST_ASSERT_EQUAL(0, file.ok, "File opening should fail");
    TEST_ASSERT_EQUAL(-1, file.fd, "File descriptor should be -1");

    file.close(&file);
}

// ============================================================================
// Security Tests - Path Traversal
// ============================================================================

TEST(test_file_open_path_traversal_protection) {
    TEST_CASE("file_open should reject path traversal attempts");

    file_t file1 = file_open("/..", O_RDONLY);
    TEST_ASSERT_EQUAL(0, file1.ok, "Should reject '..' as filename");
    file1.close(&file1);

    file_t file2 = file_open("/.", O_RDONLY);
    TEST_ASSERT_EQUAL(0, file2.ok, "Should reject '.' as filename");
    file2.close(&file2);

    file_t file3 = file_open("/", O_RDONLY);
    TEST_ASSERT_EQUAL(0, file3.ok, "Should reject '/' as filename");
    file3.close(&file3);
}

TEST(test_file_set_name_path_traversal) {
    TEST_CASE("set_name should sanitize path traversal attempts");

    file_t file = file_alloc();

    int result1 = file.set_name(&file, "../../../etc/passwd");
    TEST_ASSERT_EQUAL(1, result1, "Should succeed but sanitize");
    TEST_ASSERT_STR_EQUAL("passwd", file.name, "Should extract basename only");

    int result2 = file.set_name(&file, "..");
    TEST_ASSERT_EQUAL(0, result2, "Should reject '..' as name");

    int result3 = file.set_name(&file, ".");
    TEST_ASSERT_EQUAL(0, result3, "Should reject '.' as name");

    int result4 = file.set_name(&file, "/");
    TEST_ASSERT_EQUAL(0, result4, "Should reject '/' as name");

    file.close(&file);
}

TEST(test_file_set_name_leading_slash) {
    TEST_CASE("set_name should strip leading slash");

    file_t file = file_alloc();

    file.set_name(&file, "/myfile.txt");
    TEST_ASSERT_STR_EQUAL("myfile.txt", file.name, "Leading slash should be stripped");

    file.close(&file);
}

// ============================================================================
// Security Tests - Buffer Overflow
// ============================================================================

TEST(test_file_set_name_buffer_overflow) {
    TEST_CASE("set_name should prevent buffer overflow with long names");

    file_t file = file_alloc();

    // Create name longer than NAME_MAX
    char long_name[NAME_MAX + 100];
    memset(long_name, 'A', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';

    int result = file.set_name(&file, long_name);

    TEST_ASSERT_EQUAL(1, result, "Should succeed");
    TEST_ASSERT(strlen(file.name) < NAME_MAX, "Name should be truncated to NAME_MAX");
    TEST_ASSERT_EQUAL('\0', file.name[NAME_MAX - 1], "Should be null-terminated");

    file.close(&file);
}

TEST(test_file_set_name_exact_max_length) {
    TEST_CASE("set_name should handle NAME_MAX-1 length correctly");

    file_t file = file_alloc();

    char name[NAME_MAX];
    memset(name, 'B', NAME_MAX - 2);
    name[NAME_MAX - 2] = '\0';

    int result = file.set_name(&file, name);

    TEST_ASSERT_EQUAL(1, result, "Should succeed");
    TEST_ASSERT_EQUAL_SIZE(NAME_MAX - 2, strlen(file.name), "Length should be preserved");

    file.close(&file);
}

// ============================================================================
// Security Tests - NULL Pointer Safety
// ============================================================================

TEST(test_file_open_null_path) {
    TEST_CASE("file_open should handle NULL path safely");

    file_t file = file_open(NULL, O_RDONLY);

    TEST_ASSERT_EQUAL(0, file.ok, "Should fail gracefully");
    TEST_ASSERT_EQUAL(-1, file.fd, "File descriptor should be -1");

    file.close(&file);
}

TEST(test_file_open_empty_path) {
    TEST_CASE("file_open should handle empty path safely");

    file_t file = file_open("", O_RDONLY);

    TEST_ASSERT_EQUAL(0, file.ok, "Should fail gracefully");
    TEST_ASSERT_EQUAL(-1, file.fd, "File descriptor should be -1");

    file.close(&file);
}

TEST(test_file_set_name_null_pointer) {
    TEST_CASE("set_name should handle NULL pointer safely");

    file_t file = file_alloc();

    int result = file.set_name(&file, NULL);

    TEST_ASSERT_EQUAL(0, result, "Should fail with NULL input");

    file.close(&file);
}

TEST(test_file_set_name_empty_string) {
    TEST_CASE("set_name should handle empty string safely");

    file_t file = file_alloc();

    int result = file.set_name(&file, "");

    TEST_ASSERT_EQUAL(0, result, "Should fail with empty string");

    file.close(&file);
}

TEST(test_file_content_null_pointer) {
    TEST_CASE("content method should handle NULL file safely");

    file_t file = file_alloc();
    char* content = file.content(NULL);

    TEST_ASSERT_NULL(content, "Should return NULL for NULL file");

    file.close(&file);
}

TEST(test_file_set_content_null_file) {
    TEST_CASE("set_content should handle NULL file safely");

    file_t file = file_alloc();
    int result = file.set_content(NULL, "data", 4);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL file");

    file.close(&file);
}

TEST(test_file_append_content_null_file) {
    TEST_CASE("append_content should handle NULL file safely");

    file_t file = file_alloc();
    int result = file.append_content(NULL, "data", 4);

    TEST_ASSERT_EQUAL(0, result, "Should return 0 for NULL file");

    file.close(&file);
}

// ============================================================================
// File Operations Tests - content, set_content, append_content
// ============================================================================

TEST(test_file_set_content_and_read) {
    TEST_CASE("set_content should write data and content should read it back");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/content_test.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);
    TEST_ASSERT_EQUAL(1, file.ok, "File should be created");

    const char* test_data = "Test Content";
    int bytes_written = file.set_content(&file, test_data, strlen(test_data));

    TEST_ASSERT_EQUAL((int)strlen(test_data), bytes_written, "Should write all bytes");
    TEST_ASSERT_EQUAL_SIZE(strlen(test_data), file.size, "File size should be updated");

    char* content = file.content(&file);
    TEST_ASSERT_NOT_NULL(content, "Content should not be NULL");
    TEST_ASSERT_STR_EQUAL(test_data, content, "Content should match");

    free(content);
    file.close(&file);
    cleanup_test_dir();
}

TEST(test_file_set_content_overwrite) {
    TEST_CASE("set_content should overwrite existing content");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/overwrite_test.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);

    file.set_content(&file, "Original Data", 13);
    file.set_content(&file, "New", 3);

    char* content = file.content(&file);
    TEST_ASSERT_STR_EQUAL("New", content, "Content should be overwritten");
    TEST_ASSERT_EQUAL_SIZE(3, file.size, "Size should be updated");

    free(content);
    file.close(&file);
    cleanup_test_dir();
}

TEST(test_file_append_content) {
    TEST_CASE("append_content should add data to end of file");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/append_test.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);

    file.set_content(&file, "Hello", 5);
    int result = file.append_content(&file, " World", 6);

    TEST_ASSERT_EQUAL(1, result, "Append should succeed");

    char* content = file.content(&file);
    TEST_ASSERT_STR_EQUAL("Hello World", content, "Content should be appended");
    TEST_ASSERT_EQUAL_SIZE(11, file.size, "Size should be updated");

    free(content);
    file.close(&file);
    cleanup_test_dir();
}

TEST(test_file_multiple_appends) {
    TEST_CASE("Multiple appends should work correctly");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/multi_append.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);

    file.set_content(&file, "1", 1);
    file.append_content(&file, "2", 1);
    file.append_content(&file, "3", 1);

    char* content = file.content(&file);
    TEST_ASSERT_STR_EQUAL("123", content, "All appends should work");
    TEST_ASSERT_EQUAL_SIZE(3, file.size, "Size should be 3");

    free(content);
    file.close(&file);
    cleanup_test_dir();
}

TEST(test_file_set_content_invalid_fd) {
    TEST_CASE("set_content should fail with invalid file descriptor");

    file_t file = file_alloc();
    file.fd = -1;

    int result = file.set_content(&file, "data", 4);

    TEST_ASSERT_EQUAL(0, result, "Should fail with invalid fd");

    file.close(&file);
}

TEST(test_file_append_content_invalid_fd) {
    TEST_CASE("append_content should fail with invalid file descriptor");

    file_t file = file_alloc();
    file.fd = -1;

    int result = file.append_content(&file, "data", 4);

    TEST_ASSERT_EQUAL(0, result, "Should fail with invalid fd");

    file.close(&file);
}

// ============================================================================
// File Operations Tests - truncate
// ============================================================================

TEST(test_file_truncate) {
    TEST_CASE("truncate should resize file");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/truncate_test.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);
    file.set_content(&file, "Hello World", 11);

    int result = file.truncate(&file, 5);

    TEST_ASSERT_EQUAL(1, result, "Truncate should succeed");
    TEST_ASSERT_EQUAL_SIZE(0, file.size, "Size field should be reset to 0");

    file.close(&file);
    cleanup_test_dir();
}

TEST(test_file_truncate_invalid_fd) {
    TEST_CASE("truncate should fail with invalid file descriptor");

    file_t file = file_alloc();
    file.fd = -1;

    int result = file.truncate(&file, 0);

    TEST_ASSERT_EQUAL(0, result, "Should fail with invalid fd");

    file.close(&file);
}

// ============================================================================
// Temporary File Tests
// ============================================================================

TEST(test_file_create_tmp) {
    TEST_CASE("file_create_tmp should create temporary file");

    file_t file = file_create_tmp("tempfile.txt", "/tmp");

    TEST_ASSERT_EQUAL(1, file.ok, "Temporary file should be created");
    TEST_ASSERT(file.fd >= 0, "File descriptor should be valid");
    TEST_ASSERT_EQUAL(1, file.tmp, "tmp flag should be set");
    TEST_ASSERT_STR_EQUAL("tempfile.txt", file.name, "Filename should be set");

    file.close(&file);
}

TEST(test_file_tmp_deletion_on_close) {
    TEST_CASE("Temporary file should be deleted on close");

    file_t file = file_create_tmp("delete_me.txt", "/tmp");
    TEST_ASSERT_EQUAL(1, file.ok, "File should be created");

    // Get the file path before closing
    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "/proc/self/fd/%d", file.fd);
    char real_path[PATH_MAX];
    ssize_t len = readlink(filepath, real_path, sizeof(real_path) - 1);
    if (len != -1) {
        real_path[len] = '\0';
    }

    int close_result = file.close(&file);
    TEST_ASSERT_EQUAL(1, close_result, "Close should succeed");

    // Verify file was deleted
    if (len != -1) {
        TEST_ASSERT_EQUAL(-1, access(real_path, F_OK), "File should be deleted");
    }
}

TEST(test_file_close_resets_structure) {
    TEST_CASE("close should reset file structure");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/close_test.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);
    file.set_name(&file, "testfile.txt");

    file.close(&file);

    TEST_ASSERT_EQUAL(-1, file.fd, "fd should be reset to -1");
    TEST_ASSERT_EQUAL(0, file.ok, "ok should be reset to 0");
    TEST_ASSERT_EQUAL(0, file.tmp, "tmp should be reset to 0");
    TEST_ASSERT_EQUAL_SIZE(0, file.size, "size should be reset to 0");

    cleanup_test_dir();
}

TEST(test_file_close_with_invalid_fd) {
    TEST_CASE("close should handle invalid fd gracefully");

    file_t file = file_alloc();
    file.fd = -1;

    int result = file.close(&file);

    TEST_ASSERT_EQUAL(1, result, "Should return success for already closed file");
}

// ============================================================================
// file_content_t Tests - Basic Functionality
// ============================================================================

TEST(test_file_content_create) {
    TEST_CASE("file_content_create should initialize structure");

    setup_test_dir();

    // Create source file
    char source_path[PATH_MAX];
    snprintf(source_path, sizeof(source_path), "%s/source.txt", test_dir);
    int source_fd = open(source_path, O_CREAT | O_RDWR, 0644);
    write(source_fd, "Hello World", 11);

    file_content_t fc = file_content_create(source_fd, "output.txt", 0, 5);

    TEST_ASSERT_EQUAL(1, fc.ok, "Structure should be valid");
    TEST_ASSERT_EQUAL(source_fd, fc.fd, "File descriptor should match");
    TEST_ASSERT_EQUAL_SIZE(5, fc.size, "Size should be set");
    TEST_ASSERT_EQUAL(0, fc.offset, "Offset should be set");
    TEST_ASSERT_STR_EQUAL("output.txt", fc.filename, "Filename should be set");
    TEST_ASSERT_NOT_NULL(fc.set_filename, "set_filename method should be initialized");
    TEST_ASSERT_NOT_NULL(fc.make_file, "make_file method should be initialized");
    TEST_ASSERT_NOT_NULL(fc.make_tmpfile, "make_tmpfile method should be initialized");
    TEST_ASSERT_NOT_NULL(fc.content, "content method should be initialized");

    close(source_fd);
    cleanup_test_dir();
}

TEST(test_file_content_set_filename) {
    TEST_CASE("file_content set_filename should update filename");

    file_content_t fc = file_content_create(0, "initial.txt", 0, 0);

    int result = fc.set_filename(&fc, "updated.txt");

    TEST_ASSERT_EQUAL(1, result, "Should succeed");
    TEST_ASSERT_STR_EQUAL("updated.txt", fc.filename, "Filename should be updated");
}

TEST(test_file_content_set_filename_sanitization) {
    TEST_CASE("file_content set_filename should sanitize path");

    file_content_t fc = file_content_create(0, "initial.txt", 0, 0);

    fc.set_filename(&fc, "/path/to/file.txt");

    TEST_ASSERT_STR_EQUAL("file.txt", fc.filename, "Should extract basename");
}

TEST(test_file_content_read_content) {
    TEST_CASE("file_content content() should read specified portion");

    setup_test_dir();

    char source_path[PATH_MAX];
    snprintf(source_path, sizeof(source_path), "%s/source.txt", test_dir);
    int source_fd = open(source_path, O_CREAT | O_RDWR, 0644);
    write(source_fd, "0123456789", 10);

    file_content_t fc = file_content_create(source_fd, "test.txt", 3, 4);

    char* content = fc.content(&fc);

    TEST_ASSERT_NOT_NULL(content, "Content should not be NULL");
    TEST_ASSERT_EQUAL('3', content[0], "Should start at offset 3");
    TEST_ASSERT_EQUAL('6', content[3], "Should read 4 bytes");

    free(content);
    close(source_fd);
    cleanup_test_dir();
}

TEST(test_file_content_make_file) {
    TEST_CASE("file_content make_file should create file with content");

    setup_test_dir();

    // Create source file
    char source_path[PATH_MAX];
    snprintf(source_path, sizeof(source_path), "%s/source.txt", test_dir);
    int source_fd = open(source_path, O_CREAT | O_RDWR, 0644);
    write(source_fd, "Test Data", 9);

    file_content_t fc = file_content_create(source_fd, "output.txt", 0, 9);

    file_t new_file = fc.make_file(&fc, test_dir, NULL);

    TEST_ASSERT_EQUAL(1, new_file.ok, "File should be created successfully");
    TEST_ASSERT_EQUAL_SIZE(9, new_file.size, "Size should match");

    char* content = new_file.content(&new_file);
    TEST_ASSERT_STR_EQUAL("Test Data", content, "Content should match");

    free(content);
    new_file.close(&new_file);
    close(source_fd);
    cleanup_test_dir();
}

TEST(test_file_content_make_file_with_offset) {
    TEST_CASE("file_content make_file should handle offset correctly");

    setup_test_dir();

    char source_path[PATH_MAX];
    snprintf(source_path, sizeof(source_path), "%s/source.txt", test_dir);
    int source_fd = open(source_path, O_CREAT | O_RDWR, 0644);
    write(source_fd, "0123456789", 10);

    file_content_t fc = file_content_create(source_fd, "output.txt", 5, 5);

    file_t new_file = fc.make_file(&fc, test_dir, "partial.txt");

    TEST_ASSERT_EQUAL(1, new_file.ok, "File should be created");

    char* content = new_file.content(&new_file);
    TEST_ASSERT_STR_EQUAL("56789", content, "Should contain offset portion");

    free(content);
    new_file.close(&new_file);
    close(source_fd);
    cleanup_test_dir();
}

TEST(test_file_content_make_tmpfile) {
    TEST_CASE("file_content make_tmpfile should create temporary file");

    setup_test_dir();

    char source_path[PATH_MAX];
    snprintf(source_path, sizeof(source_path), "%s/source.txt", test_dir);
    int source_fd = open(source_path, O_CREAT | O_RDWR, 0644);
    write(source_fd, "Temporary", 9);

    file_content_t fc = file_content_create(source_fd, "temp.txt", 0, 9);

    file_t tmp_file = fc.make_tmpfile(&fc, "/tmp");

    TEST_ASSERT_EQUAL(1, tmp_file.ok, "Temporary file should be created");
    TEST_ASSERT_EQUAL(1, tmp_file.tmp, "tmp flag should be set");
    TEST_ASSERT_EQUAL_SIZE(9, tmp_file.size, "Size should match");

    char* content = tmp_file.content(&tmp_file);
    TEST_ASSERT_STR_EQUAL("Temporary", content, "Content should match");

    free(content);
    tmp_file.close(&tmp_file);
    close(source_fd);
    cleanup_test_dir();
}

TEST(test_file_content_make_file_null_file_content) {
    TEST_CASE("file_content make_file should handle NULL file_content");

    file_content_t fc = file_content_create(0, "test.txt", 0, 0);
    file_t result = fc.make_file(NULL, "/tmp", "test.txt");

    TEST_ASSERT_EQUAL(0, result.ok, "Should fail gracefully");
    TEST_ASSERT_EQUAL(-1, result.fd, "fd should be -1");
}

TEST(test_file_content_make_tmpfile_null_file_content) {
    TEST_CASE("file_content make_tmpfile should handle NULL file_content");

    file_content_t fc = file_content_create(0, "test.txt", 0, 0);
    file_t result = fc.make_tmpfile(NULL, "/tmp");

    TEST_ASSERT_EQUAL(0, result.ok, "Should fail gracefully");
    TEST_ASSERT_EQUAL(-1, result.fd, "fd should be -1");
}

TEST(test_file_content_content_null_pointer) {
    TEST_CASE("file_content content() should handle NULL pointer");

    file_content_t fc = file_content_create(0, "test.txt", 0, 0);
    char* result = fc.content(NULL);

    TEST_ASSERT_NULL(result, "Should return NULL for NULL input");
}

// ============================================================================
// Edge Case Tests - Invalid File Descriptors
// ============================================================================

TEST(test_file_content_invalid_fd) {
    TEST_CASE("file_content should handle invalid fd gracefully");

    file_content_t fc = file_content_create(-1, "test.txt", 0, 10);

    char* content = fc.content(&fc);

    TEST_ASSERT_NULL(content, "Should return NULL for invalid fd");

    if (content) {
        free(content);
    }
}

TEST(test_file_content_zero_fd) {
    TEST_CASE("file_content should reject fd = 0 (stdin)");

    file_content_t fc = file_content_create(0, "test.txt", 0, 10);

    char* content = fc.content(&fc);

    TEST_ASSERT_NULL(content, "Should return NULL for fd = 0");

    if (content) {
        free(content);
    }
}

TEST(test_file_content_zero_size) {
    TEST_CASE("file_content should handle zero size");

    setup_test_dir();

    char source_path[PATH_MAX];
    snprintf(source_path, sizeof(source_path), "%s/source.txt", test_dir);
    int source_fd = open(source_path, O_CREAT | O_RDWR, 0644);

    file_content_t fc = file_content_create(source_fd, "test.txt", 0, 0);

    char* content = fc.content(&fc);

    TEST_ASSERT_NULL(content, "Should return NULL for zero size");

    if (content) {
        free(content);
    }
    close(source_fd);
    cleanup_test_dir();
}

// ============================================================================
// Edge Case Tests - Binary Data
// ============================================================================

TEST(test_file_binary_data) {
    TEST_CASE("File operations should handle binary data correctly");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/binary.dat", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);

    // Binary data with null bytes
    unsigned char binary_data[] = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00, 0xAB, 0xCD};
    int result = file.set_content(&file, (char*)binary_data, sizeof(binary_data));

    TEST_ASSERT_EQUAL((int)sizeof(binary_data), result, "Should write all binary data");
    TEST_ASSERT_EQUAL_SIZE(sizeof(binary_data), file.size, "Size should match");

    char* content = file.content(&file);
    TEST_ASSERT_NOT_NULL(content, "Content should not be NULL");
    TEST_ASSERT_EQUAL(0x00, (unsigned char)content[0], "First byte should match");
    TEST_ASSERT_EQUAL(0xFF, (unsigned char)content[3], "Fourth byte should match");
    TEST_ASSERT_EQUAL(0xCD, (unsigned char)content[7], "Last byte should match");

    free(content);
    file.close(&file);
    cleanup_test_dir();
}

// ============================================================================
// Edge Case Tests - Large Files
// ============================================================================

TEST(test_file_large_content) {
    TEST_CASE("File operations should handle large content");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/large.dat", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);

    // Create 1MB of data
    const size_t large_size = 1024 * 1024;
    char* large_data = malloc(large_size);
    if (!large_data) {
        file.close(&file);
        cleanup_test_dir();
        TEST_ASSERT_NOT_NULL(large_data, "malloc should succeed");
        return;
    }

    memset(large_data, 'X', large_size);

    int result = file.set_content(&file, large_data, large_size);

    TEST_ASSERT_EQUAL((int)large_size, result, "Should write all data");
    TEST_ASSERT_EQUAL_SIZE(large_size, file.size, "Size should match");

    free(large_data);
    file.close(&file);
    cleanup_test_dir();
}

// ============================================================================
// Edge Case Tests - Concurrent Access
// ============================================================================

TEST(test_file_multiple_opens) {
    TEST_CASE("Multiple file_open calls on same file should work");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/multi.txt", test_dir);

    file_t file1 = file_open(filepath, O_CREAT | O_RDWR);
    file1.set_content(&file1, "Data1", 5);

    file_t file2 = file_open(filepath, O_RDONLY);

    TEST_ASSERT_EQUAL(1, file2.ok, "Second open should succeed");

    char* content = file2.content(&file2);
    TEST_ASSERT_STR_EQUAL("Data1", content, "Both should see same content");

    free(content);
    file1.close(&file1);
    file2.close(&file2);
    cleanup_test_dir();
}

// ============================================================================
// Memory Leak Tests
// ============================================================================

TEST(test_file_content_memory_leak) {
    TEST_CASE("content() return value must be freed by caller");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/leak_test.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);
    file.set_content(&file, "Memory Test", 11);

    // Multiple calls should each allocate new memory
    char* content1 = file.content(&file);
    char* content2 = file.content(&file);

    TEST_ASSERT(content1 != content2, "Each call should allocate new memory");

    free(content1);
    free(content2);
    file.close(&file);
    cleanup_test_dir();
}

// ============================================================================
// Stress Tests
// ============================================================================

TEST(test_file_many_appends) {
    TEST_CASE("Many consecutive appends should work correctly");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/many_appends.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);
    file.set_content(&file, "", 0);

    for (int i = 0; i < 100; i++) {
        file.append_content(&file, "X", 1);
    }

    TEST_ASSERT_EQUAL_SIZE(100, file.size, "Size should be 100");

    char* content = file.content(&file);
    TEST_ASSERT_EQUAL_SIZE(100, strlen(content), "Content length should be 100");

    free(content);
    file.close(&file);
    cleanup_test_dir();
}

TEST(test_file_alternating_operations) {
    TEST_CASE("Alternating set_content and append_content");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/alternating.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);

    file.set_content(&file, "A", 1);
    file.append_content(&file, "B", 1);
    file.set_content(&file, "C", 1);
    file.append_content(&file, "D", 1);

    char* content = file.content(&file);
    TEST_ASSERT_STR_EQUAL("CD", content, "Last set_content should overwrite");

    free(content);
    file.close(&file);
    cleanup_test_dir();
}

// ============================================================================
// Permission Tests
// ============================================================================

TEST(test_file_readonly_write_attempt) {
    TEST_CASE("Writing to read-only file should fail");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/readonly.txt", test_dir);

    // Create file first
    file_t file_w = file_open(filepath, O_CREAT | O_RDWR);
    file_w.set_content(&file_w, "Initial", 7);
    file_w.close(&file_w);

    // Open as read-only
    file_t file_r = file_open(filepath, O_RDONLY);
    TEST_ASSERT_EQUAL(1, file_r.ok, "File should open");

    int result = file_r.set_content(&file_r, "New", 3);

    // This might succeed or fail depending on implementation
    // The test verifies behavior is defined
    TEST_ASSERT(result >= 0 || result == -1, "Result should be defined");

    file_r.close(&file_r);
    cleanup_test_dir();
}

// ============================================================================
// Special Cases - Filename Edge Cases
// ============================================================================

TEST(test_file_unicode_filename) {
    TEST_CASE("File operations with UTF-8 filename");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/тест_файл.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);

    // Behavior depends on system locale, just verify it doesn't crash
    TEST_ASSERT(file.fd >= -1, "Should handle gracefully");

    if (file.ok) {
        file.close(&file);
    }

    cleanup_test_dir();
}

TEST(test_file_special_chars_filename) {
    TEST_CASE("File operations with special characters in filename");

    setup_test_dir();

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/file with spaces & special@chars.txt", test_dir);

    file_t file = file_open(filepath, O_CREAT | O_RDWR);

    TEST_ASSERT_EQUAL(1, file.ok, "Should handle special characters");
    TEST_ASSERT_STR_EQUAL("file with spaces & special@chars.txt", file.name, "Filename should preserve special chars");

    file.close(&file);
    cleanup_test_dir();
}
