#include "framework.h"
#include "helpers.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

// ============================================================================
// Тесты сравнения строк без учета регистра
// ============================================================================

TEST(test_cmpstr_lower_equal_strings) {
    TEST_CASE("Compare equal strings case-insensitive");

    TEST_ASSERT_EQUAL(1, cmpstr_lower("hello", "hello"), "Same case should match");
    TEST_ASSERT_EQUAL(1, cmpstr_lower("hello", "HELLO"), "Different case should match");
    TEST_ASSERT_EQUAL(1, cmpstr_lower("HeLLo", "hEllO"), "Mixed case should match");
    TEST_ASSERT_EQUAL(1, cmpstr_lower("", ""), "Empty strings should match");
}

TEST(test_cmpstr_lower_different_strings) {
    TEST_CASE("Compare different strings case-insensitive");

    TEST_ASSERT_EQUAL(0, cmpstr_lower("hello", "world"), "Different strings should not match");
    TEST_ASSERT_EQUAL(0, cmpstr_lower("hello", "WORLD"), "Different strings different case should not match");
    TEST_ASSERT_EQUAL(0, cmpstr_lower("test", "testing"), "Different lengths should not match");
    TEST_ASSERT_EQUAL(0, cmpstr_lower("", "nonempty"), "Empty vs non-empty should not match");
}

TEST(test_cmpstr_lower_special_chars) {
    TEST_CASE("Compare strings with special characters");

    TEST_ASSERT_EQUAL(1, cmpstr_lower("hello123", "HELLO123"), "Alphanumeric should match");
    TEST_ASSERT_EQUAL(1, cmpstr_lower("hello-world", "HELLO-WORLD"), "With dashes should match");
    TEST_ASSERT_EQUAL(1, cmpstr_lower("hello_world", "HELLO_WORLD"), "With underscores should match");
    TEST_ASSERT_EQUAL(1, cmpstr_lower("hello.txt", "HELLO.TXT"), "With dots should match");
}

TEST(test_cmpstrn_lower_exact_length) {
    TEST_CASE("Compare strings with exact length");

    TEST_ASSERT_EQUAL(1, cmpstrn_lower("hello", 5, "HELLO", 5), "Equal length should match");
    TEST_ASSERT_EQUAL(1, cmpstrn_lower("test", 4, "TEST", 4), "Equal length should match");
}

TEST(test_cmpstrn_lower_different_length) {
    TEST_CASE("Compare strings with different lengths");

    TEST_ASSERT_EQUAL(0, cmpstrn_lower("hello", 5, "hello", 3), "Different lengths should not match");
    TEST_ASSERT_EQUAL(0, cmpstrn_lower("test", 2, "test", 4), "Different lengths should not match");
}

TEST(test_cmpstrn_lower_partial_comparison) {
    TEST_CASE("Compare partial strings");

    TEST_ASSERT_EQUAL(1, cmpstrn_lower("hello world", 5, "HELLO", 5), "First 5 chars should match");
    TEST_ASSERT_EQUAL(1, cmpstrn_lower("testing", 4, "TEST", 4), "Partial match should work");
}

TEST(test_cmpstrn_lower_zero_length) {
    TEST_CASE("Compare zero-length strings");

    TEST_ASSERT_EQUAL(1, cmpstrn_lower("hello", 0, "world", 0), "Zero length should match");
    TEST_ASSERT_EQUAL(1, cmpstrn_lower("", 0, "", 0), "Empty zero length should match");
}

// ============================================================================
// Тесты поиска подстроки без учета регистра
// ============================================================================

TEST(test_cmpsubstr_lower_found) {
    TEST_CASE("Find substring case-insensitive");

    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("hello world", "world"), "Should find 'world'");
    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("hello world", "WORLD"), "Should find 'WORLD'");
    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("HELLO WORLD", "world"), "Should find 'world' in uppercase");
    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("hello world", "hello"), "Should find at beginning");
}

TEST(test_cmpsubstr_lower_not_found) {
    TEST_CASE("Substring not found");

    TEST_ASSERT_EQUAL(0, cmpsubstr_lower("hello world", "test"), "Should not find 'test'");
    TEST_ASSERT_EQUAL(0, cmpsubstr_lower("hello", "hello world"), "Substring longer than string");
    TEST_ASSERT_EQUAL(0, cmpsubstr_lower("", "test"), "Empty string should not contain substring");
}

TEST(test_cmpsubstr_lower_middle) {
    TEST_CASE("Find substring in the middle");

    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("the quick brown fox", "QUICK"), "Should find in middle");
    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("abcdefghijk", "def"), "Should find consecutive chars");
}

TEST(test_cmpsubstr_lower_single_char) {
    TEST_CASE("Find single character substring");

    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("hello", "h"), "Should find single char at start");
    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("hello", "o"), "Should find single char at end");
    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("hello", "l"), "Should find single char in middle");
}

TEST(test_cmpsubstr_lower_full_match) {
    TEST_CASE("Substring equals full string");

    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("hello", "hello"), "Full match should work");
    TEST_ASSERT_EQUAL(1, cmpsubstr_lower("hello", "HELLO"), "Full match case-insensitive");
}

// ============================================================================
// Тесты получения расширения файла
// ============================================================================

TEST(test_file_extension_simple) {
    TEST_CASE("Get simple file extension");

    const char* ext = file_extension("file.txt");
    TEST_ASSERT_NOT_NULL(ext, "Extension should be found");
    TEST_ASSERT_STR_EQUAL("txt", ext, "Extension should be 'txt'");
}

TEST(test_file_extension_multiple_dots) {
    TEST_CASE("Get extension with multiple dots");

    const char* ext = file_extension("archive.tar.gz");
    TEST_ASSERT_NOT_NULL(ext, "Extension should be found");
    TEST_ASSERT_STR_EQUAL("gz", ext, "Extension should be 'gz'");
}

TEST(test_file_extension_with_path) {
    TEST_CASE("Get extension from full path");

    const char* ext = file_extension("/path/to/file.pdf");
    TEST_ASSERT_NOT_NULL(ext, "Extension should be found");
    TEST_ASSERT_STR_EQUAL("pdf", ext, "Extension should be 'pdf'");
}

TEST(test_file_extension_no_extension) {
    TEST_CASE("File without extension");

    const char* ext = file_extension("README");
    TEST_ASSERT_NULL(ext, "Should return NULL for file without extension");
}

TEST(test_file_extension_directory_with_dot) {
    TEST_CASE("Directory with dot in name");

    const char* ext = file_extension("/path/to/dir.name/file");
    TEST_ASSERT_NULL(ext, "Should return NULL when dot is in directory name");
}

TEST(test_file_extension_hidden_file) {
    TEST_CASE("Hidden file extension detection");

    const char* ext = file_extension(".gitignore");
    TEST_ASSERT_NOT_NULL(ext, "Extension should be found");
    TEST_ASSERT_STR_EQUAL("gitignore", ext, "Extension should be 'gitignore'");
}

TEST(test_file_extension_dot_at_end) {
    TEST_CASE("File ending with dot");

    const char* ext = file_extension("file.");
    TEST_ASSERT_NULL(ext, "No extension after dot - should return NULL");
}

TEST(test_file_extension_null_pointer) {
    TEST_CASE("Handle NULL pointer gracefully");

    const char* ext = file_extension(NULL);
    TEST_ASSERT_NULL(ext, "NULL input should return NULL");
}

TEST(test_file_extension_empty_string_safe) {
    TEST_CASE("Handle empty string safely");

    const char* ext = file_extension("");
    TEST_ASSERT_NULL(ext, "Empty string should return NULL");
}

TEST(test_file_extension_single_dot) {
    TEST_CASE("Single dot as filename");

    const char* ext = file_extension(".");
    TEST_ASSERT_NULL(ext, "No extension after dot - should return NULL");
}

TEST(test_file_extension_bashrc) {
    TEST_CASE("Hidden bashrc file");

    const char* ext = file_extension(".bashrc");
    TEST_ASSERT_NOT_NULL(ext, "Extension should be found");
    TEST_ASSERT_STR_EQUAL("bashrc", ext, "Extension should be 'bashrc'");
}

// ============================================================================
// Тесты создания временного пути
// ============================================================================

TEST(test_create_tmppath_valid) {
    TEST_CASE("Create temporary path");

    char* path = create_tmppath("/tmp");
    TEST_ASSERT_NOT_NULL(path, "Path should be created");
    TEST_ASSERT(strstr(path, "/tmp/tmp.XXXXXX") != NULL, "Path should contain template");
    TEST_ASSERT(strlen(path) > 10, "Path should have reasonable length");

    free(path);
}

TEST(test_create_tmppath_different_base) {
    TEST_CASE("Create temporary path with different base");

    char* path = create_tmppath("/var/tmp");
    TEST_ASSERT_NOT_NULL(path, "Path should be created");
    TEST_ASSERT(strstr(path, "/var/tmp/tmp.XXXXXX") != NULL, "Path should contain base and template");

    free(path);
}

TEST(test_create_tmppath_no_trailing_slash) {
    TEST_CASE("Create temporary path without trailing slash");

    char* path = create_tmppath("/home/user");
    TEST_ASSERT_NOT_NULL(path, "Path should be created");
    TEST_ASSERT(strstr(path, "/home/user/tmp.XXXXXX") != NULL, "Should add slash automatically");

    free(path);
}

// ============================================================================
// Тесты конвертации HEX в байты и обратно
// ============================================================================

TEST(test_hex_to_bytes_valid) {
    TEST_CASE("Convert valid hex string to bytes");

    unsigned char bytes[4];
    int result = hex_to_bytes("48656c6c", bytes);

    TEST_ASSERT_EQUAL(1, result, "Conversion should succeed");
    TEST_ASSERT_EQUAL(0x48, bytes[0], "First byte should be 0x48");
    TEST_ASSERT_EQUAL(0x65, bytes[1], "Second byte should be 0x65");
    TEST_ASSERT_EQUAL(0x6c, bytes[2], "Third byte should be 0x6c");
    TEST_ASSERT_EQUAL(0x6c, bytes[3], "Fourth byte should be 0x6c");
}

TEST(test_hex_to_bytes_uppercase) {
    TEST_CASE("Convert uppercase hex to bytes");

    unsigned char bytes[2];
    int result = hex_to_bytes("ABCD", bytes);

    TEST_ASSERT_EQUAL(1, result, "Conversion should succeed");
    TEST_ASSERT_EQUAL(0xAB, bytes[0], "First byte should be 0xAB");
    TEST_ASSERT_EQUAL(0xCD, bytes[1], "Second byte should be 0xCD");
}

TEST(test_hex_to_bytes_mixed_case) {
    TEST_CASE("Convert mixed case hex to bytes");

    unsigned char bytes[2];
    int result = hex_to_bytes("aBcD", bytes);

    TEST_ASSERT_EQUAL(1, result, "Conversion should succeed");
    TEST_ASSERT_EQUAL(0xAB, bytes[0], "First byte should be 0xAB");
    TEST_ASSERT_EQUAL(0xCD, bytes[1], "Second byte should be 0xCD");
}

TEST(test_hex_to_bytes_odd_length) {
    TEST_CASE("Convert odd length hex string");

    unsigned char bytes[2];
    int result = hex_to_bytes("ABC", bytes);

    TEST_ASSERT_EQUAL(0, result, "Should fail for odd length");
}

TEST(test_hex_to_bytes_invalid_chars) {
    TEST_CASE("Convert hex with invalid characters");

    unsigned char bytes[2];
    int result = hex_to_bytes("GHIJ", bytes);

    TEST_ASSERT_EQUAL(0, result, "Should fail for invalid characters");
}

TEST(test_hex_to_bytes_empty_string) {
    TEST_CASE("Convert empty hex string");

    unsigned char bytes[1];
    int result = hex_to_bytes("", bytes);

    TEST_ASSERT_EQUAL(1, result, "Empty string should succeed");
}

TEST(test_bytes_to_hex_valid) {
    TEST_CASE("Convert bytes to hex string");

    unsigned char bytes[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    char hex[11];

    bytes_to_hex(bytes, 5, hex);

    TEST_ASSERT_STR_EQUAL("48656c6c6f", hex, "Hex string should be correct");
}

TEST(test_bytes_to_hex_single_byte) {
    TEST_CASE("Convert single byte to hex");

    unsigned char bytes[] = {0xFF};
    char hex[3];

    bytes_to_hex(bytes, 1, hex);

    TEST_ASSERT_STR_EQUAL("ff", hex, "Single byte hex should be correct");
}

TEST(test_bytes_to_hex_zero_bytes) {
    TEST_CASE("Convert zero bytes to hex");

    unsigned char bytes[] = {0x00, 0x00};
    char hex[5];

    bytes_to_hex(bytes, 2, hex);

    TEST_ASSERT_STR_EQUAL("0000", hex, "Zero bytes should convert correctly");
}

TEST(test_hex_roundtrip) {
    TEST_CASE("Hex to bytes and back roundtrip");

    const char* original = "48656c6c6f";
    unsigned char bytes[5];
    char hex[11];

    hex_to_bytes(original, bytes);
    bytes_to_hex(bytes, 5, hex);

    TEST_ASSERT_STR_EQUAL(original, hex, "Roundtrip should preserve data");
}

// ============================================================================
// Тесты URL encoding/decoding
// ============================================================================

TEST(test_urlencode_simple) {
    TEST_CASE("URL encode simple string");

    char* encoded = urlencode("hello world", 11);
    TEST_ASSERT_NOT_NULL(encoded, "Encoded string should not be NULL");
    TEST_ASSERT_STR_EQUAL("hello+world", encoded, "Space should be encoded as +");

    free(encoded);
}

TEST(test_urlencode_special_chars) {
    TEST_CASE("URL encode special characters");

    char* encoded = urlencode("hello@world.com", 15);
    TEST_ASSERT_NOT_NULL(encoded, "Encoded string should not be NULL");
    TEST_ASSERT(strstr(encoded, "%40") != NULL, "@ should be percent-encoded");

    free(encoded);
}

TEST(test_urlencode_safe_chars) {
    TEST_CASE("URL encode safe characters");

    char* encoded = urlencode("abc-123_def.ghi~", 16);
    TEST_ASSERT_NOT_NULL(encoded, "Encoded string should not be NULL");
    TEST_ASSERT_STR_EQUAL("abc-123_def.ghi~", encoded, "Safe chars should not be encoded");

    free(encoded);
}

TEST(test_urlencode_null_input) {
    TEST_CASE("URL encode NULL input");

    char* encoded = urlencode(NULL, 0);
    TEST_ASSERT_NULL(encoded, "Should return NULL for NULL input");
}

TEST(test_urlencodel_with_length) {
    TEST_CASE("URL encode with output length");

    size_t output_length = 0;
    char* encoded = urlencodel("hello world", 11, &output_length);

    TEST_ASSERT_NOT_NULL(encoded, "Encoded string should not be NULL");
    TEST_ASSERT_EQUAL_SIZE(11, output_length, "Output length should be correct");
    TEST_ASSERT_STR_EQUAL("hello+world", encoded, "Content should match");

    free(encoded);
}

TEST(test_urldecode_simple) {
    TEST_CASE("URL decode simple string");

    char* decoded = urldecode("hello+world", 11);
    TEST_ASSERT_NOT_NULL(decoded, "Decoded string should not be NULL");
    TEST_ASSERT_STR_EQUAL("hello world", decoded, "+ should be decoded as space");

    free(decoded);
}

TEST(test_urldecode_percent_encoding) {
    TEST_CASE("URL decode percent-encoded characters");

    char* decoded = urldecode("hello%20world", 13);
    TEST_ASSERT_NOT_NULL(decoded, "Decoded string should not be NULL");
    TEST_ASSERT_STR_EQUAL("hello world", decoded, "%20 should be decoded as space");

    free(decoded);
}

TEST(test_urldecode_special_chars) {
    TEST_CASE("URL decode special characters");

    char* decoded = urldecode("email%40example.com", 19);
    TEST_ASSERT_NOT_NULL(decoded, "Decoded string should not be NULL");
    TEST_ASSERT_STR_EQUAL("email@example.com", decoded, "%40 should be decoded as @");

    free(decoded);
}

TEST(test_urldecodel_with_length) {
    TEST_CASE("URL decode with output length");

    size_t output_length = 0;
    char* decoded = urldecodel("hello+world", 11, &output_length);

    TEST_ASSERT_NOT_NULL(decoded, "Decoded string should not be NULL");
    TEST_ASSERT_EQUAL_SIZE(11, output_length, "Output length should be correct");
    TEST_ASSERT_STR_EQUAL("hello world", decoded, "Content should match");

    free(decoded);
}

TEST(test_url_encode_decode_roundtrip) {
    TEST_CASE("URL encode and decode roundtrip");

    const char* original = "hello world!@#$%";
    size_t original_len = strlen(original);

    char* encoded = urlencode(original, original_len);
    TEST_ASSERT_NOT_NULL(encoded, "Encoding should succeed");

    char* decoded = urldecode(encoded, strlen(encoded));
    TEST_ASSERT_NOT_NULL(decoded, "Decoding should succeed");
    TEST_ASSERT_STR_EQUAL(original, decoded, "Roundtrip should preserve data");

    free(encoded);
    free(decoded);
}

// ============================================================================
// Тесты добавления данных в буфер
// ============================================================================

TEST(test_data_append_simple) {
    TEST_CASE("Append data to buffer");

    char buffer[100] = {0};
    size_t pos = 0;

    int result = data_append(buffer, &pos, "Hello", 5);

    TEST_ASSERT_EQUAL(1, result, "Append should succeed");
    TEST_ASSERT_EQUAL_SIZE(5, pos, "Position should be updated");
    TEST_ASSERT(memcmp(buffer, "Hello", 5) == 0, "Data should be appended");
}

TEST(test_data_append_multiple) {
    TEST_CASE("Append multiple times");

    char buffer[100] = {0};
    size_t pos = 0;

    data_append(buffer, &pos, "Hello", 5);
    data_append(buffer, &pos, " ", 1);
    data_append(buffer, &pos, "World", 5);

    TEST_ASSERT_EQUAL_SIZE(11, pos, "Position should be 11");
    TEST_ASSERT(memcmp(buffer, "Hello World", 11) == 0, "Data should be concatenated");
}

TEST(test_data_append_null_buffer) {
    TEST_CASE("Append to NULL buffer");

    size_t pos = 0;
    int result = data_append(NULL, &pos, "test", 4);

    TEST_ASSERT_EQUAL(0, result, "Should fail for NULL buffer");
}

TEST(test_data_append_null_string) {
    TEST_CASE("Append NULL string");

    char buffer[100] = {0};
    size_t pos = 0;
    int result = data_append(buffer, &pos, NULL, 4);

    TEST_ASSERT_EQUAL(0, result, "Should fail for NULL string");
}

TEST(test_data_appendn_within_limit) {
    TEST_CASE("Append data within size limit");

    char buffer[20] = {0};
    size_t pos = 0;

    int result = data_appendn(buffer, &pos, 20, "Hello", 5);

    TEST_ASSERT_EQUAL(1, result, "Append should succeed");
    TEST_ASSERT_EQUAL_SIZE(5, pos, "Position should be updated");
}

TEST(test_data_appendn_exceeds_limit) {
    TEST_CASE("Append data exceeds size limit");

    char buffer[10] = {0};
    size_t pos = 5;

    int result = data_appendn(buffer, &pos, 10, "Hello", 5);

    TEST_ASSERT_EQUAL(0, result, "Should fail when exceeding limit");
    TEST_ASSERT_EQUAL_SIZE(5, pos, "Position should not change");
}

TEST(test_data_appendn_exact_limit) {
    TEST_CASE("Append data at exact limit");

    char buffer[10] = {0};
    size_t pos = 5;

    int result = data_appendn(buffer, &pos, 10, "test", 4);

    TEST_ASSERT_EQUAL(1, result, "Should succeed at exact limit");
    TEST_ASSERT_EQUAL_SIZE(9, pos, "Position should be 9");
}

TEST(test_data_appendn_multiple_appends) {
    TEST_CASE("Multiple bounded appends");

    char buffer[20] = {0};
    size_t pos = 0;

    TEST_ASSERT_EQUAL(1, data_appendn(buffer, &pos, 20, "ABC", 3), "First append should succeed");
    TEST_ASSERT_EQUAL(1, data_appendn(buffer, &pos, 20, "DEF", 3), "Second append should succeed");
    TEST_ASSERT_EQUAL(1, data_appendn(buffer, &pos, 20, "GHI", 3), "Third append should succeed");

    TEST_ASSERT_EQUAL_SIZE(9, pos, "Position should be 9");
    TEST_ASSERT(memcmp(buffer, "ABCDEFGHI", 9) == 0, "Data should be concatenated");
}

// ============================================================================
// Тесты проверки path traversal
// ============================================================================

TEST(test_is_path_traversal_simple) {
    TEST_CASE("Detect simple path traversal");

    TEST_ASSERT_EQUAL(1, is_path_traversal("/../etc/passwd", 14), "Should detect /../");
    TEST_ASSERT_EQUAL(1, is_path_traversal("/var/../etc", 11), "Should detect /../ in middle");
}

TEST(test_is_path_traversal_at_end) {
    TEST_CASE("Detect path traversal at end");

    TEST_ASSERT_EQUAL(1, is_path_traversal("/var/www/..", 11), "Should detect /.. at end");
}

TEST(test_is_path_traversal_multiple) {
    TEST_CASE("Detect multiple path traversals");

    TEST_ASSERT_EQUAL(1, is_path_traversal("/../../etc", 10), "Should detect multiple /../");
}

TEST(test_is_path_traversal_safe_paths) {
    TEST_CASE("Safe paths should not trigger detection");

    TEST_ASSERT_EQUAL(0, is_path_traversal("/var/www/html", 13), "Normal path should be safe");
    TEST_ASSERT_EQUAL(0, is_path_traversal("/etc/nginx.conf", 15), "Normal path should be safe");
    TEST_ASSERT_EQUAL(0, is_path_traversal("", 0), "Empty path should be safe");
}

TEST(test_is_path_traversal_dotfiles) {
    TEST_CASE("Dotfiles should not trigger detection");

    TEST_ASSERT_EQUAL(0, is_path_traversal("/.gitignore", 11), "Dotfile should be safe");
    TEST_ASSERT_EQUAL(0, is_path_traversal("/var/www/.hidden", 16), "Dotfile should be safe");
}

TEST(test_is_path_traversal_single_dot) {
    TEST_CASE("Single dot should not trigger detection");

    TEST_ASSERT_EQUAL(0, is_path_traversal("/./var", 6), "/./ should be safe");
    TEST_ASSERT_EQUAL(0, is_path_traversal("/var/./www", 10), "/./ in middle should be safe");
}

TEST(test_is_path_traversal_dots_in_filename) {
    TEST_CASE("Dots in filename should not trigger");

    TEST_ASSERT_EQUAL(0, is_path_traversal("/file.name.txt", 14), "Dots in filename should be safe");
    TEST_ASSERT_EQUAL(0, is_path_traversal("/archive..tar.gz", 16), "Multiple dots should be safe");
}

TEST(test_is_path_traversal_without_slash) {
    TEST_CASE("Path traversal patterns without slash prefix");

    TEST_ASSERT_EQUAL(0, is_path_traversal("../etc/passwd", 13), ".. without leading / should be safe");
}

// ============================================================================
// Тесты копирования строк
// ============================================================================

TEST(test_copy_cstringn_simple) {
    TEST_CASE("Copy simple string");

    char* copy = copy_cstringn("hello", 5);
    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT_STR_EQUAL("hello", copy, "Copy should match original");

    free(copy);
}

TEST(test_copy_cstringn_partial) {
    TEST_CASE("Copy partial string");

    char* copy = copy_cstringn("hello world", 5);
    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT_STR_EQUAL("hello", copy, "Should copy only first 5 chars");
    TEST_ASSERT_EQUAL_SIZE(5, strlen(copy), "Length should be 5");

    free(copy);
}

TEST(test_copy_cstringn_empty) {
    TEST_CASE("Copy empty string");

    char* copy = copy_cstringn("", 0);
    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT_STR_EQUAL("", copy, "Copy should be empty");

    free(copy);
}

TEST(test_copy_cstringn_null_input) {
    TEST_CASE("Copy NULL string");

    char* copy = copy_cstringn(NULL, 5);
    TEST_ASSERT_NOT_NULL(copy, "Should allocate buffer even for NULL input");

    free(copy);
}

TEST(test_copy_cstringn_null_termination) {
    TEST_CASE("Verify null termination");

    char* copy = copy_cstringn("test", 4);
    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT_EQUAL('\0', copy[4], "Should be null-terminated");

    free(copy);
}

TEST(test_copy_cstringn_binary_data) {
    TEST_CASE("Copy binary data with null bytes");

    char data[] = {'A', 'B', '\0', 'C', 'D'};
    char* copy = copy_cstringn(data, 5);

    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT_EQUAL('A', copy[0], "First byte should be A");
    TEST_ASSERT_EQUAL('\0', copy[2], "Third byte should be null");
    TEST_ASSERT_EQUAL('D', copy[4], "Fifth byte should be D");
    TEST_ASSERT_EQUAL('\0', copy[5], "Should be null-terminated");

    free(copy);
}

TEST(test_copy_cstringn_special_chars) {
    TEST_CASE("Copy string with special characters");

    char* copy = copy_cstringn("hello\nworld\ttab", 15);
    TEST_ASSERT_NOT_NULL(copy, "Copy should not be NULL");
    TEST_ASSERT(strstr(copy, "\n") != NULL, "Should contain newline");
    TEST_ASSERT(strstr(copy, "\t") != NULL, "Should contain tab");

    free(copy);
}

// ============================================================================
// Тесты граничных случаев и производительности
// ============================================================================

TEST(test_helpers_large_data) {
    TEST_CASE("Handle large data buffers");

    char large_buffer[10000] = {0};
    size_t pos = 0;

    for (int i = 0; i < 100; i++) {
        int result = data_append(large_buffer, &pos, "0123456789", 10);
        TEST_ASSERT_EQUAL(1, result, "Large append should succeed");
    }

    TEST_ASSERT_EQUAL_SIZE(1000, pos, "Position should be 1000");
}

TEST(test_helpers_long_hex_string) {
    TEST_CASE("Convert long hex string");

    char hex[201];
    unsigned char bytes[100];
    char hex_out[201];

    for (int i = 0; i < 200; i++) {
        hex[i] = (i % 2 == 0) ? 'A' : 'B';
    }
    hex[200] = '\0';

    int result = hex_to_bytes(hex, bytes);
    TEST_ASSERT_EQUAL(1, result, "Should convert long hex string");

    bytes_to_hex(bytes, 100, hex_out);
    TEST_ASSERT(strlen(hex_out) == 200, "Output length should match");
}

TEST(test_helpers_long_url_encoding) {
    TEST_CASE("Encode long URL string");

    char long_string[500];
    memset(long_string, 'A', 499);
    long_string[499] = '\0';

    char* encoded = urlencode(long_string, 499);
    TEST_ASSERT_NOT_NULL(encoded, "Should encode long string");
    TEST_ASSERT(strlen(encoded) >= 499, "Encoded should be at least as long");

    free(encoded);
}

TEST(test_helpers_edge_case_empty_strings) {
    TEST_CASE("Handle empty strings across functions");

    TEST_ASSERT_EQUAL(1, cmpstr_lower("", ""), "Empty strings should match");
    TEST_ASSERT_EQUAL(0, cmpsubstr_lower("", "test"), "Empty string has no substring");
    TEST_ASSERT_NULL(file_extension(""), "Empty string should return NULL");

    char* encoded = urlencode("", 0);
    TEST_ASSERT_NOT_NULL(encoded, "Empty string should encode");
    free(encoded);
}

// ============================================================================
// Тесты timezone_offset
// ============================================================================

TEST(test_timezone_offset_returns_value) {
    TEST_CASE("Timezone offset returns a value");

    int offset = timezone_offset();
    TEST_ASSERT(offset >= -12 && offset <= 14, "Timezone offset should be in valid range");
}
