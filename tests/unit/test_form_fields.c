/*
 * Unit tests for the exotic field kinds of framework/form: date, time,
 * datetime, uuid, json, choice, filepath, file and multiple choice.
 *
 * Filesystem cases use an isolated directory and an open tmpfile upload.
 */

#include "framework.h"
#include "form/form.h"
#include "file.h"
#include "json.h"
#include "storagefs.h"
#include "appconfig.h"

#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FORM_FIELDS_COUNT 9
#define FIXTURE_ROOT "/tmp"
#define FIXTURE_DIR_TEMPLATE FIXTURE_ROOT "/cwfr-form-XXXXXX"
#define FIXTURE_STORAGE "form_test_storage"

/* env()/appconfig() are test doubles supplied by the runner. */
extern appconfig_t* appconfig(void);

static const char* const choices[] = { "red", "blue" };
static const char* const selected[] = { "red", "blue" };

static form_input_t text_input(const char* text) {
    return (form_input_t){ .kind = FORM_INPUT_TEXT,
                           .data.text = text ? strdup(text) : NULL };
}

static form_input_t list_input(const char* const* strings, size_t count) {
    char** items = count ? calloc(count, sizeof *items) : NULL;
    for (size_t i = 0; i < count; i++) items[i] = strdup(strings[i]);
    return (form_input_t){ .kind = FORM_INPUT_TEXT_LIST,
                           .data.text_list = { items, count } };
}

// ============================================================================
// Fixture: a temp directory holding sample.txt, plus an open upload stream
// ============================================================================

/* The filepath field borrows .directory for the lifetime of the form, so the
 * mkdtemp buffer lives in the fixture rather than in a helper's frame. The
 * field looks the directory up in FIXTURE_STORAGE, rooted at FIXTURE_ROOT. */
typedef struct {
    char directory[sizeof FIXTURE_DIR_TEMPLATE];
    char path[sizeof FIXTURE_DIR_TEMPLATE + 16];
    char link_path[sizeof FIXTURE_DIR_TEMPLATE + 16];
    char nested_path[sizeof FIXTURE_DIR_TEMPLATE + 16];
    char glob_path[sizeof FIXTURE_DIR_TEMPLATE + 16];
    FILE* upload;
    storagefs_t* storage;
    storage_t* previous_storages;
} form_fixture_t;

/* The fixture directory as seen from inside FIXTURE_STORAGE. */
static const char* fixture_storage_directory(const form_fixture_t* fx) {
    return fx->directory + sizeof FIXTURE_ROOT;
}

static void fixture_teardown(form_fixture_t* fx) {
    /* Only the rejection test creates link.txt, *.txt and nested/, and it may
     * have aborted before removing them; rmdir needs the directory empty. */
    unlink(fx->link_path);
    unlink(fx->glob_path);
    rmdir(fx->nested_path);

    appconfig()->storages = fx->previous_storages;
    storages_free((storage_t*)fx->storage);

    TEST_ASSERT_EQUAL(0, fclose(fx->upload), "the upload stream should close");
    TEST_ASSERT_EQUAL(0, unlink(fx->path), "sample.txt should be removed");
    TEST_ASSERT_EQUAL(0, rmdir(fx->directory), "the fixture directory should be removed");
}

static int fixture_setup(form_fixture_t* fx) {
    memset(fx, 0, sizeof *fx);
    memcpy(fx->directory, FIXTURE_DIR_TEMPLATE, sizeof FIXTURE_DIR_TEMPLATE);

    const char* created = mkdtemp(fx->directory);
    TEST_ASSERT_NOT_NULL(created, "mkdtemp should create the fixture directory");
    if (created == NULL) return -1;

    snprintf(fx->path, sizeof fx->path, "%s/sample.txt", fx->directory);
    snprintf(fx->link_path, sizeof fx->link_path, "%s/link.txt", fx->directory);
    snprintf(fx->nested_path, sizeof fx->nested_path, "%s/nested", fx->directory);
    snprintf(fx->glob_path, sizeof fx->glob_path, "%s/*.txt", fx->directory);

    FILE* existing = fopen(fx->path, "wb");
    TEST_ASSERT_NOT_NULL(existing, "sample.txt should be created");
    if (existing == NULL) {
        rmdir(fx->directory);
        return -1;
    }

    const size_t sample_written = fwrite("x", 1, 1, existing);
    TEST_ASSERT_EQUAL_SIZE(1, sample_written, "sample.txt should receive one byte");

    const int sample_closed = fclose(existing);
    TEST_ASSERT_EQUAL(0, sample_closed, "sample.txt should close");
    if (sample_written != 1 || sample_closed != 0) {
        unlink(fx->path);
        rmdir(fx->directory);
        return -1;
    }

    fx->upload = tmpfile();
    TEST_ASSERT_NOT_NULL(fx->upload, "tmpfile should open the upload stream");
    if (fx->upload == NULL) {
        unlink(fx->path);
        rmdir(fx->directory);
        return -1;
    }

    const size_t upload_written = fwrite("data", 1, 4, fx->upload);
    TEST_ASSERT_EQUAL_SIZE(4, upload_written, "the upload stream should receive four bytes");

    const int flushed = fflush(fx->upload);
    TEST_ASSERT_EQUAL(0, flushed, "the upload stream should flush");
    if (upload_written != 4 || flushed != 0) {
        fclose(fx->upload);
        fx->upload = NULL;
        unlink(fx->path);
        rmdir(fx->directory);
        return -1;
    }

    fx->storage = storage_create_fs(FIXTURE_STORAGE, FIXTURE_ROOT);
    TEST_ASSERT_NOT_NULL(fx->storage, "the fixture storage should be created");
    if (fx->storage == NULL) {
        fclose(fx->upload);
        fx->upload = NULL;
        unlink(fx->path);
        rmdir(fx->directory);
        return -1;
    }
    fx->previous_storages = appconfig()->storages;
    appconfig()->storages = (storage_t*)fx->storage;

    return 0;
}

/* The nine field kinds in the order both tests index them. Rebuilt per test
 * rather than kept at file scope: the filepath field borrows the directory of
 * that test's own fixture. */
static void build_fields(const form_fixture_t* fx,
                         form_field_spec_t fields[FORM_FIELDS_COUNT]) {
    fields[0] = (form_field_spec_t){ .kind = FORM_FIELD_DATE,
        .date = { .common = { .name = "date" } } };
    fields[1] = (form_field_spec_t){ .kind = FORM_FIELD_TIME,
        .time = { .common = { .name = "time" } } };
    fields[2] = (form_field_spec_t){ .kind = FORM_FIELD_DATETIME,
        .datetime = { .common = { .name = "datetime" } } };
    fields[3] = (form_field_spec_t){ .kind = FORM_FIELD_UUID,
        .uuid = { .common = { .name = "uuid" } } };
    fields[4] = (form_field_spec_t){ .kind = FORM_FIELD_JSON,
        .json = { .common = { .name = "json" } } };
    fields[5] = (form_field_spec_t){ .kind = FORM_FIELD_CHOICE, .choice = {
        .common = { .name = "choice" }, .choices = choices, .choices_count = 2,
        .invalid_choice_message = "unknown color" } };
    fields[6] = (form_field_spec_t){ .kind = FORM_FIELD_FILEPATH, .filepath = {
        .common = { .name = "path" }, .storage = FIXTURE_STORAGE,
        .directory = fixture_storage_directory(fx), .allow_files = 1 } };
    fields[7] = (form_field_spec_t){ .kind = FORM_FIELD_FILE, .file = {
        .common = { .name = "file" }, .max_size = 8,
        .max_filename_length = 20 } };
    fields[8] = (form_field_spec_t){ .kind = FORM_FIELD_MULTIPLE_CHOICE, .multiple_choice = {
        .common = { .name = "colors" }, .choices = choices, .choices_count = 2 } };
}

/* One rejection case: a single-field schema over the given input must build a
 * form, refuse it, and report exactly the expected code. label names the case
 * so a failure identifies the input. */
static void expect_error(const form_field_spec_t* field, form_input_t input,
                         form_error_t expected, const char* label) {
    char message[192];
    form_schema_t schema = { .fields = field, .fields_count = 1 };
    form_t* form = form_create(&schema, &input);

    snprintf(message, sizeof message, "%s: form_create should succeed", label);
    TEST_REQUIRE_NOT_NULL(form, message);

    snprintf(message, sizeof message, "%s: the form should be rejected", label);
    TEST_ASSERT(!form_is_valid(form), message);

    snprintf(message, sizeof message, "%s: error code should match", label);
    TEST_ASSERT_EQUAL(expected, form_error_code(form, 0), message);
    TEST_ASSERT_NULL(form_field_value(form, 0), "Rejected fields must hide their value");
    TEST_ASSERT_NULL(form_cleaned_data(form, 0), "Rejected forms must hide cleaned data");

    form_free(form);
}

// ============================================================================
// Happy path
// ============================================================================

TEST(test_form_field_kinds_parse) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("all nine field kinds parse and expose their cleaned values");

    form_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx) == 0, "the file fixture should be created");

    form_field_spec_t fields[FORM_FIELDS_COUNT];
    build_fields(&fx, fields);

    file_content_t* content = malloc(sizeof *content);
    TEST_REQUIRE_NOT_NULL_GOTO(content, "the upload wrapper should be allocated", cleanup);
    *content = file_content_create(fileno(fx.upload), "report.txt", 0, 4);
    TEST_ASSERT(content->ok, "the upload wrapper should be usable");

    form_input_t inputs[] = {
        text_input("2024-02-29"), text_input("23:59:58.123456"),
        text_input("2024-02-29T23:59:58+07:00"),
        text_input("550e8400-e29b-41d4-a716-446655440000"),
        text_input("{\"ok\":true}"), text_input("red"),
        text_input("sample.txt"),
        { .kind = FORM_INPUT_OBJECT, .data.object = content, .destroy = free },
        list_input(selected, 2)
    };
    form_schema_t schema = { .fields = fields, .fields_count = FORM_FIELDS_COUNT };

    /* form_create consumes every input, the upload wrapper included, even when
     * it fails - nothing below may free them by hand. */
    form_t* form = form_create(&schema, inputs);
    TEST_REQUIRE_NOT_NULL_GOTO(form, "form_create should succeed", cleanup);
    TEST_REQUIRE_GOTO(form_is_valid(form), "all nine fields should validate", cleanup_form);

    /* cleaned_data is NULL for a field that failed; guard every index before
     * the assertions below dereference it. */
    for (size_t i = 0; i < FORM_FIELDS_COUNT; i++) {
        TEST_REQUIRE_NOT_NULL_GOTO(form_cleaned_data(form, i),
                                   "every field should expose cleaned data", cleanup_form);
    }

    const form_value_kind_t kinds[] = {
        FORM_VALUE_DATE, FORM_VALUE_TIME, FORM_VALUE_DATETIME, FORM_VALUE_UUID,
        FORM_VALUE_OBJECT, FORM_VALUE_TEXT, FORM_VALUE_TEXT, FORM_VALUE_OBJECT,
        FORM_VALUE_TEXT_LIST
    };
    for (size_t i = 0; i < FORM_FIELDS_COUNT; i++)
        TEST_REQUIRE_GOTO(form_cleaned_data(form, i)->kind == kinds[i],
                          "Cleaned value kind should match its field", cleanup_form);

    TEST_ASSERT_EQUAL(2024, form_cleaned_data(form, 0)->data.date.year, "Date year");
    TEST_ASSERT_EQUAL(2, form_cleaned_data(form, 0)->data.date.month, "Date month");
    TEST_ASSERT_EQUAL(29, form_cleaned_data(form, 0)->data.date.day,
                      "date field should parse the leap day");
    TEST_ASSERT_EQUAL(123456, form_cleaned_data(form, 1)->data.time.microsecond,
                      "time field should keep the microseconds");
    TEST_ASSERT_EQUAL(420, form_cleaned_data(form, 2)->data.datetime.offset_minutes,
                      "datetime field should keep the +07:00 offset");
    TEST_ASSERT_EQUAL(0x55, form_cleaned_data(form, 3)->data.uuid.bytes[0],
                      "uuid field should parse the leading byte");
    TEST_ASSERT(json_is_object(json_root(form_cleaned_data(form, 4)->data.object)),
                "json field should parse an object document");
    TEST_ASSERT_STR_EQUAL("red", form_cleaned_data(form, 5)->data.text,
                          "choice field should keep the chosen value");
    TEST_ASSERT_STR_EQUAL("sample.txt", form_cleaned_data(form, 6)->data.text,
                          "filepath field should keep the basename");
    TEST_ASSERT_EQUAL(content, form_cleaned_data(form, 7)->data.object,
                      "file field should hand back the uploaded wrapper");
    TEST_ASSERT_EQUAL_SIZE(2, form_cleaned_data(form, 8)->data.text_list.count,
                           "multiple choice field should keep both values");
    const form_value_text_list_t list = form_cleaned_data(form, 8)->data.text_list;
    TEST_REQUIRE_GOTO(list.items != NULL && list.count == 2, "List contents should be accessible", cleanup_form);
    TEST_ASSERT_STR_EQUAL("red", list.items[0], "First choice must be preserved");
    TEST_ASSERT_STR_EQUAL("blue", list.items[1], "Second choice must be preserved");

cleanup_form:
    form_free(form);
cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// Rejections, optional and defaulted lists
// ============================================================================

TEST(test_form_field_kinds_reject) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("malformed input is rejected per kind, empty lists stay valid");

    form_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx) == 0, "the file fixture should be created");

    form_field_spec_t fields[FORM_FIELDS_COUNT];
    build_fields(&fx, fields);

    expect_error(&fields[0], text_input("2023-02-29"), FORM_INVALID,
                 "date, 2023 is not a leap year");
    expect_error(&fields[1], text_input("24:00"), FORM_INVALID,
                 "time, hour 24");
    expect_error(&fields[2], text_input("2024-02-29T12:00+25:00"), FORM_INVALID,
                 "datetime, offset +25:00");
    expect_error(&fields[3], text_input("bad-uuid"), FORM_INVALID,
                 "uuid, malformed value");
    expect_error(&fields[4], text_input("{broken"), FORM_INVALID,
                 "json, unterminated object");
    expect_error(&fields[4], text_input("1 2"), FORM_INVALID,
                 "json, trailing token after a number");
    expect_error(&fields[4], text_input("[1 2]"), FORM_INVALID,
                 "json, array without a separator");
    expect_error(&fields[4], text_input("   "), FORM_INVALID,
                 "json, blank text");
    expect_error(&fields[5], text_input("green"), FORM_INVALID_CHOICE,
                 "choice, value outside the choices");
    expect_error(&fields[6], text_input("../sample.txt"), FORM_INVALID_CHOICE,
                 "filepath, escape from the directory");

    TEST_REQUIRE_GOTO(symlink("sample.txt", fx.link_path) == 0,
                      "the symlink fixture should be created", cleanup);
    expect_error(&fields[6], text_input("link.txt"), FORM_INVALID_CHOICE,
                 "filepath, symlink inside the directory");
    expect_error(&fields[6], text_input("missing.txt"), FORM_INVALID_CHOICE,
                 "filepath, no such file");
    /* Even an existing file literally named "*.txt": storage_file_get would
     * expand the name as a glob and could open sample.txt instead. */
    FILE* glob_file = fopen(fx.glob_path, "wb");
    TEST_REQUIRE_GOTO(glob_file != NULL && fclose(glob_file) == 0,
                      "the *.txt fixture should be created", cleanup);
    expect_error(&fields[6], text_input("*.txt"), FORM_INVALID_CHOICE,
                 "filepath, glob pattern");
    expect_error(&fields[6], text_input(".."), FORM_INVALID_CHOICE,
                 "filepath, parent directory");

    TEST_REQUIRE_GOTO(mkdir(fx.nested_path, 0700) == 0,
                      "the nested directory fixture should be created", cleanup);
    expect_error(&fields[6], text_input("nested"), FORM_INVALID_CHOICE,
                 "filepath, directory while only files are allowed");

    form_field_spec_t directory_field = fields[6];
    directory_field.filepath.allow_files = 0;
    directory_field.filepath.allow_directories = 1;
    expect_error(&directory_field, text_input("sample.txt"), FORM_INVALID_CHOICE,
                 "filepath, file while only directories are allowed");

    form_field_spec_t unknown_storage = fields[6];
    unknown_storage.filepath.storage = "no_such_storage";
    expect_error(&unknown_storage, text_input("sample.txt"), FORM_INVALID_CHOICE,
                 "filepath, unknown storage");

    const char* const bad_list[] = { "red", "green" };
    expect_error(&fields[8], list_input(bad_list, 2), FORM_INVALID_CHOICE,
                 "multiple choice, one value outside the choices");

    file_content_t* empty_file = malloc(sizeof *empty_file);
    TEST_REQUIRE_NOT_NULL_GOTO(empty_file, "the empty upload wrapper should be allocated", cleanup);
    *empty_file = file_content_create(fileno(fx.upload), "empty.txt", 0, 0);
    expect_error(&fields[7], (form_input_t){ .kind = FORM_INPUT_OBJECT,
                 .data.object = empty_file, .destroy = free }, FORM_EMPTY_FILE,
                 "file, zero-sized upload");

    file_content_t* oversized_file = malloc(sizeof *oversized_file);
    TEST_REQUIRE_NOT_NULL_GOTO(oversized_file, "the oversized upload wrapper should be allocated", cleanup);
    *oversized_file = file_content_create(fileno(fx.upload), "report.txt", 0, 4);
    form_field_spec_t size_field = fields[7];
    size_field.file.max_size = 3;
    expect_error(&size_field, (form_input_t){ .kind = FORM_INPUT_OBJECT,
                 .data.object = oversized_file, .destroy = free }, FORM_MAX_SIZE,
                 "file, upload above max_size");

    form_input_t no_choices[] = { list_input(NULL, 0) };
    form_schema_t multi_schema = { .fields = &fields[8], .fields_count = 1 };
    form_t* optional = form_create(&multi_schema, no_choices);
    TEST_REQUIRE_NOT_NULL_GOTO(optional, "form_create should succeed for an empty list", cleanup);
    TEST_REQUIRE_GOTO(form_is_valid(optional),
                      "an empty list is valid while the field is optional", cleanup_optional);
    TEST_REQUIRE_NOT_NULL_GOTO(form_cleaned_data(optional, 0),
                               "the optional list should expose cleaned data", cleanup_optional);
    TEST_ASSERT_EQUAL(FORM_VALUE_TEXT_LIST, form_cleaned_data(optional, 0)->kind,
                      "an empty selection stays a text list");
    TEST_ASSERT_EQUAL_SIZE(0, form_cleaned_data(optional, 0)->data.text_list.count,
                           "the cleaned list should be empty");
    form_free(optional);

    form_field_spec_t default_field = fields[8];
    default_field.multiple_choice.default_values = selected;
    default_field.multiple_choice.default_values_count = 2;
    form_schema_t default_schema = { .fields = &default_field, .fields_count = 1 };
    form_input_t missing[] = { list_input(NULL, 0) };
    form_t* with_default = form_create(&default_schema, missing);
    TEST_REQUIRE_NOT_NULL_GOTO(with_default, "form_create should succeed for a defaulted list", cleanup);
    TEST_REQUIRE_GOTO(form_is_valid(with_default),
                      "a missing list should fall back to the defaults", cleanup_default);
    TEST_REQUIRE_NOT_NULL_GOTO(form_cleaned_data(with_default, 0),
                               "the defaulted list should expose cleaned data", cleanup_default);
    TEST_ASSERT_EQUAL_SIZE(2, form_cleaned_data(with_default, 0)->data.text_list.count,
                           "both defaults should reach the cleaned list");
    form_free(with_default);

    TEST_ASSERT_EQUAL(0, unlink(fx.link_path), "the symlink should be removed");
    fixture_teardown(&fx);
    return;

cleanup_optional:
    form_free(optional);
    fixture_teardown(&fx);
    return;

cleanup_default:
    form_free(with_default);
cleanup:
    fixture_teardown(&fx);
}

// ============================================================================
// clean() on choice lists
// ============================================================================

#define TEST_CLEAN_TRIM 1

/* Trims spaces when TEST_CLEAN_TRIM is set. Like a real clean() it edits the
 * buffer in place and returns a pointer past the leading spaces, so a form that
 * later frees the returned pointer instead of the original one breaks under
 * ASan. */
static char* test_clean_trim(char* text, int flags) {
    if (text == NULL || !(flags & TEST_CLEAN_TRIM)) return text;
    while (*text == ' ') text++;
    size_t length = strlen(text);
    while (length > 0 && text[length - 1] == ' ') text[--length] = 0;
    return text;
}

TEST(test_form_multiple_choice_clean) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("clean() applies to every multiple choice item, with the field's flags");

    static const char* const padded[] = { "  red", "blue  " };
    form_field_spec_t fields[] = {
        { .kind = FORM_FIELD_CHOICE, .choice = {
            .common = { .name = "choice" }, .clean_flags = TEST_CLEAN_TRIM,
            .choices = choices, .choices_count = 2 } },
        { .kind = FORM_FIELD_MULTIPLE_CHOICE, .multiple_choice = {
            .common = { .name = "colors" }, .clean_flags = TEST_CLEAN_TRIM,
            .choices = choices, .choices_count = 2 } },
    };
    form_schema_t schema = { .fields = fields, .fields_count = 2,
                             .clean = test_clean_trim };

    form_input_t inputs[] = { text_input(" red "), list_input(padded, 2) };
    form_t* form = form_create(&schema, inputs);
    TEST_REQUIRE_NOT_NULL(form, "form_create should succeed");

    TEST_REQUIRE_GOTO(form_is_valid(form),
                      "padded values should match their choices after clean()", done);
    TEST_ASSERT_STR_EQUAL("red", form_cleaned_data(form, 0)->data.text,
                          "the single choice should be cleaned");

    const form_value_t* colors = form_cleaned_data(form, 1);
    TEST_REQUIRE_GOTO(colors->data.text_list.count == 2,
                      "both items should reach the cleaned list", done);
    TEST_ASSERT_STR_EQUAL("red", colors->data.text_list.items[0],
                          "leading spaces should be cleaned from a list item");
    TEST_ASSERT_STR_EQUAL("blue", colors->data.text_list.items[1],
                          "trailing spaces should be cleaned from a list item");

done:
    /* Frees the original item pointers, not the cleaned ones. */
    form_free(form);

    /* The flags come from the multiple choice spec: without them the padded
     * items stay as they are and are not valid choices. */
    fields[1].multiple_choice.clean_flags = 0;
    form_input_t unflagged_inputs[] = { text_input("red"), list_input(padded, 2) };
    form_t* unflagged = form_create(&schema, unflagged_inputs);
    TEST_REQUIRE_NOT_NULL(unflagged, "form_create should succeed without flags");
    TEST_ASSERT(!form_is_valid(unflagged),
                "padded items should be rejected when the field has no clean flags");
    form_free(unflagged);
}

// ============================================================================
// FilePathField over a storage: directories and the storage root
// ============================================================================

/* A single-field form over text must validate and keep text as its value. */
static void expect_filepath(const form_field_spec_t* field, const char* text,
                            const char* label) {
    form_schema_t schema = { .fields = field, .fields_count = 1 };
    form_input_t inputs[] = { text_input(text) };
    form_t* form = form_create(&schema, inputs);
    TEST_REQUIRE_NOT_NULL(form, label);
    TEST_ASSERT(form_is_valid(form), label);
    const form_value_t* value = form_cleaned_data(form, 0);
    TEST_ASSERT(value != NULL && value->data.text != NULL &&
                strcmp(value->data.text, text) == 0, label);
    form_free(form);
}

TEST(test_form_filepath_storage) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("filepath accepts directories when allowed and names in the storage root");

    form_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx) == 0, "the file fixture should be created");
    TEST_REQUIRE_GOTO(mkdir(fx.nested_path, 0700) == 0,
                      "the nested directory fixture should be created", cleanup);

    form_field_spec_t fields[FORM_FIELDS_COUNT];
    build_fields(&fx, fields);

    form_field_spec_t directories = fields[6];
    directories.filepath.allow_directories = 1;
    expect_filepath(&directories, "nested", "a directory is accepted with allow_directories");
    expect_filepath(&directories, "sample.txt", "files stay accepted with allow_files");

    /* NULL directory is the storage root: the fixture directory itself is a
     * name there. A trailing slash on directory is not doubled. */
    form_field_spec_t root = fields[6];
    root.filepath.directory = NULL;
    root.filepath.allow_files = 0;
    root.filepath.allow_directories = 1;
    expect_filepath(&root, fixture_storage_directory(&fx), "a name in the storage root is accepted");

    char slashed[sizeof fx.directory + 1];
    snprintf(slashed, sizeof slashed, "%s/", fixture_storage_directory(&fx));
    form_field_spec_t trailing = fields[6];
    trailing.filepath.directory = slashed;
    expect_filepath(&trailing, "sample.txt", "a trailing slash on directory is accepted");
    expect_error(&fields[6], text_input("."), FORM_INVALID_CHOICE, "Current directory is not a name");
    expect_error(&fields[6], text_input(fx.path), FORM_INVALID_CHOICE, "Absolute paths are rejected");
    char long_directory[PATH_MAX];
    memset(long_directory, 'x', sizeof long_directory - 1);
    long_directory[sizeof long_directory - 1] = 0;
    trailing.filepath.directory = long_directory;
    expect_error(&trailing, text_input("sample.txt"), FORM_INVALID_CHOICE, "Path must not be truncated");

cleanup:
    fixture_teardown(&fx);
}

/* The expectation is supplied by the case, including its error message. */
static void expect_result(const form_field_spec_t* field, form_input_t input,
                          form_error_t error, const char* message, const char* label) {
    const form_schema_t local = { .fields = field, .fields_count = 1 };
    form_t* form = form_create(&local, &input);
    TEST_REQUIRE_NOT_NULL(form, label);
    TEST_ASSERT_EQUAL(error == FORM_VALID, form_is_valid(form), label);
    TEST_ASSERT_EQUAL(error, form_error_code(form, 0), label);
    if (message != NULL)
        TEST_ASSERT_STR_EQUAL(message, form_error_message(form, 0), label);
    else
        TEST_ASSERT_NULL(form_error_message(form, 0), label);
    if (error != FORM_VALID) {
        TEST_ASSERT_NULL(form_field_value(form, 0), label);
        TEST_ASSERT_NULL(form_cleaned_data(form, 0), label);
    }
    form_free(form);
}

TEST(test_form_temporal_boundaries) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("Calendar, clock and timezone boundaries preserve all components");
    const struct {
        form_field_kind_t kind;
        const char* text;
        form_datetime_t expected;
    } valid[] = {
        { FORM_FIELD_DATE, "0001-01-01", { .date = {1, 1, 1} } },
        { FORM_FIELD_DATE, "9999-12-31", { .date = {9999, 12, 31} } },
        { FORM_FIELD_DATE, "2000-02-29", { .date = {2000, 2, 29} } },
        { FORM_FIELD_TIME, "00:00", { .time = {0, 0, 0, 0} } },
        { FORM_FIELD_TIME, "23:59:59.999999", { .time = {23, 59, 59, 999999} } },
        { FORM_FIELD_TIME, "12:34:56.1", { .time = {12, 34, 56, 100000} } },
        { FORM_FIELD_DATETIME, "2024-02-29T12:34:56.123456Z",
            { .date = {2024, 2, 29}, .time = {12, 34, 56, 123456}, .has_offset = 1 } },
        { FORM_FIELD_DATETIME, "2024-02-29 12:34",
            { .date = {2024, 2, 29}, .time = {12, 34, 0, 0} } },
        { FORM_FIELD_DATETIME, "2024-02-29T12:34-03:30",
            { .date = {2024, 2, 29}, .time = {12, 34, 0, 0}, .has_offset = 1, .offset_minutes = -210 } },
        { FORM_FIELD_DATETIME, "2024-02-29T12:34+23:59",
            { .date = {2024, 2, 29}, .time = {12, 34, 0, 0}, .has_offset = 1, .offset_minutes = 1439 } },
        { FORM_FIELD_DATETIME, "2024-02-29T12:34-23:59",
            { .date = {2024, 2, 29}, .time = {12, 34, 0, 0}, .has_offset = 1, .offset_minutes = -1439 } }
    };
    for (size_t i = 0; i < sizeof valid / sizeof *valid; i++) {
        TEST_CASE(valid[i].text);
        form_field_spec_t field = { .kind = valid[i].kind };
        if (field.kind == FORM_FIELD_DATE) field.date.common.name = "date";
        if (field.kind == FORM_FIELD_TIME) field.time.common.name = "time";
        if (field.kind == FORM_FIELD_DATETIME) field.datetime.common.name = "datetime";
        const form_schema_t local = { .fields = &field, .fields_count = 1 };
        form_input_t input = text_input(valid[i].text);
        form_t* form = form_create(&local, &input);
        TEST_REQUIRE_NOT_NULL(form, "Temporal form should build");
        TEST_REQUIRE_GOTO(form_is_valid(form), "Temporal input should validate", next);
        const form_value_t* value = form_cleaned_data(form, 0);
        TEST_REQUIRE_NOT_NULL_GOTO(value, "Temporal value should be accessible", next);
        form_date_t date = {0};
        form_time_t time = {0};
        if (field.kind == FORM_FIELD_DATE) {
            TEST_REQUIRE_GOTO(value->kind == FORM_VALUE_DATE, "Date kind", next);
            date = value->data.date;
        } else if (field.kind == FORM_FIELD_TIME) {
            TEST_REQUIRE_GOTO(value->kind == FORM_VALUE_TIME, "Time kind", next);
            time = value->data.time;
        } else {
            TEST_REQUIRE_GOTO(value->kind == FORM_VALUE_DATETIME, "Datetime kind", next);
            date = value->data.datetime.date;
            time = value->data.datetime.time;
            TEST_ASSERT_EQUAL(valid[i].expected.has_offset, value->data.datetime.has_offset, "Explicit offset flag");
            TEST_ASSERT_EQUAL(valid[i].expected.offset_minutes, value->data.datetime.offset_minutes, "Signed offset");
        }
        TEST_ASSERT_EQUAL(valid[i].expected.date.year, date.year, "Year");
        TEST_ASSERT_EQUAL(valid[i].expected.date.month, date.month, "Month");
        TEST_ASSERT_EQUAL(valid[i].expected.date.day, date.day, "Day");
        TEST_ASSERT_EQUAL(valid[i].expected.time.hour, time.hour, "Hour");
        TEST_ASSERT_EQUAL(valid[i].expected.time.minute, time.minute, "Minute");
        TEST_ASSERT_EQUAL(valid[i].expected.time.second, time.second, "Second");
        TEST_ASSERT_EQUAL(valid[i].expected.time.microsecond, time.microsecond, "Fraction padding");
next:
        form_free(form);
    }

    const struct { form_field_kind_t kind; const char* text; } invalid[] = {
        { FORM_FIELD_DATE, "1900-02-29" }, { FORM_FIELD_DATE, "0000-01-01" },
        { FORM_FIELD_DATE, "2024-00-01" }, { FORM_FIELD_DATE, "2024-13-01" },
        { FORM_FIELD_DATE, "2024-01-00" }, { FORM_FIELD_DATE, "2024-04-31" },
        { FORM_FIELD_DATE, "2024-2-29" }, { FORM_FIELD_DATE, "2024/02/29" },
        { FORM_FIELD_DATE, "2024-02-29x" }, { FORM_FIELD_DATE, "2" },
        { FORM_FIELD_TIME, "12:60" }, { FORM_FIELD_TIME, "12:00:60" },
        { FORM_FIELD_TIME, "12:00:00." }, { FORM_FIELD_TIME, "12:00:00.1234567" },
        { FORM_FIELD_TIME, "12:00Z" }, { FORM_FIELD_TIME, "1:00" },
        { FORM_FIELD_TIME, "12" }, { FORM_FIELD_TIME, "12:00:" },
        { FORM_FIELD_DATETIME, "2024-02-29X12:00" },
        { FORM_FIELD_DATETIME, "2024-02-29T24:00" },
        { FORM_FIELD_DATETIME, "2024-02-29T12:00+00:60" },
        { FORM_FIELD_DATETIME, "2024-02-29T12:00-24:00" },
        { FORM_FIELD_DATETIME, "2024-02-29T12:00+01" },
        { FORM_FIELD_DATETIME, "2024-02-29T12:00Zx" }
    };
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; i++) {
        form_field_spec_t field = { .kind = invalid[i].kind };
        if (field.kind == FORM_FIELD_DATE) field.date.common.name = "date";
        if (field.kind == FORM_FIELD_TIME) field.time.common.name = "time";
        if (field.kind == FORM_FIELD_DATETIME) field.datetime.common.name = "datetime";
        expect_error(&field, text_input(invalid[i].text), FORM_INVALID, invalid[i].text);
    }
}

TEST(test_form_uuid_variants) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("UUID accepts both spellings and preserves all sixteen bytes");
    const form_field_spec_t field = { .kind = FORM_FIELD_UUID, .uuid = { .common = { .name = "uuid" } } };
    const char* valid[] = { "00112233-4455-6677-8899-aabbccddeeff", "00112233445566778899AABBCCDDEEFF" };
    const unsigned char expected[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    for (size_t i = 0; i < 2; i++) {
        const form_schema_t local = { .fields = &field, .fields_count = 1 };
        form_input_t input = text_input(valid[i]);
        form_t* form = form_create(&local, &input);
        TEST_REQUIRE_NOT_NULL(form, "UUID form should build");
        TEST_REQUIRE_GOTO(form_is_valid(form), valid[i], next_uuid);
        const form_value_t* value = form_cleaned_data(form, 0);
        TEST_REQUIRE_GOTO(value != NULL && value->kind == FORM_VALUE_UUID, "UUID value kind", next_uuid);
        TEST_ASSERT(memcmp(expected, value->data.uuid.bytes, sizeof expected) == 0, "Every UUID byte matches");
next_uuid:
        form_free(form);
    }
    const char* invalid[] = {
        "00112233_4455-6677-8899-aabbccddeeff", "00112233445566778899aabbccddeefg",
        "g0112233445566778899aabbccddeeff", "00112233445566778899aabbccddeeffx"
    };
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; i++)
        expect_error(&field, text_input(invalid[i]), FORM_INVALID, invalid[i]);
}

TEST(test_form_file_boundaries) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("File metadata, descriptor, byte range and exact limits are checked");
    form_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx) == 0, "File fixture should build");
    form_field_spec_t field = { .kind = FORM_FIELD_FILE, .file = {
        .common = { .name = "upload", .invalid_message = "bad file" },
        .max_size = 4, .max_filename_length = 10,
        .max_size_message = "too large", .max_filename_length_message = "name too long",
        .empty_file_message = "empty file" } };
    file_content_t file = file_content_create(fileno(fx.upload), "report.txt", 0, 4);
    const form_input_t input = { .kind = FORM_INPUT_OBJECT, .data.object = &file };
    expect_result(&field, input, FORM_VALID, NULL, "Exact size and filename limits are inclusive");
    field.file.max_size = 3;
    expect_result(&field, input, FORM_MAX_SIZE, "too large", "Size limit message");
    field.file.max_size = 4;
    field.file.max_filename_length = 9;
    expect_result(&field, input, FORM_MAX_LENGTH, "name too long", "Filename limit message");
    field.file.max_filename_length = 10;

    const file_content_t valid = file;
    file.size = 0;
    expect_result(&field, input, FORM_EMPTY_FILE, "empty file", "Empty file rejected by default");
    field.file.allow_empty_file = 1;
    file.offset = 4;
    expect_result(&field, input, FORM_VALID, NULL, "Empty slice at EOF can be allowed");
    file = valid;
    file.offset = 1;
    file.size = 3;
    expect_result(&field, input, FORM_VALID, NULL, "Nonzero offset slice ending at EOF");

    for (int i = 0; i < 11; i++) {
        file = valid;
        const char* label = NULL;
        switch (i) {
        case 0: file.ok = 0; label = "Failed upload"; break;
        case 1: file.fd = -1; label = "Negative descriptor"; break;
        case 2: file.offset = -1; label = "Negative offset"; break;
        case 3: file.offset = 5; label = "Offset beyond EOF"; break;
        case 4: file.offset = 1; label = "Slice extends beyond EOF"; break;
        case 5: file.size = SIZE_MAX; label = "Huge size cannot wrap around"; break;
        case 6: file.filename[0] = 0; label = "Empty filename"; break;
        case 7: strcpy(file.filename, "a/b"); label = "Slash in filename"; break;
        case 8: strcpy(file.filename, "a\\b"); label = "Backslash in filename"; break;
        case 9: memset(file.filename, 'x', sizeof file.filename); label = "Unterminated filename"; break;
        case 10: file.fd = INT_MAX; label = "Unopened descriptor"; break;
        }
        expect_result(&field, input, FORM_INVALID, "bad file", label);
    }
    int directory_fd = open(fx.directory, O_RDONLY | O_DIRECTORY);
    TEST_REQUIRE_GOTO(directory_fd >= 0, "Directory descriptor should open", cleanup_file);
    file = valid;
    file.fd = directory_fd;
    expect_result(&field, input, FORM_INVALID, "bad file", "A directory is not a regular upload");
    TEST_ASSERT_EQUAL(0, close(directory_fd), "Directory descriptor closes");
    TEST_ASSERT(fcntl(fileno(fx.upload), F_GETFD) >= 0, "Form never closes the request-owned upload descriptor");
cleanup_file:
    fixture_teardown(&fx);
}

TEST(test_form_choice_defaults_and_required) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("Choices validate defaults, required lists and malformed list storage");
    form_field_spec_t single = { .kind = FORM_FIELD_CHOICE, .choice = {
        .common = { .name = "color" }, .choices = choices, .choices_count = 2,
        .default_value = "red", .invalid_choice_message = "unknown color" } };
    expect_result(&single, text_input(NULL), FORM_VALID, NULL, "Valid choice default");
    single.choice.default_value = "green";
    expect_result(&single, text_input(NULL), FORM_INVALID_CHOICE, "unknown color", "Invalid choice default");
    expect_result(&single, text_input("blue"), FORM_VALID, NULL, "Explicit choice overrides invalid default");

    form_field_spec_t multi = { .kind = FORM_FIELD_MULTIPLE_CHOICE, .multiple_choice = {
        .common = { .name = "colors", .required = 1, .required_message = "choose colors" },
        .choices = choices, .choices_count = 2, .default_values = selected, .default_values_count = 2,
        .invalid_choice_message = "unknown colors" } };
    expect_result(&multi, list_input(NULL, 0), FORM_REQUIRED, "choose colors", "Required list does not use defaults");
    multi.multiple_choice.common.required = 0;
    const char* bad[] = { "green" };
    multi.multiple_choice.default_values = bad;
    multi.multiple_choice.default_values_count = 1;
    expect_result(&multi, list_input(NULL, 0), FORM_INVALID_CHOICE, "unknown colors", "Defaults must belong to choices");
    expect_result(&multi, list_input(selected, 2), FORM_VALID, NULL, "Explicit list overrides invalid defaults");
    expect_result(&multi, (form_input_t){ .kind = FORM_INPUT_TEXT_LIST, .data.text_list = { NULL, 1 } },
                  FORM_INVALID, NULL, "Nonempty list needs an array");
    char** items = calloc(1, sizeof *items);
    TEST_REQUIRE_NOT_NULL(items, "List containing NULL should allocate");
    expect_result(&multi, (form_input_t){ .kind = FORM_INPUT_TEXT_LIST, .data.text_list = { items, 1 } },
                  FORM_INVALID_CHOICE, "unknown colors", "NULL list item is rejected");
}

TEST(test_form_field_defaults) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("Typed defaults preserve values and borrow JSON and file objects");
    form_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx) == 0, "File fixture should build");
    json_doc_t* doc = json_parse("{\"ok\":true}");
    TEST_REQUIRE_NOT_NULL_GOTO(doc, "JSON default should parse", cleanup_fixture);
    file_content_t file = file_content_create(fileno(fx.upload), "report.txt", 0, 4);
    form_field_spec_t specs[FORM_FIELDS_COUNT];
    build_fields(&fx, specs);
    specs[0].date.has_default = 1;
    specs[0].date.default_value = (form_date_t){2024, 2, 29};
    specs[1].time.has_default = 1;
    specs[1].time.default_value = (form_time_t){12, 34, 56, 123456};
    specs[2].datetime.has_default = 1;
    specs[2].datetime.default_value = (form_datetime_t){ .date = {2024, 2, 29},
        .time = {12, 34, 56, 123456}, .has_offset = 1, .offset_minutes = -210 };
    specs[3].uuid.has_default = 1;
    specs[3].uuid.default_value = (form_uuid_t){ .bytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16} };
    specs[4].json.default_value = doc;
    specs[5].choice.default_value = "blue";
    specs[6].filepath.default_value = "sample.txt";
    specs[7].file.default_value = &file;
    specs[8].multiple_choice.default_values = selected;
    specs[8].multiple_choice.default_values_count = 2;
    const form_schema_t local = { .fields = specs, .fields_count = FORM_FIELDS_COUNT };
    form_input_t inputs[FORM_FIELDS_COUNT] = {0};
    form_t* form = form_create(&local, inputs);
    TEST_REQUIRE_NOT_NULL_GOTO(form, "Default form should build", cleanup_doc);
    TEST_REQUIRE_GOTO(form_is_valid(form), "All typed defaults should validate", cleanup_form);
    for (size_t i = 0; i < FORM_FIELDS_COUNT; i++)
        TEST_REQUIRE_NOT_NULL_GOTO(form_cleaned_data(form, i), "Every default should be accessible", cleanup_form);
    TEST_ASSERT_EQUAL(2024, form_cleaned_data(form, 0)->data.date.year, "Default year");
    TEST_ASSERT_EQUAL(29, form_cleaned_data(form, 0)->data.date.day, "Default leap day");
    TEST_ASSERT_EQUAL(123456, form_cleaned_data(form, 1)->data.time.microsecond, "Default fractional time");
    TEST_ASSERT_EQUAL(-210, form_cleaned_data(form, 2)->data.datetime.offset_minutes, "Default offset");
    TEST_ASSERT(memcmp(specs[3].uuid.default_value.bytes, form_cleaned_data(form, 3)->data.uuid.bytes, 16) == 0, "Default UUID bytes");
    TEST_ASSERT(form_cleaned_data(form, 4)->data.object == doc, "JSON default is borrowed");
    TEST_ASSERT(form_cleaned_data(form, 4)->destroy == NULL, "JSON default is not owned");
    TEST_ASSERT_STR_EQUAL("blue", form_cleaned_data(form, 5)->data.text, "Choice default");
    TEST_ASSERT_STR_EQUAL("sample.txt", form_cleaned_data(form, 6)->data.text, "Path default");
    TEST_ASSERT(form_cleaned_data(form, 7)->data.object == &file, "File default is borrowed");
    const form_value_text_list_t list = form_cleaned_data(form, 8)->data.text_list;
    TEST_REQUIRE_GOTO(list.count == 2 && list.items != NULL, "Default list shape", cleanup_form);
    TEST_ASSERT_STR_EQUAL("red", list.items[0], "First default choice");
    TEST_ASSERT_STR_EQUAL("blue", list.items[1], "Second default choice");
cleanup_form:
    form_free(form);
    TEST_ASSERT(json_is_object(json_root(doc)), "Borrowed JSON survives form_free");
cleanup_doc:
    json_free(doc);
cleanup_fixture:
    fixture_teardown(&fx);
}

TEST(test_form_field_schema_rejections) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("Invalid typed defaults and malformed choice/path schemas fail construction");
    const char* null_item[] = { NULL };
    const form_field_spec_t invalid[] = {
        { .kind = FORM_FIELD_DATE, .date = { .common = { .name = "x" }, .has_default = 1, .default_value = {2023, 2, 29} } },
        { .kind = FORM_FIELD_TIME, .time = { .common = { .name = "x" }, .has_default = 1, .default_value = {24, 0, 0, 0} } },
        { .kind = FORM_FIELD_DATETIME, .datetime = { .common = { .name = "x" }, .has_default = 1,
            .default_value = { .date = {2024, 1, 1}, .has_offset = 1, .offset_minutes = 1440 } } },
        { .kind = FORM_FIELD_DATETIME, .datetime = { .common = { .name = "x" }, .has_default = 1,
            .default_value = { .date = {2024, 1, 1}, .offset_minutes = 1 } } },
        { .kind = FORM_FIELD_CHOICE, .choice = { .common = { .name = "x" }, .choices_count = 1 } },
        { .kind = FORM_FIELD_CHOICE, .choice = { .common = { .name = "x" }, .choices = null_item, .choices_count = 1 } },
        { .kind = FORM_FIELD_MULTIPLE_CHOICE, .multiple_choice = { .common = { .name = "x" }, .choices_count = 1 } },
        { .kind = FORM_FIELD_MULTIPLE_CHOICE, .multiple_choice = { .common = { .name = "x" }, .choices = null_item, .choices_count = 1 } },
        { .kind = FORM_FIELD_MULTIPLE_CHOICE, .multiple_choice = { .common = { .name = "x" }, .default_values_count = 1 } },
        { .kind = FORM_FIELD_MULTIPLE_CHOICE, .multiple_choice = { .common = { .name = "x" }, .default_values = null_item, .default_values_count = 1 } },
        { .kind = FORM_FIELD_FILEPATH, .filepath = { .common = { .name = "x" }, .allow_files = 1 } },
        { .kind = FORM_FIELD_FILEPATH, .filepath = { .common = { .name = "x" }, .storage = FIXTURE_STORAGE } }
    };
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; i++) {
        const form_schema_t local = { .fields = &invalid[i], .fields_count = 1 };
        form_input_t input = text_input("unused");
        form_t* form = form_create(&local, &input);
        TEST_ASSERT_NULL(form, "Malformed field specification must fail at construction");
        form_free(form);
    }
}

TEST(test_form_field_input_kinds) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("Each field rejects a nonempty input of an incompatible kind");
    form_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx) == 0, "File fixture should build");
    form_field_spec_t specs[FORM_FIELDS_COUNT];
    build_fields(&fx, specs);
    int object = 1;
    for (size_t i = 0; i < FORM_FIELDS_COUNT; i++) {
        form_input_t input = (i == 7 || i == 8)
            ? text_input("red")
            : (form_input_t){ .kind = FORM_INPUT_OBJECT, .data.object = &object };
        expect_error(&specs[i], input, FORM_INVALID, "Incompatible input kind");
    }
    expect_error(&specs[0], (form_input_t){ .kind = (form_input_kind_t)-1 }, FORM_INVALID, "Unknown input kind");
    fixture_teardown(&fx);
}

TEST(test_form_json_values) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("JSON accepts scalar and container roots and preserves their values");
    const form_field_spec_t field = { .kind = FORM_FIELD_JSON, .json = { .common = { .name = "json" } } };
    const form_schema_t local = { .fields = &field, .fields_count = 1 };
    const char* texts[] = { "null", "false", "42", "\"hello\"", "[1,true]" };
    for (size_t i = 0; i < sizeof texts / sizeof *texts; i++) {
        form_input_t input = text_input(texts[i]);
        form_t* form = form_create(&local, &input);
        TEST_REQUIRE_NOT_NULL(form, "JSON form should build");
        TEST_REQUIRE_GOTO(form_is_valid(form), texts[i], next_json);
        const form_value_t* value = form_cleaned_data(form, 0);
        TEST_REQUIRE_GOTO(value != NULL && value->kind == FORM_VALUE_OBJECT, "JSON value is an object wrapper", next_json);
        const json_token_t* root = json_root(value->data.object);
        TEST_REQUIRE_NOT_NULL_GOTO(root, "JSON root should exist", next_json);
        switch (i) {
        case 0: TEST_ASSERT(json_is_null(root), "JSON null is a document, not a missing field"); break;
        case 1: TEST_ASSERT(json_is_bool(root) && !json_bool(root), "JSON false is preserved"); break;
        case 2: TEST_ASSERT(json_is_number(root) && json_ldouble(root) == 42, "JSON number is preserved"); break;
        case 3: TEST_ASSERT_STR_EQUAL("hello", json_string(root), "JSON string is preserved"); break;
        case 4: TEST_ASSERT(json_is_array(root), "JSON array root is accepted"); break;
        }
next_json:
        form_free(form);
    }
}

TEST(test_form_fields_clean_and_empty) {
    TEST_SUITE("form fields: exotic kinds");
    TEST_CASE("Cleaning flags reach typed parsers, missing optional fields stay empty");
    form_fixture_t fx;
    TEST_REQUIRE(fixture_setup(&fx) == 0, "File fixture should build");
    form_field_spec_t specs[FORM_FIELDS_COUNT];
    build_fields(&fx, specs);
    specs[0].date.clean_flags = TEST_CLEAN_TRIM;
    specs[1].time.clean_flags = TEST_CLEAN_TRIM;
    specs[2].datetime.clean_flags = TEST_CLEAN_TRIM;
    specs[3].uuid.clean_flags = TEST_CLEAN_TRIM;
    specs[4].json.clean_flags = TEST_CLEAN_TRIM;
    specs[5].choice.clean_flags = TEST_CLEAN_TRIM;
    specs[6].filepath.clean_flags = TEST_CLEAN_TRIM;
    specs[8].multiple_choice.clean_flags = TEST_CLEAN_TRIM;
    const form_schema_t local = { .fields = specs, .fields_count = FORM_FIELDS_COUNT, .clean = test_clean_trim };
    const char* padded[] = { " red ", " blue " };
    form_input_t inputs[] = {
        text_input(" 2024-02-29 "), text_input(" 12:34 "), text_input(" 2024-02-29T12:34Z "),
        text_input(" 00112233445566778899aabbccddeeff "), text_input(" null "),
        text_input(" blue "), text_input(" sample.txt "), { .kind = FORM_INPUT_OBJECT }, list_input(padded, 2)
    };
    form_t* form = form_create(&local, inputs);
    TEST_REQUIRE_NOT_NULL_GOTO(form, "Cleaned form should build", cleanup_clean);
    TEST_ASSERT(form_is_valid(form), "Padded typed inputs validate after cleaning");
    form_free(form);
    form_input_t missing[FORM_FIELDS_COUNT] = {0};
    form = form_create(&local, missing);
    TEST_REQUIRE_NOT_NULL_GOTO(form, "Missing optional form should build", cleanup_clean);
    TEST_REQUIRE_GOTO(form_is_valid(form), "Missing optional fields validate", cleanup_form);
    for (size_t i = 0; i < FORM_FIELDS_COUNT; i++) {
        const form_value_t* value = form_cleaned_data(form, i);
        TEST_REQUIRE_NOT_NULL_GOTO(value, "Optional cleaned value is accessible", cleanup_form);
        TEST_ASSERT_EQUAL(i == 8 ? FORM_VALUE_TEXT_LIST : FORM_VALUE_EMPTY, value->kind, "Optional kind");
    }
cleanup_form:
    form_free(form);
cleanup_clean:
    fixture_teardown(&fx);
}
