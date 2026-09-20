/*
 * Юнит-тесты чистых хелперов S3-ветки: форматирование Range, разбор
 * Content-Range, отображение статуса S3 в статус клиенту и выбор размера
 * порции. Сетевые части (storages3_head / storages3_fetch) проверяются
 * интеграционно против MinIO — tests/storage_routes.sh.
 */

#include "framework.h"
#include "storages3.h"

#include <string.h>

TEST(test_storages3_range_format) {
    TEST_SUITE("storages3: range helpers");
    TEST_CASE("storages3_range_format builds an inclusive byte range");

    char out[64] = {0};

    TEST_ASSERT_EQUAL(1, storages3_range_format(out, sizeof out, 0, 8388607),
                      "a range should be formatted");
    TEST_ASSERT_STR_EQUAL("bytes=0-8388607", out, "the range should be inclusive");

    TEST_ASSERT_EQUAL(1, storages3_range_format(out, sizeof out, 5, 5),
                      "a single byte range should be formatted");
    TEST_ASSERT_STR_EQUAL("bytes=5-5", out, "a single byte is start == end");

    TEST_ASSERT_EQUAL(0, storages3_range_format(out, 4, 0, 100),
                      "a buffer too small should fail");
    TEST_ASSERT_EQUAL(0, storages3_range_format(out, sizeof out, 10, 4),
                      "an inverted range should fail");
    TEST_ASSERT_EQUAL(0, storages3_range_format(NULL, 64, 0, 100),
                      "a NULL buffer should fail");
}

TEST(test_storages3_content_range_parse) {
    TEST_CASE("storages3_content_range_parse reads start, end and total");

    size_t start = 0, end = 0, total = 0;

    TEST_ASSERT_EQUAL(1, storages3_content_range_parse("bytes 0-99/1000", &start, &end, &total),
                      "a well-formed Content-Range should parse");
    TEST_ASSERT_EQUAL_SIZE(0, start, "start should be 0");
    TEST_ASSERT_EQUAL_SIZE(99, end, "end should be 99");
    TEST_ASSERT_EQUAL_SIZE(1000, total, "total should be 1000");

    TEST_ASSERT_EQUAL(1, storages3_content_range_parse("bytes 200-1023/1024", &start, &end, &total),
                      "a mid-object range should parse");
    TEST_ASSERT_EQUAL_SIZE(200, start, "start should be 200");
    TEST_ASSERT_EQUAL_SIZE(1023, end, "end should be 1023");
    TEST_ASSERT_EQUAL_SIZE(1024, total, "total should be 1024");

    TEST_ASSERT_EQUAL(0, storages3_content_range_parse("bytes */1024", &start, &end, &total),
                      "an unsatisfied form carries no range");
    TEST_ASSERT_EQUAL(0, storages3_content_range_parse("items 0-99/1000", &start, &end, &total),
                      "a non-bytes unit should be refused");
    TEST_ASSERT_EQUAL(0, storages3_content_range_parse("bytes 99-0/1000", &start, &end, &total),
                      "an inverted range should be refused");
    TEST_ASSERT_EQUAL(0, storages3_content_range_parse(NULL, &start, &end, &total),
                      "NULL should be refused");
}

/* 403 от S3 — это про креды сервера, а не про права клиента на объект.
 * Отдать клиенту 403 значило бы предложить ему исправить чужую проблему. */
TEST(test_storages3_http_status) {
    TEST_CASE("storages3_http_status maps S3 answers to what the client gets");

    TEST_ASSERT_EQUAL(200, storages3_http_status(200), "200 passes through");
    TEST_ASSERT_EQUAL(206, storages3_http_status(206), "206 passes through");
    TEST_ASSERT_EQUAL(304, storages3_http_status(304), "304 passes through");
    TEST_ASSERT_EQUAL(416, storages3_http_status(416), "416 passes through");
    TEST_ASSERT_EQUAL(404, storages3_http_status(404), "404 stays 404");
    TEST_ASSERT_EQUAL(502, storages3_http_status(403), "403 becomes 502");
    TEST_ASSERT_EQUAL(503, storages3_http_status(0), "a transport failure becomes 503");
    TEST_ASSERT_EQUAL(502, storages3_http_status(500), "an unexpected S3 status becomes 502");
}

/* Клиент отбивает ответ крупнее main.client_max_body_size, так что порция,
 * не влезающая в этот лимит, не скачалась бы никогда. */
TEST(test_storages3_chunk_limit) {
    TEST_CASE("the chunk size never exceeds what the HTTP client will accept");

    TEST_ASSERT_EQUAL_SIZE(STORAGES3_CHUNK_LIMIT, storages3_chunk_size(0),
                           "no limit configured leaves the constant");
    TEST_ASSERT_EQUAL_SIZE(STORAGES3_CHUNK_LIMIT, storages3_chunk_size(STORAGES3_CHUNK_LIMIT * 2),
                           "a generous limit leaves the constant");
    TEST_ASSERT_EQUAL_SIZE(1048576, storages3_chunk_size(1048576),
                           "a smaller limit wins");
    TEST_ASSERT_EQUAL_SIZE(1, storages3_chunk_size(1),
                           "even an absurd limit yields a usable chunk");
}
