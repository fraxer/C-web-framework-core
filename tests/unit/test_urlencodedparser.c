#include "framework.h"
#include "urlencodedparser.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ---- helpers ----------------------------------------------------------- */

/* Кладёт payload во временный файл, возвращает fd. Файл анонимный (unlinked). */
static int make_payload(const char* data, size_t len) {
    char tmpl[] = "/tmp/urlenc_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    unlink(tmpl);
    if (len) {
        ssize_t w = write(fd, data, len);
        if (w < 0 || (size_t)w != len) { close(fd); return -1; }
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

/* Освобождает односвязный список полей. */
static void free_fields(http_payloadfield_t* field) {
    http_payloadfield_free(field);
}

/* Считает количество полей (пар) в связном списке. */
static int count_fields(http_payloadfield_t* head) {
    int n = 0;
    while (head) {
        n++;
        head = head->next;
    }
    return n;
}

/*
 * Сверяет ключ и значение пары по индексу.
 * Структура списка: [field0] -> [field1] -> ...
 * Каждое поле содержит декодированные key/value.
 */
static int verify_field(http_payloadfield_t* head, int idx,
                        const char* exp_key, const char* exp_val) {
    http_payloadfield_t* f = head;
    for (int i = 0; i < idx && f; i++)
        f = f->next;

    if (!f) return 0;

    /* Проверяем ключ */
    if (!f->key) return 0;
    if (strcmp(f->key, exp_key) != 0) return 0;

    /* Проверяем значение */
    if (!f->value) return 0;
    if (strcmp(f->value, exp_val) != 0) return 0;

    return 1;
}

/* Однократный разбор: buffer == payload. */
static void run_parse(const char* body, size_t len,
                      urlencodedparser_t* parser, int* fd) {
    *fd = make_payload(body, len);
    urlencodedparser_init(parser, *fd, len);
    char* buf = malloc(len ? len : 1);
    if (!buf) return;
    memcpy(buf, body, len);
    urlencodedparser_parse(parser, buf, len);
    free(buf);
}

/* Потоковый разбор: подаём тело кусками заданного размера. */
static void run_chunked(const char* body, size_t len,
                        const size_t* chunks, int nchunks,
                        urlencodedparser_t* parser, int* fd) {
    *fd = make_payload(body, len);
    urlencodedparser_init(parser, *fd, len);

    size_t pos = 0;
    for (int c = 0; c < nchunks && pos < len; c++) {
        size_t csz = chunks[c];
        if (pos + csz > len) csz = len - pos;
        char* buf = malloc(csz ? csz : 1);
        if (!buf) return;
        memcpy(buf, body + pos, csz);
        urlencodedparser_parse(parser, buf, csz);
        free(buf);
        pos += csz;
    }
    if (pos < len) {
        size_t csz = len - pos;
        char* buf = malloc(csz);
        if (!buf) return;
        memcpy(buf, body + pos, csz);
        urlencodedparser_parse(parser, buf, csz);
        free(buf);
    }
}

/* ============================================================================
 * Test Suite 1: Базовые случаи
 * ============================================================================ */

TEST(test_basic_single_pair) {
    TEST_SUITE("URLEncodedParser — базовые случаи");
    TEST_CASE("Одна пара: a=b");

    const char* body = "a=b";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "Должна быть 1 пара");
    TEST_ASSERT(verify_field(head, 0, "a", "b"), "Пара a=b");

    free_fields(head);
    close(fd);
}

TEST(test_basic_two_pairs) {
    TEST_SUITE("URLEncodedParser — базовые случаи");
    TEST_CASE("Две пары: a=b&c=d");

    const char* body = "a=b&c=d";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(2, count_fields(head), "Должно быть 2 пары");
    TEST_ASSERT(verify_field(head, 0, "a", "b"), "Пара a=b");
    TEST_ASSERT(verify_field(head, 1, "c", "d"), "Пара c=d");

    free_fields(head);
    close(fd);
}

TEST(test_basic_multiletter_keys) {
    TEST_SUITE("URLEncodedParser — базовые случаи");
    TEST_CASE("Многобуквенные ключи и значения");

    const char* body = "name=John&city=Amsterdam";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(2, count_fields(head), "Должно быть 2 пары");
    TEST_ASSERT(verify_field(head, 0, "name", "John"), "Пара name=John");
    TEST_ASSERT(verify_field(head, 1, "city", "Amsterdam"), "Пара city=Amsterdam");

    free_fields(head);
    close(fd);
}

TEST(test_basic_many_pairs) {
    TEST_SUITE("URLEncodedParser — базовые случаи");
    TEST_CASE("Много пар: 5 полей");

    const char* body = "a=1&b=2&c=3&d=4&e=5";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(5, count_fields(head), "Должно быть 5 пар");
    TEST_ASSERT(verify_field(head, 0, "a", "1"), "a=1");
    TEST_ASSERT(verify_field(head, 4, "e", "5"), "e=5");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 2: Пустые ключи и значения
 * ============================================================================ */

TEST(test_empty_value) {
    TEST_SUITE("URLEncodedParser — пустые ключи/значения");
    TEST_CASE("Пустое значение: a=");

    const char* body = "a=";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT(verify_field(head, 0, "a", ""), "a=");

    free_fields(head);
    close(fd);
}

TEST(test_empty_key) {
    TEST_SUITE("URLEncodedParser — пустые ключи/значения");
    TEST_CASE("Пустой ключ: =b");

    const char* body = "=b";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT(verify_field(head, 0, "", "b"), "=b");

    free_fields(head);
    close(fd);
}

TEST(test_both_empty) {
    TEST_SUITE("URLEncodedParser — пустые ключи/значения");
    TEST_CASE("Оба пустые: =");

    const char* body = "=";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT(verify_field(head, 0, "", ""), "=");

    free_fields(head);
    close(fd);
}

TEST(test_empty_value_in_middle) {
    TEST_SUITE("URLEncodedParser — пустые ключи/значения");
    TEST_CASE("Пустое значение в середине: k1=v1&k2=&k3=v3");

    const char* body = "k1=v1&k2=&k3=v3";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(3, count_fields(head), "3 пары");
    TEST_ASSERT(verify_field(head, 0, "k1", "v1"), "k1=v1");
    TEST_ASSERT(verify_field(head, 1, "k2", ""), "k2=");
    TEST_ASSERT(verify_field(head, 2, "k3", "v3"), "k3=v3");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 3: Ключ без '=' (ключ без значения)
 * ============================================================================ */

TEST(test_key_without_equals) {
    TEST_SUITE("URLEncodedParser — ключ без '='");
    TEST_CASE("Одинокий ключ: a");

    const char* body = "a";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT(verify_field(head, 0, "a", ""), "a с пустым значением");

    free_fields(head);
    close(fd);
}

TEST(test_key_without_equals_mixed) {
    TEST_SUITE("URLEncodedParser — ключ без '='");
    TEST_CASE("Микс: a&b=c");

    const char* body = "a&b=c";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(2, count_fields(head), "2 пары");
    TEST_ASSERT(verify_field(head, 0, "a", ""), "a с пустым значением");
    TEST_ASSERT(verify_field(head, 1, "b", "c"), "b=c");

    free_fields(head);
    close(fd);
}

TEST(test_multiple_keys_without_equals) {
    TEST_SUITE("URLEncodedParser — ключ без '='");
    TEST_CASE("Несколько без '=': a&b&c");

    const char* body = "a&b&c";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(3, count_fields(head), "3 пары");
    TEST_ASSERT(verify_field(head, 0, "a", ""), "a пустое");
    TEST_ASSERT(verify_field(head, 1, "b", ""), "b пустое");
    TEST_ASSERT(verify_field(head, 2, "c", ""), "c пустое");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 4: Лишние амперсанды
 * ============================================================================ */

TEST(test_trailing_ampersand) {
    TEST_SUITE("URLEncodedParser — лишние амперсанды");
    TEST_CASE("Замыкающий &: a=b&");

    const char* body = "a=b&";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара, замыкающий & не создаёт фантомную");
    TEST_ASSERT(verify_field(head, 0, "a", "b"), "a=b");

    free_fields(head);
    close(fd);
}

TEST(test_leading_ampersand) {
    TEST_SUITE("URLEncodedParser — лишние амперсанды");
    TEST_CASE("Ведущий &: &a=b");

    const char* body = "&a=b";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара, ведущий & не создаёт фантомную");
    TEST_ASSERT(verify_field(head, 0, "a", "b"), "a=b");

    free_fields(head);
    close(fd);
}

TEST(test_double_ampersand) {
    TEST_SUITE("URLEncodedParser — лишние амперсанды");
    TEST_CASE("Двойной &: a=1&&b=2");

    const char* body = "a=1&&b=2";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(2, count_fields(head), "2 пары, двойной & игнорируется");
    TEST_ASSERT(verify_field(head, 0, "a", "1"), "a=1");
    TEST_ASSERT(verify_field(head, 1, "b", "2"), "b=2");

    free_fields(head);
    close(fd);
}

TEST(test_only_ampersand) {
    TEST_SUITE("URLEncodedParser — лишние амперсанды");
    TEST_CASE("Только &: &");

    const char* body = "&";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_NULL(head, "Нет частей для одного &");

    free_fields(head);
    close(fd);
}

TEST(test_multiple_ampersands) {
    TEST_SUITE("URLEncodedParser — лишние амперсанды");
    TEST_CASE("Несколько &: &&&");

    const char* body = "&&&";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_NULL(head, "Нет частей для множества &");

    free_fields(head);
    close(fd);
}

TEST(test_empty_body) {
    TEST_SUITE("URLEncodedParser — лишние амперсанды");
    TEST_CASE("Пустое тело: \"\"");

    const char* body = "";
    size_t len = 0;
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_NULL(head, "Нет частей для пустого тела");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 5: '=' внутри значения
 * ============================================================================ */

TEST(test_equals_in_value) {
    TEST_SUITE("URLEncodedParser — '=' внутри значения");
    TEST_CASE("= в значении: a=b=c");

    const char* body = "a=b=c";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT(verify_field(head, 0, "a", "b=c"), "a=b=c");

    free_fields(head);
    close(fd);
}

TEST(test_multiple_equals_in_value) {
    TEST_SUITE("URLEncodedParser — '=' внутри значения");
    TEST_CASE("Несколько = в значении: token=a=b=c=d&x=y");

    const char* body = "token=a=b=c=d&x=y";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(2, count_fields(head), "2 пары");
    TEST_ASSERT(verify_field(head, 0, "token", "a=b=c=d"), "token=a=b=c=d");
    TEST_ASSERT(verify_field(head, 1, "x", "y"), "x=y");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 6: URL-декодирование
 * ============================================================================ */

TEST(test_url_decode_percent) {
    TEST_SUITE("URLEncodedParser — URL-декодирование");
    TEST_CASE("Проценты декодируются: q=a%20b");

    const char* body = "q=a%20b";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT(verify_field(head, 0, "q", "a b"), "q=a b (декодировано)");

    free_fields(head);
    close(fd);
}

TEST(test_url_decode_plus) {
    TEST_SUITE("URLEncodedParser — URL-декодирование");
    TEST_CASE("+ декодируется в пробел: q=hello+world");

    const char* body = "q=hello+world";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT(verify_field(head, 0, "q", "hello world"), "+ декодирован в пробел");

    free_fields(head);
    close(fd);
}

TEST(test_url_decode_mixed) {
    TEST_SUITE("URLEncodedParser — URL-декодирование");
    TEST_CASE("Проценты и плюс вместе: q=a+b%20c");

    const char* body = "q=a+b%20c";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT(verify_field(head, 0, "q", "a b c"), "%20 и + оба декодированы в пробелы");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 7: Потоковый разбор (несколько вызовов parse)
 * ============================================================================ */

TEST(test_streaming_byte_by_byte) {
    TEST_SUITE("URLEncodedParser — потоковый разбор");
    TEST_CASE("По 1 байту: a=b&c=d");

    const char* body = "a=b&c=d";
    size_t len = strlen(body);
    const size_t chunks[] = {1, 1, 1, 1, 1, 1, 1};

    urlencodedparser_t p;
    int fd;
    run_chunked(body, len, chunks, 7, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(2, count_fields(head), "2 пары");
    TEST_ASSERT(verify_field(head, 0, "a", "b"), "a=b");
    TEST_ASSERT(verify_field(head, 1, "c", "d"), "c=d");

    free_fields(head);
    close(fd);
}

TEST(test_streaming_split_at_equals) {
    TEST_SUITE("URLEncodedParser — потоковый разбор");
    TEST_CASE("Разрез по '=': name=John&city=Adam");

    const char* body = "name=John&city=Adam";
    size_t len = strlen(body);
    const size_t chunks[] = {5, 4, 5, 5};

    urlencodedparser_t p;
    int fd;
    run_chunked(body, len, chunks, 4, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(2, count_fields(head), "2 пары");
    TEST_ASSERT(verify_field(head, 0, "name", "John"), "name=John");
    TEST_ASSERT(verify_field(head, 1, "city", "Adam"), "city=Adam");

    free_fields(head);
    close(fd);
}

TEST(test_streaming_split_at_ampersand) {
    TEST_SUITE("URLEncodedParser — потоковый разбор");
    TEST_CASE("Разрез на '&': a=1&b=2&c=3");

    const char* body = "a=1&b=2&c=3";
    size_t len = strlen(body);
    const size_t chunks[] = {4, 4, 3};

    urlencodedparser_t p;
    int fd;
    run_chunked(body, len, chunks, 3, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(3, count_fields(head), "3 пары");
    TEST_ASSERT(verify_field(head, 0, "a", "1"), "a=1");
    TEST_ASSERT(verify_field(head, 1, "b", "2"), "b=2");
    TEST_ASSERT(verify_field(head, 2, "c", "3"), "c=3");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 8: Buffer длиннее тела (pipelined хвост)
 * ============================================================================ */

TEST(test_oversized_buffer) {
    TEST_SUITE("URLEncodedParser — oversized buffer");
    TEST_CASE("Хвост после тела: a=b + &evil=1&more=2");

    const char* body = "a=b";
    size_t len = strlen(body);
    const char* trailing = "&evil=1&more=2";
    size_t tlen = strlen(trailing);
    int fd = make_payload(body, len);

    urlencodedparser_t p;
    urlencodedparser_init(&p, fd, len);

    size_t total = len + tlen;
    char* buf = malloc(total);
    if (!buf) { close(fd); return; }
    memcpy(buf, body, len);
    memcpy(buf + len, trailing, tlen);
    urlencodedparser_parse(&p, buf, total);
    free(buf);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара, хвост игнорируется");
    TEST_ASSERT(verify_field(head, 0, "a", "b"), "a=b");

    free_fields(head);
    close(fd);
}

TEST(test_oversized_trailing_after_ampersand) {
    TEST_SUITE("URLEncodedParser — oversized buffer");
    TEST_CASE("Хвост после &: a=b& + GET / HTTP/1.1");

    const char* body = "a=b&";
    size_t len = strlen(body);
    const char* trailing = "GET / HTTP/1.1";
    size_t tlen = strlen(trailing);
    int fd = make_payload(body, len);

    urlencodedparser_t p;
    urlencodedparser_init(&p, fd, len);

    size_t total = len + tlen;
    char* buf = malloc(total);
    if (!buf) { close(fd); return; }
    memcpy(buf, body, len);
    memcpy(buf + len, trailing, tlen);
    urlencodedparser_parse(&p, buf, total);
    free(buf);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара, хвост после & игнорируется");
    TEST_ASSERT(verify_field(head, 0, "a", "b"), "a=b");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 9: Дублирующиеся ключи (HTTP parameter pollution)
 * ============================================================================ */

TEST(test_duplicate_keys) {
    TEST_SUITE("URLEncodedParser — дублирующиеся ключи");
    TEST_CASE("Одинаковые ключи: id=1&id=2&id=3");

    const char* body = "id=1&id=2&id=3";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(3, count_fields(head), "3 пары с одинаковым ключом");
    TEST_ASSERT(verify_field(head, 0, "id", "1"), "id=1");
    TEST_ASSERT(verify_field(head, 1, "id", "2"), "id=2");
    TEST_ASSERT(verify_field(head, 2, "id", "3"), "id=3");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 10: Специальные символы в значениях
 * ============================================================================ */

TEST(test_special_chars_in_value) {
    TEST_SUITE("URLEncodedParser — спецсимволы в значениях");
    TEST_CASE("Спецсимволы: a=b+c@d#e");

    const char* body = "a=b+c@d#e";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT(verify_field(head, 0, "a", "b c@d#e"), "Спецсимволы сохранены, + → пробел");

    free_fields(head);
    close(fd);
}

TEST(test_binary_like_value) {
    TEST_SUITE("URLEncodedParser — спецсимволы в значениях");
    TEST_CASE("Бинарные символы в значении");

    const char body[] = "key=\x01\x02\x03\x04\x05";
    size_t len = sizeof(body) - 1;
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT_NOT_NULL(head, "field не NULL");
    TEST_ASSERT_NOT_NULL(head->value, "value не NULL");
    TEST_ASSERT_EQUAL_SIZE(5, head->value_length, "Размер значения 5 байт");
    TEST_ASSERT_EQUAL(0, memcmp(head->value, "\x01\x02\x03\x04\x05", 5), "Бинарные байты сохранены");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 11: UTF-8 в ключах и значениях
 * ============================================================================ */

TEST(test_utf8_key_and_value) {
    TEST_SUITE("URLEncodedParser — UTF-8");
    TEST_CASE("UTF-8 ключ и значение");

    /* "имя" = "значение" в UTF-8 */
    const char* body = "\xd0\xb8\xd0\xbc\xd1\x8f=\xd0\xb7\xd0\xbd\xd0\xb0\xd1\x87\xd0\xb5\xd0\xbd\xd0\xb8\xd0\xb5";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT(verify_field(head, 0,
                            "\xd0\xb8\xd0\xbc\xd1\x8f",
                            "\xd0\xb7\xd0\xbd\xd0\xb0\xd1\x87\xd0\xb5\xd0\xbd\xd0\xb8\xd0\xb5"),
                "UTF-8 ключ и значение");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 12: Инициализация
 * ============================================================================ */

TEST(test_init_state) {
    TEST_SUITE("URLEncodedParser — инициализация");
    TEST_CASE("Проверка начального состояния после init");

    urlencodedparser_t p;
    urlencodedparser_init(&p, -1, 0);

    TEST_ASSERT_EQUAL_SIZE(0, p.payload_size, "payload_size = 0");
    TEST_ASSERT_EQUAL_SIZE(0, p.payload_offset, "payload_offset = 0");
    TEST_ASSERT_EQUAL_SIZE(0, p.offset, "offset = 0");
    TEST_ASSERT_EQUAL_SIZE(0, p.size, "size = 0");
    TEST_ASSERT_NULL(p.field, "field = NULL");
    TEST_ASSERT_NULL(p.last_field, "last_field = NULL");
    TEST_ASSERT_EQUAL(1, p.find_amp, "find_amp = 1");
    TEST_ASSERT_EQUAL(0, p.field_count, "field_count = 0");
    TEST_ASSERT_EQUAL(-1, p.payload_fd, "payload_fd = -1");
}

/* ============================================================================
 * Test Suite 13: Part count
 * ============================================================================ */

TEST(test_field_count_single_pair) {
    TEST_SUITE("URLEncodedParser — field_count");
    TEST_CASE("field_count для одной пары");

    const char* body = "a=b";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    TEST_ASSERT_EQUAL(1, p.field_count, "1 поле (одна пара)");

    free_fields(urlencodedparser_field(&p));
    close(fd);
}

TEST(test_field_count_multiple_pairs) {
    TEST_SUITE("URLEncodedParser — field_count");
    TEST_CASE("field_count для трёх пар");

    const char* body = "x=1&y=2&z=3";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    TEST_ASSERT_EQUAL(3, p.field_count, "3 поля (3 пары)");

    free_fields(urlencodedparser_field(&p));
    close(fd);
}

/* ============================================================================
 * Test Suite 14: Структура списка
 * ============================================================================ */

TEST(test_list_structure_key_has_field) {
    TEST_SUITE("URLEncodedParser — структура списка");
    TEST_CASE("У пары выставлен field с key и value");

    const char* body = "a=b";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_NOT_NULL(head, "head не NULL");
    TEST_ASSERT_NOT_NULL(head, "field != NULL");
    TEST_ASSERT_NOT_NULL(head->key, "field->key != NULL");
    TEST_ASSERT_STR_EQUAL("a", head->key, "field->key = a");
    TEST_ASSERT_NOT_NULL(head->value, "field->value != NULL");
    TEST_ASSERT_STR_EQUAL("b", head->value, "field->value = b");

    free_fields(head);
    close(fd);
}

TEST(test_list_structure_value_has_length) {
    TEST_SUITE("URLEncodedParser — структура списка");
    TEST_CASE("field->key_length и field->value_length");

    const char* body = "hello=world";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL_SIZE(5, head->key_length, "key_length = 5");
    TEST_ASSERT_EQUAL_SIZE(5, head->value_length, "value_length = 5");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 15: Смешанные ключи (с '=' и без)
 * ============================================================================ */

TEST(test_mixed_keys_with_and_without_equals) {
    TEST_SUITE("URLEncodedParser — смешанные ключи");
    TEST_CASE("Микс: flag&a=b&empty=&c");

    const char* body = "flag&a=b&empty=&c";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(4, count_fields(head), "4 пары");
    TEST_ASSERT(verify_field(head, 0, "flag", ""), "flag без значения");
    TEST_ASSERT(verify_field(head, 1, "a", "b"), "a=b");
    TEST_ASSERT(verify_field(head, 2, "empty", ""), "empty=");
    TEST_ASSERT(verify_field(head, 3, "c", ""), "c без значения");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 16: Длинные значения
 * ============================================================================ */

TEST(test_long_value) {
    TEST_SUITE("URLEncodedParser — длинные значения");
    TEST_CASE("Длинное значение (1KB)");

    char body[1200];
    memcpy(body, "data=", 5);
    size_t val_len = 1024;
    memset(body + 5, 'X', val_len);
    body[5 + val_len] = 0;
    size_t len = 5 + val_len;

    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT_EQUAL_SIZE(val_len, head->value_length, "Размер значения = 1024");

    int all_x = 1;
    for (size_t i = 0; i < head->value_length; i++) {
        if (head->value[i] != 'X') { all_x = 0; break; }
    }
    TEST_ASSERT(all_x, "Все байты значения = 'X'");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 17: Только ключ без '=' в конце после &
 * ============================================================================ */

TEST(test_trailing_key_no_equals) {
    TEST_SUITE("URLEncodedParser — trailing key без '='");
    TEST_CASE("Ключ без '=' в конце: a=1&flag");

    const char* body = "a=1&flag";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(2, count_fields(head), "2 пары");
    TEST_ASSERT(verify_field(head, 0, "a", "1"), "a=1");
    TEST_ASSERT(verify_field(head, 1, "flag", ""), "flag с пустым значением");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 18: Один символ
 * ============================================================================ */

TEST(test_single_char_key) {
    TEST_SUITE("URLEncodedParser — один символ");
    TEST_CASE("Один символ: x");

    const char* body = "x";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(1, count_fields(head), "1 пара");
    TEST_ASSERT(verify_field(head, 0, "x", ""), "x с пустым значением");

    free_fields(head);
    close(fd);
}

/* ============================================================================
 * Test Suite 19: Реальный form data (типичные POST-тела)
 * ============================================================================ */

TEST(test_real_world_login_form) {
    TEST_SUITE("URLEncodedParser — реальный POST");
    TEST_CASE("Форма логина");

    const char* body = "username=admin&password=secret123&remember=on";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(3, count_fields(head), "3 пары");
    TEST_ASSERT(verify_field(head, 0, "username", "admin"), "username=admin");
    TEST_ASSERT(verify_field(head, 1, "password", "secret123"), "password=secret123");
    TEST_ASSERT(verify_field(head, 2, "remember", "on"), "remember=on");

    free_fields(head);
    close(fd);
}

TEST(test_real_world_search_query) {
    TEST_SUITE("URLEncodedParser — реальный POST");
    TEST_CASE("Поисковый запрос со спецсимволами");

    const char* body = "q=hello+world&lang=en&page=1&sort=relevance";
    size_t len = strlen(body);
    urlencodedparser_t p;
    int fd;
    run_parse(body, len, &p, &fd);

    http_payloadfield_t* head = urlencodedparser_field(&p);
    TEST_ASSERT_EQUAL(4, count_fields(head), "4 пары");
    TEST_ASSERT(verify_field(head, 0, "q", "hello world"), "q: + декодирован в пробел");
    TEST_ASSERT(verify_field(head, 1, "lang", "en"), "lang=en");
    TEST_ASSERT(verify_field(head, 2, "page", "1"), "page=1");
    TEST_ASSERT(verify_field(head, 3, "sort", "relevance"), "sort=relevance");

    free_fields(head);
    close(fd);
}
