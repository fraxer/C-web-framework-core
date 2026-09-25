#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include "framework.h"
#include "appconfig.h"
#include "mimetype.h"
#include "mailattachment.h"

static int mail_test_part_contains(const mail_attachment_part_t part, const char* needle) {
    return part.data != NULL && strstr(part.data, needle) != NULL;
}

static int mail_test_part_endswith(const mail_attachment_part_t part, const char* suffix) {
    const size_t sl = strlen(suffix);
    return part.data != NULL && part.size >= sl &&
           memcmp(part.data + part.size - sl, suffix, sl) == 0;
}

static void mail_test_mimetype_setup(void) {
    if (appconfig()->mimetype != NULL) return;

    mimetype_t* table = mimetype_create();
    if (table == NULL) return;

    mimetype_add(table, MIMETYPE_TABLE_EXT, "pdf", "application/pdf");
    mimetype_add(table, MIMETYPE_TABLE_EXT, "png", "image/png");
    mimetype_add(table, MIMETYPE_TABLE_EXT, "jpg", "image/jpeg");
    mimetype_add(table, MIMETYPE_TABLE_EXT, "jpeg", "image/jpeg");
    mimetype_add(table, MIMETYPE_TABLE_EXT, "docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document");

    appconfig()->mimetype = table;
}

TEST(test_mailattachment_content_type_known) {
    TEST_SUITE("mailattachment");
    TEST_CASE("известные расширения дают тип из таблицы конфигурации");

    mail_test_mimetype_setup();
    TEST_REQUIRE_NOT_NULL(appconfig()->mimetype, "таблица создана");

    TEST_ASSERT_STR_EQUAL("application/pdf", mailattachment_content_type("договор.pdf"), "pdf");
    TEST_ASSERT_STR_EQUAL("image/png", mailattachment_content_type("shot.PNG"), "регистр не важен");
    TEST_ASSERT_STR_EQUAL("image/jpeg", mailattachment_content_type("a.b.jpeg"), "последнее расширение");
    TEST_ASSERT_STR_EQUAL(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        mailattachment_content_type("спецификация.docx"), "docx");
}

TEST(test_mailattachment_content_type_unknown) {
    TEST_SUITE("mailattachment");
    TEST_CASE("промах по таблице и файл без расширения — octet-stream");

    mail_test_mimetype_setup();

    TEST_ASSERT_STR_EQUAL("application/octet-stream", mailattachment_content_type("data.xyz123"), "нет в таблице");
    TEST_ASSERT_STR_EQUAL("application/octet-stream", mailattachment_content_type("noext"), "без точки");
    TEST_ASSERT_STR_EQUAL("application/octet-stream", mailattachment_content_type(NULL), "NULL");
    TEST_ASSERT_STR_EQUAL("application/octet-stream", mailattachment_content_type(""), "пустое имя");
}

TEST(test_mailattachment_ascii_filename) {
    TEST_SUITE("mailattachment");
    TEST_CASE("basename, безопасные символы, fallback");

    char out[256];

    mailattachment_ascii_filename("report_2026.pdf", out, sizeof(out));
    TEST_ASSERT_STR_EQUAL("report_2026.pdf", out, "безопасное имя не меняется");

    mailattachment_ascii_filename("/tmp/../../etc/passwd", out, sizeof(out));
    TEST_ASSERT_STR_EQUAL("passwd", out, "path traversal схлопывается в basename");

    mailattachment_ascii_filename("C:\\Users\\иван\\файл.txt", out, sizeof(out));
    TEST_ASSERT_STR_EQUAL("________.txt", out, "кириллица и обратные слэши заменяются на _");

    mailattachment_ascii_filename("договор.pdf", out, sizeof(out));
    TEST_ASSERT_STR_EQUAL("______________.pdf", out, "небезопасные байты → _");

    mailattachment_ascii_filename("", out, sizeof(out));
    TEST_ASSERT_STR_EQUAL("attachment", out, "пустое имя → attachment");
}

TEST(test_mailattachment_percent_encode) {
    TEST_SUITE("mailattachment");
    TEST_CASE("RFC 3986: незарезервированные остаются, прочее — %XX верхним регистром");

    char out[128];

    mailattachment_percent_encode("abc-._~123", out, sizeof(out));
    TEST_ASSERT_STR_EQUAL("abc-._~123", out, "незарезервированные не трогаются");

    mailattachment_percent_encode(" ", out, sizeof(out));
    TEST_ASSERT_STR_EQUAL("%20", out, "пробел");

    mailattachment_percent_encode("д", out, sizeof(out));
    TEST_ASSERT_STR_EQUAL("%D0%B4", out, "кириллица побайтово");
}

TEST(test_mailattachment_part_build_structure) {
    TEST_SUITE("mailattachment");
    TEST_CASE("часть: разделитель, заголовки, base64 тела, CRLF в конце");

    mail_test_mimetype_setup();

    const char data[] = "PDFDATA";
    const mail_attachment_t attachment = {
        .filename = "отчёт.pdf",
        .content_type = NULL,
        .data = data,
        .size = sizeof(data) - 1
    };

    /* Конвенция boundary: значение С "=_"-префиксом (например "=_b1"), как в
     * Content-Type; разделители — "--" + это значение. */
    mail_attachment_part_t part = mailattachment_part_build(&attachment, "=_b1");
    TEST_REQUIRE_NOT_NULL(part.data, "часть собирается");

    /* base64("PDFDATA") = UERGREFUQQ== (вычислить при необходимости: printf PDFDATA | base64) */
    TEST_ASSERT(mail_test_part_contains(part, "--=_b1\r\nContent-Type: application/pdf; name=\"__________.pdf\"\r\n"), "заголовок типа");
    TEST_ASSERT(mail_test_part_contains(part, "Content-Disposition: attachment; filename=\"__________.pdf\";\r\n"), "disposition");
    TEST_ASSERT(mail_test_part_contains(part, "filename*=UTF-8''%D0%BE%D1%82%D1%87%D1%91%D1%82.pdf"), "RFC 2231 имя");
    TEST_ASSERT(mail_test_part_contains(part, "Content-Transfer-Encoding: base64\r\n\r\n"), "CTE части");
    TEST_ASSERT(mail_test_part_endswith(part, "UERGREFUQQ==\r\n"), "base64 данных с CRLF");

    mail_attachment_part_free(&part);
    TEST_ASSERT_NULL(part.data, "free обнуляет");
}

TEST(test_mailattachment_part_build_inline_cid) {
    TEST_SUITE("mailattachment");
    TEST_CASE("cid делает часть inline: Content-Disposition: inline и Content-ID");

    mail_test_mimetype_setup();

    const char data[] = "PNGDATA";
    const mail_attachment_t attachment = {
        .filename = "logo-blue.png",
        .content_type = NULL,
        .cid = "logo@synecta.tech",
        .data = data,
        .size = sizeof(data) - 1
    };

    mail_attachment_part_t part = mailattachment_part_build(&attachment, "=_b1");
    TEST_REQUIRE_NOT_NULL(part.data, "часть собирается");

    TEST_ASSERT(mail_test_part_contains(part, "Content-Type: image/png; name=\"logo-blue.png\"\r\n"), "тип по расширению");
    TEST_ASSERT(mail_test_part_contains(part, "Content-Disposition: inline; filename=\"logo-blue.png\";\r\n"), "disposition inline");
    /* угловые скобки живут в заголовке, в cid:-ссылке их нет */
    TEST_ASSERT(mail_test_part_contains(part, "Content-ID: <logo@synecta.tech>\r\n"), "Content-ID в скобках");
    TEST_ASSERT(mail_test_part_contains(part, "Content-Transfer-Encoding: base64\r\n\r\n"), "CTE части");

    mail_attachment_part_free(&part);
}

TEST(test_mailattachment_part_build_without_cid_stays_attachment) {
    TEST_SUITE("mailattachment");
    TEST_CASE("пустой cid не меняет обычное вложение");

    mail_test_mimetype_setup();

    const mail_attachment_t attachment = {
        .filename = "a.pdf", .cid = "", .data = "x", .size = 1
    };

    mail_attachment_part_t part = mailattachment_part_build(&attachment, "=_b1");
    TEST_REQUIRE_NOT_NULL(part.data, "часть собирается");

    TEST_ASSERT(mail_test_part_contains(part, "Content-Disposition: attachment;"), "disposition attachment");
    TEST_ASSERT(!mail_test_part_contains(part, "Content-ID:"), "Content-ID не выводится");

    mail_attachment_part_free(&part);
}

TEST(test_mailattachment_cid_valid) {
    TEST_SUITE("mailattachment");
    TEST_CASE("cid: непустой видимый ASCII без пробелов, скобок и кавычек");

    TEST_ASSERT(mailattachment_cid_valid("logo@synecta.tech"), "обычный addr-spec");
    TEST_ASSERT(mailattachment_cid_valid("logo"), "без домена — тоже значение");
    TEST_ASSERT(!mailattachment_cid_valid(NULL), "NULL");
    TEST_ASSERT(!mailattachment_cid_valid(""), "пустой");
    TEST_ASSERT(!mailattachment_cid_valid("logo @synecta.tech"), "пробел");
    TEST_ASSERT(!mailattachment_cid_valid("<logo@synecta.tech>"), "угловые скобки");
    TEST_ASSERT(!mailattachment_cid_valid("logo\"@synecta.tech"), "кавычка");
    TEST_ASSERT(!mailattachment_cid_valid("логотип@synecta.tech"), "не-ASCII");
    TEST_ASSERT(!mailattachment_cid_valid("logo\n@synecta.tech"), "перевод строки");

    char long_cid[MAILATTACHMENT_CID_MAX + 2];
    memset(long_cid, 'a', sizeof(long_cid) - 1);
    long_cid[sizeof(long_cid) - 1] = 0;
    TEST_ASSERT(!mailattachment_cid_valid(long_cid), "длиннее MAILATTACHMENT_CID_MAX");

    long_cid[MAILATTACHMENT_CID_MAX] = 0;
    TEST_ASSERT(mailattachment_cid_valid(long_cid), "ровно MAILATTACHMENT_CID_MAX");
}

TEST(test_mailattachment_part_build_rejects_bad_cid) {
    TEST_SUITE("mailattachment");
    TEST_CASE("некорректный cid отклоняет часть целиком");

    mail_test_mimetype_setup();

    const mail_attachment_t attachment = {
        .filename = "logo.png", .cid = "logo @synecta.tech", .data = "x", .size = 1
    };

    mail_attachment_part_t part = mailattachment_part_build(&attachment, "=_b1");
    TEST_ASSERT_NULL(part.data, "часть не собрана");
}

TEST(test_mailattachment_part_build_rejects_bad_content_type) {
    TEST_SUITE("mailattachment");
    TEST_CASE("content_type с управляющими символами отклоняет часть");

    /* Тип печатается в заголовок части как есть: CR/LF в нём начинал новый
     * заголовок. Найдено fuzz_mail_message. Параметры через ";" остаются
     * законными. */
    mail_test_mimetype_setup();

    const mail_attachment_t injected = {
        .filename = "a.txt", .content_type = "text/plain\r\nX-Evil: 1", .data = "x", .size = 1
    };
    mail_attachment_part_t part = mailattachment_part_build(&injected, "=_b1");
    TEST_ASSERT_NULL(part.data, "CRLF в типе отклонён");

    const mail_attachment_t tab = {
        .filename = "a.txt", .content_type = "text/plain\t", .data = "x", .size = 1
    };
    part = mailattachment_part_build(&tab, "=_b1");
    TEST_ASSERT_NULL(part.data, "управляющий символ в типе отклонён");

    const mail_attachment_t params = {
        .filename = "a.txt", .content_type = "text/plain; charset=utf-8", .data = "x", .size = 1
    };
    part = mailattachment_part_build(&params, "=_b1");
    TEST_ASSERT_NOT_NULL(part.data, "тип с параметром собран");
    mail_attachment_part_free(&part);
}

TEST(test_mailattachment_part_build_guards) {
    TEST_SUITE("mailattachment");
    TEST_CASE("пустое вложение и NULL отклоняются на входе");

    const mail_attachment_t empty_name = { .filename = "", .data = "x", .size = 1 };
    const mail_attachment_t empty_data = { .filename = "a.pdf", .data = "x", .size = 0 };

    mail_attachment_part_t p1 = mailattachment_part_build(&empty_name, "=_b");
    TEST_ASSERT_NULL(p1.data, "пустое имя отклонено");

    mail_attachment_part_t p2 = mailattachment_part_build(&empty_data, "=_b");
    TEST_ASSERT_NULL(p2.data, "нулевой размер отклонён");

    mail_attachment_part_t p3 = mailattachment_part_build(NULL, "=_b");
    TEST_ASSERT_NULL(p3.data, "NULL отклонён");
}

TEST(test_mailattachment_part_build_wrap76) {
    TEST_SUITE("mailattachment");
    TEST_CASE("base64 части переносится по 76 символов");

    char big[200];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    const mail_attachment_t attachment = {
        .filename = "big.bin", .data = big, .size = sizeof(big) - 1
    };

    mail_attachment_part_t part = mailattachment_part_build(&attachment, "=_b");
    TEST_REQUIRE_NOT_NULL(part.data, "часть собирается");

    /* 199 байт → 268 base64-символов → минимум одна строка длиннее 76 существует */
    int max_line = 0, line = 0;
    for (size_t i = 0; i < part.size; i++) {
        if (part.data[i] == '\n') { if (line > max_line) max_line = line; line = 0; }
        else if (part.data[i] != '\r') line++;
    }
    TEST_ASSERT(max_line > 0 && max_line <= 76, "строки base64 не длиннее 76");

    mail_attachment_part_free(&part);
}

TEST(test_mailattachment_part_build_truncated_headers) {
    TEST_SUITE("mailattachment");
    TEST_CASE("заголовки, обрезанные snprintf'ом, отклоняются");

    char type[601];
    memset(type, 'x', sizeof(type) - 1);
    type[sizeof(type) - 1] = '\0';

    /* все байты имени небезопасные: percent-кодирование раздувает заголовки */
    char name[701];
    memset(name, (char)0xE9, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';

    const mail_attachment_t attachment = {
        .filename = name,
        .content_type = type,
        .data = "x",
        .size = 1
    };

    mail_attachment_part_t part = mailattachment_part_build(&attachment, "=_b");
    TEST_ASSERT_NULL(part.data, "обрезанные заголовки отклонены");
}
