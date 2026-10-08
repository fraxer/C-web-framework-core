#include "framework.h"

#include <stdlib.h>
#include <string.h>

#include "aes256gcm.h"

/* framework/session/aes256gcm.c -- what stands between a session cookie from
 * the network and the session data. Decryption returns the plaintext or NULL,
 * never part of it; a key is read from exactly 64 hex digits or not at all. */

static const unsigned char __key[AES256GCM_KEY_SIZE] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
};

TEST(test_aes256gcm_roundtrip) {
    TEST_CASE("decrypt(encrypt(x)) is x, for empty, 8-bit and long values");

    static const char* const values[] = { "", "a", "\xff\xfe\x80 not utf-8", "{\"user\":1}" };
    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        char* sealed = aes256gcm_encrypt(values[i], __key);
        TEST_REQUIRE_NOT_NULL(sealed, "encrypt");
        char* opened = aes256gcm_decrypt(sealed, __key);
        TEST_ASSERT(opened != NULL && strcmp(opened, values[i]) == 0, "decrypt gives it back");
        free(opened);
        free(sealed);
    }

    char* long_value = malloc(100001);
    TEST_REQUIRE_NOT_NULL(long_value, "100 000 bytes buffer");
    memset(long_value, 'x', 100000);
    long_value[100000] = '\0';
    char* sealed = aes256gcm_encrypt(long_value, __key);
    char* opened = sealed ? aes256gcm_decrypt(sealed, __key) : NULL;
    TEST_ASSERT(opened != NULL && strcmp(opened, long_value) == 0, "100 000 bytes");
    free(opened);
    free(sealed);
    free(long_value);
}

TEST(test_aes256gcm_tamper) {
    TEST_CASE("a changed character, a wrong key or a cut value decrypts to NULL");

    char* sealed = aes256gcm_encrypt("session data", __key);
    TEST_REQUIRE_NOT_NULL(sealed, "encrypt");

    unsigned char other[AES256GCM_KEY_SIZE];
    memcpy(other, __key, sizeof other);
    other[0] ^= 1;
    TEST_ASSERT_NULL(aes256gcm_decrypt(sealed, other), "wrong key");

    const size_t n = strlen(sealed);
    for (size_t i = 0; i < n; i++) {
        char* copy = strdup(sealed);
        TEST_REQUIRE_NOT_NULL_GOTO(copy, "copy", cleanup);
        copy[i] = copy[i] == 'A' ? 'B' : 'A';
        char* opened = aes256gcm_decrypt(copy, __key);
        /* A change in the unused bits of the last character can leave the
         * bytes as they were; anything else must fail. Never a prefix. */
        TEST_ASSERT(opened == NULL || strcmp(opened, "session data") == 0, "changed character");
        free(opened);
        free(copy);
    }

    for (size_t cut = 0; cut < n; cut++) {
        char* copy = strndup(sealed, cut);
        char* opened = aes256gcm_decrypt(copy, __key);
        /* Only the '=' padding can go without losing a byte. */
        TEST_ASSERT(opened == NULL || (sealed[cut] == '=' && strcmp(opened, "session data") == 0), "cut short");
        free(opened);
        free(copy);
    }

    TEST_ASSERT_NULL(aes256gcm_decrypt("", __key), "empty");
    TEST_ASSERT_NULL(aes256gcm_decrypt("!!!!", __key), "not base64");

cleanup:
    free(sealed);
}

static int __hex(const char* text, unsigned char out[AES256GCM_KEY_SIZE]) {
    /* An allocation of exactly the string, so a read past its end is ASan's. */
    char* copy = strdup(text);
    const int ok = aes256gcm_key_from_hex(copy, out);
    free(copy);
    return ok;
}

TEST(test_aes256gcm_key_from_hex) {
    TEST_CASE("a key is exactly 64 hex digits");

    /* sscanf("%02x") read two characters at every even offset: an odd length
     * read past the terminator, leading blanks and signs were taken, and
     * anything after the 64th digit was ignored. */
    const char* good = "000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F";
    unsigned char key[AES256GCM_KEY_SIZE];
    TEST_ASSERT_EQUAL(1, __hex(good, key), "64 hex digits");
    for (int i = 0; i < AES256GCM_KEY_SIZE; i++)
        TEST_ASSERT_EQUAL(i, key[i], "byte value");

    TEST_ASSERT_EQUAL(0, __hex("0", key), "one digit");
    TEST_ASSERT_EQUAL(0, __hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1", key), "63 digits");
    TEST_ASSERT_EQUAL(0, __hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00", key), "66 digits");
    TEST_ASSERT_EQUAL(0, __hex(" 00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key), "a leading blank");
    TEST_ASSERT_EQUAL(0, __hex("+f0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key), "a sign");
    TEST_ASSERT_EQUAL(0, __hex("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key), "a 0x prefix");
    TEST_ASSERT_EQUAL(0, __hex("g00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1", key), "a non-hex digit");
    TEST_ASSERT_EQUAL(0, __hex("", key), "empty");
    TEST_ASSERT_EQUAL(0, aes256gcm_key_from_hex(NULL, key), "NULL");
}
