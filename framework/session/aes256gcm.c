#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>

#include "aes256gcm.h"
#include "random.h"
#include "base64.h"
#include "sha256.h"

#define NONCE_SIZE 12
#define TAG_SIZE   16

char* aes256gcm_encrypt(const char* plaintext, const unsigned char key[AES256GCM_KEY_SIZE]) {
    if (plaintext == NULL || key == NULL)
        return NULL;

    int plaintext_len = (int)strlen(plaintext);
    int binary_len = NONCE_SIZE + plaintext_len + TAG_SIZE;

    unsigned char* binary = malloc(binary_len);
    if (binary == NULL)
        return NULL;

    unsigned char* nonce      = binary;
    unsigned char* ciphertext = binary + NONCE_SIZE;
    unsigned char* tag        = binary + NONCE_SIZE + plaintext_len;

    if (random_bytes(nonce, NONCE_SIZE) != 1) {
        free(binary);
        return NULL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(binary);
        return NULL;
    }

    int ok = 1;
    int len = 0;

    ok = ok && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL);
    ok = ok && EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    ok = ok && EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*)plaintext, plaintext_len);
    ok = ok && EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        free(binary);
        return NULL;
    }

    int b64_len = base64_encode_len(binary_len);
    char* result = malloc(b64_len);
    if (result == NULL) {
        free(binary);
        return NULL;
    }

    base64_encode(result, (const char*)binary, binary_len);
    free(binary);

    return result;
}

char* aes256gcm_decrypt(const char* ciphertext_b64, const unsigned char key[AES256GCM_KEY_SIZE]) {
    if (ciphertext_b64 == NULL || key == NULL)
        return NULL;

    int binary_max = base64_decode_len(ciphertext_b64);
    unsigned char* binary = malloc(binary_max);
    if (binary == NULL)
        return NULL;

    int decoded_len = base64_decode((char*)binary, ciphertext_b64);

    if (decoded_len <= NONCE_SIZE + TAG_SIZE) {
        free(binary);
        return NULL;
    }

    unsigned char* nonce      = binary;
    unsigned char* ciphertext = binary + NONCE_SIZE;
    int ciphertext_len        = decoded_len - NONCE_SIZE - TAG_SIZE;
    unsigned char* tag        = binary + NONCE_SIZE + ciphertext_len;

    char* plaintext = malloc(ciphertext_len + 1);
    if (plaintext == NULL) {
        free(binary);
        return NULL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(binary);
        free(plaintext);
        return NULL;
    }

    int ok = 1;
    int len = 0;
    int plaintext_len = 0;

    ok = ok && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL);
    ok = ok && EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    ok = ok && EVP_DecryptUpdate(ctx, (unsigned char*)plaintext, &len, ciphertext, ciphertext_len);
    if (ok) plaintext_len = len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag);
    ok = ok && (EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext + plaintext_len, &len) > 0);
    if (ok) plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    free(binary);

    if (!ok) {
        free(plaintext);
        return NULL;
    }

    plaintext[plaintext_len] = '\0';
    return plaintext;
}

void aes256gcm_key_from_passphrase(const char* passphrase, unsigned char key_out[AES256GCM_KEY_SIZE]) {
    sha256((const unsigned char*)passphrase, strlen(passphrase), key_out);
}

int aes256gcm_key_from_hex(const char* hex64, unsigned char key_out[AES256GCM_KEY_SIZE]) {
    if (hex64 == NULL || key_out == NULL)
        return 0;

    for (int i = 0; i < AES256GCM_KEY_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex64 + i * 2, "%02x", &byte) != 1)
            return 0;
        key_out[i] = (unsigned char)byte;
    }

    return 1;
}
