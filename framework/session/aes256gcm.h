#ifndef __AES256GCM__
#define __AES256GCM__

#define AES256GCM_KEY_SIZE 32

// Шифрует plaintext с помощью AES-256-GCM.
// Возвращает base64(nonce[12] || ciphertext || tag[16]).
// Возвращает NULL при ошибке. Вызывающий освобождает память через free().
char* aes256gcm_encrypt(const char* plaintext, const unsigned char key[32]);

// Расшифровывает и проверяет GCM-тег.
// Возвращает NULL при ошибке или повреждении данных. Вызывающий освобождает память через free().
char* aes256gcm_decrypt(const char* ciphertext_b64, const unsigned char key[32]);

// Конвертирует 64-символьный hex-ключ в 32 байта.
// Возвращает 1 при успехе, 0 при ошибке.
int aes256gcm_key_from_hex(const char* hex64, unsigned char key_out[32]);

// Производит 32-байтный ключ из строки произвольной длины через SHA-256.
void aes256gcm_key_from_passphrase(const char* passphrase, unsigned char key_out[32]);

#endif
