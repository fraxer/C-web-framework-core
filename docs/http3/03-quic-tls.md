# Фаза 3. QUIC-TLS: интеграция с OpenSSL, ключи, защита пакетов

RFC 9001. Это единственная фаза, где мы опираемся на библиотеку, поэтому границу
надо провести аккуратно: libssl делает **только** рукопожатие TLS 1.3 и выдаёт
секреты. Всё, что превращает секрет в защищённый пакет, — наше.

---

## 1. Что даёт OpenSSL 3.5

Проверено в заголовках на машине сборки:

```c
/* openssl/ssl.h */
int SSL_set_quic_tls_cbs(SSL *s, const OSSL_DISPATCH *qtdis, void *arg);
int SSL_set_quic_tls_transport_params(SSL *s, const unsigned char *params, size_t len);
int SSL_set_quic_tls_early_data_enabled(SSL *s, int enabled);

#define OSSL_RECORD_PROTECTION_LEVEL_NONE        0
#define OSSL_RECORD_PROTECTION_LEVEL_EARLY       1
#define OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE   2
#define OSSL_RECORD_PROTECTION_LEVEL_APPLICATION 3

/* openssl/core_dispatch.h */
OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND        2001
OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD    2002
OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD 2003
OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET       2004
OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS 2005
OSSL_FUNC_SSL_QUIC_TLS_ALERT              2006
```

`SSL_set_quic_tls_cbs()` переводит `SSL` в режим «QUIC TLS»: никаких TLS-записей
и BIO, обмен идёт через шесть колбэков. Это ровно тот API, ради которого
поднимали требование до OpenSSL 3.5.

---

## 2. `quictls.{c,h}` — шлюз

Держим его узким специально: под ним можно будет реализовать backend на
`SSL_QUIC_METHOD` (quictls/BoringSSL), если понадобится собраться на другой
библиотеке.

```c
typedef enum {
    QUIC_ENC_INITIAL = 0,
    QUIC_ENC_EARLY,        /* 0-RTT, фаза 9 */
    QUIC_ENC_HANDSHAKE,
    QUIC_ENC_APP,
    QUIC_ENC_COUNT
} quic_enc_level_e;

typedef struct quictls {
    SSL*      ssl;
    quicconn_t* conn;              /* обратная ссылка, приходит как arg */

    /* исходящие CRYPTO-данные, накопленные колбэком crypto_send,
     * по одному буферу на уровень */
    quicbuf_t out[QUIC_ENC_COUNT];

    /* входящие CRYPTO-данные: собранный без дыр префикс, который
     * crypto_recv_rcd отдаёт libssl */
    quicrecvbuf_t in[QUIC_ENC_COUNT];
    quic_enc_level_e in_level;     /* текущий уровень чтения */

    int handshake_complete;
    int handshake_confirmed;       /* HANDSHAKE_DONE отправлен */
    uint8_t alert;                 /* установлен колбэком alert */
    int alert_raised;
} quictls_t;

int  quictls_init_server(quictls_t*, quicconn_t*, SSL_CTX*);
/* Прокачать рукопожатие: вызывает SSL_do_handshake(), разбирает результат.
 * Возвращает 0 при ошибке (соединение закрывается CRYPTO_ERROR(alert)). */
int  quictls_advance(quictls_t*);
/* Скормить полученный CRYPTO-фрейм. */
int  quictls_recv_crypto(quictls_t*, quic_enc_level_e, uint64_t off,
                         const uint8_t* data, size_t len);
void quictls_free(quictls_t*);
```

### 2.1 Колбэки

```c
static const OSSL_DISPATCH quic_tls_dispatch[] = {
  { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,          (void(*)(void))cb_crypto_send },
  { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,      (void(*)(void))cb_crypto_recv_rcd },
  { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,   (void(*)(void))cb_crypto_release_rcd },
  { OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,         (void(*)(void))cb_yield_secret },
  { OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void(*)(void))cb_got_tp },
  { OSSL_FUNC_SSL_QUIC_TLS_ALERT,                (void(*)(void))cb_alert },
  { 0, NULL }
};
```

- **`crypto_send(ssl, buf, buf_len, *consumed, arg)`** — libssl отдаёт байты
  рукопожатия. Дописываем их в `out[текущий_уровень]`, ставим `*consumed = buf_len`.
  Уровень определяется по последнему `yield_secret` для направления write.
  Из этого буфера транспорт нарезает CRYPTO-фреймы (с учётом MTU и cwnd).
- **`crypto_recv_rcd(ssl, **buf, *bytes_read, arg)`** — libssl просит входные
  байты. Отдаём указатель на непрерывный префикс `in[in_level]`. Если непрерывных
  байт нет — `*bytes_read = 0`, возврат 1 (не ошибка).
- **`crypto_release_rcd(ssl, bytes_read, arg)`** — libssl подтверждает, сколько
  съела; сдвигаем префикс.
- **`yield_secret(ssl, prot_level, direction, secret, secret_len, arg)`** — тот
  самый момент, ради которого всё затевалось: получаем `secret` уровня и
  направления. `direction`: 0 — read (клиент→сервер), 1 — write. Вызываем
  `quiccrypto_install(conn, level, dir, secret, len, SSL_get_current_cipher(ssl))`.
- **`got_transport_params(ssl, params, len, arg)`** — декодируем через
  `quictp_decode()` и применяем к соединению (открываются окна, лимиты потоков).
- **`alert(ssl, alert_code, arg)`** — TLS-ошибка. Закрываем соединение с
  `CRYPTO_ERROR(alert_code)`.

### 2.2 Настройка `SSL_CTX`

Тот же контекст, что у TCP-TLS (vhost, SNI, сертификаты). Отличия:

- `SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)` — **для QUIC-SSL**.
  Так как контекст общий с TCP, где допустим TLS 1.2, ставим на `SSL` уровне:
  `SSL_set_min_proto_version(ssl, TLS1_3_VERSION)`.
- ALPN: в `__openssl_alpn_select_cb` добавляется `h3` — **но только для
  QUIC-соединений**. Колбэк ставится на `SSL_CTX`, а не на `SSL`, поэтому
  различаем через `SSL_get_ex_data(ssl, quic_ssl_ex_index)`: если там
  `quicconn_t*` — предлагаем только `h3`; иначе прежний порядок `h2` → `http/1.1`.
  Предлагать `h2` по QUIC нельзя, и наоборот.
- `SSL_set_quic_tls_transport_params()` — до `SSL_do_handshake()`.
- Ключевое ограничение RFC 9001 §4.4: QUIC требует AEAD-шифр; TLS 1.3 их и так
  даёт. Существующая проверка `openssl_cipher_ok_for_http2()` для h3 не нужна —
  TLS 1.3 обязателен по определению, — но повторно используется как assert.
- `SSL_CTX_set_max_early_data(ctx, 0)` в v1 — 0-RTT выключен явно.

### 2.3 Драйв рукопожатия

Сервер: `SSL_set_accept_state(ssl)`, затем на каждый принятый CRYPTO-фрейм —
`SSL_do_handshake(ssl)`. Возврат:

- `1` — рукопожатие завершено. **Тогда** отправляем `HANDSHAKE_DONE`,
  выдаём `NEW_TOKEN` и сбрасываем Initial/Handshake-ключи (§4.9 RFC 9001).
- `<= 0` + `SSL_get_error()` = `SSL_ERROR_WANT_READ` — ждём ещё CRYPTO.
- иначе — ошибка; `cb_alert` уже сообщил код.

**Важно:** сервер обязан уметь принять клиентский Initial, разбитый на несколько
пакетов и пришедший **не по порядку** (ClientHello с большим списком расширений
+ ECH легко превышает 1200 байт). Поэтому `in[]` — не простой буфер, а
`quicrecvbuf_t` с дырами (`04-quic-transport.md` §3).

Ограничение памяти: суммарный объём буферизованных CRYPTO-данных на уровень
ограничен (по умолчанию 64 КБ). Превышение → `CRYPTO_BUFFER_EXCEEDED`.

---

## 3. `quiccrypto.{c,h}` — key schedule и защита пакетов

### 3.1 HKDF-Expand-Label

QUIC использует TLS-шную конструкцию с префиксом `"tls13 "`:

```c
int quic_hkdf_expand_label(const EVP_MD* md,
                           const uint8_t* secret, size_t secret_len,
                           const char* label, /* без префикса, напр. "quic key" */
                           const uint8_t* context, size_t context_len,
                           uint8_t* out, size_t out_len);
```

Реализация — через `EVP_KDF_fetch(NULL, "HKDF", NULL)` в режиме
`EVP_KDF_HKDF_MODE_EXPAND_ONLY`, `info` собирается вручную:

```
struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
label = "tls13 " || label
```

Метки QUIC: `"quic key"`, `"quic iv"`, `"quic hp"`, `"quic ku"`.

### 3.2 Initial-секреты

```
initial_salt = 38762cf7f55934b34d179ae6a4c80cadccbb7f0a           (QUIC v1)
initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
```

`client_dst_connection_id` — DCID из **первого** Initial клиента (и, если мы
отправили Retry, — DCID из Initial, пришедшего *после* Retry, то есть наш
Retry-SCID). Хеш — SHA-256, шифр — AES-128-GCM, фиксированно.

Соль версии — константа в `quiccrypto.c`, вынесенная в таблицу на случай
добавления QUIC v2 (там своя соль).

### 3.3 Ключи уровня

Из секрета уровня (своего для read и write):

```
key = HKDF-Expand-Label(secret, "quic key", "", key_len)
iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
hp  = HKDF-Expand-Label(secret, "quic hp",  "", key_len)
```

`key_len` и AEAD — из выбранного TLS-шифра:

| Шифр | AEAD | key | hash | HP-шифр |
|---|---|---|---|---|
| `TLS_AES_128_GCM_SHA256` | AES-128-GCM | 16 | SHA-256 | AES-128-ECB |
| `TLS_AES_256_GCM_SHA384` | AES-256-GCM | 32 | SHA-384 | AES-256-ECB |
| `TLS_CHACHA20_POLY1305_SHA256` | ChaCha20-Poly1305 | 32 | SHA-256 | ChaCha20 |
| `TLS_AES_128_CCM_SHA256` | AES-128-CCM | 16 | SHA-256 | AES-128-ECB |

CCM в v1 не поддерживаем (исключаем из ciphersuites) — он редок и требует
отдельного обращения с тегом.

Структура:

```c
typedef struct quickeys {
    EVP_CIPHER_CTX* aead;      /* инициализирован ключом, переиспользуется */
    uint8_t  iv[12];
    EVP_CIPHER_CTX* hp;        /* AES-ECB или ChaCha20 */
    uint8_t  hp_key[32];
    size_t   tag_len;          /* 16 */
    uint64_t pkt_count;        /* для AEAD confidentiality limit */
    int      valid;
} quickeys_t;

typedef struct quiccrypto {
    quickeys_t rx[QUIC_ENC_COUNT];
    quickeys_t tx[QUIC_ENC_COUNT];
    uint8_t    rx_secret[QUIC_ENC_COUNT][EVP_MAX_MD_SIZE];  /* для key update */
    uint8_t    tx_secret[QUIC_ENC_COUNT][EVP_MAX_MD_SIZE];
    size_t     secret_len;
    const EVP_MD* md;
    int        key_phase;      /* текущая фаза 1-RTT */
    quickeys_t rx_next, tx_next;  /* заранее выведенные ключи следующей фазы */
    quickeys_t rx_prev;           /* предыдущая фаза, живёт 3×PTO */
    uint64_t   prev_expire_us;
    uint64_t   decrypt_failures;
} quiccrypto_t;
```

### 3.4 Защита полезной нагрузки

```
nonce = iv XOR (packet_number, выровненный вправо на 12 байт)
AAD   = весь заголовок пакета, включая номер пакета, в открытом виде
        (то есть до применения header protection)
```

```c
int quiccrypto_seal(quickeys_t*, uint64_t pn,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* pt, size_t pt_len,
                    uint8_t* out /* pt_len + 16 */);
int quiccrypto_open(quickeys_t*, uint64_t pn,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* ct, size_t ct_len,
                    uint8_t* out, size_t* out_len);
```

Реализация — `EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, nonce)` на уже
инициализированном ключом контексте: так на пакет не пересоздаётся `EVP_CIPHER_CTX`.
Это заметная разница по производительности (в 3–4 раза на мелких пакетах).

**Лимиты AEAD (§6.6)** — MUST:

| Шифр | Лимит шифрования | Лимит неудачных расшифровок |
|---|---|---|
| AES-GCM | 2^23 пакетов | 2^52 |
| ChaCha20-Poly1305 | 2^62 | 2^36 |

Превышение лимита шифрования → обязательный key update; превышение лимита
неудачных расшифровок → закрытие с `AEAD_LIMIT_REACHED`.

### 3.5 Header protection (`quichp.{c,h}`)

```
sample_offset = pn_offset + 4          /* всегда 4, независимо от реальной длины PN */
sample        = packet[sample_offset .. sample_offset+16]

AES:      mask = AES-ECB-Encrypt(hp_key, sample)[0..4]
ChaCha20: mask = ChaCha20(hp_key, counter = sample[0..3] LE, nonce = sample[4..15],
                          plaintext = 5 нулевых байт)

first_byte ^= mask[0] & (long header ? 0x0f : 0x1f)
pn_bytes[i] ^= mask[1 + i]             /* i < длина PN */
```

Порядок операций:

- **отправка**: сначала AEAD-шифрование payload, потом header protection;
- **приём**: сначала снятие header protection (только после этого известна длина
  PN и key phase), потом AEAD.

Проверка на приёме: если после `pn_offset` в пакете меньше `4 + 16` байт —
пакет отбрасывается (не хватает на sample). Это же требование обязывает
дополнять короткие пакеты PADDING при отправке.

```c
int quichp_apply(quickeys_t*, uint8_t* pkt, size_t pkt_len, size_t pn_offset);
int quichp_remove(quickeys_t*, uint8_t* pkt, size_t pkt_len, size_t pn_offset,
                  size_t* out_pn_len, uint64_t* out_truncated_pn, int* out_key_phase);
```

### 3.6 Key update (§6)

Инициируется любой стороной сменой бита Key Phase в short header.

- Заранее выводим `next_secret = HKDF-Expand-Label(secret, "quic ku", "", len)`
  и ключи из него, чтобы обновление не требовало вычислений на горячем пути.
- При приёме пакета с чужой фазой пробуем `rx_next`. Успех → фиксируем
  обновление, сдвигаем поколения, старые `rx` держим ещё 3×PTO (пакеты в полёте),
  и **обязаны** сами перейти на новую фазу отправки.
- Ограничения: нельзя инициировать обновление до подтверждения рукопожатия
  (`handshake_confirmed`); нельзя обновляться чаще, чем раз в 3×PTO — иначе
  `KEY_UPDATE_ERROR`.
- Сами инициируем обновление при приближении к лимиту `pkt_count` и раз в
  ~1 час на долгих соединениях.

Это классический источник трудноуловимых багов — в тестах обязательны:
обновление, инициированное клиентом; наше; пакет старой фазы после обновления;
попытка обновления дважды подряд.

---

## 4. Retry и валидация адреса (`quicretry.{c,h}`)

### 4.1 Retry-пакет

```
Retry = long header(type=3) || Retry Token || Retry Integrity Tag(16)
Retry Integrity Tag = AES-128-GCM(
        key   = be0c690b9f66575a1d766b54e368c84e,
        nonce = 461599d35d632bf2239825bb,
        aad   = ODCID Len(8) || Original DCID || Retry-пакет без тега,
        pt    = "")
```

Ключ и nonce — константы v1 из RFC 9001 §5.8; тег вычисляется тем же
`EVP_aead`-путём, что и обычные пакеты.

### 4.2 Токены

Два вида, оба выпускает сервер и оба надо уметь проверить:

| Вид | Где | Содержимое |
|---|---|---|
| Retry-токен | в Retry-пакете, клиент вернёт в следующем Initial | ODCID + адрес клиента + время + признак «retry» |
| NEW_TOKEN | во фрейме NEW_TOKEN после рукопожатия, для будущих соединений | адрес клиента + время + признак «new_token» |

Формат (наш, RFC его не задаёт):

```
version(1) | kind(1) | timestamp(8) | addr_len(1) | addr | odcid_len(1) | odcid
+ AES-256-GCM(endpoint->token_key, nonce=RAND(12)) поверх всего
итог: nonce(12) || ciphertext || tag(16)
```

Проверки: срок жизни (Retry — 30 с, NEW_TOKEN — 24 ч), совпадение адреса
(для NEW_TOKEN — только IP, порт меняется), различение kind (Retry-токен в
NEW_TOKEN-позиции → `INVALID_TOKEN`; NEW_TOKEN, поданный как Retry-токен, —
не ошибка, но и не даёт `retry_source_connection_id`).

Невалидный токен в Initial: RFC 9000 §8.1.3 — **не** закрывать соединение
ошибкой, если токен из NEW_TOKEN (просто игнорировать его и продолжить как
невалидированный адрес); закрывать `INVALID_TOKEN`, если токен пришёл в ответ
на наш Retry.

### 4.3 Когда отправлять Retry

Постоянный Retry стоит клиенту лишний RTT. Политика:

- по умолчанию **выключен**;
- включается автоматически, когда число рукопожатий в полёте превышает порог
  (`http3_retry_threshold`, по умолчанию 1000) — так под атакой отражения
  сервер перестаёт тратить память на непроверенные адреса;
- принудительно включается/выключается конфигом.

Независимо от Retry действует **anti-amplification** (`04` §8): до валидации
адреса сервер не отправляет больше 3× полученных байт. Это MUST и работает
всегда.

---

## 5. Порядок обработки входящего пакета

Сводим воедино то, что размазано по фазам 2–3:

```
датаграмма
 └ для каждого пакета (quicpkt_next):
    1. quicpkt_parse_header            → форма, версия, CID, pn_offset
    2. выбрать уровень шифрования по типу пакета
    3. ключи уровня есть?              нет → буферизовать (до N пакетов) или отбросить
    4. quichp_remove                   → длина PN, усечённый PN, key phase
    5. quicpkt_decode_pn(largest_acked_in_space, ...)
    6. защита от повтора: pn уже принят в этом пространстве? → отбросить молча
    7. quiccrypto_open                 неудача → счётчик, лимит §3.4, отбросить молча
    8. quicframe_next по payload       → обработка фреймов
    9. записать pn в ACK-состояние пространства, отметить ack-eliciting
```

Шаг 3 нюанс: 1-RTT-пакеты вполне могут обогнать Handshake (переупорядочивание).
Их надо **буферизовать** (небольшой кольцевой буфер, 10 пакетов), иначе на
плохой сети рукопожатие будет разваливаться. Аналогично 0-RTT в фазе 9.

Шаг 6: множество принятых номеров — это тот же ACK-диапазон, что нужен для
отправки ACK. Отдельной структуры не заводим (`04` §4).

---

## 6. Сброс ключей

- После получения **Handshake**-пакета от клиента — Initial-ключи и всё
  состояние Initial-пространства выбрасываются (§4.9.1).
- После подтверждения рукопожатия (сервер: как только рукопожатие завершено;
  клиент: по HANDSHAKE_DONE) — Handshake-ключи выбрасываются (§4.9.2).
- 0-RTT read-ключи выбрасываются после получения первого 1-RTT-пакета.

Сброс не косметика: он освобождает память и закрывает целый класс атак с
подмешиванием старых пакетов.

---

## 7. Stateless reset (RFC 9000 §10.3)

Пакет, оформленный так, чтобы его нельзя было отличить от обычного short-header:

```
0|1|случайные 5 бит | случайные байты (>= 4, чтобы длина была >= 21) | reset token(16)
```

Правила:

- отправляем на short-header-пакет с неизвестным CID;
- размер ответа **меньше** размера триггера (иначе усилитель); минимум — 21 байт,
  ниже которого не отправляем вовсе;
- собственный бюджет (token bucket), иначе это DoS-усилитель;
- на приёме сами тоже должны распознавать stateless reset от клиента — сравнивая
  последние 16 байт с токенами известных нам CID (это O(число CID) и делается
  только при неудачной расшифровке).

---

## 8. Юнит-тесты фазы

`tests/unit/test_quic_crypto.c`, `test_quic_hp.c`, `test_quic_retry.c`:

1. **RFC 9001 Приложение A** целиком — там даны байт в байт: клиентский Initial
   (§A.1–A.2), серверный Initial (§A.3), Retry (§A.4), ChaCha20-пример со
   snapshot-ключами (§A.5). Это лучший из существующих наборов векторов: если он
   сходится, key schedule, AEAD и header protection точно верны.
2. HKDF-Expand-Label на векторах RFC 8448.
3. Key update: своя лестница секретов, троекратное обновление, приём пакета
   предыдущей фазы.
4. Retry integrity tag на векторе §A.4.
5. Токены: round-trip, истечение срока, смена адреса, порча байта →
   провал аутентификации.
6. Порядок «HP → AEAD» на приёме и обратный на отправке: тест, который
   отправляет собственный пакет и сам же его разбирает.

**Готово, когда:** векторы Приложения A сходятся; `curl --http3` (сборка с
ngtcp2) доходит до завершения рукопожатия и получает `HANDSHAKE_DONE`;
Wireshark с `SSLKEYLOGFILE` расшифровывает трафик.
