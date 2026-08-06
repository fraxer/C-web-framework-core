# Фаза 2. Ядро QUIC: varint, пакеты, фреймы, CID, transport parameters

Чистые кодеки без состояния соединения — по образцу `h2frame.{c,h}`: модуль
зависит только от libc, покрывается юнит-тестами в изоляции.

RFC 9000 §16–§19, RFC 8999.

---

## 1. `varint.{c,h}` — переменная длина

Двухбитный префикс первого байта задаёт длину: 1, 2, 4 или 8 байт; полезная
нагрузка — оставшиеся 62 бита.

```c
/* Читает varint. Возвращает число прочитанных байт (1/2/4/8), либо 0, если
 * буфера не хватает. */
size_t varint_read(const uint8_t* p, size_t avail, uint64_t* out);

/* Пишет varint минимальной длины. Возвращает число записанных байт, 0 если
 * value > VARINT_MAX или места мало. */
size_t varint_write(uint8_t* p, size_t cap, uint64_t value);

/* Сколько байт займёт value. */
size_t varint_size(uint64_t value);

/* Записать value в заранее известной длине len (нужно для полей, которые
 * дописываются задним числом — например Length в long header). */
size_t varint_write_fixed(uint8_t* p, size_t cap, uint64_t value, size_t len);

#define VARINT_MAX 0x3FFFFFFFFFFFFFFFULL
```

Тонкости, которые ловят тесты:

- **Не-минимальная кодировка допустима на приёме** (RFC 9000 §16: «values do not
  need to be encoded on the minimum number of bytes»). Отвергать её нельзя —
  это распространённая ошибка. Кодируем всегда минимально, декодируем любое.
- Исключение: там, где RFC требует конкретную интерпретацию (`Frame Type`), для
  сравнения используем декодированное значение, а не байты.
- `varint_write_fixed` нужен для `Length` в long header: длину payload узнаём
  после сборки, а место под неё резервируем заранее — резервируем 2 байта
  (до 16383), для больших пакетов 4.

Тесты: граничные значения 0, 63, 64, 16383, 16384, 2^30−1, 2^30, 2^62−1, 2^62
(ошибка); все примеры из RFC 9000 §A.1.

---

## 2. `quicpacket.{c,h}` — заголовки пакетов

### 2.1 Формы

**Long header** (Initial, 0-RTT, Handshake, Retry):

```
1|1|T T|R R|P P   Version(32)   DCID Len(8) DCID(0..160)  SCID Len(8) SCID(0..160)
[Token Length(i) Token(..)]           — только Initial
Length(i)  Packet Number(8..32)  Payload
```

**Short header** (1-RTT):

```
0|1|S|R R|K|P P   DCID(0..160)  Packet Number(8..32)  Payload
```

**Retry** — без Packet Number и Length: `... Retry Token(..) Retry Integrity Tag(128)`.

**Version Negotiation** — `1|unused(7) Version=0 DCID SCID Supported Versions(32)*`.

### 2.2 Двухэтапный разбор

Критично: биты `P P` (длина номера пакета) и `K` (key phase) находятся **под
header protection** и до снятия защиты недоступны. Поэтому разбор разделён:

```c
/* Этап 1 — версионно-независимый (RFC 8999). Не трогает защищённые биты.
 * Даёт всё, что нужно для маршрутизации и для снятия HP. */
typedef struct quicpkt_hdr {
    int      is_long;
    uint32_t version;            /* 0 для short header */
    uint8_t  type;               /* QUIC_PKT_INITIAL/0RTT/HANDSHAKE/RETRY */
    uint8_t  dcid[QUIC_MAX_CID_LEN]; size_t dcid_len;
    uint8_t  scid[QUIC_MAX_CID_LEN]; size_t scid_len;
    const uint8_t* token;  size_t token_len;      /* Initial */
    uint64_t length;                              /* Length поля (long) */
    size_t   pn_offset;   /* смещение начала Packet Number от начала пакета */
    size_t   hdr_len;     /* смещение pn_offset, синоним для читаемости */
    size_t   pkt_len;     /* полная длина пакета внутри датаграммы */
} quicpkt_hdr_t;

typedef enum {
    QUICPKT_OK, QUICPKT_SHORT_BUFFER, QUICPKT_BAD_FORM,
    QUICPKT_VERSION_NEGOTIATION, QUICPKT_UNSUPPORTED_VERSION
} quicpkt_status_e;

quicpkt_status_e quicpkt_parse_header(const uint8_t* buf, size_t len,
                                      size_t local_cid_len, quicpkt_hdr_t* out);
```

`local_cid_len` нужен для short header: длина DCID там не передаётся, её знает
только тот, кто эти CID выдавал. Поэтому **все server-chosen CID должны быть
одной длины** — фиксируем 8 байт.

Этап 2 (снятие HP, извлечение номера пакета, расшифровка) — в `03-quic-tls.md`.

### 2.3 Номера пакетов

Кодируются усечённо (1–4 байта). Восстановление полного номера — алгоритм из
RFC 9000 §A.3 (`decode_packet_number(largest_pn, truncated_pn, pn_nbits)`).
Выбор длины при отправке — §A.2: столько байт, чтобы покрыть удвоенное число
неподтверждённых пакетов.

```c
uint64_t quicpkt_decode_pn(uint64_t largest_acked, uint64_t truncated, size_t nbits);
size_t   quicpkt_pn_length(uint64_t pn, uint64_t largest_acked);
```

Отдельный тест на переполнение: `largest_acked` = 2^62−1.

### 2.4 Сборка

```c
/* Пишет long header, оставляя место под Length и Packet Number; возвращает
 * позиции для последующей дозаписи. */
size_t quicpkt_write_long_header(uint8_t* dst, size_t cap,
                                 uint8_t type, uint32_t version,
                                 const quiccid_t* dcid, const quiccid_t* scid,
                                 const uint8_t* token, size_t token_len,
                                 uint64_t pn, size_t pn_len,
                                 size_t* out_length_field_off,
                                 size_t* out_pn_off);
size_t quicpkt_write_short_header(uint8_t* dst, size_t cap, const quiccid_t* dcid,
                                  int key_phase, uint64_t pn, size_t pn_len,
                                  size_t* out_pn_off);
```

### 2.5 Коалесценция

Одна датаграмма может содержать несколько пакетов подряд: типично
`Initial + Handshake` или `Handshake + 1-RTT`. Правила:

- пакеты со short header — только последними (у них нет Length);
- у всех пакетов датаграммы должен быть **один DCID** (§12.2), иначе пакеты
  после первого отбрасываются;
- Initial-пакет, идущий первым в датаграмме от клиента, требует, чтобы
  **датаграмма** была ≥ 1200 байт — добивается PADDING.

Функция обхода:

```c
/* Итератор пакетов внутри датаграммы. */
int quicpkt_next(const uint8_t* dgram, size_t dgram_len, size_t* off,
                 size_t local_cid_len, quicpkt_hdr_t* out);
```

### 2.6 Version Negotiation

```c
size_t quicpkt_write_version_negotiation(uint8_t* dst, size_t cap,
                                         const quiccid_t* dcid, const quiccid_t* scid);
```

DCID и SCID **меняются местами** относительно принятого пакета. В список версий
включаем `0x00000001` и одну зарезервированную GREASE-версию вида `0x?a?a?a?a`,
чтобы клиенты не «зашивали» точный список.

---

## 3. `quiccid.{c,h}` — Connection ID

```c
typedef struct { uint8_t data[QUIC_MAX_CID_LEN /*20*/]; uint8_t len; } quiccid_t;
```

**Генерация серверных CID** — 8 байт:

```
[0]        индекс воркера (для будущей аффинности; фаза 9)
[1..7]     RAND_bytes
```

Требование RFC 9000 §5.1: CID не должен позволять связать соединения между
собой — 7 случайных байт достаточно; индекс воркера утечкой не считается
(nginx/quiche делают то же самое).

**Последовательности.** У каждого CID есть `sequence number` и (опционально)
`stateless reset token` (16 байт). Сервер обязан:

- выдать клиенту дополнительные CID через `NEW_CONNECTION_ID` — минимум
  `active_connection_id_limit` штук (клиенты требуют 2–8), иначе клиент не
  сможет мигрировать;
- обрабатывать `RETIRE_CONNECTION_ID`, снимая CID с таблицы **с задержкой**
  (пакеты в полёте ещё придут на него) — retire через 3×PTO;
- уважать `Retire Prior To`.

Структура на соединении:

```c
typedef struct quiccid_entry {
    quiccid_t cid;
    uint64_t  seq;
    uint8_t   reset_token[16];
    int       retired;
    uint64_t  retire_at_us;
} quiccid_entry_t;
```

Плюс список **клиентских** CID (те, что мы ставим в DCID исходящих пакетов) с
их последовательностями — клиент точно так же присылает нам `NEW_CONNECTION_ID`.

**Stateless reset token** выводится детерминированно, чтобы его можно было
вычислить и после потери состояния:

```
token = HMAC-SHA256(endpoint->reset_key, cid)[0..15]
```

Ключ — общий на процесс, генерируется при старте (`RAND_bytes`); при
`reload: soft` сохраняется, иначе после перезапуска старые токены не сойдутся
(это допустимо, но лучше вынести ключ в конфиг для кластера).

---

## 4. `quicframe.{c,h}` — фреймы

Полный список RFC 9000 §19 (тип — varint):

| Тип | Имя | Пакетные пространства |
|---|---|---|
| 0x00 | PADDING | IH01 |
| 0x01 | PING | IH01 |
| 0x02–0x03 | ACK (0x03 — с ECN counts) | IH_1 |
| 0x04 | RESET_STREAM | __01 |
| 0x05 | STOP_SENDING | __01 |
| 0x06 | CRYPTO | IH_1 |
| 0x07 | NEW_TOKEN | ___1 |
| 0x08–0x0f | STREAM (биты OFF/LEN/FIN) | __01 |
| 0x10 | MAX_DATA | __01 |
| 0x11 | MAX_STREAM_DATA | __01 |
| 0x12–0x13 | MAX_STREAMS (bidi/uni) | __01 |
| 0x14 | DATA_BLOCKED | __01 |
| 0x15 | STREAM_DATA_BLOCKED | __01 |
| 0x16–0x17 | STREAMS_BLOCKED | __01 |
| 0x18 | NEW_CONNECTION_ID | __01 |
| 0x19 | RETIRE_CONNECTION_ID | __01 |
| 0x1a | PATH_CHALLENGE | __01 |
| 0x1b | PATH_RESPONSE | ___1 |
| 0x1c–0x1d | CONNECTION_CLOSE (0x1d — только в 1-RTT/0-RTT) | ih01 |
| 0x1e | HANDSHAKE_DONE | ___1 |
| 0x30–0x31 | DATAGRAM (RFC 9221) | не реализуем в v1 |

Колонка «пространства» — I=Initial, H=Handshake, 0=0-RTT, 1=1-RTT. Проверка
допустимости фрейма в пространстве — обязательна: нарушение →
`PROTOCOL_VIOLATION`. Таблица кодируется как битовая маска на тип, проверка —
одна операция.

### 4.1 API

По образцу `h2frame_parser_feed`, но без резюмируемости: QUIC-пакет всегда
приходит целиком (датаграмма атомарна), поэтому парсер фреймов работает по
готовому расшифрованному буферу.

```c
typedef struct quicframe {
    uint64_t type;
    union {
        struct { uint64_t largest, delay, first_range;
                 const uint8_t* ranges; size_t ranges_len;
                 uint64_t ect0, ect1, ecn_ce; int has_ecn; } ack;
        struct { uint64_t id, error, final_size; }            reset_stream;
        struct { uint64_t id, error; }                        stop_sending;
        struct { uint64_t offset, len; const uint8_t* data; } crypto;
        struct { uint64_t len; const uint8_t* data; }         new_token;
        struct { uint64_t id, offset, len; const uint8_t* data; int fin; } stream;
        struct { uint64_t max; }                              max_data;
        struct { uint64_t id, max; }                          max_stream_data;
        struct { uint64_t max; int uni; }                     max_streams;
        /* ... */
        struct { uint64_t seq, retire_prior_to; quiccid_t cid; uint8_t token[16]; } new_cid;
        struct { uint8_t data[8]; }                           path;
        struct { uint64_t error, frame_type; const char* reason; size_t reason_len;
                 int is_app; }                                conn_close;
    } u;
} quicframe_t;

typedef enum {
    QUICFRAME_OK, QUICFRAME_DONE, QUICFRAME_ERR_ENCODING, QUICFRAME_ERR_UNKNOWN_TYPE
} quicframe_status_e;

/* Итератор по фреймам расшифрованного payload. */
quicframe_status_e quicframe_next(const uint8_t* buf, size_t len, size_t* off,
                                  quicframe_t* out);

/* Сборка. Каждая пишет фрейм в dst, возвращает длину или 0 (не влезло). */
size_t quicframe_write_ack(uint8_t* dst, size_t cap, const quicack_state_t*, ...);
size_t quicframe_write_stream(uint8_t* dst, size_t cap, uint64_t id, uint64_t off,
                              const uint8_t* data, size_t len, int fin, int last_in_pkt);
/* ... по одной на тип */
```

### 4.2 Тонкости, которые обязательно должны быть в тестах

- **STREAM без LEN-бита** занимает весь остаток пакета. `last_in_pkt` в
  сборщике выбирает эту форму, экономя 1–2 байта.
- **ACK Range** кодируется как «Gap / ACK Range Length», каждое поле на 1 меньше
  фактического (RFC §19.3.1). Классический источник off-by-one; тест обязан
  включать примеры из RFC.
- **ACK Delay** масштабируется `ack_delay_exponent` пира (по умолчанию 3).
  В Initial/Handshake экспонента **всегда 3**, независимо от transport
  parameters (§18.2) — отдельная ловушка.
- **PADDING** может идти сплошным блоком; итератор должен схлопывать его
  за один шаг, иначе 1200-байтный Initial даст 1100 итераций.
- **Неизвестный тип фрейма** → `FRAME_ENCODING_ERROR` (не игнорирование! в
  отличие от HTTP/3, где неизвестные *кадры* игнорируются).
- **Фрейм длиной 0 байт полезной нагрузки в непустом пакете** — легален;
  а вот пакет **без единого фрейма** — `PROTOCOL_VIOLATION`.
- **CONNECTION_CLOSE типа 0x1d** (application) запрещён в Initial/Handshake;
  при необходимости закрыться там используется 0x1c с
  `APPLICATION_ERROR`.

### 4.3 Ack-eliciting и congestion-controlled

Две классификации, от которых зависит вся логика восстановления:

- **ack-eliciting** — всё, кроме ACK, PADDING, CONNECTION_CLOSE;
- **in-flight (congestion-controlled)** — пакет, содержащий что-либо кроме ACK,
  PADDING и CONNECTION_CLOSE... точнее: пакет считается in-flight, если он
  ack-eliciting **или** содержит PADDING.

Обе выражаются функциями `quicframe_is_ack_eliciting(type)` и агрегируются при
сборке пакета в `quicpkt_sent_t` (`04-quic-transport.md` §5).

---

## 5. `quictp.{c,h}` — transport parameters

Кодируются как последовательность `{id: varint, len: varint, value}` и
передаются в TLS-расширении `quic_transport_parameters` (0x39) — libssl делает
это за нас через `SSL_set_quic_tls_transport_params()` /
колбэк `got_transport_params`.

| ID | Имя | Роль сервера |
|---|---|---|
| 0x00 | `original_destination_connection_id` | **обязателен** для сервера: DCID из первого Initial клиента |
| 0x01 | `max_idle_timeout` | из конфига, по умолчанию 30 с |
| 0x02 | `stateless_reset_token` | токен для CID, выданного в SCID первого ответа |
| 0x03 | `max_udp_payload_size` | 1472 (v4) / 1452 (v6); минимум 1200 |
| 0x04 | `initial_max_data` | окно соединения, по умолчанию 1 МБ |
| 0x05 | `initial_max_stream_data_bidi_local` | 0 (сервер не открывает bidi) |
| 0x06 | `initial_max_stream_data_bidi_remote` | окно потока запроса, 256 КБ |
| 0x07 | `initial_max_stream_data_uni` | 256 КБ (служебные потоки h3) |
| 0x08 | `initial_max_streams_bidi` | 100 — аналог `H2_MAX_CONCURRENT_STREAMS` |
| 0x09 | `initial_max_streams_uni` | 3 + запас на GREASE = 8 |
| 0x0a | `ack_delay_exponent` | 3 |
| 0x0b | `max_ack_delay` | 25 мс |
| 0x0c | `disable_active_migration` | не ставим |
| 0x0d | `preferred_address` | не ставим |
| 0x0e | `active_connection_id_limit` | 4 (минимум по RFC — 2) |
| 0x0f | `initial_source_connection_id` | **обязателен**: SCID наших пакетов |
| 0x10 | `retry_source_connection_id` | обязателен, **если** отправляли Retry |
| 0x11 | `version_information` (RFC 9368) | опционально, фаза 9 |
| 0x20 | `max_datagram_frame_size` (RFC 9221) | не ставим |

```c
size_t quictp_encode(uint8_t* dst, size_t cap, const quictp_t* tp);
int    quictp_decode(const uint8_t* src, size_t len, quictp_t* out); /* 0 = TRANSPORT_PARAMETER_ERROR */
```

Проверки на приёме (каждая — `TRANSPORT_PARAMETER_ERROR`):

- дубликат любого параметра;
- `max_udp_payload_size` < 1200;
- `ack_delay_exponent` > 20;
- `max_ack_delay` ≥ 2^14;
- `active_connection_id_limit` < 2;
- `initial_max_streams_*` > 2^60;
- клиент прислал `original_destination_connection_id`, `preferred_address`,
  `retry_source_connection_id` или `stateless_reset_token` — эти только у сервера;
- `initial_source_connection_id` клиента не совпадает с SCID его Initial-пакета
  (§7.3) — обязательная антиспуфинг-проверка, её часто забывают;
- **GREASE**: параметры вида `31 * N + 27` обязаны игнорироваться. Проверяем, что
  игнорируем, и сами один такой отправляем.

---

## 6. `quicerror.h`

```c
#define QUIC_NO_ERROR                 0x00
#define QUIC_INTERNAL_ERROR           0x01
#define QUIC_CONNECTION_REFUSED       0x02
#define QUIC_FLOW_CONTROL_ERROR       0x03
#define QUIC_STREAM_LIMIT_ERROR       0x04
#define QUIC_STREAM_STATE_ERROR       0x05
#define QUIC_FINAL_SIZE_ERROR         0x06
#define QUIC_FRAME_ENCODING_ERROR     0x07
#define QUIC_TRANSPORT_PARAMETER_ERROR 0x08
#define QUIC_CONNECTION_ID_LIMIT_ERROR 0x09
#define QUIC_PROTOCOL_VIOLATION       0x0a
#define QUIC_INVALID_TOKEN            0x0b
#define QUIC_APPLICATION_ERROR        0x0c
#define QUIC_CRYPTO_BUFFER_EXCEEDED   0x0d
#define QUIC_KEY_UPDATE_ERROR         0x0e
#define QUIC_AEAD_LIMIT_REACHED       0x0f
#define QUIC_NO_VIABLE_PATH           0x10
#define QUIC_CRYPTO_ERROR(alert)      (0x0100 | (alert))
```

Как и в `h2frame.h`, коды разделяются осмысленно: реализатор клиента читает код,
чтобы найти свою ошибку. Тот же принцип, что применён в `docs/http2/08` фаза C.

---

## 6a. Что из этой фазы перенесено

**Управление Connection ID (§3) — в фазу 4.** Генерация, последовательности,
`NEW_CONNECTION_ID`/`RETIRE_CONNECTION_ID`, отложенный retire через 3×PTO — это
состояние соединения, а не кодек: списки живут в `quicconn_t`, которого до фазы 4
нет. Кодек самого фрейма `NEW_CONNECTION_ID` сделан здесь, вместе с остальными.
Тип `quiccid_t` и таблица маршрутизации уже есть с фазы 1.

## 7. Юнит-тесты фазы

**Статус: сделано.** +216 проверок (100 309 → 100 525), ASan чист, сборка без
флага не изменилась (100 156).

Две ошибки, которые поймали сами тесты:

- **`quicpkt_pn_length` ошибался на степенях двойки.** Формула §A.2 записана как
  `ceil((log2(unacked) + 1) / 8)` над вещественными числами; при переводе в
  целочисленную арифметику «в лоб» она даёт на байт больше ровно на границах
  (128 неподтверждённых пакетов требуют одного байта, 129 — двух). Заменено на
  точную эквивалентную формулировку: наименьшая ширина `b`, при которой
  `unacked <= 2^(8b-1)`.
- **`quicpkt_decode_pn` переполнялся снизу.** Псевдокод §A.3 написан для
  чисел произвольной точности, где `expected_pn - pn_hwin` и
  `candidate_pn - pn_win` не могут уйти ниже нуля. В `uint64_t` могут — в начале
  соединения и для маленьких кандидатов. Условия переписаны так, чтобы
  вычитания не происходило.

`tests/unit/test_quic_varint.c`, `test_quic_packet.c`, `test_quic_frame.c`,
`test_quic_tp.c`, `test_quic_cid.c`:

1. varint: все граничные значения, не-минимальные кодировки, round-trip.
2. Заголовки: разбор захардкоженного Initial из RFC 9001 §A.1 (там есть готовый
   байтовый пример клиентского Initial), Retry из §A.4, Version Negotiation.
3. Восстановление номера пакета: таблица из RFC 9000 §A.3.
4. Все фреймы: round-trip encode→decode; ACK с 0, 1 и 5 диапазонами; STREAM во
   всех восьми вариантах битов; CONNECTION_CLOSE с reason и без.
5. Транспорт-параметры: полный набор, GREASE, каждая из проверок §5.
6. Фаззинг (`08-testing.md` §5): `quicframe_next` и `quicpkt_parse_header` на
   случайных байтах — не должны падать и не должны выходить за буфер.

**Готово, когда:** все векторы RFC сходятся, ASan чист, покрытие ветвей кодеков
> 90 %.
