# Фаза 6. QPACK

RFC 9204. Сжатие полей для HTTP/3. Сложнее HPACK не по объёму кода, а
концептуально: HPACK опирался на то, что все блоки заголовков приходят в едином
порядке по одному TCP-потоку. В QUIC потоки доставляются независимо, поэтому
ссылка на динамическую таблицу может прийти **раньше**, чем инструкция,
создавшая запись. QPACK решает это ценой отдельного протокола синхронизации.

---

## 1. Что переиспользуется из HPACK

| Компонент | Статус |
|---|---|
| Код Хаффмана (RFC 7541 Приложение B) | **Идентичен.** RFC 9204 §5 прямо ссылается на HPACK |
| Целое с префиксом N бит (`prefix integer`) | **Идентично** |
| Литеральные строки с флагом Хаффмана | Идентичны по кодированию |
| Статическая таблица | **Другая**: 99 записей вместо 61, другой порядок |
| Динамическая таблица | Другая индексация (абсолютная/относительная/post-base), другая эвикция |
| Представления | Другие опкоды |

**Рефакторинг перед фазой:** из `hpack.c` выносится в `misc/huffman.{c,h}`:

```c
size_t huffman_encoded_len(const uint8_t* src, size_t len);
size_t huffman_encode(uint8_t* dst, size_t cap, const uint8_t* src, size_t len);
/* Возвращает длину или -1 при ошибке (EOS в потоке, неверный паддинг). */
ssize_t huffman_decode(uint8_t* dst, size_t cap, const uint8_t* src, size_t len);
size_t  prefix_int_encode(uint8_t* dst, size_t cap, uint64_t v, uint8_t prefix_bits,
                          uint8_t flags);
size_t  prefix_int_decode(const uint8_t* src, size_t len, uint8_t prefix_bits,
                          uint64_t* out);
```

`hpack.c` начинает вызывать их вместо своих статических копий; поведение не
меняется, тесты `test_hpack.c` остаются зелёными — это и есть проверка
рефакторинга.

`gen_tables.py` расширяется целью `qpack_statictable.h` (99 записей из RFC 9204
Приложение A), генерируемой тем же способом, что `hpack_statictable.h`, включая
хеш-индекс «имя → первый индекс» и «имя+значение → индекс».

---

## 2. Три потока

```
поток запроса   : Encoded Field Section  (блоки заголовков)
encoder stream  : клиент → сервер, инструкции вставки в НАШУ таблицу декодера
decoder stream  : сервер → клиент, подтверждения
```

И зеркально для нашей стороны: мы отправляем инструкции по своему encoder-потоку,
клиент подтверждает по своему decoder-потоку.

**Правило, которое всё определяет:** блок заголовков может ссылаться только на
записи, о которых декодер уже узнал. Если ссылка «из будущего» — поток
блокируется до прихода нужной инструкции. Число одновременно блокированных
потоков ограничено `SETTINGS_QPACK_BLOCKED_STREAMS`.

---

## 3. Динамическая таблица

```c
typedef struct qpack_dtable {
    qpack_entry_t* entries;      /* кольцевой буфер */
    size_t   count, cap;
    uint64_t insert_count;       /* абсолютный номер следующей вставки */
    uint64_t dropped_count;      /* сколько вытеснено (нижняя граница индексов) */
    size_t   size, capacity;     /* размер записи = name+value+32 */
    uint64_t known_received;     /* декодер пира подтвердил вставки до этого */
    /* число «активных» ссылок на запись — нельзя вытеснять запись,
     * на которую ссылается неподтверждённый блок */
    uint32_t* refcount;
} qpack_dtable_t;
```

Три системы индексации, каждую надо реализовать и протестировать отдельно:

- **абсолютный индекс** — порядковый номер вставки, монотонный;
- **относительный индекс** — от `Base` блока, назад (`abs = base − 1 − rel`);
- **post-base индекс** — вперёд от `Base` (`abs = base + rel`), нужен, когда блок
  ссылается на записи, вставленные во время его же кодирования;
- на encoder-потоке относительный индекс считается **от `insert_count`**, а не
  от Base, — отдельная ловушка.

**Required Insert Count** и **Base** кодируются в префиксе блока:

```
Required Insert Count (8-bit prefix, закодирован по модулю MaxEntries)
S | Delta Base (7-bit prefix)
```

Кодирование RIC по модулю (§4.5.1.1) — обязательный алгоритм; ошибка здесь даёт
редкие, невоспроизводимые падения. Тестируется отдельно на всех примерах §4.5.1.

## 4. Представления

**В блоке заголовков** (`Encoded Field Section`):

| Опкод | Представление |
|---|---|
| `1Tiiiiii` | Indexed Field Line (T: 1 — статическая, 0 — динамическая) |
| `0001iiii` | Indexed Field Line With Post-Base Index |
| `01NTiiii` | Literal With Name Reference (N — never-indexed) |
| `0000Niii` | Literal With Post-Base Name Reference |
| `001Nhiii` | Literal With Literal Name |

**На encoder-потоке:**

| Опкод | Инструкция |
|---|---|
| `1Tiiiiii` | Insert With Name Reference |
| `01Hiiiii` | Insert With Literal Name |
| `001iiiii` | Set Dynamic Table Capacity |
| `000iiiii` | Duplicate |

**На decoder-потоке:**

| Опкод | Инструкция |
|---|---|
| `1iiiiiii` | Section Acknowledgment |
| `01iiiiii` | Stream Cancellation |
| `00iiiiii` | Insert Count Increment |

Каждая инструкция decoder-потока обязана отправляться в строго определённый
момент, иначе кодировщик пира навсегда останется без подтверждений и перестанет
использовать таблицу:

- **Section Acknowledgment** — после полной обработки блока с `RIC > 0`;
- **Stream Cancellation** — когда поток сброшен/отменён, а его блок ещё не
  обработан;
- **Insert Count Increment** — когда декодер обработал вставки, но
  соответствующего блока не было (иначе `known_received` пира не растёт).

## 5. API

```c
/* ---- Декодер: их таблица, наш приём ---- */
qpack_decoder_t* qpack_decoder_create(size_t max_capacity, size_t max_blocked);
void qpack_decoder_free(qpack_decoder_t*);

/* Инструкции с encoder-потока пира. */
qpack_status_e qpack_decoder_read_encoder(qpack_decoder_t*, const uint8_t*, size_t);

typedef enum {
    QPACK_OK, QPACK_BLOCKED,       /* нужны ещё инструкции — поток ждёт */
    QPACK_ERR_DECOMPRESSION,       /* -> QPACK_DECOMPRESSION_FAILED (соединение) */
    QPACK_ERR_ENCODER_STREAM, QPACK_ERR_DECODER_STREAM,
    QPACK_ERR_MEMORY, QPACK_ERR_TOO_LARGE
} qpack_status_e;

/* Декодировать блок. При QPACK_BLOCKED вызывающий обязан сохранить блок и
 * повторить после следующего qpack_decoder_read_encoder(). */
qpack_status_e qpack_decode_block(qpack_decoder_t*, uint64_t stream_id,
                                  const uint8_t* block, size_t len,
                                  size_t max_list_size,
                                  http_header_t** out, size_t* out_count);

/* Байты, которые нужно отправить по нашему decoder-потоку. */
size_t qpack_decoder_pending(qpack_decoder_t*, const uint8_t** out);
void   qpack_decoder_consume(qpack_decoder_t*, size_t n);
void   qpack_decoder_stream_cancelled(qpack_decoder_t*, uint64_t stream_id);

/* ---- Кодировщик: наша таблица ---- */
qpack_encoder_t* qpack_encoder_create(size_t max_capacity, size_t max_blocked);
size_t qpack_encode_block(qpack_encoder_t*, uint64_t stream_id,
                          const http_header_t* fields, size_t count,
                          uint8_t* dst, size_t cap);
qpack_status_e qpack_encoder_read_decoder(qpack_encoder_t*, const uint8_t*, size_t);
size_t qpack_encoder_pending(qpack_encoder_t*, const uint8_t** out);
```

Форма API намеренно повторяет `hpack.h` — это упрощает и ревью, и порт
`h2_write_filter` → `h3_write_filter`.

## 6. Стратегия внедрения: сначала QPACK-lite

Полный QPACK с динамической таблицей — это ~1200 строк и половина всех багов
фазы. Поэтому внедряем в два шага, и **первый шаг полностью работоспособен**:

**Шаг 6.1 — QPACK-lite (обязательный минимум по RFC).**

- Наш декодер: объявляем `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` и
  `QPACK_BLOCKED_STREAMS = 0`. Клиент не имеет права вставлять записи, encoder-
  поток от него будет пустым (но открыть его он может и, вероятно, откроет —
  читать обязаны). Блоки ссылаются только на статическую таблицу и литералы.
  `Required Insert Count` всегда 0 — блокировок не бывает.
- Наш кодировщик: не вставляем ничего, используем статическую таблицу и
  литералы (с Хаффманом). Свой encoder-поток открываем и оставляем пустым.
- Соответствие RFC полное: динамическая таблица опциональна с обеих сторон.
- Потеря сжатия относительно h2 — порядка 10–20 % на типичных заголовках. Для
  запуска приемлемо.

**Шаг 6.2 — полная динамическая таблица.**

- Поднимаем `QPACK_MAX_TABLE_CAPACITY` до 4096 и `QPACK_BLOCKED_STREAMS` до 16;
- реализуем все три системы индексации, refcount на записи, encoder/decoder-
  инструкции, обработку блокированных потоков;
- политика кодировщика: вставлять поле в таблицу, если оно встречалось ранее и
  его размер < 1/8 таблицы; никогда не вставлять поля из списка чувствительных
  (`authorization`, `cookie`, `set-cookie` — тот же принцип «never indexed», что
  реализован для HPACK в `h2_write_filter`), никогда не создавать ссылку,
  которая заблокировала бы поток, если блокированных уже `max_blocked`.

Между шагами проходит фаза 7 — то есть работающий h3-сервер появляется раньше,
чем полный QPACK.

## 7. Обязательные проверки (каждая — ошибка соединения)

| Ситуация | Код |
|---|---|
| Ссылка на индекс за пределами таблицы | `QPACK_DECOMPRESSION_FAILED` |
| `Required Insert Count` больше, чем возможно | `QPACK_DECOMPRESSION_FAILED` |
| Ссылка на вытесненную запись | `QPACK_DECOMPRESSION_FAILED` |
| Блокированных потоков больше объявленного лимита | `QPACK_DECOMPRESSION_FAILED` |
| Ошибка Хаффмана (EOS в потоке, паддинг ≠ единицы, паддинг > 7 бит) | `QPACK_DECOMPRESSION_FAILED` |
| `Set Dynamic Table Capacity` больше объявленного максимума | `QPACK_ENCODER_STREAM_ERROR` |
| Вставка, не влезающая в таблицу даже после эвикции | `QPACK_ENCODER_STREAM_ERROR` |
| Эвикция записи с ненулевым refcount | `QPACK_ENCODER_STREAM_ERROR` |
| `Insert Count Increment` на 0 или сверх известного | `QPACK_DECODER_STREAM_ERROR` |
| Подтверждение для потока без ожидающего блока | `QPACK_DECODER_STREAM_ERROR` |

Плюс общий предел на размер декодированного списка (`MAX_FIELD_SECTION_SIZE`) —
как в HPACK, чтобы «бомба сжатия» не съела память; превышение → 431 на потоке,
по образцу `docs/http2/08` фаза A.4.

## 8. Тесты

`test_qpack_static.c` — поиск по статической таблице, все 99 записей.
`test_qpack_prefix.c` — целые с префиксом, кодирование RIC по модулю (§4.5.1.1),
все примеры RFC.
`test_qpack_dtable.c` — вставка, эвикция, refcount, Duplicate, изменение
capacity.
`test_qpack_decode.c` — **векторы RFC 9204 Приложение B** целиком: B.1 (только
литералы), B.2 (динамическая таблица), B.3 (Duplicate), B.4 (эвикция),
B.5 (блокировка потока). Это единственный полный набор векторов, он покрывает
все три системы индексации.
`test_qpack_roundtrip.c` — кодировщик → декодер на случайных наборах полей,
включая длинные значения, UTF-8, повторяющиеся имена, `cookie`-разбиение.
`test_qpack_blocked.c` — сценарий: блок приходит раньше инструкций; приходит
после; поток отменён в блокированном состоянии; превышение лимита блокированных.

**Готово, когда (6.1):** Chrome и Firefox открывают сайт по h3.
**Chrome — да** (2026-08-08): страница отдана по HTTP/3, 303 КБ по QUIC.
QPACK-lite оказался достаточен, как и предполагалось: браузер согласовал
`SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` и работает только по статической
таблице и литералам. Firefox не проверялся.
**Готово, когда (6.2):** векторы Приложения B сходятся; interop-тест `qpack`
зелёный; сжатие не хуже h2 на наборе типичных заголовков (сравнительный
бенчмарк в тестах).

---

## 9. Ход работ

**Сделано (рефакторинг перед фазой, §1):** код Хаффмана и целое с префиксом N
бит вынесены из `hpack.c` в общий `misc/huffman.{c,h}`; таблица Хаффмана
переехала в `misc/huffman_table.h` (переименована `hpack_huff_*` → `huff_*`,
`HPACK_HUFF_*` → `HUFF_*`; значения побайтово те же — проверено обратным
переименование и diff против исходного `hpack_huffman.h`). `gen_tables.py`
обновлён под новые имена и путь `misc/huffman_table.h`.

API (нейтральное, как в §1): `huffman_encoded_len`, `huffman_encode`/`huffman_decode`
(оба `ssize_t`, -1 — ошибка; `encode` в доке был `size_t`, но `ssize_t` неотличимо
отличает пустой вход от переполнения), `prefix_int_encode`/`prefix_int_decode`
(`uint64_t`, продолжение ограничено 9 байтами ≈ 2^63 — без bounded work peer не
может раскрутить декодер). `hpack.c` делегирует: `hpack_huffman_*`,
`hpack_encode_int`, `hpack_decode_int` и внутренний `bb_encode_int` стали тонкими
обёртками; мёртвый после рефакторинга `bb_putc` удалён. Поведение h2 не изменилось
— `test_hpack.c` зелёный (это и есть проверка), +33 проверки в новом
`test_huffman.c` (roundtrip всех 256 байтов, padding, EOS, примеры §C.1.1/§C.1.2,
флаги, усечение, бесконечное продолжение). Сборка с h3 и без — ASan-чисто.

**Сделано (6.1 — статическая таблица):** `protocols/http3/qpack/qpack_statictable.h`
— 99 записей RFC 9204 Приложение A, **0-индексация** (в отличие от HPACK:
индекс 0 = `:authority`, не пустышка). Отдельный генератор
`gen_qpack_static.py` (не расширение `gen_tables.py` — тот парсит RFC 7541, а
эта таблица из RFC 9204; исходник иной, скрипт отдельный, генерирует один
артефакт). Хеш-индексы (имя→индекс, имя+значение→индекс) НЕ добавлены — HPACK
линейно сканирует 61 запись, QPACK-lite так же линейно сканирует 99; для full-
кодировщика (6.2) можно добавить при необходимости. Записи проверены на краях
(0=`:authority`, 17=`:method`/GET, 23=`:scheme`/https, 98=`x-frame-options`/
sameorigin).

**Сделано (6.1 — lite-декодер):** `qpack.{h,c}` разбирает Field Section
(префикс RIC 8-бит + S|Delta Base 7-бит; в lite RIC обязан быть 0, Delta Base
не используется) и представления: Indexed Static (`1T`), Literal With Name
Reference статический (`01NT`), Literal With Literal Name (`001Nh` — имя и
значение через общий `misc/huffman`, Хаффман для обоих). Все динамические/ post-
base представления → `QPACK_ERR_DECOMPRESSION` (таблицы нет). `never_indexed`
пробрасывается. `max_list_size` → `QPACK_ERR_TOO_LARGE` (как в HPACK/`docs/
http2/08` A.4). Вывод — `qpack_header_t` (зеркало `hpack_header_t`), malloc-
массив, освобождается `qpack_headers_free`. API сознательно урезан до lite
(`decode_block`/`create`/`free`/`headers_free`); `read_encoder`, `pending`,
`stream_id` придут с full-декодером 6.2. +34 проверки в `test_qpack_decode.c`
(вектор RFC 9204 §B.1, indexed/literal/Huffman-имя/Huffman-значение, never-
indexed, пустой блок, 5 ошибочных случаев). h3-сборка: 101 147 проверок ASan-
чисто.

**Сделано (6.1 — lite-кодировщик):** `qpack_encode_block` собирает Field Section
для ответа: префикс всегда `00 00` (RIC=0, Delta Base=0), для каждого поля —
Indexed Static на точном совпадении, иначе Literal With Name Reference ( статическое
имя), иначе Literal With Literal Name; Хаффман для имени/значения только если он
короче; `never_indexed` → литерал с N=1 (никогда не indexed, как в HPACK). Пишет в
буфер вызывающего, возвращает байты (0 = не влезло/OOM; даже пустой блок = 2 байта,
так что 0 однозначно). `qpack_encoder_{create,free}`. +9 проверок в
`test_qpack_encode.c` (точные байты для indexed `:method`/`:path`/`:scheme`,
round-trip смешанного блока с Хаффманом, never-indexed не даёт indexed, пустой =
префикс, cap-переполнение). Ловушка, найденная тестом: длина имени в literal-
literal-name по проводу — **хаффмановская**, а не сырая (`hlen` при H=1), иначе
декодер читает не те байты — у значения (`enc_value`) это было правильно, у имени
появилось и исправлено. h3: 101 156 проверок ASan-чисто; без h3 — 100 189 (qpack
под гейтом).

**Static-only QPACK (6.1) готов целиком:** декодер и кодировщик разбирают и собирают
Field Section только по статической таблице и литералам, соответствие RFC полное
(динамическая таблица опциональна с обеих сторон).

**Сделано (6.1 — encoder-поток пира):** `qpack_decoder_read_encoder()` — с
объявленной ёмкостью 0 у пира остаётся ровно одна легальная инструкция,
`Set Dynamic Table Capacity 0`, и её клиенты действительно шлют первой. Поэтому
«отвергать любой байт на encoder-потоке» — неверная стратегия, хотя и выглядит
безопасной; отвергается всё остальное (Insert With Name Reference, Insert With
Literal Name, Duplicate, любая ёмкость выше объявленной) →
`QPACK_ENCODER_STREAM_ERROR`. Ловушка резюмируемости решена без буфера: если
5-битный префикс равен 0x1f (значение ≥ 31) и 31 уже превышает объявленное,
вердикт известен по первому октету, так что в lite недочитанных инструкций не
бывает вовсе; `consumed` в API оставлен для 6.2.

**Исправлено в декодере:**

- **чтение за границей массива** на пути ошибки: при неудачном `realloc`
  `count == cap`, и `headers[count]` — элемент за концом. Достижимо только на
  OOM, но это UB; появился флаг `partial`, который отмечает слот как зануленный
  и потому безопасный для `free`;
- **префикс блока проверяется, а не игнорируется.** §4.5.1.2: `Base =
  RIC + DeltaBase` при S=0 и `RIC − DeltaBase − 1` при S=1. С `RIC = 0` знак S=1
  уводит Base в минус, а любой `DeltaBase > 0` называет запись несуществующей
  таблицы — оба случая malformed, а не «просто неиспользуемые», и теперь дают
  `QPACK_DECOMPRESSION_FAILED`.

**Осталось:** подключить QPACK к `h3_write_filter` (HEADERS-кадр h3
несёт Field Section; статус `:status` и поля ответа идут через кодировщик, вход —
через декодер и будущий общий `httpfields_to_request()`) — после этого
`curl --http3` получит первый ответ. Full QPACK (6.2 — динамическая таблица,
encoder/decoder-потоки, blocked streams) откладывается до работающего h3.

## 6.2. Full QPACK — текущая реализация

### 6.2a. Decoder dynamic table

Начат full QPACK без преждевременного изменения SETTINGS production-сервера.
Decoder теперь содержит динамическую таблицу с текущей и максимальной ёмкостью,
точным учётом `name + value + 32`, монотонным absolute insert count и eviction
самых старых записей. Encoder stream разбирает все четыре инструкции RFC 9204
§4.3: Set Dynamic Table Capacity, Insert With Name Reference (static/dynamic),
Insert With Literal Name и Duplicate. Разбор остаётся resumable: неполная
инструкция не потребляется и повторно подаётся после следующего чтения stream.

Field Section decoder раскодирует modulo Required Insert Count, Base, relative
и post-base ссылки на динамические записи. Ссылка на ещё не полученный insert
возвращает отдельный `QPACK_BLOCKED`, а не ошибочно закрывает соединение.
Static-only режим не изменён: при `max_capacity=0` любая table-mutating
инструкция по-прежнему немедленно даёт `QPACK_ENCODER_STREAM_ERROR`.

Добавлены unit-сценарии capacity, insert, relative static/dynamic name,
Duplicate, eviction, split instruction, relative/post-base Field Line и future
Required Insert Count. H3 runner под ASan: 1949/1949.

Этот этап намеренно ещё не включает non-zero SETTINGS: сначала нужны хранение и
повторный запуск заблокированных field sections, лимит blocked streams,
Section Acknowledgment/Stream Cancellation, а также encoder-side dynamic table.
До завершения этих частей сервер продолжает рекламировать capacity=0 и остаётся
совместимым с прежним static-only поведением.

### 6.2b. Исходящий decoder stream и границы QUIC reads

Decoder формирует собственный поток инструкций RFC 9204 §4.4. Каждая успешная
вставка ставит в очередь Insert Count Increment; доступны Section
Acknowledgment и Stream Cancellation. Очередь допускает частичную отправку
(`pending`/`consume`) и дренируется `h3conn_write()` на открытый критический
QPACK decoder stream до response data. Повторный write-turn не дублирует уже
переданные инструкции.

Исправлена необходимая для full QPACK граница потокового разбора. В lite любая
легальная encoder-инструкция помещалась в один read, поэтому `consumed < len`
можно было оставить теоретическим контрактом. Dynamic Insert содержит две
строки и закономерно режется между QUIC STREAM frames. Теперь `h3uni_recv_t`
хранит непотреблённый суффикс обоих QPACK service streams, дополняет его на
следующем read и ограничивает накопление одним MiB. Превышение этого предела
закрывает соединение с `H3_EXCESSIVE_LOAD`, OOM — с `H3_INTERNAL_ERROR`.

Unit-тест фиксирует реальный split внутри literal name: после первой половины
insert count остаётся нулевым, после второй появляется ровно одна запись и
staging buffer пуст. Дополнительно проверены точные wire bytes decoder
instructions и их частичное consume. H3 runner под ASan: 1966/1966.

Connection glue считает blocked request streams ровно один раз на stream.
Достижение `max_blocked` превращает следующий блок в
`QPACK_DECOMPRESSION_FAILED`. Успешный retry освобождает слот и ставит Section
Acknowledgment; RESET_STREAM либо ошибка повторного decode освобождает слот,
очищает deferred bytes и ставит Stream Cancellation.

### 6.2d. Привязка исходящих field sections к request stream

Реальный response path теперь передаёт QPACK encoder идентификатор QUIC-потока
для всех трёх видов field section: informational response, финальных заголовков
и trailers. Если encoder использует динамическую запись, секция атомарно
регистрируется как outstanding вместе с её Required Insert Count. Полученный от
клиента Section Acknowledgment освобождает одну секцию, Stream Cancellation —
все секции данного потока. Это защищает ещё используемые записи от eviction и
позволяет корректно иметь несколько секций на одном request stream.

Старые функции кодирования сохранены как совместимые обёртки и не регистрируют
stream-specific состояние. Production SETTINGS пока остаются нулевыми, поэтому
этот путь не меняет wire format действующих ответов до отдельного включения
capacity/blocked streams и политики наполнения encoder table.

### 6.2e. SETTINGS клиента и лимиты исходящего encoder

После получения SETTINGS сервер применяет объявленные клиентом
`QPACK_MAX_TABLE_CAPACITY` и `QPACK_BLOCKED_STREAMS` к исходящему encoder. Это
именно верхние границы клиента: локальная политика дополнительно ограничивает
их значениями 4096 байт и 16 blocked sections. При ненулевой согласованной
ёмкости `Set Dynamic Table Capacity` ставится в очередь encoder stream.

Лимиты принимаются только у pristine encoder и становятся неизменяемыми после
первой инструкции, вставки или field section. Наши входящие SETTINGS пока
остаются `0/0`: клиент всё ещё не может создавать динамические записи в decoder
server-side, пока их память не включена в общий HTTP/3 memory budget.

Encoder отдельно соблюдает `QPACK_BLOCKED_STREAMS`: считаются уникальные request
streams с Required Insert Count выше уже подтверждённого клиентом insert count.
Если новая секция превысила бы лимит, она кодируется static/literal без
динамической ссылки. Несколько outstanding sections одного уже блокированного
stream не расходуют дополнительные слоты; после acknowledgment слот снова
доступен.

### 6.2c. Инвариант blocked request stream

Перед подключением `QPACK_BLOCKED` к `h3stream` зафиксирован важный lifetime:
`quicstream_read()` удаляет из receive buffer весь выданный chunk, тогда как
HEADERS может закончиться в середине этого chunk и за ним уже находиться DATA.
Поэтому недостаточно сохранить только Field Section из `h3frame_parser` — при
остановке на blocked HEADERS потеряется хвост уже прочитанного chunk. Реализация
blocked-stream обязана владеть одновременно копией Field Section, всеми байтами
после неё и флагом FIN; после insert сначала повторяется QPACK decode, затем тот
же сохранённый хвост снова проходит обычную frame state machine. Этот буфер
входит в HTTP/3 memory budget и освобождается при decode, RESET_STREAM и
закрытии соединения.
