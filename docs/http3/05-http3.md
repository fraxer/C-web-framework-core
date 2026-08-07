# Фаза 5. Слой HTTP/3

RFC 9114. Здесь HTTP/3 подключается к уже существующему верхнему слою сервера —
роутингу, middleware, хендлерам и цепочке фильтров. По объёму эта фаза
существенно меньше транспорта: мультиплексирование, приоритеты и flow control
уже сделал QUIC.

---

## 1. Что делает h3 и чего не делает

| Задача | В h2 | В h3 |
|---|---|---|
| Мультиплексирование | кадры со stream id | потоки QUIC |
| Flow control | WINDOW_UPDATE | транспорт |
| Порядок доставки | внутри соединения | внутри потока (между потоками — нет!) |
| Отмена запроса | RST_STREAM | STOP_SENDING + RESET_STREAM |
| Сжатие заголовков | HPACK | QPACK (`06`) |
| Кадры | 10 типов, 9-байтный заголовок | 7 типов, varint |

Главное следствие для реализации: **служебные потоки h3 и потоки запросов
доставляются независимо**. SETTINGS может прийти позже первого запроса; QPACK-
инструкции — раньше или позже блока заголовков, который их требует. Отсюда
вся сложность QPACK и требование «не блокировать соединение в ожидании SETTINGS».

---

## 2. `h3frame.{c,h}`

Кадр: `Type (varint) | Length (varint) | Payload`.

| Тип | Имя | Где допустим |
|---|---|---|
| 0x00 | DATA | поток запроса, после HEADERS |
| 0x01 | HEADERS | поток запроса |
| 0x03 | CANCEL_PUSH | control |
| 0x04 | SETTINGS | control, **первым и ровно один раз** |
| 0x05 | PUSH_PROMISE | поток запроса (мы не отправляем) |
| 0x07 | GOAWAY | control |
| 0x0d | MAX_PUSH_ID | control |
| `0x1f*N+0x21` | GREASE | игнорировать везде |

```c
typedef enum {
    H3FRAME_CONTINUE,     /* нужно больше байт */
    H3FRAME_HEAD_READY,   /* известны тип и длина; payload идёт потоком */
    H3FRAME_READY,        /* кадр собран целиком (для мелких кадров) */
    H3FRAME_ERR_ENCODING, /* H3_FRAME_ERROR */
    H3FRAME_ERR_TOO_LARGE
} h3frame_status_e;
```

**Резюмируемость.** Как и у `h2frame_parser_t`, парсер держит состояние между
вызовами: поток QUIC доставляет байты произвольными кусками. Но, в отличие от h2,
у DATA-кадра **нет верхнего предела длины**, поэтому его payload нельзя
буферизовать целиком — парсер отдаёт `HEAD_READY` и дальше стримит тело в
существующий механизм приёма тела запроса (`httppayload.c`, включая выгрузку в
tmp-файл при превышении `client_max_body_size`).

**Ошибки, которые обязаны различаться:**

- неизвестный тип → **игнорировать** (в отличие от QUIC-фреймов!), прочитав
  Length байт;
- усечённый кадр в конце потока → `H3_FRAME_ERROR`;
- DATA до HEADERS → `H3_FRAME_UNEXPECTED`;
- SETTINGS не первым кадром control-потока → `H3_MISSING_SETTINGS`;
- второй SETTINGS → `H3_FRAME_UNEXPECTED`;
- SETTINGS/GOAWAY/MAX_PUSH_ID на потоке запроса → `H3_FRAME_UNEXPECTED`;
- HEADERS/DATA на control-потоке → `H3_FRAME_UNEXPECTED`;
- зарезервированные типы `0x02`, `0x06`, `0x08`, `0x09` (бывшие h2-кадры) →
  `H3_FRAME_UNEXPECTED`. Это отдельное требование §11.2.1, ловушка для тех, кто
  портирует h2.

---

## 3. Служебные потоки

Однонаправленный поток начинается с varint-типа:

| Тип | Поток |
|---|---|
| 0x00 | Control |
| 0x01 | Push |
| 0x02 | QPACK encoder |
| 0x03 | QPACK decoder |
| `0x1f*N+0x21` | GREASE — читать и выбрасывать |
| прочее | неизвестный — `STOP_SENDING(H3_STREAM_CREATION_ERROR)` и выбросить |

Правила:

- каждого типа — ровно один в каждую сторону; второй →
  `H3_STREAM_CREATION_ERROR`;
- закрытие control/QPACK-потока (FIN или RESET) →
  `H3_CLOSED_CRITICAL_STREAM`, это **фатально для соединения**;
- сервер обязан открыть свой control-поток и отправить SETTINGS **до** любого
  другого кадра. Практически: сразу после завершения рукопожатия открываем три
  uni-потока (control, QPACK encoder, QPACK decoder), пишем типы и SETTINGS;
- клиент может прислать данные QPACK-потоков раньше, чем мы прочитаем SETTINGS, —
  это нормально и должно работать.

Мы также отправляем **GREASE-поток** и **GREASE-настройку** — это дёшево и
защищает экосистему (и наши тесты) от «зашитых» списков.

## 4. SETTINGS

| ID | Имя | Наше значение |
|---|---|---|
| 0x01 | `QPACK_MAX_TABLE_CAPACITY` | 0 в первой итерации, 4096 после `06` §7 |
| 0x06 | `MAX_FIELD_SECTION_SIZE` | как `http2_max_header_list_size` |
| 0x07 | `QPACK_BLOCKED_STREAMS` | 0, затем 16 |
| 0x08 | `ENABLE_CONNECT_PROTOCOL` | 1, если у vhost есть секция `websockets` |
| 0x33 | `H3_DATAGRAM` | не отправляем |

Проверки: дубликат идентификатора → `H3_SETTINGS_ERROR`; идентификаторы
`0x02/0x03/0x04/0x05` (бывшие h2) → `H3_SETTINGS_ERROR`; незнакомые —
игнорировать.

Как и в h2, `MAX_FIELD_SECTION_SIZE` пира — рекомендация: превышение логируем,
но ответ не режем (то же решение, что закреплено в `h2session.h`).

## 5. `h3session.{c,h}` и `h3stream.{c,h}`

Структура — прямой аналог `h2session_t`, с тем же контрактом «первым полем идёт
`void (*free)(void*)`, потому что лежит в `ctx->parser`».

```c
typedef struct h3session {
    void (*free)(void*);
    connection_t*  connection;
    quicconn_t*    qc;

    /* служебные потоки */
    uint64_t       ctrl_send_id, ctrl_recv_id;
    uint64_t       qpack_enc_send_id, qpack_enc_recv_id;
    uint64_t       qpack_dec_send_id, qpack_dec_recv_id;
    int            peer_settings_seen;

    qpack_decoder_t* qdec;
    qpack_encoder_t* qenc;

    /* настройки пира */
    uint64_t       peer_max_field_section_size;
    uint64_t       peer_qpack_max_table_capacity;
    uint64_t       peer_qpack_blocked_streams;
    int            peer_enable_connect_protocol;

    /* публикация ответов из хендлерных потоков — как в h2 */
    cqueue_t*      publish_queue;

    /* жизненный цикл */
    uint64_t       goaway_id;      /* отправленный GOAWAY */
    int            goaway_sent;
    int            peer_goaway;
    uint64_t       last_activity_us;

    /* бюджеты злоупотреблений — по образцу docs/http2/08 фаза A */
    int64_t        abort_tokens;  uint64_t abort_epoch_us;
    int64_t        ctrl_tokens;   uint64_t ctrl_epoch_us;
} h3session_t;
```

`h3stream_t` (в `stream->app`):

```c
typedef struct h3stream {
    uint64_t          id;
    quicstream_t*     qs;
    h3frame_parser_t  parser;
    httprequest_t*    request;
    httpresponse_t*   response;
    int               headers_done, body_done, trailers_seen;
    int               blocked_on_qpack;   /* ждёт инструкций encoder-потока */
    uint64_t          required_insert_count;
    int               tunnel;             /* Extended CONNECT / WebSocket */
} h3stream_t;
```

## 6. Отображение запроса и ответа

### 6.1 Запрос

`HEADERS` (QPACK) → список полей → `httprequest_t`. Правила §4.1–§4.3 совпадают
с h2 почти дословно:

- обязательные псевдо-заголовки `:method`, `:scheme`, `:path`
  (кроме CONNECT), `:authority` вместо `Host`;
- псевдо-заголовки только в начале, дубликаты запрещены;
- запрещены `Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`,
  `Upgrade`; `TE` только со значением `trailers`;
- имена полей строчными; валидность символов — RFC 9114 §4.3, те же правила,
  что реализованы в `h2field.{c,h}` (модуль переиспользуется без изменений);
- любое нарушение → `H3_MESSAGE_ERROR` на **потоке**, а не на соединении.

**Рефакторинг:** функция `h2_build_request()` (~220 строк в `h2session.c`)
разбирается на две части — «получить список полей» (протокольно-зависимая) и
«собрать `httprequest_t` из списка полей» (общая). Вторая переезжает в
`protocols/http/httpfields.c` как

```c
typedef enum { HTTP_FIELDS_H2, HTTP_FIELDS_H3 } http_fields_proto_e;
http_fields_status_e httpfields_to_request(httprequest_t*, const http_header_t* fields,
                                           size_t count, http_fields_proto_e proto);
```

и вызывается из обоих. Это снимает риск, что правило исправят в одном протоколе
и забудут в другом (уже случалось: см. заметку о расхождении h1.1/h2 в
`docs/http2/08` фаза B).

Тело: `DATA`-кадры → существующий `httppayload`. Trailers: `HEADERS` после
`DATA` → те же правила, что в h2.

### 6.2 Диспетчеризация

Без изменений относительно h2:

```
h3_on_headers → httpfields_to_request → h3_dispatch
   → connection_queue_append_parallel(item)      /* тот же fan-out, что у h2 */
      → хендлерный поток → http_server_dispatch → пользовательский код
         → httpresponse_t заполнен
            → h3_server_response_ready()   /* publish_queue + quicendpoint_want_write */
```

`h3_server_response_ready()` — копия `h2_server_response_ready()`, где вместо
`epoll_ctl` вызывается `quicendpoint_want_write()`. Как и в h2, нужен «inline»-
вариант для ответов, которые воркер сформировал сам под уже взятым локом
(`__post_response` для 404/redirect/статики) — иначе дедлок на нерекурсивном
спинлоке. Это ровно та ловушка, что описана в `docs/concurrency/01` фаза B.1;
здесь она известна заранее.

### 6.3 Ответ

`h3_write_filter.c` — терминальная стадия цепочки, аналог `h2_write_filter.c`,
но проще:

- статус → `:status`, поля → QPACK → `HEADERS`-кадр;
- тело → `DATA`-кадры; **никакого учёта окон** — их держит транспорт, фильтр
  просто пишет в `quicsendbuf` и получает отказ, когда буфер полон
  (тогда `CWF_EVENT_AGAIN`, как сейчас);
- никакого разбиения по `max_frame_size` — длина кадра varint, ограничена лишь
  здравым смыслом (режем по 16 КБ, чтобы не держать гигантский непрерывный
  блок);
- FIN потока вместо `END_STREAM`;
- trailers — второй `HEADERS`-кадр перед FIN (портируется из
  `h2_write_filter_trailers`);
- 103 Early Hints — отдельный `HEADERS`-кадр без FIN (портируется из
  `h2_write_filter_early_hints`);
- 100 Continue — то же самое (портируется из `h2_write_filter_continue`).

Все предшествующие стадии (`range`, `not_modified`, `data`, `gzip`) —
без единого изменения.

### 6.4 Отмена

- Клиент прислал `STOP_SENDING` на потоке запроса → хендлер, если он ещё
  работает, доводится до конца, но ответ выбрасывается; поток закрывается
  `RESET_STREAM(H3_REQUEST_CANCELLED)`. Логика «поток живёт, пока не закончился
  хендлер» уже решена в h2 (`h2_server_stream_release`) — переносим.
- `RESET_STREAM` от клиента на неотвеченном потоке тратит `abort_tokens`
  (защита от Rapid Reset, `docs/http2/08` фаза A.2). QUIC делает эту атаку
  дешевле, чем в h2, — бюджет обязателен.

## 7. GOAWAY и завершение

`GOAWAY` в h3 несёт **stream id** (для сервера — id первого непринятого
клиентского bidi-потока), а не «последний обработанный», как в h2.

- Мягкая остановка (`shutdown`/reload): GOAWAY с текущим верхним id →
  дождаться завершения открытых потоков → `CONNECTION_CLOSE(H3_NO_ERROR)`.
- Повторный GOAWAY допустим только с **меньшим или равным** id;
  больший → `H3_ID_ERROR`.
- Клиентский GOAWAY: клиент сообщает, что не будет принимать server push;
  фиксируем и продолжаем.

Двухфазная остановка (как в h2: GOAWAY(последний id 2^31−1), пауза RTT, затем
настоящий) в h3 менее актуальна, но реализуется тем же кодом.

## 8. Extended CONNECT — WebSocket поверх HTTP/3 (RFC 9220)

RFC 9220 — это RFC 8441, перенесённый на h3, и почти всё уже сделано в `h2ws.c`
(`docs/http2/09`). Отличия:

- сигнал — `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08) в h3-SETTINGS;
- туннель — обычный bidi-поток QUIC; кадры `DATA` несут байты WebSocket;
- **нет `h2data.c`-подобной проблемы порядка**: поток QUIC уже упорядочен;
- `permessage-deflate` остаётся сериализованным на соединение, как в h2;
- признак `server_websockets_t.configured` (введён в фазе 09 для h2) используется
  без изменений: vhost без секции `websockets` отвечает 501.

Модуль `h3ws.{c,h}` — прямой порт `h2ws.c` с заменой кадрирования. Оценка: ~250
строк вместо 355, потому что упорядочивание отдаёт транспорт.

**Ловушка, известная из h2:** `ctx->parser` — `void*`, и его тип зависит от
протокола. В h2 это дало две ошибки type confusion, найденные ASan
(`docs/http2/09`). Теперь вариантов три (h1.1 / h2 / h3), поэтому вводим
проверку через явный тег протокола в `connection_server_ctx_t`, а не через пару
битов, и функции доступа `h3_session_of(connection)` возвращают NULL, если
протокол не тот, — как это уже сделано у `h2_session_of()`.

## 9. Приоритеты (RFC 9218)

Позиция та же, что принята для h2 (`docs/http2/08` фаза F.1): заголовок
`Priority` и кадр `PRIORITY_UPDATE` (0xf0700/0xf0701) **разбираются и
валидируются**, но планирование по urgency не реализуется — на этой архитектуре
его невозможно осмысленно измерить. Некорректный `PRIORITY_UPDATE` →
`H3_FRAME_ERROR`; неизвестный id → игнорировать.

## 10. Коды ошибок

```
H3_NO_ERROR 0x0100  H3_GENERAL_PROTOCOL_ERROR 0x0101  H3_INTERNAL_ERROR 0x0102
H3_STREAM_CREATION_ERROR 0x0103  H3_CLOSED_CRITICAL_STREAM 0x0104
H3_FRAME_UNEXPECTED 0x0105  H3_FRAME_ERROR 0x0106  H3_EXCESSIVE_LOAD 0x0107
H3_ID_ERROR 0x0108  H3_SETTINGS_ERROR 0x0109  H3_MISSING_SETTINGS 0x010a
H3_REQUEST_REJECTED 0x010b  H3_REQUEST_CANCELLED 0x010c
H3_REQUEST_INCOMPLETE 0x010d  H3_MESSAGE_ERROR 0x010e  H3_CONNECT_ERROR 0x010f
H3_VERSION_FALLBACK 0x0110
QPACK_DECOMPRESSION_FAILED 0x0200  QPACK_ENCODER_STREAM_ERROR 0x0201
QPACK_DECODER_STREAM_ERROR 0x0202
```

Разделение «ошибка потока» / «ошибка соединения» проводим строго: ошибка
сообщения (`H3_MESSAGE_ERROR`) убивает поток, ошибка кадрирования или
критического потока — соединение. Смешать их — самая частая претензия h3spec.

## 10a. Ход работ

**Сделано:** `h3frame.{h,c}` — резюмируемый парсер кадров и кодек SETTINGS.
+52 проверки (100 958 → 101 010).

Три правила здесь противоположны рефлексам, выработанным на HTTP/2, и каждое
покрыто отдельно:

- **неизвестный тип кадра игнорируется**, а не рвёт соединение — длина для
  того и есть; в QUIC-транспорте наоборот, потому что там пропускать нечего;
- **кодпойнты HTTP/2** (0x02, 0x06, 0x08, 0x09) отвергаются, а не
  игнорируются: §11.2.1 требует этого именно чтобы транслирующий прокси не
  смог протащить кадр между версиями;
- **DATA не буферизуется** — тело ответа это один кадр неограниченного
  размера, поэтому payload отдаётся кусками (`H3FRAME_DATA_CHUNK`).
  Предел накопления действует только на управляющие кадры.

Тест на разрезание кадра **в каждой возможной точке** — включая середину
varint'а — ловит именно то, что даёт QUIC-поток: байты приходят порциями,
которые выбрал не отправитель.

**Сделано:** `h3unistream.{h,c}` (`protocols/http3/server/`) — типы
однонаправленных потоков (§3): резюмируемый парсер префикса-varint, трекер
дубликатов по направлениям, серверная политика `h3uni_server_classify()` и
предикаты (`is_known`/`is_critical`/`is_grease`). +70 проверок
(101 010 → 101 080).

Здесь тоже три правила идут против HTTP/2-рефлексов, и каждое покрыто отдельно:

- **неизвестный тип потока не фатален** — §6.2.3 разрешает STOP_SENDING +
  discard; мы так и делаем. На транспортном слое QUIC наоборот: там неизвестный
  тип кадра рвёт соединение, потому что пропустить его нечем. Два слоя выглядят
  одинаково и ведут себя противоположно;
- **три служебных потока критичны и уникальны** — control и оба QPACK-потока:
  по одному на направление, закрытие любого (FIN или RESET) →
  `H3_CLOSED_CRITICAL_STREAM` для соединения, второй экземпляр →
  `H3_STREAM_CREATION_ERROR`. Push не уникален и не критичен;
- **push от клиента нелегален с первого раза** — пушит только сервер
  (§6.2.2), поэтому для сервера type 0x01 от клиента сразу даёт
  `H3_STREAM_CREATION_ERROR`, а не «неизвестный тип». Трекер дубликатов push
  не отслеживает именно поэтому.

Парсер, как и у кадров, разрезается **в каждой точке varint'а** (включая
середину двухбайтного типа); после READY повторная подача — no-op, чтобы байты
содержимого потока не прочитались как второй тип.

**Сделано:** рефакторинг §6.1 — `h2_build_request()` разобран на HPACK-декод
(остался в h2) и общий `protocols/http/httpfields.c::httpfields_to_request()`
(валидность полей, псевдо-заголовки, запрещённые/TE/content-length, обязательные
псевдо, asterisk-form, cookie/range, версия; выбор vhost — у вызывающего, т.к.
нужен connection). h2 вызывает его через `HTTP_FIELDS_H2`, h3 будет через
`HTTP_FIELDS_H3`; правила сегодня идентичны. Поле-дескриптор `httpfields_field_t`
layout-совместим с `hpack_header_t`/`qpack_header_t` (guard — `_Static_assert`).
`h2field.{c,h}` переехали из `protocols/http2/server/` в `protocols/http/` (общий
слой валидности имён/значений ниже и h2, и h3; переименовывать функции не стали).
`h2_consume_trailers` теперь зовёт `httpfields_is_forbidden_header`. Поведение h2
не изменилось — существующие h2-тесты зелёные; +21 проверка в новом
`test_httpfields.c` (12 нарушений §4.1/§8.3, positives для h2 и h3, content-length,
OPTIONS\*). h3: 101 177, без h3: 100 210, ASan-чисто.

**Сделано:** `h3stream.{h,c}` — приёмная половина потока запроса (§6.1): парсер
кадров → QPACK → `httpfields_to_request` → тело в `httppayload` (tmp-файл, как в
h2). Тестируемое ядро: сессия передаёт общий `qpack_decoder_t*`, транспорт —
только байты и `fin`.

Три правила здесь стоили отдельной работы, и каждое проверяется тестом:

- **разделение «ошибка потока» / «ошибка соединения» проведено по коду, а не по
  ощущению.** §4.1 и §7.1 требуют *connection error* для порядка кадров и для
  кадрирования, тогда как malformed-сообщение (§4.1.2) убивает только поток.
  Статусы несут по одному коду каждый (`h3stream_status_error`), а
  `h3stream_status_is_connection` отвечает на вопрос «кого закрывать». Первая
  версия схлопывала `ERR_ENCODING`/`ERR_RESERVED`/`ERR_TOO_LARGE` в один статус —
  ровно та ошибка, о которой предупреждает §10;
- **пустой фид легален.** FIN в QUIC приходит на STREAM-кадре без байтов, и
  именно тогда обязаны отработать проверки конца потока. `*pp == end` (включая
  NULL/NULL) — это «нечего добавить», а не плохой аргумент; так же исправлены
  `h3frame_parser_feed` и `h3uni_parser_feed`;
- **что проверяется только на FIN:** §7.1 — кадр, разрезанный чистым FIN'ом
  (`h3frame_parser_at_boundary`), это *connection error*; §4.1.2 — `content-length`
  против фактически принятого тела (та же проверка, что в `h2_dispatch`).
  Порядок важен: усечённая DATA иначе отчиталась бы как несовпадение длины —
  не тот код и не тот масштаб.

`MAX_FIELD_SECTION_SIZE` держится здесь же (`h3stream_create`), превышение → 431
на потоке, соединение живо (`docs/http2/08` фаза A.4). +48 проверок в
`test_h3stream.c`.

**Сделано:** `h3session.{h,c}` — уровень соединения (§3, §4, §7). Модуль
сознательно не знает ни про `quicconn_t`, ни про `connection_t`: на вход байты
однонаправленного потока, на выход вердикт (`OK` / `STOP_SENDING(code)` /
`CONN_ERROR(code)`). Транспортный клей — фаза 7.

- служебные потоки пира: `h3uni_recv_t` (живёт в `quicstream_t::app`) держит
  резюмируемый парсер префикса-варинта, потому что тип может быть разрезан;
  классификация — через `h3uni_server_classify`;
- control-поток: SETTINGS первым и ровно один раз (иначе `H3_MISSING_SETTINGS` /
  `H3_FRAME_UNEXPECTED`), GOAWAY и MAX_PUSH_ID с проверкой монотонности
  (`H3_ID_ERROR`), CANCEL_PUSH → `H3_ID_ERROR` (мы не пушим, поэтому любой
  push id за пределом), HEADERS/DATA/PUSH_PROMISE → `H3_FRAME_UNEXPECTED`,
  неизвестные типы пропускаются парсером;
- QPACK encoder-поток пира: в lite легальна ровно одна инструкция — `Set Dynamic
  Table Capacity 0`. Отвергать *все* байты было бы неверно: capacity 0 клиенты
  реально шлют. Появился `qpack_decoder_read_encoder()` (док 06 §5), который
  решает вердикт по первому октету, если 31 уже превышает объявленное, — так
  в lite не остаётся недочитанных инструкций для переноса между фидами;
- QPACK decoder-поток пира дренится без разбора: при `RIC = 0` во всех наших
  секциях подтверждать нечего (RFC 9204 §2.2.2). Разбор придёт с 6.2;
- закрытие критического потока (FIN или RESET) → `H3_CLOSED_CRITICAL_STREAM`;
  поток, оборвавшийся до прихода типа, критичным быть не мог и безвреден.

+78 проверок в `test_h3session.c`. Сборка с h3: 101 296 проверок ASan-чисто.

**Сделано:** `h3response.{h,c}` — кодировщик ответной стороны (§6.3): `:status`
плюс поля → QPACK → `HEADERS`-кадр, informational (100/103), трейлеры, заголовок
`DATA`-кадра. Вынесен **до** появления фильтра, а не после: в h2 то же самое
пришлось извлекать из `h2_write_filter.c` задним числом (`h2data.{c,h}`,
`docs/http2/09` §4.3), когда потребителей стало двое — обычный ответ и туннель
Extended CONNECT. Здесь их заведомо будет двое, и модуль без сессии и сокета
проверяется побайтово уже сейчас.

Чего в h3-версии нет по сравнению с h2 — и это и есть «фильтр проще»: нет учёта
окон (их держит транспорт), нет CONTINUATION (секция полей — один кадр любой
длины), нет флага `END_STREAM` (его роль играет FIN потока).

Правила «запрещённое поле / чувствительное поле / нижний регистр» переехали в
`protocols/http/httpfields.c` (`httpfields_is_forbidden_response_header`,
`httpfields_is_sensitive_header`, `httpfields_lowercase`), а `h2_write_filter.c`
переключён на них. Списки для ответа и для запроса **разные** — в ответе `te`
запрещён целиком, в запросе допустим со значением `trailers`, — поэтому это две
функции, а не одна с флагом. Третья копия тех же правил в h3 была бы ровно тем
расхождением, из-за которого `httpfields.c` и появился.

Трейлеры: псевдо-заголовки и `content-length` из ответа **отбрасываются молча**,
а не отвергаются. Это наш собственный ответ, а не чужой запрос: хендлер, который
их выставил, ошибся, и мы это тихо исправляем. Пустая секция трейлеров кадром не
становится — вызывающий просто закрывает поток.

+31 проверка в `test_h3response.c` (каждый случай кодируется и **декодируется
обратно** — единственное утверждение об кодировщике, которое чего-то стоит).
Сборка с h3: 101 340 проверок ASan-чисто, без h3 — 100 210.

**Осталось:** `h3_write_filter` — терминальная стадия цепочки поверх
`h3response` (нужен выходной буфер сессии, а он появляется вместе с транспортным
клеем); подключение к dispatch (§6.2); Extended CONNECT (§8); фаза 7 — чтение
потоков QUIC, `stream->app`, публикация ответов.

## 11. Тесты фазы

`test_h3frame.c` — все типы, GREASE, зарезервированные, усечённые, огромный DATA.
**Сделано.** Включает и SETTINGS (дубликаты, h2-идентификаторы, GREASE) —
отдельного `test_h3settings.c` не заводилось.

`test_h3unistream.c` — типы uni-потоков, дубликаты, закрытие критического,
политика classify (ROUTE/IGNORE/STOP_DROP/CONN_ERROR), round-trip записи.
**Сделано** (модуль назван `h3unistream`, а не `h3stream_types`).

`test_httpfields.c` — общая сборка запроса для h2 и h3 (после рефакторинга §6.1),
с полным набором нарушений §4.1. **Сделано** (12 нарушений + positives h2/h3 +
content-length + OPTIONS\* + forbidden-header).

**Готово, когда:** `curl --http3 https://host/` отдаёт статический файл и ответ
хендлера; POST с телом 10 МБ проходит; работают trailers, 103, gzip, Range;
одновременные 50 запросов в одном соединении обслуживаются параллельно
(`/metrics` показывает `handlers_inflight > 1`).
