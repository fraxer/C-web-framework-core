# Фаза 4. Транспорт: потоки, flow control, ACK, восстановление, перегрузка

Самая большая фаза. RFC 9000 §2–§13, RFC 9002 целиком. К её концу QUIC-соединение
живёт само по себе: переносит данные, восстанавливается после потерь, не топит
сеть и корректно закрывается — ещё без единой строчки HTTP/3.

---

## 1. `quicconn_t` — состояние соединения

```c
typedef struct quicconn {
    connection_t          conn;        /* ВСТРОЕН, а не указатель: весь верхний
                                          слой работает с &qc->conn как обычно */
    quicendpoint_t*       ep;          /* владелец: чей timerfd и tx-очередь */

    /* идентификация */
    quiccid_entry_t       local_cids[QUIC_MAX_LOCAL_CIDS];   /* наши, выданные клиенту */
    quiccid_entry_t       peer_cids[QUIC_MAX_PEER_CIDS];     /* клиентские, для DCID */
    quiccid_t             odcid;       /* DCID первого Initial — для tp и Retry */
    quiccid_t             retry_scid;  /* если отправляли Retry */
    uint64_t              cid_seq_next;

    /* криптография */
    quictls_t             tls;
    quiccrypto_t          crypto;

    /* пакетные пространства */
    quicpnspace_t         pns[QUIC_ENC_COUNT];   /* Initial, 0-RTT(=App tx), Handshake, App */

    /* потоки */
    hashmap_t*            streams;     /* stream_id -> quicstream_t* */
    uint64_t              next_uni_id; /* серверные uni: 0x03, 0x07, ... */
    quicstream_t*         send_head;   /* round-robin список готовых к отправке */

    /* flow control соединения */
    quicflow_t            fc;

    /* путь */
    quicpath_t            path;
    quicpath_t            probing;     /* проверяемый путь при миграции */
    uint64_t              amplification_budget;  /* 3x до валидации адреса */
    int                   address_validated;

    /* восстановление и перегрузка */
    quicloss_t            loss;
    quiccc_t              cc;
    quicpacer_t           pacer;

    /* таймеры */
    uint64_t              idle_deadline_us;
    uint64_t              close_deadline_us;
    uint64_t              next_timer_us;   /* то, что лежит в куче эндпоинта */

    /* закрытие */
    enum { QC_ACTIVE, QC_CLOSING, QC_DRAINING, QC_DEAD } state;
    uint8_t               close_pkt[QUIC_MAX_DATAGRAM];  /* заготовленный
                                CONNECTION_CLOSE, переотправляется по запросу */
    size_t                close_pkt_len;

    /* приложение */
    struct h3session*     h3;

    struct quicconn*      ep_next;     /* список эндпоинта */
    struct quicconn*      tx_next;     /* очередь "есть что отправить" */
} quicconn_t;
```

Контракт конкурентности — тот же, что у `h2session_t`: **всё** трогается только
под `connection_s_lock()`.

### 1.1 Пакетное пространство

```c
typedef struct quicpnspace {
    uint64_t        next_pn;           /* следующий номер на отправку */
    uint64_t        largest_acked;     /* наибольший подтверждённый нами */
    quicack_t       ack;               /* принятые номера -> генерация ACK */
    quicsent_t*     sent;              /* отсортированный список отправленных
                                          неподтверждённых пакетов */
    size_t          sent_count;
    uint64_t        loss_time_us;      /* время срабатывания таймера потерь */
    int             ack_eliciting_in_flight;
    quicbuf_t       crypto_out;        /* исходящие CRYPTO этого уровня */
    uint64_t        crypto_out_off;    /* сколько уже отправлено */
    quicrecvbuf_t   crypto_in;
} quicpnspace_t;
```

---

## 2. Потоки (`quicstream.{c,h}`)

### 2.1 Идентификаторы

```
биты 0..1 младшие:
  0x00  client-initiated bidirectional     ← запросы HTTP/3
  0x01  server-initiated bidirectional     ← не используем
  0x02  client-initiated unidirectional    ← control/QPACK клиента
  0x03  server-initiated unidirectional    ← control/QPACK наши
```

Открытие потока с id N неявно открывает все потоки того же типа с меньшим id
(§2.1) — если клиент прислал STREAM для id 12, потоки 0, 4, 8 считаются
открытыми и закрытыми. Забыть это = падать на реальных клиентах.

### 2.2 Конечные автоматы

Приёмная сторона (§3.2): `Recv → Size Known → Data Recvd → Data Read`,
плюс `Reset Recvd → Reset Read`.
Передающая (§3.1): `Ready → Send → Data Sent → Data Recvd`, плюс
`Reset Sent → Reset Recvd`.

```c
typedef struct quicstream {
    uint64_t   id;
    quicconn_t* conn;

    /* приём */
    quicrecvbuf_t recv;
    uint64_t   recv_final_size;   /* известен после FIN/RESET_STREAM */
    int        recv_fin;
    int        recv_reset;  uint64_t recv_reset_code;
    quicflow_t recv_fc;

    /* передача */
    quicsendbuf_t send;
    int        send_fin;
    int        send_reset;  uint64_t send_reset_code;
    int        stop_sending_received;  uint64_t stop_sending_code;
    quicflow_t send_fc;

    uint8_t    recv_state, send_state;

    /* приложение */
    void*      app;               /* h3stream_t* */

    struct quicstream* send_next; /* round-robin список готовых */
} quicstream_t;
```

Проверки, каждая со своим кодом ошибки:

| Ситуация | Ошибка |
|---|---|
| Данные за пределом объявленного final size | `FINAL_SIZE_ERROR` |
| Второй FIN с другим final size | `FINAL_SIZE_ERROR` |
| RESET_STREAM с final size ≠ уже полученному максимуму | `FINAL_SIZE_ERROR` |
| STREAM/RESET на потоке, который может только отправлять (наш uni) | `STREAM_STATE_ERROR` |
| MAX_STREAM_DATA на потоке, куда мы не отправляем | `STREAM_STATE_ERROR` |
| Превышение `initial_max_streams_*` | `STREAM_LIMIT_ERROR` |
| Данные сверх окна потока/соединения | `FLOW_CONTROL_ERROR` |
| `offset + len` > 2^62−1 | `FRAME_ENCODING_ERROR` |

### 2.3 `quicrecvbuf.{c,h}` — приём с дырами

Данные приходят не по порядку. Нужна структура «набор диапазонов с байтами».

Решение: **список сегментов**, отсортированный по offset, с слиянием соседей.
Контроль: приложению отдаётся только непрерывный префикс от `read_off`.

```c
typedef struct quicrecvseg { uint64_t off; size_t len; uint8_t* data;
                             struct quicrecvseg* next; } quicrecvseg_t;
typedef struct quicrecvbuf {
    quicrecvseg_t* head;
    uint64_t read_off;       /* всё до этого отдано приложению */
    uint64_t contig_end;     /* конец непрерывного префикса */
    uint64_t max_off;        /* максимальный принятый offset+len */
    size_t   buffered;       /* байт в сегментах вне префикса — для лимита */
} quicrecvbuf_t;

int  quicrecvbuf_insert(quicrecvbuf_t*, uint64_t off, const uint8_t*, size_t);
/* Указатель на непрерывный префикс. */
size_t quicrecvbuf_peek(quicrecvbuf_t*, const uint8_t** out);
void quicrecvbuf_consume(quicrecvbuf_t*, size_t n);
```

Тонкости: перекрывающиеся сегменты легальны и должны совпадать по содержимому
(проверять не обязаны, но обязаны не портить данные); полностью дублирующий
сегмент отбрасывается; `buffered` ограничен (иначе клиент, шлющий байт на
offset 10^9, съест память) — превышение трактуем как `FLOW_CONTROL_ERROR`.

### 2.4 `quicsendbuf.{c,h}` — передача с ретрансмиссией

Ключевое следствие ADR-6: буфер отправки не может быть простым FIFO. Байты
живут, пока не подтверждены, и могут понадобиться повторно **из середины**.

```c
typedef struct quicsendbuf {
    quicbuf_t   data;         /* непрерывный буфер от base_off */
    uint64_t    base_off;     /* offset первого байта в data */
    uint64_t    write_off;    /* сколько байт приложение уже положило */
    uint64_t    sent_off;     /* до какого offset отправлено хотя бы раз */
    quicrange_t* acked;       /* подтверждённые диапазоны (для сдвига base) */
    quicrange_t* lost;        /* потерянные диапазоны — отправить заново */
} quicsendbuf_t;
```

Алгоритм выбора данных для следующего пакета:

1. если `lost` непуст — берём оттуда (ретрансмиссия приоритетнее);
2. иначе — `[sent_off, write_off)`, ограниченное flow control, cwnd и местом в пакете.

`base_off` сдвигается, когда `acked` покрывает начало, — тогда память
освобождается. Диапазоны — обычный отсортированный связный список с слиянием
(диапазонов на практике единицы).

---

## 3. Flow control (`quicflow.{c,h}`)

Два уровня, каждый в обе стороны:

```c
typedef struct quicflow {
    uint64_t limit;        /* сколько нам разрешено / мы разрешили */
    uint64_t used;         /* сколько израсходовано */
    uint64_t auto_target;  /* целевой размер окна (авто-тюнинг) */
    int      blocked_sent; /* DATA_BLOCKED/STREAM_DATA_BLOCKED уже отправлен */
} quicflow_t;
```

**Приём.** Мы объявляем `initial_max_data` / `initial_max_stream_data_*` и по
мере чтения приложением поднимаем лимит `MAX_DATA` / `MAX_STREAM_DATA`.
Правило обновления: отправлять новый лимит, когда потреблено больше половины
окна, — реже нельзя (клиент встанет), чаще незачем (лишние фреймы).

Авто-тюнинг окна — тот же приём, что уже применён в h2 (`h2_recv_window_t`,
`stream_recv_learned`): если поток упирается в окно чаще, чем раз в RTT, окно
удваивается до `http3_recv_window_max`. Логику можно портировать почти дословно.

**Передача.** Перед формированием STREAM-фрейма — минимум из окна потока и
окна соединения. Упёрлись — один раз отправляем `STREAM_DATA_BLOCKED` /
`DATA_BLOCKED` (не на каждый пакет, иначе это флуд) и ждём `MAX_*`.

**Лимиты потоков.** `MAX_STREAMS` поднимается по мере закрытия потоков, так же
по правилу «половина». Аналог `SETTINGS_MAX_CONCURRENT_STREAMS` из h2 —
согласуем значение с `H2_MAX_CONCURRENT_STREAMS` (100).

---

## 4. ACK (`quicack.{c,h}`)

```c
typedef struct quicack {
    quicrange_t* ranges;        /* принятые номера, по убыванию, ≤ 32 диапазонов */
    uint64_t     largest;
    uint64_t     largest_recv_us;   /* время приёма largest — для ACK Delay */
    int          ack_eliciting_pending;  /* сколько ack-eliciting не подтверждено */
    uint64_t     ack_deadline_us;
    uint64_t     ect0, ect1, ce;    /* ECN, фаза 9 */
} quicack_t;
```

Правила (RFC 9000 §13.2):

- ACK отправляется **немедленно**, если получено 2 ack-eliciting пакета подряд,
  или обнаружено переупорядочивание/дыра;
- иначе — не позже `max_ack_delay` (25 мс), по таймеру;
- ACK **не** отправляется в ответ на пакет, содержащий только ACK/PADDING;
- в Initial и Handshake ACK отправляется немедленно **всегда** — задержка там
  напрямую удлиняет рукопожатие;
- число диапазонов ограничиваем 32: иначе злонамеренный клиент с «гребёнкой»
  потерь заставит нас слать огромные ACK. Лишние (самые старые) отбрасываются;
- `ACK Delay` = (сейчас − `largest_recv_us`) >> `ack_delay_exponent` пира;
  в Initial/Handshake экспонента фиксирована 3.

Кодирование диапазонов (§19.3.1) — самое багоопасное место фазы; тест обязан
включать пример из RFC и round-trip на случайных наборах.

---

## 5. Loss detection (`quicloss.{c,h}`, RFC 9002)

### 5.1 Учёт отправленного

```c
typedef struct quicsent {
    uint64_t pn;
    uint64_t sent_us;
    size_t   size;             /* байт в датаграмме — для cwnd */
    int      ack_eliciting;
    int      in_flight;
    /* что вернуть в очередь при потере */
    quicframe_ref_t* frames;   /* список ссылок: {тип, поток, диапазон offset} */
    struct quicsent* next;
} quicsent_t;
```

`quicframe_ref_t` не хранит байты — только описание, чтобы восстановить фрейм:
для STREAM это `{stream_id, off, len, fin}`, для CRYPTO — `{level, off, len}`,
для MAX_DATA — просто «отправить актуальное значение», и так далее.

### 5.2 RTT

```
latest_rtt   = now − sent_us(largest_acked)      /* только если largest_acked новый
                                                    и пакет был ack-eliciting */
adjusted_rtt = latest_rtt − min(ack_delay, max_ack_delay)   /* только после
                                                    подтверждения рукопожатия */
min_rtt      = min(min_rtt, latest_rtt)
smoothed_rtt = 7/8·smoothed_rtt + 1/8·adjusted_rtt
rttvar       = 3/4·rttvar + 1/4·|smoothed_rtt − adjusted_rtt|
```

Первый образец: `smoothed_rtt = latest_rtt`, `rttvar = latest_rtt/2`.
`kInitialRtt = 333 мс`.

### 5.3 Обнаружение потерь

Пакет считается потерянным, если он старше `largest_acked` и выполняется:

- **порог по номеру**: `largest_acked − pn >= kPacketThreshold (3)`; или
- **порог по времени**: `now − sent_us > max(9/8 · max(smoothed_rtt, latest_rtt),
  kGranularity (1 мс))`.

Не сработавшие по времени пакеты задают `loss_time_us` — таймер, по которому
проверка повторится.

### 5.4 PTO

```
pto = smoothed_rtt + max(4·rttvar, kGranularity) + max_ack_delay
      (max_ack_delay учитывается только в Application-пространстве)
pto_timeout = время_последнего_ack_eliciting + pto · 2^pto_count
```

По срабатыванию: **не** объявлять потери, а отправить 1–2 ack-eliciting пакета
(зонды). Если отправлять нечего — PING. `pto_count` растёт до сброса при
получении подтверждения.

Отдельно: пока адрес не валидирован и сервер упёрся в anti-amplification, PTO
взводить нельзя (иначе бессмысленный цикл) — вместо этого ждём пакет от клиента.

### 5.5 Порядок пространств

Таймер выбирается по наименьшему дедлайну среди пространств, с приоритетом
Initial > Handshake > Application, и Application учитывается только после
подтверждения рукопожатия.

---

## 6. Congestion control (`quiccc.{c,h}`)

v1 — **NewReno** из RFC 9002 §7, дословно:

```
kInitialWindow      = min(10·max_datagram_size, max(14720, 2·max_datagram_size))
kMinimumWindow      = 2·max_datagram_size
kLossReductionFactor= 0.5
kPersistentCongestionThreshold = 3
```

- slow start: `cwnd += acked_bytes`, пока `cwnd < ssthresh`;
- congestion avoidance: `cwnd += max_datagram_size · acked_bytes / cwnd`;
- при потере: если пакет не в текущем recovery-периоде →
  `ssthresh = cwnd/2`, `cwnd = max(ssthresh, kMinimumWindow)`, новый период;
- **persistent congestion**: если все пакеты в интервале длиной
  `(smoothed_rtt + 4·rttvar + max_ack_delay) · 3` потеряны →
  `cwnd = kMinimumWindow`, сброс в slow start;
- ECN-CE трактуется как потеря (фаза 9);
- `bytes_in_flight` не должен превышать `cwnd`.

Интерфейс делаем виртуальным (структура с указателями на функции), чтобы CUBIC
и BBR в фазе 9 добавлялись без правок в `quicloss`:

```c
typedef struct quiccc_ops {
    void (*on_packet_sent)(quiccc_t*, size_t bytes);
    void (*on_ack)(quiccc_t*, size_t bytes, uint64_t sent_us, uint64_t now_us);
    void (*on_loss)(quiccc_t*, size_t bytes, uint64_t sent_us, int persistent);
    void (*on_pto_expired)(quiccc_t*);
    size_t (*can_send)(const quiccc_t*);
} quiccc_ops_t;
```

## 6.1 Pacing (`quicpacer.{c,h}`)

Без pacing NewReno выдаёт cwnd одним залпом и топит буферы. Формула из
RFC 9002 §7.7:

```
interval = smoothed_rtt · packet_size / (N · cwnd),   N = 1.25 (slow start: 2.0)
```

Реализация — токен-бакет с пополнением по времени; когда токенов не хватает,
соединение не ставится в tx-очередь, а получает таймер (§ таймеры в `01`).
Всплеск ограничиваем 10 пакетами, чтобы не платить таймером за каждый пакет.

---

## 7. Валидация пути и миграция (`quicpath.{c,h}`)

- Пакет, пришедший с **нового** адреса на известный CID, — вероятная миграция.
  Сервер обязан: (а) не переключаться сразу, (б) отправить `PATH_CHALLENGE`
  (8 случайных байт) на новый адрес, (в) переключиться только по совпадающему
  `PATH_RESPONSE`.
- До валидации нового пути действует anti-amplification (3×) уже **на этом пути**.
- При смене пути сбрасываются congestion controller и RTT-оценки (§9.4) — новый
  путь ничего не знает о старом. Оставляем `min_rtt` как нижнюю оценку.
- Сервер обязан использовать **новый** DCID из числа выданных клиентом при
  миграции (§9.5), иначе на пути видна связь старого и нового адреса.
- Ограничение: не более одного проверяемого пути одновременно, и не чаще одной
  миграции за 3×PTO — иначе это вектор DoS.
- `NAT rebinding` (сменился только порт) обрабатывается тем же путём.

## 8. Anti-amplification

До валидации адреса клиента (успешное рукопожатие или валидный токен) сервер не
отправляет более **3×** полученных от клиента байт на этом пути. Практическое
следствие: серверный flight (сертификат!) часто упирается в лимит, и клиенту
приходится слать PING/PADDING. Поэтому:

- бюджет уменьшается на размер **датаграммы**, а не пакета;
- при исчерпании бюджета соединение просто не ставится в tx-очередь;
- при получении новых байт бюджет пополняется и соединение будится;
- сертификатную цепочку стоит держать короткой (документируем в
  `07-integration.md`).

## 9. Закрытие соединения

| Причина | Механизм |
|---|---|
| Idle timeout | `min(наш max_idle_timeout, пиров)`, отсчёт от последнего пакета; при истечении — молча в `QC_DEAD`, без CONNECTION_CLOSE |
| Ошибка транспорта | `CONNECTION_CLOSE` (0x1c) с кодом, состояние `QC_CLOSING` |
| Ошибка приложения (H3) | `CONNECTION_CLOSE` (0x1d) с кодом H3 |
| Штатное завершение (shutdown) | H3 GOAWAY → дождаться потоков → CONNECTION_CLOSE(NO_ERROR) |
| Stateless reset от пира | немедленно `QC_DEAD` |

`QC_CLOSING`: держим заготовленный пакет `close_pkt` и переотправляем его в ответ
на входящие пакеты, но **не чаще** чем экспоненциально реже (иначе усилитель).
Длительность — `3×PTO`. Новых фреймов не формируем и не обрабатываем.

`QC_DRAINING` (получили CONNECTION_CLOSE от пира): ничего не отправляем,
ждём `3×PTO`, чтобы дать пиру дослать.

Освобождение: `QC_DEAD` → снять все CID с глобальной таблицы → `connection_s_dec`.
Ровно как в h2, освобождение идёт через refcount, потому что хендлерный поток
может держать соединение.

---

## 10. qlog (`quicqlog.{c,h}`)

Настаиваем: без qlog фаза 4 отлаживается неделями вместо дней.

Минимальный набор событий (схема draft-ietf-quic-qlog-quic-events):
`connectivity:connection_started`, `transport:packet_sent`,
`transport:packet_received`, `transport:packet_dropped`,
`recovery:metrics_updated` (cwnd, bytes_in_flight, rtt),
`recovery:packet_lost`, `recovery:congestion_state_updated`.

Формат — JSON-SEQ (`.sqlog`), одна строка на событие, через существующий
`misc/json.h`. Включается конфигом на конкретный CID-префикс или на N первых
соединений, иначе на нагрузке это само по себе DoS. Готовые визуализаторы
(qvis) принимают этот формат и рисуют диаграммы cwnd/потоков — это и есть
основной инструмент отладки восстановления.

---

## 10a. Ход работ

**Сделано (первый срез фазы):** структуры данных и восстановление —
`quicrange`, `quicrecvbuf`, `quicsendbuf`, `quiccc` (NewReno + pacer),
`quicloss` (RTT, пороги по номеру и по времени, PTO, persistent congestion,
сброс пространства). +156 проверок (100 704 → 100 860), ASan с
`detect_stack_use_after_return=1` чист.

**Сделано (второй срез):** `quicack` (дубликаты, правила §13.2 о немедленном и
отложенном ACK, генерация кадра, ограничение числа диапазонов), `quicflow`
(два уровня, монотонность лимитов, кредит по половине окна, авто-тюнинг),
`quicstream` (идентификаторы, оба конечных автомата, полная таблица ошибок
§2.2 — каждая со своим кодом). +98 проверок (100 860 → 100 958).

`quicrange` в плане не значился — он появился, потому что одна и та же
структура «множество целых как отсортированные непересекающиеся отрезки»
нужна в трёх местах: принятые номера пакетов (для ACK), подтверждённые
смещения потока (для сдвига базы в `quicsendbuf`) и потерянные (для
ретрансмиссии). Ключевое свойство — склейка **смежных** отрезков: `[1,3]` и
`[4,6]` обязаны стать `[1,6]`, потому что кодирование ACK не умеет выражать
нулевой промежуток.

**Сделано (третий срез):**

- `connection_t::transport` и обход `epoll_ctl` в `multiplexingepoll.c`. Учёт
  соединения в списке воркера и в счётчике сохраняется — по нему ходят
  таймерный сметатель и дренаж при остановке; заменён только сам `epoll_ctl`.
  `control_mod(MPXOUT)` для QUIC означает «есть что отправить» и будит эндпоинт.
- `quicendpoint_send` / `quicendpoint_wake` + очередь отправки эндпоинта с
  leaf-локом (достижима из хендлерного потока).
- `quicconn.{h,c}`: приём пакета (снятие HP → расшифровка → фреймы →
  диспетчеризация, с проверкой дубликатов и допустимости фрейма по
  пространству), сборка пакета (коалесценция уровней, anti-amplification,
  cwnd), обработка всех фреймов RFC 9000, создание из Initial с выводом
  Initial-секретов, закрытие с сохранённым CONNECTION_CLOSE-пакетом,
  idle timeout, таймеры.

Циклическая зависимость заголовков решена так: `quicconn.h` и
`quicendpoint.h` держат друг друга непрозрачными указателями, а полный тип
видит ровно один `.c` — `quicendpoint.c`.

**Осталось до конца фазы 4 — одно:** `quicconn_accept`/`quicconn_recv` пока
**никем не вызываются**. Демультиплексор всё ещё считает Initial-пакеты
счётчиком `initial_dropped_no_tls` и отбрасывает их. Чтобы соединение ожило,
нужно в `__dispatch`:

1. на Initial без соединения — выбрать vhost, вызвать `quicconn_accept`,
   зарегистрировать оба CID в таблице, добавить в список воркера через
   `control_add`;
2. на найденном соединении — взять `connection_s_lock`, вызвать
   `quicconn_recv`, затем `quicconn_send`;
3. в проходе отправки эндпоинта — разобрать `tx_head`;
4. в `__mpx_on_tick` — вызвать `quicconn_tick` рядом с `h2_server_tick`.

Это ~150 строк проводки. Всё, что под ней, написано, собирается без
предупреждений под `-Wall -Wextra -Wpedantic -fanalyzer` и покрыто тестами
там, где поддаётся изоляции.

### Заметка о тестировании порога по времени

Порог потери — 9/8 RTT. При RTT в 1 мс пакет возрастом 3 мс потерян
**по-настоящему**, и тест, который отправляет пакеты с интервалом 1 мс и тут же
их подтверждает, проверяет не то, что кажется: он создаёт путь с RTT 1 мс.
Осмысленный сценарий переупорядочивания требует пути, медленного относительно
интервала между пакетами, — поэтому тест сначала устанавливает RTT 100 мс.
Первая версия теста этого не делала и «падала» на верном коде.

## 11. Юнит-тесты фазы

Время инжектируется (`quic_time_set_source`), сеть эмулируется — тесты полностью
детерминированы.

`test_quic_recvbuf.c` — вставки в разном порядке, перекрытия, дубликаты, лимит.
`test_quic_sendbuf.c` — ретрансмиссия из середины, сдвиг base, слияние диапазонов.
`test_quic_ack.c` — векторы RFC §19.3.1, генерация при 32+ диапазонах.
`test_quic_flow.c` — обновление лимитов, DATA_BLOCKED ровно один раз.
`test_quic_stream.c` — все переходы автоматов, каждая ошибка из таблицы §2.2.
`test_quic_loss.c` — RTT-оценка, порог по номеру, порог по времени, PTO с
экспонентой, persistent congestion.
`test_quic_cc.c` — slow start, выход в avoidance, реакция на потерю, минимум cwnd.
`test_quic_conn.c` — сквозной прогон «клиент↔сервер» на паре объектов в памяти
(наш же код в роли клиента — минимальный тестовый клиент, ~600 строк, окупается
многократно) с инжекцией потерь 0 %, 5 %, 20 % и переупорядочивания.

**Готово, когда:** тестовый клиент передаёт 100 МБ через один поток при 5 % потерь
за время, соответствующее оценке пропускной способности; TSan чист на 4 воркерах;
qlog открывается в qvis и графики выглядят разумно.
