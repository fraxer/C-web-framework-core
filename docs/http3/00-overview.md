# HTTP/3 в cwfr — обзор, границы и карта фаз

Документ №0 из серии. Остальные:

| Файл | Содержание |
|---|---|
| `01-udp-endpoint.md` | UDP-слой, демультиплексирование по CID, интеграция с epoll и моделью `connection_t` |
| `02-quic-core.md` | varint, пакеты, фреймы, Connection ID, transport parameters |
| `03-quic-tls.md` | OpenSSL QUIC TLS API, key schedule, AEAD, header protection, Retry, 0-RTT |
| `04-quic-transport.md` | Потоки, flow control, ACK, loss detection, congestion control, миграция, закрытие |
| `05-http3.md` | Кадры HTTP/3, служебные потоки, отображение на существующий dispatch и фильтры |
| `06-qpack.md` | QPACK: статическая/динамическая таблица, потоки encoder/decoder, blocked streams |
| `07-integration.md` | Конфиг, Alt-Svc, метрики, лимиты злоупотреблений, shutdown/reload |
| `08-testing.md` | Юнит-векторы, interop-раннер, h3spec, qlog, фаззинг, нагрузка |
| `09-options.md` | Отложенное, разделённое на обязательное / производительность / опции: цена, зависимости и критерий готовности каждого пункта |

---

## 1. Что вообще требуется

HTTP/3 — это не «ещё один протокол поверх сокета», как были h2c и WebSocket. Это
собственный транспорт. Ниже — полный список того, что придётся написать, чтобы
браузер открыл страницу по `h3`:

1. **UDP-эндпоинт**: один сокет обслуживает много соединений; соединение
   опознаётся не 4-кортежем, а Connection ID.
2. **QUIC-транспорт (RFC 9000)**: пакеты, номера пакетов в трёх пространствах,
   ~20 типов фреймов, потоки с собственными конечными автоматами, двухуровневый
   flow control, валидация пути, миграция, идентификаторы соединения.
3. **QUIC-TLS (RFC 9001)**: TLS 1.3 handshake переносится в CRYPTO-фреймы,
   ключи выводятся по HKDF-Expand-Label, каждый пакет шифруется AEAD, заголовок
   защищается отдельным шифром, ключи обновляются на лету.
4. **Восстановление потерь и контроль перегрузки (RFC 9002)**: RTT-оценка, PTO,
   ретрансмиссия *фреймов* (не пакетов), NewReno/CUBIC, pacing.
5. **HTTP/3 (RFC 9114)**: своё кадрирование, служебные однонаправленные потоки,
   SETTINGS, GOAWAY, свои коды ошибок.
6. **QPACK (RFC 9204)**: сжатие заголовков, устойчивое к переупорядочиванию
   потоков — принципиально сложнее HPACK.
7. **Обнаружение**: заголовок `Alt-Svc` в ответах h1.1/h2, иначе клиент никогда
   не узнает, что h3 доступен.

По объёму это сравнимо со всем текущим `core/protocols/` вместе взятым.
Оценка — **16–18 тыс. строк C** плюс ~3 тыс. строк тестов.

## 2. Ограничение «без готовых библиотек, кроме криптографии»

### 2.1 Что берём из OpenSSL

В системе установлен `libssl-dev 3.5.5`, чьи заголовки содержат

```c
int SSL_set_quic_tls_cbs(SSL *s, const OSSL_DISPATCH *qtdis, void *arg);
int SSL_set_quic_tls_transport_params(SSL *s, const unsigned char *params, size_t len);
int SSL_set_quic_tls_early_data_enabled(SSL *s, int enabled);
```

и диспетчерские слоты `OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND` (2001) …
`OSSL_FUNC_SSL_QUIC_TLS_ALERT` (2006) в `core_dispatch.h`. Символы присутствуют
и в библиотеке: `SSL_set_quic_tls_cbs@@OPENSSL_3.5.0` в
`/usr/lib/x86_64-linux-gnu/libssl.so.3`.

> **Историческая заметка (решено 2026-08-06).** До этой даты машина сборки
> системного OpenSSL не видела: в `/usr/local` лежал собранный из исходников в
> 2021 году OpenSSL 1.1.1k — и заголовки, и библиотеки. `/usr/local/include`
> стоит в списке поиска gcc **перед** `/usr/include`, а `/usr/local/lib` находит
> CMake, поэтому проект компилировался и линковался с 1.1.1k.
>
> Обойти это флагами нельзя: `-I/usr/include` не помогает (gcc игнорирует `-I`
> для каталога из стандартной цепочки, сохраняя его позицию), а
> `-isystem /usr/include` порядок меняет, но ломает `pcre.h` и `idn2.h`, которые
> тоже лежат в `/usr/local/include` при библиотеках из `/usr/local/lib`.
>
> Починено переносом 1.1.1k в `/root/openssl-1.1.1k-2026-08-06`. Проверено, что
> от него ничего не зависело: единственными потребителями сонеймов
> `libssl.so.1.1`/`libcrypto.so.1.1` были его собственные файлы и Sublime Text,
> который несёт свои копии в `/opt/sublime_text` и находит их через
> `RUNPATH $ORIGIN`. После переноса `cwfr` линкуется с `libssl.so.3`, гейт
> `INCLUDE_HTTP3=yes` проходит, `SSL_set_quic_tls_cbs` найден, все юнит-тесты
> зелёные. Строка `ciphers` из `config.json` принята обеими половинами API
> (`set_cipher_list` + `set_ciphersuites`), политика в `/etc/ssl/openssl.cnf`
> ничего не ужесточает.

Это **QUIC TLS API** — режим, в котором libssl делает только рукопожатие TLS 1.3
и отдаёт наружу байты для CRYPTO-фреймов и выведенные секреты уровней. Весь
QUIC-транспорт при этом наш. Ровно то разделение, которое просил заказчик.

Из библиотеки используем:

- TLS 1.3 handshake, сертификаты, SNI, ALPN, session tickets — `SSL`/`SSL_CTX`;
- примитивы: `EVP_AEAD`-эквиваленты (`EVP_CIPHER` AES-128-GCM, AES-256-GCM,
  ChaCha20-Poly1305), AES-ECB и ChaCha20 для header protection,
  HKDF (`EVP_KDF` «HKDF») либо HMAC-SHA256/384 напрямую, `RAND_bytes`.

Из библиотеки **не** используем: `OSSL_QUIC_client_method()` и всё, что в
`openssl/quic.h`, — это встроенный QUIC-стек OpenSSL, он у нас запрещён (и на
сервере он в 3.5 всё равно неполноценен).

### 2.2 Что пишем сами — целиком

varint; парсинг/сборка long и short header; version negotiation; все фреймы;
Connection ID и stateless reset; transport parameters; key schedule поверх
секретов от libssl; AEAD-обёртки пакетов; header protection; Retry и токены
валидации адреса; реассемблирование CRYPTO; конечные автоматы потоков; буферы
приёма с дырами и передачи с диапазонами ретрансмиссии; flow control обоих
уровней; генерация и разбор ACK-диапазонов; loss detection и PTO; congestion
control; pacing; path validation и миграция; anti-amplification; таймеры;
всё HTTP/3; весь QPACK; qlog.

### 2.3 Требование к версии OpenSSL

QUIC TLS API появился в **OpenSSL 3.5**. Проект сейчас собирается с 1.1.1+.
Поэтому HTTP/3 — **опциональная сборка**:

```cmake
option(INCLUDE_HTTP3 "Build QUIC/HTTP/3 support" OFF)
```

и в CMake — жёсткая проверка: при `INCLUDE_HTTP3=yes` требуется
`OPENSSL_VERSION_MAJOR >= 3 && OPENSSL_VERSION_MINOR >= 5`, иначе конфигурация
падает с внятным сообщением. Весь код QUIC/H3 компилируется только при этом
флаге; в `connection_s.h` и `server.h` поля под h3 закрываются `#ifdef`, чтобы
сборка без h3 не менялась ни на байт.

Запасной вариант, если понадобится поддержать старый OpenSSL: интерфейс
`quictls_t` (см. `03-quic-tls.md` §2) спроектирован как узкий вентиль из шести
колбэков — под ним можно реализовать backend на `SSL_QUIC_METHOD` (quictls
fork / BoringSSL) без изменений в транспорте. Свой TLS 1.3 писать не будем: это
не «криптография как библиотека», это отдельный проект.

## 3. Границы версии 1

**Входит:**

- QUIC v1 (`0x00000001`), только серверная роль;
- TLS 1.3, 1-RTT, ALPN `h3`;
- Retry и валидация адреса токеном;
- полный набор фреймов RFC 9000, включая миграцию и path validation;
- NewReno или CUBIC (RFC 9438) + pacing;
- HTTP/3: GET/POST/PUT/…, тела запросов, trailers и 103 Early Hints;
- Full QPACK: динамические encoder/decoder tables, оба instruction streams,
  blocked request streams, acknowledgments/cancellation и защищённая eviction;
- IPv4 endpoint; UDP GSO (`UDP_SEGMENT`) для пакетной отправки;
- 0-RTT (RFC 9001 §4.6) за ключом `http3_early_data`, по умолчанию выключенный.

**Не входит (осознанно):**

| Что | Почему |
|---|---|
| Server Push (`PUSH_PROMISE`) | По тем же причинам, что h2-push был удалён из проекта — см. `docs/http2/07`. Реализуем только приём `MAX_PUSH_ID` и игнорирование |
| QUIC v2 (RFC 9369), совместимое согласование версий (RFC 9368) | Только version negotiation-пакет для неизвестных версий |
| Unreliable datagrams (RFC 9221), MASQUE | Нет потребителя |
| Extended CONNECT / WebSocket over HTTP/3 (RFC 9220) | **Закрыто решением (2026-08-15).** Не реализовал ни один браузер и ни один распространённый клиент; нишу двунаправленного канала поверх h3 занял WebTransport. Обоснование и условия пересмотра — `05` §8. WebSocket поверх h1.1 и h2 работает как прежде |
| IPv6 endpoint | Текущий endpoint поддерживает только IPv4 |
| DPLPMTUD (RFC 8899) | Реализован: padded probes, подтверждение ACK, повтор и black-hole fallback |
| ECN | Реализован: ECT(0), ACK_ECN, валидация и реакция на CE |
| UDP GRO | Реализован с автоматическим fallback на обычный receive |
| BBR | NewReno и CUBIC реализованы; BBR отложен до измерений |
| RFC 9218 `PRIORITY_UPDATE` | Оба типа валидируются и учитываются control budget; корректный сигнал игнорируется, urgency scheduling отсутствует |

### 3.1 Актуальная capability matrix

Эта таблица — источник текущего состояния. Фазовые записи ниже сохранены как
журнал разработки и могут описывать первоначальные планы.

| Возможность | Статус |
|---|---|
| QUIC v1, TLS 1.3, Retry, migration, loss recovery, pacing | Готово |
| NewReno / CUBIC / BBR (`http3_cc`) | Готово |
| HTTP/3 server, Alt-Svc, graceful shutdown | Готово |
| Soft reload с сохранением UDP socket/CID | Реализовано; production-статус ждёт integration-гейта с `SIGUSR1` |
| Process connection/memory limits и process-wide rate buckets | Готово |
| QPACK | Полный: динамические таблицы обеих сторон, оба instruction stream, blocked streams |
| UDP batching / GSO | `recvmmsg`, `sendmmsg`, `UDP_SEGMENT` |
| UDP GRO, ECN, DPLPMTUD | Готово |
| IPv6 endpoint | Не реализовано: сокет-слой умеет `AF_INET6`, но `quicendpoint` привязан к IPv4 |
| 0-RTT / early data (`http3_early_data`) | Готово, по умолчанию выключено |
| QUIC v2 | Не реализовано |
| HTTP/3 client, Server Push, Extended CONNECT (RFC 9220) | Вне scope по решению |

## 4. Что переиспользуется из существующего кода

Это главный аргумент за то, что задача выполнима: весь верхний слой уже есть.

| Существующее | Как используется в h3 |
|---|---|
| `hpack_huffman.h` + Huffman-кодек из `hpack.c` | QPACK использует **тот же** код Хаффмана (RFC 9204 ссылается на RFC 7541 Приложение B). Выносим кодек в `misc/huffman.{c,h}`, обе реализации на него ссылаются |
| `gen_tables.py` | Расширяем, чтобы генерировать `qpack_statictable.h` (99 записей) тем же способом |
| `h2field.{c,h}` | Правила валидности имён/значений полей в RFC 9114 §4.3 те же, что в RFC 9113 §8.2.1 — модуль переиспользуется как есть |
| `h2_build_request()` (псевдо-заголовки, склейка `cookie`, `:path`, Range, Content-Length) | ~200 строк, идентичных для h2 и h3. **Рефакторим** в общий `httpfields_to_request()` в `protocols/http/` и вызываем из обоих |
| Цепочка фильтров (`http_range_filter`, `http_data_filter`, `http_gzip_filter`, `http_not_modified_filter`) | Без изменений; терминальный `h3_write_filter` вместо `h2_write_filter` |
| `http_server_dispatch()`, роутинг, middleware, ratelimiter, sessions, ORM | Без изменений |
| `connection_queue_append_parallel()`, `connection_s_lock()`, publish-queue | Модель конкурентности h2 переносится 1:1 (см. `docs/concurrency/`) |
| `src/metrics/` | Добавляем секции `quic` и `http3`, новые `LOCK_SITE_*` |
| Паттерн timerfd из `multiplexingepoll.c` | QUIC-эндпоинт заводит собственный timerfd с динамическим взводом |
| SNI-колбэки, `openssl_t` на vhost | Тот же `SSL_CTX`, добавляется `h3` в ALPN |
| `h2ws.c` | Не переиспользуется: WebSocket-over-h3 закрыт решением (`05` §8), `h3ws.c` не существует |

**Не** переиспользуется: `h2frame`, `h2session`, `h2stream`, `h2data`,
`h2_write_filter` — кадрирование и мультиплексирование в h3 принципиально
другие (мультиплексирование ушло в транспорт).

## 5. Ключевые архитектурные решения

Расписаны подробно в `01`, здесь — резюме, чтобы решения были видны сразу.

**ADR-1. Виртуальные соединения, а не сокет на соединение.**
Один UDP-сокет на воркер + таблица `DCID → quicconn_t`. Альтернатива —
`connect()`-нутый UDP-сокет на каждое QUIC-соединение — позволила бы не трогать
`connection_t`/epoll вообще, но ломает миграцию и NAT-rebinding (пакет с нового
адреса уйдёт на wildcard-сокет) и тратит дескриптор на соединение. Отклонено.

**ADR-2. `quicconn_t` содержит настоящий `connection_t`.**
Так весь верхний слой (контексты, локи, refcount, очередь хендлеров, фильтры)
работает без правок. Но `connection_t` перестаёт быть «то, что лежит в epoll»:
вводим `connection_t::transport` (`TCP`/`QUIC`), и все `control_add/mod/del`,
`rearm`, `connection_park_rearm` для QUIC уходят не в `epoll_ctl`, а в
«эндпоинту есть что отправить».

**ADR-3. Таблица соединений — глобальная и шардированная, не по воркерам.**
Воркеры — потоки одного процесса, память общая. Пакет, попавший «не на тот»
воркер (SO_REUSEPORT хеширует по 4-кортежу, а QUIC живёт по CID и мигрирует),
обрабатывается на месте под `connection_s_lock`, а пробуждается сокет
соединения-владельца. Корректность от этого не зависит; локальность зависит,
поэтому соединение, которому чужой воркер достался всерьёз (миграция,
NAT-rebind), переносится к нему — `09` §2.6. Аффинность сделана переносом
владения, а не разбором CID: байт `[0]` server-chosen CID так и остался
незанятым, и там же объяснено, почему в сервере на потоках он не окупается.

**ADR-4. Собственный timerfd у эндпоинта.**
Тик воркера — 500 мс, для PTO и pacing это на два порядка грубо. Эндпоинт держит
min-heap дедлайнов и перевзводит свой timerfd на ближайший. Регистрация — как у
`api->timerfd`, через `ev.data.ptr` с тегом.

**ADR-5. Адреса — `sockaddr_storage` с самого начала.**
Сейчас сокет-слой чисто IPv4 (`in_addr_t`, `AF_INET`). QUIC обязан хранить
локальный и удалённый адрес на каждом пути и уметь их менять, поэтому
QUIC-структуры используют `sockaddr_storage`, а на wildcard-bind обязателен
`IP_PKTINFO`/`IPV6_RECVPKTINFO` — иначе ответ уйдёт с неверного источника.
Побочный эффект: h3 станет первым куском проекта с IPv6. Совместимость с
`connection_t::remote_ip` (используется ratelimiter) обеспечивается заполнением
поля для IPv4 и отдельным путём для IPv6 (см. `01` §7).

**ADR-6. Ретрансмиссия на уровне фреймов.**
Пакет никогда не отправляется повторно. Потерянный пакет разбирается на список
фреймов, «нужные» (STREAM, CRYPTO, RESET_STREAM, MAX_*, …) возвращаются в
очередь на отправку и уезжают в новом пакете с новым номером. Это требование
RFC 9000 §13.3 и оно определяет форму `quicsendbuf` и `quicloss`.

## 6. Карта фаз

Фазы упорядочены так, чтобы каждая заканчивалась чем-то проверяемым.

| Фаза | Название | Документ | Объём | Критерий готовности |
|---|---|---|---|---|
| 0 | Каркас сборки, `INCLUDE_HTTP3`, скелет модулей, qlog-заглушка | `01` §1 | S | **Сделано.** Собирается с и без флага; тесты зелёные в обеих |
| 1 | UDP-эндпоинт, демультиплексирование, таймеры | `01` | L | **Сделано.** Эндпоинт принимает датаграммы, отвечает Version Negotiation и stateless reset, бюджеты держат, метрики считают. Виртуальные соединения и таймеры ушли в фазы 3–4: в фазе 1 нет ни соединений, ни дедлайнов |
| 2 | Ядро QUIC: varint, пакеты, фреймы, transport params | `02` | L | **Сделано.** Векторы RFC 9000 Приложения A сходятся; +216 проверок. Управление CID (последовательности, retire) перенесено в фазу 4 — это состояние соединения, а не кодек |
| 3 | QUIC-TLS: key schedule, AEAD, header protection, интеграция с libssl | `03` | L | **Сделано.** Векторы RFC 9001 Приложения A сходятся; рукопожатие TLS 1.3 проходит между двумя мостами в памяти. Проверка `curl --http3` перенесена в фазу 4: без `quicconn_t` соединения не создаются, и QUIC-клиента в системе нет |
| 4 | Транспорт: потоки, flow control, ACK, loss detection, NewReno, pacing, закрытие | `04` | XL | **Сделано.** Соединение живёт: настоящий Initial принят, расшифрован, PING обработан, ACK вернулся расшифровываемым. Пропускная способность и устойчивость к потерям — фаза 8, нужен тестовый клиент |
| 5 | HTTP/3: кадры, служебные потоки, SETTINGS, интеграция с dispatch и фильтрами | `05` | L | `curl --http3 https://host/` отдаёт страницу; статические файлы, POST с телом |
| 6 | QPACK | `06` | L | Векторы RFC 9204 Приложение B; Chrome/Firefox открывают сайт |
| 7 | Интеграция: конфиг, Alt-Svc, метрики, лимиты, shutdown/reload (WebSocket over h3 исключён решением, `05` §8) | `07` | M | Браузер сам переключается на h3 после Alt-Svc; `/metrics` показывает секцию quic |
| 8 | Тесты и interop | `08` | L | quic-interop-runner: handshake, transfer, retry, resumption, multiplexing, http3 — зелёные; h3spec без падений |
| 9 | Отложенное: обязательное (закрыто), производительность (BBR, аффинность, обход списка потоков — остальное сделано), опции (0-RTT сделан, QUIC v2 — по потребности) | `09` | — | По отдельности, каждый пункт за своим флагом и со своим критерием — см. `09` |

Таблица выше сохраняет исторический порядок внедрения. Фазы 2 и 3 частично
параллелились; 5 и 6 — нет. Начальный QPACK-lite впоследствии заменён full
QPACK; актуальное состояние описано в `06` §6.2.

## 7. Порядок каталогов

```
core/src/udp/                      udpsocket.{c,h}   — сокет, опции, recvmmsg/sendmmsg
                                   quicendpoint.{c,h}— демультиплексор, таблица CID, таймеры

core/protocols/quic/
  common/  quic.h        varint.{c,h}      quicpacket.{c,h}  quicframe.{c,h}
           quiccid.{c,h} quictp.{c,h}      quicerror.{c,h}
           quictime.{c,h}  quicqlog.{c,h}  — время и qlog нужны всем слоям,
                                             поэтому здесь, а не в transport/
  crypto/  quiccrypto.{c,h}  quichp.{c,h}  quicretry.{c,h}  quictls.{c,h}
  transport/ quicconn.{c,h}   quicstream.{c,h}  quicrecvbuf.{c,h} quicsendbuf.{c,h}
             quicflow.{c,h}   quicack.{c,h}     quicloss.{c,h}    quiccc.{c,h}
             quicpacer.{c,h}  quicpath.{c,h}    quictimer.{c,h}

core/protocols/http3/
  frame/   h3frame.{c,h}  h3error.{c,h}
  qpack/   qpack.{c,h}  qpack_statictable.h  (+ misc/huffman.{c,h} общий с HPACK)
  server/  h3session.{c,h}  h3stream.{c,h}  h3_write_filter.{c,h}
```

Каждый каталог — свой `CMakeLists.txt` по образцу существующих; всё попадает в
`libcwfr_framework.so`, как и h2.

## 8. Риски

| Риск | Митигация |
|---|---|
| Отладка бинарного шифрованного протокола | qlog с первой фазы (`04` §10) + `SSLKEYLOGFILE` + Wireshark. Без этого фаза 4 неотлаживаема |
| Loss detection — источник тонких багов | Юнит-тесты на детерминированном таймере (время инжектируется, а не берётся из `clock_gettime`) |
| QPACK blocked streams — самый сложный кусок | Стартуем с capacity 0 (лимит на нашей стороне), полная динамическая таблица — отдельным шагом с векторами |
| Гонки: пакеты одного соединения на двух воркерах | `connection_s_lock` уже покрывает; TSan-сборка обязательна в CI фазы 4 (`-DSANITIZE=thread`) |
| Amplification-атаки и DoS | Anti-amplification 3× — MUST, реализуется в фазе 4 вместе с path validation; бюджеты по образцу `docs/http2/08` фаза A |
| ASan-сборка искажает измерения производительности | Как и в h2: замеры только на Release; `detect_stack_use_after_return=0` при профилировании |

## 9. Ссылки

RFC 8999 (version-independent), **9000** (transport), **9001** (TLS),
**9002** (recovery), 8899 (DPLPMTUD), **9114** (HTTP/3), **9204** (QPACK),
9218 (priorities), 9220 (WebSocket over h3), 9221 (datagram), 9287 (grease bit),
9368/9369 (v2), 7838 (Alt-Svc), 9460 (SVCB/HTTPS RR),
draft-ietf-quic-qlog-* (qlog).
