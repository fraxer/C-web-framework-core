# C Web Framework

Высокопроизводительный веб-сервер и фреймворк для создания веб-приложений на языке C для Linux. Построен на базе событийно-ориентированной архитектуры epoll, обеспечивающей эффективную обработку большого количества одновременных соединений.

Фреймворк предоставляет полный набор инструментов для разработки современных веб-приложений: от базового HTTP-сервера до работы с базами данных, WebSocket-соединениями, системой аутентификации и файловыми хранилищами.

Документация доступна по адресу: [https://cwebframework.tech/en/introduction.html](https://cwebframework.tech/en/introduction.html)

## Основные возможности

### HTTP Сервер
* **HTTP/1.1** - полная поддержка протокола HTTP/1.1
* **Маршрутизация** - гибкая система роутинга с поддержкой динамических параметров
* **Редиректы** - настраиваемые правила перенаправления с поддержкой регулярных выражений
* **Middleware** - система промежуточных обработчиков для HTTP и WebSocket запросов
* **Фильтры** - встроенные фильтры для chunked encoding, range requests, gzip, cache control
* **Multipart/Form-data** - обработка файловых загрузок и форм
* **Cookie** - полная поддержка cookie с настройками secure, httpOnly, sameSite
* **Gzip сжатие** - автоматическое сжатие ответов для поддерживаемых типов контента
* **TLS/SSL** - защищенные соединения с настраиваемыми cipher suites

### WebSocket
* **WebSocket сервер** - полная поддержка протокола WebSocket
* **Broadcasting** - система рассылки сообщений группам клиентов
* **Кастомные каналы** - создание именованных каналов с фильтрацией получателей
* **JSON over WebSocket** - встроенная поддержка JSON-сообщений
* **WebSocket middleware** - система промежуточных обработчиков для WebSocket

### Базы данных
* **PostgreSQL** - нативная поддержка с prepared statements
* **MySQL** - нативная поддержка с защитой от SQL-инъекций
* **Redis** - поддержка Redis для кеширования и сессий
* **ORM-подобная работа** - система моделей для работы с таблицами
* **Миграции** - система версионирования схемы базы данных с up/down миграциями
* **Query Builder** - безопасное построение SQL-запросов с параметризацией
* **Prepared Statements** - защита от SQL-инъекций на уровне фреймворка

### Аутентификация и безопасность
* **Система аутентификации** - встроенная система регистрации и авторизации
* **Сессии** - поддержка файловых сессий и сессий в Redis
* **Хеширование паролей** - безопасное хранение паролей с использованием salt и hash
* **Валидация** - валидаторы для email, паролей и других данных
* **Middleware аутентификации** - защита роутов с проверкой сессий
* **RBAC** - система ролей и прав доступа (Role-Based Access Control)

### Файловое хранилище
* **Локальное хранилище** - работа с файловой системой
* **S3-совместимое хранилище** - интеграция с S3 и S3-совместимыми сервисами
* **Файловые операции** - создание, чтение, обновление, удаление файлов
* **Временные файлы** - автоматическое управление временными файлами
* **Загрузка файлов** - обработка multipart загрузок с сохранением в хранилище

### Email
* **SMTP клиент** - отправка email через SMTP
* **DKIM подпись** - поддержка DKIM-подписи для аутентификации отправителя
* **Шаблоны писем** - возможность использования шаблонов для email

### Шаблонизатор
* **Template Engine** - встроенный движок шаблонов
* **Переменные и циклы** - динамическая генерация HTML
* **Интеграция с моделями** - прямая передача моделей в шаблоны

### JSON
* **JSON парсер** - высокопроизводительный парсер JSON
* **JSON генератор** - сериализация данных в JSON
* **Потокобезопасность** - thread-safe операции с JSON
* **Unicode поддержка** - корректная обработка Unicode-символов и surrogate pairs

### Производительность и масштабируемость
* **Event-Driven Architecture** - архитектура на основе epoll
* **Многопоточность** - поддержка нескольких worker-потоков
* **Пул соединений** - переиспользование соединений к базам данных
* **Rate Limiting** - ограничение частоты запросов (защита от DDoS)
* **Горячая перезагрузка** - обновление приложения без остановки сервера

### Утилиты и структуры данных
* **String (str_t)** - динамические строки с SSO-оптимизацией
* **Array** - динамические массивы
* **HashMap/Map** - ассоциативные массивы для быстрого поиска
* **JSON структуры** - работа с JSON как с объектами
* **Логирование** - система логирования с разными уровнями
* **Base64** - кодирование/декодирование Base64

### Дополнительно
* **Модульная архитектура** - легкое подключение и отключение компонентов
* **Динамическая загрузка** - загрузка обработчиков из shared libraries (.so)
* **Настройка через JSON** - централизованная конфигурация в config.json
* **MIME types** - автоматическое определение типов контента
* **Домены и виртуальные хосты** - поддержка нескольких доменов на одном сервере

## Архитектура проекта

```
backend/
├── core/                          # Ядро фреймворка
│   ├── framework/                 # Компоненты фреймворка
│   │   ├── database/             # Работа с БД (PostgreSQL, MySQL, Redis)
│   │   ├── model/                # ORM-система моделей
│   │   ├── session/              # Система сессий
│   │   ├── storage/              # Файловые хранилища (FS, S3)
│   │   ├── view/                 # Шаблонизатор
│   │   ├── middleware/           # Система middleware
│   │   └── query/                # Query builder
│   ├── protocols/                # Реализация протоколов
│   │   ├── http/                 # HTTP/1.1 сервер и клиент
│   │   ├── websocket/            # WebSocket сервер
│   │   └── smtp/                 # SMTP клиент, DKIM
│   ├── src/                      # Основные компоненты
│   │   ├── broadcast/            # Broadcasting система
│   │   ├── connection/           # Управление соединениями
│   │   ├── server/               # HTTP сервер
│   │   ├── route/                # Система маршрутизации
│   │   ├── thread/               # Многопоточность
│   │   └── multiplexing/         # Epoll multiplexing
│   └── misc/                     # Утилиты
│       ├── str.h                 # Динамические строки
│       ├── array.h               # Массивы
│       ├── hashmap.h/map.h       # Ассоциативные массивы
│       ├── json.h                # JSON парсер
│       ├── log.h                 # Логирование
│       └── gzip.h                # Gzip сжатие
│
└── app/                          # Пользовательское приложение
    ├── routes/                   # HTTP и WebSocket обработчики
    │   ├── auth/                # Аутентификация (login, registration)
    │   ├── index/               # Главная страница
    │   ├── ws/                  # WebSocket handlers
    │   ├── files/               # Работа с файлами
    │   ├── models/              # API для работы с моделями
    │   ├── email/               # Отправка email
    │   └── db/                  # Примеры работы с БД
    ├── models/                   # Модели данных
    │   ├── user.c               # Модель пользователя
    │   ├── role.c               # Модель роли
    │   ├── permission.c         # Модель прав доступа
    │   └── *view.c              # View модели для JOIN-запросов
    ├── middlewares/              # Пользовательские middleware
    │   ├── httpmiddlewares.c    # HTTP middleware (auth, rate limit)
    │   └── wsmiddlewares.c      # WebSocket middleware
    ├── migrations/               # Миграции базы данных
    │   ├── s1/                  # Миграции для сервера s1
    │   └── s2/                  # Миграции для сервера s2
    ├── broadcasting/             # Broadcasting каналы
    │   └── mybroadcast.c        # Пример broadcasting канала
    ├── auth/                     # Модуль аутентификации
    │   ├── auth.c               # Функции аутентификации
    │   ├── password_validator.c # Валидация паролей
    │   └── email_validator.c    # Валидация email
    ├── contexts/                 # Контексты запросов
    │   ├── httpcontext.c        # HTTP контекст
    │   └── wscontext.c          # WebSocket контекст
    └── views/                    # Шаблоны
        ├── index.tpl            # Главная страница
        └── header.tpl           # Хедер

config.json                       # Конфигурация приложения
```

## Примеры использования

### HTTP обработчик

```c
#include "http1.h"

void my_handler(httpctx_t* ctx) {
    // Получение query параметра
    const char* name = ctx->request->query(ctx->request, "name");

    // Получение JSON из тела запроса
    json_doc_t* doc = ctx->request->payload_json(ctx->request);

    // Работа с JSON
    json_token_t* root = json_root(doc);
    json_object_set(root, "status", json_create_string("success"));

    // Установка заголовка
    ctx->response->header_add(ctx->response, "Content-Type", "application/json");

    // Отправка ответа
    ctx->response->data(ctx->response, json_stringify(doc));

    json_free(doc);
}
```

### WebSocket обработчик с Broadcasting

```c
#include "websockets.h"
#include "broadcast.h"

void ws_join_channel(wsctx_t* ctx) {
    // Присоединение к broadcasting каналу
    broadcast_add("my_channel", ctx->request->connection,
                  user_id_struct, send_callback);

    ctx->response->data(ctx, "Joined channel");
}

void ws_send_message(wsctx_t* ctx) {
    websockets_protocol_resource_t* protocol =
        (websockets_protocol_resource_t*)ctx->request->protocol;

    char* message = protocol->payload(protocol);

    // Отправка сообщения всем в канале
    broadcast_send("my_channel", ctx->request->connection,
                   message, strlen(message), filter_struct, compare_func);

    free(message);
}
```

### Работа с базой данных

```c
#include "db.h"
#include "model.h"

void get_users(httpctx_t* ctx) {
    // Параметризованный запрос (защита от SQL-инъекций)
    mparams_create_array(params,
        mparam_int(id, 123),
        mparam_text(email, "user@example.com")
    );

    dbresult_t* result = dbquery("postgresql",
        "SELECT * FROM users WHERE id = :id OR email = :email",
        params);

    array_free(params);

    if (!dbresult_ok(result)) {
        ctx->response->data(ctx->response, "Query error");
        dbresult_free(result);
        return;
    }

    // Обработка результатов
    for (int row = 0; row < dbresult_query_rows(result); row++) {
        const db_table_cell_t* field = dbresult_cell(result, row, 0);
        // Работа с данными...
    }

    dbresult_free(result);
}
```

### Работа с моделями (ORM)

```c
#include "user.h"

void create_user_example(httpctx_t* ctx) {
    // Создание экземпляра модели
    user_t* user = user_instance();

    // Установка значений
    user_set_email(user, "newuser@example.com");
    user_set_name(user, "John Doe");

    // Генерация хеша пароля
    str_t* secret = generate_secret("password123");
    user_set_secret(user, str_get(secret));
    str_free(secret);

    // Сохранение в БД
    if (!user_create(user)) {
        ctx->response->data(ctx->response, "Error creating user");
        model_free(user);
        return;
    }

    // Вывод модели в JSON
    ctx->response->model(ctx->response, user,
                        display_fields("id", "email", "name"));

    model_free(user);
}
```

### Middleware

```c
#include "httpmiddlewares.h"

// Защищенный роут с middleware
void secret_page(httpctx_t* ctx) {
    // Проверка аутентификации через middleware
    middleware(
        middleware_http_auth(ctx)
    )

    // Этот код выполнится только если пользователь авторизован
    user_t* user = httpctx_get_user(ctx);
    ctx->response->data(ctx->response, "Welcome to secret page!");
}
```

### Файловое хранилище

```c
#include "storage.h"

void upload_file(httpctx_t* ctx) {
    // Получение загруженного файла
    file_content_t content = ctx->request->payload_filef(ctx->request, "myfile");

    if (!content.ok) {
        ctx->response->data(ctx->response, "File not found");
        return;
    }

    // Сохранение в S3-хранилище
    storage_file_content_put("remote", &content,
                            "uploads/%s", content.filename);

    ctx->response->data(ctx->response, "File uploaded");
}

void download_file(httpctx_t* ctx) {
    // Получение файла из локального хранилища
    file_t file = storage_file_get("local", "/path/to/file.txt");

    if (!file.ok) {
        ctx->response->data(ctx->response, "File not found");
        return;
    }

    // Отправка файла клиенту
    ctx->response->file(ctx->response, file.path);
    file.close(&file);
}
```

### Отправка Email с DKIM

```c
#include "mail.h"

void send_email(httpctx_t* ctx) {
    mail_payload_t payload = {
        .from = "noreply@example.com",
        .from_name = "My Application",
        .to = "user@example.com",
        .subject = "Welcome!",
        .body = "Welcome to our service!"
    };

    if (!send_mail(&payload)) {
        ctx->response->data(ctx->response, "Error sending email");
        return;
    }

    ctx->response->data(ctx->response, "Email sent");
}
```

## Конфигурация

Фреймворк использует `config.json` для централизованной настройки:

```json
{
  "main": {
    "workers": 4,
    "threads": 2,
    "reload": "hard",
    "buffer_size": 16384,
    "gzip": ["text/html", "application/json"]
  },
  "servers": {
    "s1": {
      "domains": ["example.com", "*.example.com"],
      "ip": "127.0.0.1",
      "port": 80,
      "http": {
        "routes": {
          "/api/users": {
            "GET": ["path/to/handler.so", "get_users"]
          }
        }
      },
      "websockets": {
        "routes": {
          "/ws": {
            "GET": ["path/to/ws_handler.so", "websocket_handler"]
          }
        }
      },
      "tls": {
        "fullchain": "/path/to/fullchain.pem",
        "private": "/path/to/privkey.pem"
      }
    }
  },
  "databases": {
    "postgresql": [{
      "host_id": "p1",
      "ip": "127.0.0.1",
      "port": 5432,
      "dbname": "mydb",
      "user": "dbuser",
      "password": "dbpass"
    }]
  },
  "sessions": {
    "driver": "redis",
    "lifetime": 3600
  }
}
```

## Системные требования

* **Glibc** 2.35 или выше
* **GCC** 9.5.0 или выше
* **CMake** 3.12.4 или выше
* **PCRE** 8.43 (Regular Expression Library)
* **Zlib** 1.2.11 (data compression library)
* **OpenSSL** 1.1.1k или выше
* **LibXml2** 2.9.13

### Опциональные зависимости:
* **PostgreSQL** development libraries (для поддержки PostgreSQL)
* **MySQL/MariaDB** development libraries (для поддержки MySQL)
* **Redis** (для Redis-сессий и кеширования)

## Сборка проекта

```bash
# Создание директории для сборки
mkdir build && cd build

# Конфигурация с CMake
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DINCLUDE_POSTGRESQL=yes \
         -DINCLUDE_MYSQL=yes \
         -DINCLUDE_REDIS=yes

# Сборка
cmake --build . -j4

# Запуск
./exec/app
```

### Режимы сборки:
* **Release** - оптимизированная версия для production
* **Debug** - версия с отладочными символами и AddressSanitizer
* **RelWithDebInfo** - оптимизированная версия с отладочной информацией

## Ключевые особенности

### Производительность
* **Zero-copy** операции где возможно
* **Пул соединений** к базам данных для минимизации overhead
* **Epoll** для эффективного мультиплексирования I/O
* **SSO (Small String Optimization)** для строк
* **Lazy-loading** конфигурации и модулей

### Безопасность
* **Prepared statements** для защиты от SQL-инъекций
* **Валидация входных данных** на всех уровнях
* **HTTPS/TLS** с современными cipher suites
* **Secure cookie** с httpOnly и sameSite флагами
* **Rate limiting** для защиты от DDoS
* **DKIM** подписи для email-аутентификации
* **Хеширование паролей** с использованием криптографически стойких функций

### Масштабируемость
* **Горизонтальное масштабирование** через несколько worker-процессов
* **Вертикальное масштабирование** через многопоточность
* **Поддержка виртуальных хостов** для множества доменов
* **Broadcasting** для эффективной рассылки WebSocket-сообщений
* **Асинхронная обработка** запросов

### Удобство разработки
* **Модульная архитектура** - подключайте только нужные компоненты
* **Динамическая загрузка** обработчиков без перезапуска сервера
* **Система миграций** для версионирования БД
* **ORM-like модели** для упрощения работы с данными
* **Middleware система** для переиспользования логики
* **Template Engine** для генерации динамического контента
* **Централизованная конфигурация** через JSON

## Применение

Фреймворк подходит для разработки:

* **REST API** - высокопроизводительные API для мобильных и веб-приложений
* **Real-time приложения** - чаты, уведомления, live-обновления через WebSocket
* **Веб-сервисы** - микросервисы и монолитные приложения
* **API Gateway** - маршрутизация и проксирование запросов
* **Админ-панели** - с аутентификацией, RBAC и CRUD-операциями
* **File upload сервисы** - с поддержкой локального и облачного хранилища
* **Email сервисы** - отправка транзакционных писем с DKIM

## Документация

Полная документация доступна по адресу: [https://cwebframework.tech/en/introduction.html](https://cwebframework.tech/en/introduction.html)

