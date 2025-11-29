# Тесты для backend/core

Этот каталог содержит unit-тесты для проекта cpdy.

## Структура

- `framework.h` - заголовочный файл с макросами тестового фреймворка
- `runner.c` - основной раннер, который автоматически запускает все зарегистрированные тесты
- `test_json.c` - тесты для JSON парсера
- `CMakeLists.txt` - конфигурация сборки тестов (автоматически собирает все файлы `test_*.c`)

## Сборка тестов

### Базовая сборка

```bash
cd backend
mkdir -p build
cd build
cmake .. -DBUILD_TESTS=ON
cmake --build .
```

### Сборка только тестов

```bash
cd build
cmake --build . --target runner
```

## Запуск тестов

### Запуск всех тестов напрямую

```bash
cd build
./exec/runner
```

### Запуск через CTest

CTest автоматически найдёт и запустит все тесты:

```bash
cd build
ctest
```

### Запуск с подробным выводом

```bash
ctest --verbose
```

или показать вывод только при ошибках:

```bash
ctest --output-on-failure
```

### Запуск конкретного теста

```bash
ctest -R core_tests
```

## Отключение сборки тестов

Если вы не хотите собирать тесты:

```bash
cmake .. -DBUILD_TESTS=OFF
```

## Написание новых тестов

### Структура теста

1. Создайте новый файл `test_<module>.c` в этой директории
2. Включите заголовочный файл `framework.h`
3. Напишите тестовые функции
4. Зарегистрируйте тесты с помощью одного из макросов регистрации

CMakeLists.txt автоматически подхватит все файлы, начинающиеся с `test_*.c`!

### Доступные макросы

**Объявление тестов:**
- `TEST_SUITE(name)` - объявление набора тестов
- `TEST_CASE(name)` - объявление тестового случая

**Проверки (assertions):**
- `TEST_ASSERT(condition, message)` - проверка условия
- `TEST_ASSERT_EQUAL(expected, actual, message)` - проверка равенства чисел (int, long и т.д.)
- `TEST_ASSERT_EQUAL_SIZE(expected, actual, message)` - проверка равенства size_t (для strlen, sizeof и т.д.)
- `TEST_ASSERT_EQUAL_UINT(expected, actual, message)` - проверка равенства unsigned int
- `TEST_ASSERT_STR_EQUAL(expected, actual, message)` - проверка равенства строк
- `TEST_ASSERT_NOT_NULL(ptr, message)` - проверка, что указатель не NULL
- `TEST_ASSERT_NULL(ptr, message)` - проверка, что указатель NULL

**Регистрация тестов:**
- `REGISTER_TEST_SUITE(func)` - автоматическая регистрация набора тестов
- `REGISTER_TEST_CASE(func)` - автоматическая регистрация отдельной тестовой функции
- `TEST(name)` - объявление и автоматическая регистрация теста в одной строке (рекомендуется)

### Пример 1: Использование макроса TEST() (РЕКОМЕНДУЕТСЯ ✨)

Самый простой и короткий способ - использовать макрос `TEST()`:

```c
#include "framework.h"
#include "my_module.h"

TEST(test_addition) {
    TEST_CASE("Test addition operation");
    TEST_ASSERT_EQUAL(5, my_add(2, 3), "2 + 3 should equal 5");
    TEST_ASSERT_EQUAL(10, my_add(7, 3), "7 + 3 should equal 10");
}

TEST(test_subtraction) {
    TEST_CASE("Test subtraction operation");
    TEST_ASSERT_EQUAL(3, my_subtract(5, 2), "5 - 2 should equal 3");
    TEST_ASSERT_EQUAL(-5, my_subtract(0, 5), "0 - 5 should equal -5");
}

TEST(test_string_operations) {
    TEST_CASE("Test string operations");
    char* result = my_concat("hello", " world");
    TEST_ASSERT_NOT_NULL(result, "Result should not be NULL");
    TEST_ASSERT_STR_EQUAL("hello world", result, "Concatenation should work");
    free(result);
}
```

**Вот и всё!** Никаких дополнительных строк с `REGISTER_*` не нужно.

### Пример 2: Группировка тестов в Test Suite

Для группировки связанных тестов используйте `REGISTER_TEST_SUITE`:

```c
#include "framework.h"

static void test_basic_ops(void) {
    TEST_CASE("Basic operations");
    TEST_ASSERT_EQUAL(4, 2 + 2, "2 + 2 should equal 4");
    TEST_ASSERT_EQUAL(10, 5 * 2, "5 * 2 should equal 10");
}

static void test_edge_cases(void) {
    TEST_CASE("Edge cases");
    TEST_ASSERT_EQUAL(0, 0 * 100, "0 * 100 should equal 0");
    TEST_ASSERT_EQUAL(-5, 0 - 5, "0 - 5 should equal -5");
}

static void run_math_tests(void) {
    TEST_SUITE("Math Module Tests");
    test_basic_ops();
    test_edge_cases();
}

REGISTER_TEST_SUITE(run_math_tests)
```

### Пример 3: Регистрация отдельных функций

Можно регистрировать каждую функцию отдельно:

```c
#include "framework.h"

static void test_addition(void) {
    TEST_CASE("Addition test");
    TEST_ASSERT_EQUAL(4, 2 + 2, "2 + 2 should equal 4");
}
REGISTER_TEST_CASE(test_addition)

static void test_string_ops(void) {
    TEST_CASE("String operations");
    TEST_ASSERT_EQUAL_SIZE(5, strlen("hello"), "Length should be 5");
}
REGISTER_TEST_CASE(test_string_ops)
```

---

## Какой вариант выбрать?

Все три варианта работают одинаково. Выбирайте тот, который удобнее:

1. **`TEST(name)`** - самый короткий и удобный способ ✨ (используется в test_json.c)
2. **`REGISTER_TEST_CASE`** - когда нужно явно показать регистрацию
3. **`REGISTER_TEST_SUITE`** - для группировки связанных тестов в набор

### Пример реального теста

Посмотрите [test_json.c](test_json.c) для примера использования макроса `TEST()`.

### Регистрация нового теста

Тесты регистрируются **автоматически**! Просто создайте файл `test_<name>.c`, и он будет автоматически собран:

```cmake
# CMakeLists.txt автоматически находит все файлы test_*.c
file(GLOB ALL_TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/test_*.c")
```

**Важно:** Используйте один из макросов регистрации (`TEST`, `REGISTER_TEST_SUITE` или `REGISTER_TEST_CASE`), и тесты будут автоматически обнаружены при запуске!

## Примеры запуска

```bash
# Полная пересборка с тестами
cd backend
rm -rf build
mkdir build
cd build
cmake .. -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build .
./exec/runner

# Быстрый запуск после изменений
cd build
cmake --build . --target runner && ./exec/runner

# Запуск через CTest
ctest --output-on-failure
```

## Отладка тестов

Для отладки тестов с помощью gdb:

```bash
cd build
gdb ./exec/runner
(gdb) run
```

Или с AddressSanitizer для поиска утечек памяти:

```bash
cd build
cmake .. -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON
cmake --build .
./exec/runner
```

## Continuous Integration

Для CI можно использовать следующую команду:

```bash
cmake .. -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build .
ctest --output-on-failure
```

Эта команда завершится с ненулевым кодом возврата, если хотя бы один тест упадёт.
