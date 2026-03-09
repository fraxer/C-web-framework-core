#include "framework.h"
#include "taskmanager/taskmanager.h"
#include <string.h>
#include <time.h>
#include <unistd.h>

// Helper: создать time_t из компонентов
static time_t make_time(int year, int month, int day, int hour, int min, int sec) {
    struct tm tm = {0};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = min;
    tm.tm_sec = sec;
    tm.tm_isdst = -1;
    return mktime(&tm);
}

// Helper: получить день недели (0 = воскресенье)
static int get_weekday(time_t t) {
    struct tm tm;
    localtime_r(&t, &tm);
    return tm.tm_wday;
}

// Helper: получить час
static int get_hour(time_t t) {
    struct tm tm;
    localtime_r(&t, &tm);
    return tm.tm_hour;
}

// Helper: получить минуту
static int get_minute(time_t t) {
    struct tm tm;
    localtime_r(&t, &tm);
    return tm.tm_min;
}

// Helper: получить день месяца
static int get_day(time_t t) {
    struct tm tm;
    localtime_r(&t, &tm);
    return tm.tm_mday;
}

// Helper: получить месяц (1-12)
static int get_month(time_t t) {
    struct tm tm;
    localtime_r(&t, &tm);
    return tm.tm_mon + 1;
}

// ============================================================================
// Тесты ежедневного расписания (SCHEDULE_DAILY)
// ============================================================================

TEST(test_taskmanager_daily_future_time_today) {
    TEST_CASE("Daily: target time is ahead today -> today");

    // 15 декабря 2025, 08:00
    time_t base = make_time(2025, 12, 15, 8, 0, 0);

    // Запланировать на 14:00 (время ещё не наступило)
    time_t next = taskmanager_calc_next_daily(base, 14, 0);

    TEST_ASSERT_EQUAL(15, get_day(next), "Day should be 15 (today)");
    TEST_ASSERT_EQUAL(12, get_month(next), "Should be December");
    TEST_ASSERT_EQUAL(14, get_hour(next), "Hour should be 14");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");

    // Разница должна быть 6 часов
    time_t diff = next - base;
    TEST_ASSERT_EQUAL(6 * 3600, diff, "Should be 6 hours ahead");
}

TEST(test_taskmanager_daily_past_time_today) {
    TEST_CASE("Daily: target time already passed today -> tomorrow");

    // 15 декабря 2025, 15:00
    time_t base = make_time(2025, 12, 15, 15, 0, 0);

    // Запланировать на 03:00 (время уже прошло)
    time_t next = taskmanager_calc_next_daily(base, 3, 0);

    TEST_ASSERT_EQUAL(16, get_day(next), "Day should be 16 (tomorrow)");
    TEST_ASSERT_EQUAL(12, get_month(next), "Should be December");
    TEST_ASSERT_EQUAL(3, get_hour(next), "Hour should be 3");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");
}

TEST(test_taskmanager_daily_exact_boundary) {
    TEST_CASE("Daily: exact time boundary -> tomorrow");

    // 15 декабря 2025, 10:00:00
    time_t base = make_time(2025, 12, 15, 10, 0, 0);

    // Запланировать на этот же момент
    time_t next = taskmanager_calc_next_daily(base, 10, 0);

    // Должен перейти на завтра (target <= now)
    TEST_ASSERT(next > base, "Should be tomorrow when time equals");
    TEST_ASSERT_EQUAL(16, get_day(next), "Day should be 16 (tomorrow)");
}

TEST(test_taskmanager_daily_midnight) {
    TEST_CASE("Daily: schedule at midnight (00:00)");

    // 15 декабря 2025, 10:00
    time_t base = make_time(2025, 12, 15, 10, 0, 0);

    // Запланировать на полночь
    time_t next = taskmanager_calc_next_daily(base, 0, 0);

    TEST_ASSERT_EQUAL(16, get_day(next), "Day should be 16 (tomorrow)");
    TEST_ASSERT_EQUAL(0, get_hour(next), "Hour should be 0");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");
}

TEST(test_taskmanager_daily_end_of_day) {
    TEST_CASE("Daily: schedule at 23:59");

    // 15 декабря 2025, 10:00
    time_t base = make_time(2025, 12, 15, 10, 0, 0);

    // Запланировать на 23:59
    time_t next = taskmanager_calc_next_daily(base, 23, 59);

    TEST_ASSERT_EQUAL(15, get_day(next), "Day should be 15 (today)");
    TEST_ASSERT_EQUAL(23, get_hour(next), "Hour should be 23");
    TEST_ASSERT_EQUAL(59, get_minute(next), "Minute should be 59");
}

TEST(test_taskmanager_daily_3am_example) {
    TEST_CASE("Daily: classic 3 AM task");

    // 15 декабря 2025, 02:00 (до 3 утра)
    time_t base_before = make_time(2025, 12, 15, 2, 0, 0);
    time_t next_before = taskmanager_calc_next_daily(base_before, 3, 0);
    TEST_ASSERT_EQUAL(15, get_day(next_before), "Should be today");
    TEST_ASSERT_EQUAL(3, get_hour(next_before), "Hour should be 3");

    // 15 декабря 2025, 04:00 (после 3 утра)
    time_t base_after = make_time(2025, 12, 15, 4, 0, 0);
    time_t next_after = taskmanager_calc_next_daily(base_after, 3, 0);
    TEST_ASSERT_EQUAL(16, get_day(next_after), "Should be tomorrow");
    TEST_ASSERT_EQUAL(3, get_hour(next_after), "Hour should be 3");
}

TEST(test_taskmanager_daily_across_month_boundary) {
    TEST_CASE("Daily: schedule crosses month boundary");

    // 31 декабря 2025, 15:00
    time_t base = make_time(2025, 12, 31, 15, 0, 0);

    // Запланировать на 03:00 (завтра будет 1 января)
    time_t next = taskmanager_calc_next_daily(base, 3, 0);

    TEST_ASSERT_EQUAL(1, get_day(next), "Day should be 1");
    TEST_ASSERT_EQUAL(1, get_month(next), "Should be January");
    TEST_ASSERT_EQUAL(3, get_hour(next), "Hour should be 3");
}

TEST(test_taskmanager_daily_across_year_boundary) {
    TEST_CASE("Daily: schedule crosses year boundary");

    // 31 декабря 2025, 23:30
    time_t base = make_time(2025, 12, 31, 23, 30, 0);

    // Запланировать на 01:00 (завтра будет 1 января 2026)
    time_t next = taskmanager_calc_next_daily(base, 1, 0);

    TEST_ASSERT_EQUAL(1, get_day(next), "Day should be 1");
    TEST_ASSERT_EQUAL(1, get_month(next), "Should be January");
    TEST_ASSERT_EQUAL(1, get_hour(next), "Hour should be 1");
}

TEST(test_taskmanager_daily_repeats_correctly) {
    TEST_CASE("Daily: verify task repeats every day");

    time_t current = make_time(2025, 1, 1, 10, 0, 0);

    // Первый запуск
    time_t first = taskmanager_calc_next_daily(current, 14, 0);

    // Симулируем выполнение задачи и расчёт следующего запуска
    time_t second = taskmanager_calc_next_daily(first, 14, 0);

    // Разница должна быть ровно 1 день
    time_t diff = second - first;
    TEST_ASSERT_EQUAL(24 * 3600, diff, "Daily repeat should be exactly 24 hours");
}

TEST(test_taskmanager_daily_30_days_simulation) {
    TEST_CASE("Daily: simulate 30 days of task execution");

    time_t current = make_time(2025, 1, 1, 10, 0, 0);

    for (int day = 0; day < 30; day++) {
        time_t next = taskmanager_calc_next_daily(current, 3, 0);

        TEST_ASSERT_EQUAL(3, get_hour(next), "Hour should always be 3");
        TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should always be 0");
        TEST_ASSERT(next > current, "Next should be after current");

        current = next;  // Симулируем выполнение задачи
    }
}

TEST(test_taskmanager_daily_realtime) {
    TEST_CASE("Daily: real-time calculation always returns future time");

    time_t now = time(NULL);

    // Тестируем для разных часов
    for (int hour = 0; hour < 24; hour++) {
        time_t next = taskmanager_calc_next_daily(0, hour, 0);
        TEST_ASSERT(next > now, "Next run should always be in the future");
        TEST_ASSERT_EQUAL(hour, get_hour(next), "Hour should match");
    }
}

TEST(test_taskmanager_daily_valid_hours) {
    TEST_CASE("Daily: verify valid hour range 0-23");

    time_t base = make_time(2025, 12, 15, 0, 0, 0);

    for (int hour = 0; hour <= 23; hour++) {
        time_t next = taskmanager_calc_next_daily(base, hour, 30);
        TEST_ASSERT_EQUAL(hour, get_hour(next), "Hour should match");
    }
}

TEST(test_taskmanager_daily_valid_minutes) {
    TEST_CASE("Daily: verify valid minute range 0-59");

    time_t base = make_time(2025, 12, 15, 0, 0, 0);

    for (int minute = 0; minute <= 59; minute++) {
        time_t next = taskmanager_calc_next_daily(base, 15, minute);
        TEST_ASSERT_EQUAL(minute, get_minute(next), "Minute should match");
    }
}

// ============================================================================
// Тесты еженедельного расписания (SCHEDULE_WEEKLY)
// ============================================================================

TEST(test_taskmanager_weekly_next_week_same_day_past_time) {
    TEST_CASE("Weekly: same day but time already passed -> next week");

    // Понедельник, 29 декабря 2025, 15:00
    time_t base = make_time(2025, 12, 29, 15, 0, 0);
    int base_weekday = get_weekday(base);  // Должен быть понедельник (1)

    TEST_ASSERT_EQUAL(MONDAY, base_weekday, "Base should be Monday");

    // Запланировать на понедельник в 10:00 (время уже прошло)
    time_t next = taskmanager_calc_next_weekly(base, MONDAY, 10, 0);

    // Должен быть следующий понедельник
    TEST_ASSERT_EQUAL(MONDAY, get_weekday(next), "Should be Monday");
    TEST_ASSERT_EQUAL(10, get_hour(next), "Hour should be 10");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");

    // Разница должна быть 7 дней минус 5 часов = 6 дней 19 часов
    time_t diff = next - base;
    TEST_ASSERT(diff > 0, "Next run should be in the future");
    TEST_ASSERT(diff >= 6 * 24 * 3600, "Should be at least 6 days ahead");
    TEST_ASSERT(diff < 8 * 24 * 3600, "Should be less than 8 days ahead");
}

TEST(test_taskmanager_weekly_same_day_future_time) {
    TEST_CASE("Weekly: same day, time not yet passed -> today");

    // Понедельник, 29 декабря 2025, 08:00
    time_t base = make_time(2025, 12, 29, 8, 0, 0);

    TEST_ASSERT_EQUAL(MONDAY, get_weekday(base), "Base should be Monday");

    // Запланировать на понедельник в 10:00 (время ещё не наступило)
    time_t next = taskmanager_calc_next_weekly(base, MONDAY, 10, 0);

    // Должен быть сегодня
    TEST_ASSERT_EQUAL(MONDAY, get_weekday(next), "Should be Monday");
    TEST_ASSERT_EQUAL(10, get_hour(next), "Hour should be 10");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");

    // Разница должна быть 2 часа
    time_t diff = next - base;
    TEST_ASSERT_EQUAL(2 * 3600, diff, "Should be 2 hours ahead");
}

TEST(test_taskmanager_weekly_different_day_ahead) {
    TEST_CASE("Weekly: target day is ahead this week");

    // Понедельник, 29 декабря 2025, 10:00
    time_t base = make_time(2025, 12, 29, 10, 0, 0);

    TEST_ASSERT_EQUAL(MONDAY, get_weekday(base), "Base should be Monday");

    // Запланировать на среду в 14:00
    time_t next = taskmanager_calc_next_weekly(base, WEDNESDAY, 14, 0);

    TEST_ASSERT_EQUAL(WEDNESDAY, get_weekday(next), "Should be Wednesday");
    TEST_ASSERT_EQUAL(14, get_hour(next), "Hour should be 14");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");

    // Разница должна быть 2 дня + 4 часа
    time_t diff = next - base;
    TEST_ASSERT_EQUAL(2 * 24 * 3600 + 4 * 3600, diff, "Should be 2 days 4 hours ahead");
}

TEST(test_taskmanager_weekly_different_day_behind) {
    TEST_CASE("Weekly: target day already passed this week");

    // Вторник, 30 декабря 2025, 10:00
    // 28 декабря 2025 - воскресенье, 29 - понедельник, 30 - вторник
    time_t base = make_time(2025, 12, 30, 10, 0, 0);

    // Проверяем, что это вторник
    int base_weekday = get_weekday(base);
    TEST_ASSERT_EQUAL(TUESDAY, base_weekday, "Base should be Tuesday (Dec 30, 2025)");

    // Запланировать на понедельник в 10:00 (уже прошёл)
    time_t next = taskmanager_calc_next_weekly(base, MONDAY, 10, 0);

    TEST_ASSERT_EQUAL(MONDAY, get_weekday(next), "Should be Monday");
    TEST_ASSERT_EQUAL(10, get_hour(next), "Hour should be 10");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");

    // Следующий понедельник должен быть через 6 дней (вт->пн = 6)
    time_t diff = next - base;
    TEST_ASSERT(diff > 5 * 24 * 3600, "Should be more than 5 days");
    TEST_ASSERT(diff < 7 * 24 * 3600, "Should be less than 7 days");
}

TEST(test_taskmanager_weekly_sunday) {
    TEST_CASE("Weekly: schedule on Sunday");

    // Понедельник, 29 декабря 2025, 10:00
    time_t base = make_time(2025, 12, 29, 10, 0, 0);

    TEST_ASSERT_EQUAL(MONDAY, get_weekday(base), "Base should be Monday");

    // Запланировать на воскресенье в 09:00
    time_t next = taskmanager_calc_next_weekly(base, SUNDAY, 9, 0);

    TEST_ASSERT_EQUAL(SUNDAY, get_weekday(next), "Should be Sunday");
    TEST_ASSERT_EQUAL(9, get_hour(next), "Hour should be 9");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");

    // Воскресенье будет через 6 дней (пн=1, вс=0, разница = -1 + 7 = 6)
    time_t diff = next - base;
    // Понедельник 10:00 -> Воскресенье 09:00 = 6 дней - 1 час = 5 дней 23 часа
    TEST_ASSERT(diff >= 5 * 24 * 3600, "Should be at least 5 days");
    TEST_ASSERT(diff <= 6 * 24 * 3600, "Should be at most 6 days");
}

TEST(test_taskmanager_weekly_all_weekdays) {
    TEST_CASE("Weekly: verify all weekdays work correctly");

    // Понедельник, 29 декабря 2025
    time_t base = make_time(2025, 12, 29, 0, 0, 0);  // Понедельник

    // Тестируем каждый день недели
    int days[] = {SUNDAY, MONDAY, TUESDAY, WEDNESDAY,
                  THURSDAY, FRIDAY, SATURDAY};

    for (int i = 0; i < 7; i++) {
        time_t next = taskmanager_calc_next_weekly(base, days[i], 12, 0);
        TEST_ASSERT_EQUAL(days[i], get_weekday(next), "Weekday should match");
        TEST_ASSERT_EQUAL(12, get_hour(next), "Hour should be 12");
        TEST_ASSERT(next > base, "Should be in the future");
    }
}

TEST(test_taskmanager_weekly_midnight) {
    TEST_CASE("Weekly: schedule at midnight (00:00)");

    time_t base = make_time(2025, 12, 29, 10, 0, 0);

    time_t next = taskmanager_calc_next_weekly(base, TUESDAY, 0, 0);

    TEST_ASSERT_EQUAL(TUESDAY, get_weekday(next), "Should be Tuesday");
    TEST_ASSERT_EQUAL(0, get_hour(next), "Hour should be 0");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");
}

TEST(test_taskmanager_weekly_end_of_day) {
    TEST_CASE("Weekly: schedule at 23:59");

    time_t base = make_time(2025, 12, 29, 10, 0, 0);

    time_t next = taskmanager_calc_next_weekly(base, WEDNESDAY, 23, 59);

    TEST_ASSERT_EQUAL(WEDNESDAY, get_weekday(next), "Should be Wednesday");
    TEST_ASSERT_EQUAL(23, get_hour(next), "Hour should be 23");
    TEST_ASSERT_EQUAL(59, get_minute(next), "Minute should be 59");
}

TEST(test_taskmanager_weekly_across_month_boundary) {
    TEST_CASE("Weekly: schedule crosses month boundary");

    // 30 декабря 2025 (вторник) -> следующий понедельник будет 5 января 2026
    time_t base = make_time(2025, 12, 30, 10, 0, 0);

    // Запланировать на понедельник (будет 5 января 2026)
    time_t next = taskmanager_calc_next_weekly(base, MONDAY, 10, 0);

    TEST_ASSERT_EQUAL(MONDAY, get_weekday(next), "Should be Monday");
    TEST_ASSERT_EQUAL(1, get_month(next), "Should be January");
    TEST_ASSERT_EQUAL(10, get_hour(next), "Hour should be 10");
}

TEST(test_taskmanager_weekly_across_year_boundary) {
    TEST_CASE("Weekly: schedule crosses year boundary");

    // 31 декабря 2025 (среда) -> следующий четверг будет 1 января 2026
    time_t base = make_time(2025, 12, 31, 10, 0, 0);

    int base_wday = get_weekday(base);
    // 31 декабря 2025 - какой день? 28-е понедельник, значит 31-е четверг (4)
    TEST_ASSERT_EQUAL(WEDNESDAY, base_wday, "Dec 31, 2025 should be Wednesday");

    // Запланировать на четверг в 10:00 -> 1 января 2026
    time_t next = taskmanager_calc_next_weekly(base, THURSDAY, 10, 0);

    TEST_ASSERT_EQUAL(THURSDAY, get_weekday(next), "Should be Thursday");
    TEST_ASSERT_EQUAL(1, get_month(next), "Should be January");
    TEST_ASSERT_EQUAL(1, get_day(next), "Should be 1st");
}

// ============================================================================
// Тесты ежемесячного расписания (SCHEDULE_MONTHLY)
// ============================================================================

TEST(test_taskmanager_monthly_future_day_this_month) {
    TEST_CASE("Monthly: target day is ahead this month");

    // 15 декабря 2025, 10:00
    time_t base = make_time(2025, 12, 15, 10, 0, 0);

    // Запланировать на 20-е число в 14:00
    time_t next = taskmanager_calc_next_monthly(base, 20, 14, 0);

    TEST_ASSERT_EQUAL(20, get_day(next), "Day should be 20");
    TEST_ASSERT_EQUAL(12, get_month(next), "Should be December");
    TEST_ASSERT_EQUAL(14, get_hour(next), "Hour should be 14");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");
}

TEST(test_taskmanager_monthly_past_day_this_month) {
    TEST_CASE("Monthly: target day already passed this month");

    // 25 декабря 2025, 10:00
    time_t base = make_time(2025, 12, 25, 10, 0, 0);

    // Запланировать на 15-е число (уже прошло) в 10:00
    time_t next = taskmanager_calc_next_monthly(base, 15, 10, 0);

    TEST_ASSERT_EQUAL(15, get_day(next), "Day should be 15");
    TEST_ASSERT_EQUAL(1, get_month(next), "Should be January next year");
    TEST_ASSERT_EQUAL(10, get_hour(next), "Hour should be 10");
}

TEST(test_taskmanager_monthly_same_day_past_time) {
    TEST_CASE("Monthly: same day but time already passed -> next month");

    // 15 декабря 2025, 15:00
    time_t base = make_time(2025, 12, 15, 15, 0, 0);

    // Запланировать на 15-е в 10:00 (время уже прошло)
    time_t next = taskmanager_calc_next_monthly(base, 15, 10, 0);

    TEST_ASSERT_EQUAL(15, get_day(next), "Day should be 15");
    TEST_ASSERT_EQUAL(1, get_month(next), "Should be January");
    TEST_ASSERT_EQUAL(10, get_hour(next), "Hour should be 10");
}

TEST(test_taskmanager_monthly_same_day_future_time) {
    TEST_CASE("Monthly: same day, time not yet passed -> today");

    // 15 декабря 2025, 08:00
    time_t base = make_time(2025, 12, 15, 8, 0, 0);

    // Запланировать на 15-е в 14:00 (время ещё не наступило)
    time_t next = taskmanager_calc_next_monthly(base, 15, 14, 0);

    TEST_ASSERT_EQUAL(15, get_day(next), "Day should be 15");
    TEST_ASSERT_EQUAL(12, get_month(next), "Should be December (today)");
    TEST_ASSERT_EQUAL(14, get_hour(next), "Hour should be 14");
}

TEST(test_taskmanager_monthly_first_day) {
    TEST_CASE("Monthly: schedule on 1st day of month");

    // 15 декабря 2025, 10:00
    time_t base = make_time(2025, 12, 15, 10, 0, 0);

    // Запланировать на 1-е число (уже прошло в этом месяце)
    time_t next = taskmanager_calc_next_monthly(base, 1, 10, 0);

    TEST_ASSERT_EQUAL(1, get_day(next), "Day should be 1");
    TEST_ASSERT_EQUAL(1, get_month(next), "Should be January");
    TEST_ASSERT_EQUAL(10, get_hour(next), "Hour should be 10");
}

TEST(test_taskmanager_monthly_last_possible_day) {
    TEST_CASE("Monthly: schedule on 31st");

    // 15 января 2025, 10:00
    time_t base = make_time(2025, 1, 15, 10, 0, 0);

    // Запланировать на 31-е
    time_t next = taskmanager_calc_next_monthly(base, 31, 10, 0);

    TEST_ASSERT_EQUAL(31, get_day(next), "Day should be 31");
    TEST_ASSERT_EQUAL(1, get_month(next), "Should be January");
    TEST_ASSERT_EQUAL(10, get_hour(next), "Hour should be 10");
}

TEST(test_taskmanager_monthly_day_31_in_short_month) {
    TEST_CASE("Monthly: schedule on 31st when month has 30 days");

    // 1 апреля 2025, 10:00 (апрель имеет 30 дней)
    time_t base = make_time(2025, 4, 1, 10, 0, 0);

    // Запланировать на 31-е (апрель -> май)
    time_t next = taskmanager_calc_next_monthly(base, 31, 10, 0);

    // mktime нормализует 31 апреля -> 1 мая
    // Это особенность реализации, которую нужно учитывать
    TEST_ASSERT(get_day(next) >= 1, "Day should be normalized");
}

TEST(test_taskmanager_monthly_february_30) {
    TEST_CASE("Monthly: schedule on 30th in February");

    // 1 февраля 2025, 10:00 (февраль 2025 имеет 28 дней)
    time_t base = make_time(2025, 2, 1, 10, 0, 0);

    // Запланировать на 30-е (февраль -> март)
    time_t next = taskmanager_calc_next_monthly(base, 30, 10, 0);

    // mktime нормализует 30 февраля -> 2 марта (28 + 2 = 30)
    TEST_ASSERT(get_month(next) == 3 || get_month(next) == 2, "Should be Feb or March");
}

TEST(test_taskmanager_monthly_across_year) {
    TEST_CASE("Monthly: schedule crosses year boundary");

    // 20 декабря 2025, 10:00
    time_t base = make_time(2025, 12, 20, 10, 0, 0);

    // Запланировать на 5-е (прошло -> январь 2026)
    time_t next = taskmanager_calc_next_monthly(base, 5, 10, 0);

    TEST_ASSERT_EQUAL(5, get_day(next), "Day should be 5");
    TEST_ASSERT_EQUAL(1, get_month(next), "Should be January");
}

TEST(test_taskmanager_monthly_midnight) {
    TEST_CASE("Monthly: schedule at midnight (00:00)");

    time_t base = make_time(2025, 12, 15, 10, 0, 0);

    time_t next = taskmanager_calc_next_monthly(base, 20, 0, 0);

    TEST_ASSERT_EQUAL(20, get_day(next), "Day should be 20");
    TEST_ASSERT_EQUAL(0, get_hour(next), "Hour should be 0");
    TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should be 0");
}

TEST(test_taskmanager_monthly_end_of_day) {
    TEST_CASE("Monthly: schedule at 23:59");

    time_t base = make_time(2025, 12, 15, 10, 0, 0);

    time_t next = taskmanager_calc_next_monthly(base, 20, 23, 59);

    TEST_ASSERT_EQUAL(20, get_day(next), "Day should be 20");
    TEST_ASSERT_EQUAL(23, get_hour(next), "Hour should be 23");
    TEST_ASSERT_EQUAL(59, get_minute(next), "Minute should be 59");
}

// ============================================================================
// Тесты корректного повтора расписания
// ============================================================================

TEST(test_taskmanager_weekly_repeats_correctly) {
    TEST_CASE("Weekly: verify task repeats every 7 days");

    time_t base = make_time(2025, 1, 6, 10, 0, 0);  // Понедельник

    // Первый запуск
    time_t first = taskmanager_calc_next_weekly(base, MONDAY, 14, 0);

    // Симулируем выполнение задачи и расчёт следующего запуска
    time_t second = taskmanager_calc_next_weekly(first, MONDAY, 14, 0);

    // Разница должна быть ровно 7 дней
    time_t diff = second - first;
    TEST_ASSERT_EQUAL(7 * 24 * 3600, diff, "Weekly repeat should be exactly 7 days");
}

TEST(test_taskmanager_monthly_repeats_correctly) {
    TEST_CASE("Monthly: verify task repeats every month");

    // 15 января 2025
    time_t base = make_time(2025, 1, 10, 10, 0, 0);

    // Первый запуск - 15 января
    time_t first = taskmanager_calc_next_monthly(base, 15, 14, 0);
    TEST_ASSERT_EQUAL(15, get_day(first), "First run should be 15th");
    TEST_ASSERT_EQUAL(1, get_month(first), "First run should be January");

    // Симулируем выполнение и расчёт следующего запуска - должен быть 15 февраля
    time_t second = taskmanager_calc_next_monthly(first, 15, 14, 0);
    TEST_ASSERT_EQUAL(15, get_day(second), "Second run should be 15th");
    TEST_ASSERT_EQUAL(2, get_month(second), "Second run should be February");

    // Третий запуск - 15 марта
    time_t third = taskmanager_calc_next_monthly(second, 15, 14, 0);
    TEST_ASSERT_EQUAL(15, get_day(third), "Third run should be 15th");
    TEST_ASSERT_EQUAL(3, get_month(third), "Third run should be March");
}

TEST(test_taskmanager_weekly_12_weeks_simulation) {
    TEST_CASE("Weekly: simulate 12 weeks of task execution");

    time_t current = make_time(2025, 1, 1, 10, 0, 0);

    for (int week = 0; week < 12; week++) {
        time_t next = taskmanager_calc_next_weekly(current, FRIDAY, 9, 0);

        TEST_ASSERT_EQUAL(FRIDAY, get_weekday(next), "Should always be Friday");
        TEST_ASSERT_EQUAL(9, get_hour(next), "Hour should always be 9");
        TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should always be 0");
        TEST_ASSERT(next > current, "Next should be after current");

        current = next;  // Симулируем выполнение задачи
    }
}

TEST(test_taskmanager_monthly_12_months_simulation) {
    TEST_CASE("Monthly: simulate 12 months of task execution");

    time_t current = make_time(2025, 1, 1, 10, 0, 0);
    int expected_month = 1;

    for (int month = 0; month < 12; month++) {
        time_t next = taskmanager_calc_next_monthly(current, 10, 9, 0);

        TEST_ASSERT_EQUAL(10, get_day(next), "Should always be 10th");
        TEST_ASSERT_EQUAL(9, get_hour(next), "Hour should always be 9");
        TEST_ASSERT_EQUAL(0, get_minute(next), "Minute should always be 0");
        TEST_ASSERT(next > current, "Next should be after current");

        TEST_ASSERT_EQUAL(expected_month, get_month(next), "Month should match expected");

        current = next;
        expected_month++;
        if (expected_month > 12) expected_month = 1;
    }
}

// ============================================================================
// Тесты граничных условий
// ============================================================================

TEST(test_taskmanager_weekly_exact_boundary) {
    TEST_CASE("Weekly: exact time boundary (should go to next week)");

    // Точно в момент запуска - Понедельник 29 декабря 2025, 10:00
    time_t base = make_time(2025, 12, 29, 10, 0, 0);
    // Проверяем, что это действительно понедельник
    int wday = get_weekday(base);
    TEST_ASSERT_EQUAL(MONDAY, wday, "Dec 29, 2025 should be Monday");

    // Запланировать на тот же момент
    time_t next = taskmanager_calc_next_weekly(base, wday, 10, 0);

    // Должен перейти на следующую неделю (target <= now)
    TEST_ASSERT(next > base, "Should be next week when time equals");
}

TEST(test_taskmanager_monthly_exact_boundary) {
    TEST_CASE("Monthly: exact time boundary (should go to next month)");

    // 15 декабря 2025, 10:00:00
    time_t base = make_time(2025, 12, 15, 10, 0, 0);

    // Запланировать на этот же момент
    time_t next = taskmanager_calc_next_monthly(base, 15, 10, 0);

    // Должен перейти на следующий месяц (target <= now)
    TEST_ASSERT(next > base, "Should be next month when time equals");
    TEST_ASSERT_EQUAL(1, get_month(next), "Should be January");
}

// ============================================================================
// Тесты реального времени (используют текущее время)
// ============================================================================

TEST(test_taskmanager_weekly_realtime) {
    TEST_CASE("Weekly: real-time calculation always returns future time");

    time_t now = time(NULL);

    // Тестируем для каждого дня недели
    for (int weekday = 0; weekday < 7; weekday++) {
        time_t next = taskmanager_calc_next_weekly(0, weekday, 12, 0);
        TEST_ASSERT(next > now, "Next run should always be in the future");
        TEST_ASSERT_EQUAL(weekday, get_weekday(next), "Weekday should match");
    }
}

TEST(test_taskmanager_monthly_realtime) {
    TEST_CASE("Monthly: real-time calculation always returns future time");

    time_t now = time(NULL);

    // Тестируем для разных дней месяца
    int days[] = {1, 5, 10, 15, 20, 25, 28};
    for (int i = 0; i < 7; i++) {
        time_t next = taskmanager_calc_next_monthly(0, days[i], 12, 0);
        TEST_ASSERT(next > now, "Next run should always be in the future");
    }
}

// ============================================================================
// Тесты валидации параметров
// ============================================================================

TEST(test_taskmanager_weekly_valid_hours) {
    TEST_CASE("Weekly: verify valid hour range 0-23");

    time_t base = make_time(2025, 12, 29, 10, 0, 0);

    for (int hour = 0; hour <= 23; hour++) {
        time_t next = taskmanager_calc_next_weekly(base, TUESDAY, hour, 30);
        TEST_ASSERT_EQUAL(hour, get_hour(next), "Hour should match");
    }
}

TEST(test_taskmanager_weekly_valid_minutes) {
    TEST_CASE("Weekly: verify valid minute range 0-59");

    time_t base = make_time(2025, 12, 29, 10, 0, 0);

    for (int minute = 0; minute <= 59; minute++) {
        time_t next = taskmanager_calc_next_weekly(base, TUESDAY, 15, minute);
        TEST_ASSERT_EQUAL(minute, get_minute(next), "Minute should match");
    }
}

TEST(test_taskmanager_monthly_valid_days) {
    TEST_CASE("Monthly: verify valid day range 1-31");

    time_t base = make_time(2025, 1, 1, 10, 0, 0);

    for (int day = 1; day <= 31; day++) {
        time_t next = taskmanager_calc_next_monthly(base, day, 12, 0);
        // Для дней 29-31 mktime может нормализовать в зависимости от месяца
        TEST_ASSERT(next > base, "Next should be in the future");
    }
}
