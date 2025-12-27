#define _GNU_SOURCE
#include <sys/types.h>
#include <time.h>
#include "taskmanager.h"

// Вычисление следующего запуска для daily расписания
time_t taskmanager_calc_next_daily(time_t base_time, int hour, int minute) {
    time_t now = base_time > 0 ? base_time : time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    // Устанавливаем время
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = 0;

    time_t target = mktime(&tm);

    // Если время в прошлом, переходим на следующий день
    if (target <= now) {
        tm.tm_mday += 1;
        target = mktime(&tm);
    }

    return target;
}

// Вычисление следующего запуска для weekly расписания
time_t taskmanager_calc_next_weekly(time_t base_time, int weekday, int hour, int minute) {
    time_t now = base_time > 0 ? base_time : time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    // Устанавливаем время
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = 0;

    // Вычисляем разницу в днях до нужного дня недели
    int current_wday = tm.tm_wday;
    int days_ahead = weekday - current_wday;

    if (days_ahead < 0) {
        days_ahead += 7;
    } else if (days_ahead == 0) {
        // Тот же день - проверяем время
        time_t target = mktime(&tm);
        if (target <= now) {
            days_ahead = 7;  // Следующая неделя
        }
    }

    tm.tm_mday += days_ahead;
    return mktime(&tm);
}

// Вычисление следующего запуска для monthly расписания
time_t taskmanager_calc_next_monthly(time_t base_time, int day, int hour, int minute) {
    time_t now = base_time > 0 ? base_time : time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    // Устанавливаем время
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = 0;
    tm.tm_mday = day;

    time_t target = mktime(&tm);

    // Если дата в прошлом, переходим на следующий месяц
    if (target <= now) {
        tm.tm_mon += 1;
        target = mktime(&tm);
    }

    return target;
}
