#ifndef __TASKMANAGER__
#define __TASKMANAGER__

#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

#include "cqueue.h"

typedef struct appconfig appconfig_t;

typedef void (*task_fn_t)(void* data);
typedef void (*task_free_fn_t)(void* data);

typedef enum {
    TASK_STATUS_PENDING = 0,
    TASK_STATUS_RUNNING,
    TASK_STATUS_COMPLETED,
    TASK_STATUS_FAILED
} task_status_e;

typedef enum {
    INTERVAL_SECOND  = 1,
    INTERVAL_MINUTE  = 60,
    INTERVAL_HOURLY  = 3600,
    INTERVAL_DAILY   = 86400,
    INTERVAL_WEEKLY  = 604800
} task_interval_e;

typedef enum {
    SCHEDULE_INTERVAL = 0,  // каждые N секунд
    SCHEDULE_DAILY,         // каждый день в определённое время
    SCHEDULE_WEEKLY,        // по дням недели
    SCHEDULE_MONTHLY        // по дням месяца
} schedule_type_e;

typedef enum {
    MONDAY    = 1,
    TUESDAY   = 2,
    WEDNESDAY = 3,
    THURSDAY  = 4,
    FRIDAY    = 5,
    SATURDAY  = 6,
    SUNDAY    = 0
} weekday_e;

typedef struct task {
    task_fn_t       run;
    task_free_fn_t  free_data;
    void*           data;
    task_status_e   status;
} task_t;

typedef struct scheduled_task_entry {
    char            name[128];
    task_fn_t       run;
    void*           data;
    int             interval;
    time_t          last_run;
    time_t          next_run;
    short           enabled;

    schedule_type_e schedule_type;
    int             schedule_day;   // день недели (0-6) или день месяца (1-31)
    int             schedule_hour;  // час запуска (0-23)
    int             schedule_min;   // минута запуска (0-59)

    struct scheduled_task_entry* next;
} scheduled_task_entry_t;

typedef struct taskmanager {
    cqueue_t*       async_queue;
    pthread_t       async_thread;
    pthread_mutex_t async_mutex;
    pthread_cond_t  async_cond;

    scheduled_task_entry_t* scheduled_tasks;
    pthread_t       scheduler_thread;
    pthread_mutex_t scheduler_mutex;
} taskmanager_t;

taskmanager_t* taskmanager_init(void);
void taskmanager_free(taskmanager_t* manager);
int taskmanager_create_threads(appconfig_t* config);

int taskmanager_async(task_fn_t run, void* data);
int taskmanager_async_with_free(task_fn_t run, void* data, task_free_fn_t free_fn);

// Интервальное расписание (каждые N секунд)
int taskmanager_schedule(taskmanager_t* manager, const char* name, int interval, task_fn_t run);
int taskmanager_schedule_with_data(taskmanager_t* manager, const char* name, int interval, task_fn_t run, void* data);

// Ежедневное расписание (каждый день в указанное время)
// hour: 0-23, minute: 0-59
int taskmanager_schedule_daily(taskmanager_t* manager, const char* name, int hour, int minute, task_fn_t run);
int taskmanager_schedule_daily_with_data(taskmanager_t* manager, const char* name, int hour, int minute, task_fn_t run, void* data);

// Еженедельное расписание (по дню недели)
// weekday: MONDAY-SUNDAY, hour: 0-23, minute: 0-59
int taskmanager_schedule_weekly(taskmanager_t* manager, const char* name, weekday_e weekday, int hour, int minute, task_fn_t run);
int taskmanager_schedule_weekly_with_data(taskmanager_t* manager, const char* name, weekday_e weekday, int hour, int minute, task_fn_t run, void* data);

// Ежемесячное расписание (по дню месяца)
// day: 1-31, hour: 0-23, minute: 0-59
int taskmanager_schedule_monthly(taskmanager_t* manager, const char* name, int day, int hour, int minute, task_fn_t run);
int taskmanager_schedule_monthly_with_data(taskmanager_t* manager, const char* name, int day, int hour, int minute, task_fn_t run, void* data);

int taskmanager_unschedule(taskmanager_t* manager, const char* name);
int taskmanager_trigger(taskmanager_t* manager, const char* name);

int taskmanager_enable(taskmanager_t* manager, const char* name);
int taskmanager_disable(taskmanager_t* manager, const char* name);
scheduled_task_entry_t* taskmanager_get(taskmanager_t* manager, const char* name);

// Функции расчёта следующего запуска (для тестирования и внешнего использования)
// base_time: базовое время для расчёта (0 = использовать текущее время)
time_t taskmanager_calc_next_daily(time_t base_time, int hour, int minute);
time_t taskmanager_calc_next_weekly(time_t base_time, int weekday, int hour, int minute);
time_t taskmanager_calc_next_monthly(time_t base_time, int day, int hour, int minute);

#endif
