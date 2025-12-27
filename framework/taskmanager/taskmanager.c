#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "taskmanager.h"
#include "scheduled_task.h"
#include "log.h"

static taskmanager_t* __manager = NULL;

static task_t* __task_create(task_fn_t run, void* data, task_free_fn_t free_fn) {
    task_t* task = malloc(sizeof(task_t));
    if (task == NULL) return NULL;

    task->run = run;
    task->data = data;
    task->free_data = free_fn;
    task->status = TASK_STATUS_PENDING;

    return task;
}

static void __task_free(void* arg) {
    task_t* task = arg;
    if (task == NULL) return;

    if (task->free_data && task->data) {
        task->free_data(task->data);
    }

    free(task);
}

static void* __async_worker(void* arg) {
    taskmanager_t* manager = arg;

    while (atomic_load(&manager->running)) {
        pthread_mutex_lock(&manager->async_mutex);

        while (cqueue_empty(manager->async_queue) && atomic_load(&manager->running)) {
            pthread_cond_wait(&manager->async_cond, &manager->async_mutex);
        }

        if (!atomic_load(&manager->running)) {
            pthread_mutex_unlock(&manager->async_mutex);
            break;
        }

        task_t* task = cqueue_pop(manager->async_queue);
        pthread_mutex_unlock(&manager->async_mutex);

        if (task != NULL) {
            task->status = TASK_STATUS_RUNNING;

            if (task->run) {
                task->run(task->data);
            }

            task->status = TASK_STATUS_COMPLETED;
            __task_free(task);
        }
    }

    pthread_exit(NULL);
}

// Вычисление следующего запуска для weekly расписания
static time_t __calc_next_weekly(int weekday, int hour, int minute) {
    time_t now = time(NULL);
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
static time_t __calc_next_monthly(int day, int hour, int minute) {
    time_t now = time(NULL);
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

// Вычисление следующего запуска
static time_t __calc_next_run(scheduled_task_entry_t* entry) {
    time_t now = time(NULL);

    switch (entry->schedule_type) {
        case SCHEDULE_WEEKLY:
            return __calc_next_weekly(entry->schedule_day, entry->schedule_hour, entry->schedule_min);

        case SCHEDULE_MONTHLY:
            return __calc_next_monthly(entry->schedule_day, entry->schedule_hour, entry->schedule_min);

        case SCHEDULE_INTERVAL:
        default:
            return now + entry->interval;
    }
}

static void __execute_scheduled_task(scheduled_task_entry_t* entry) {
    time_t now = time(NULL);

    log_info("taskmanager: executing scheduled task '%s'\n", entry->name);

    if (entry->run) {
        entry->run(entry->data);
    }

    entry->last_run = now;
    entry->next_run = __calc_next_run(entry);

    scheduled_task_t* db_task = scheduled_task_get_by_name(entry->name);
    if (db_task) {
        scheduled_task_set_last_run_at(db_task, entry->last_run);
        scheduled_task_set_next_run_at(db_task, entry->next_run);
        scheduled_task_update(db_task);
        scheduled_task_free(db_task);
    }
}

static void* __scheduler_worker(void* arg) {
    taskmanager_t* manager = arg;

    while (atomic_load(&manager->running)) {
        sleep(1);

        if (!atomic_load(&manager->running)) break;

        time_t now = time(NULL);

        pthread_mutex_lock(&manager->scheduler_mutex);

        scheduled_task_entry_t* entry = manager->scheduled_tasks;
        while (entry != NULL) {
            if (entry->enabled && entry->next_run <= now) {
                __execute_scheduled_task(entry);
            }
            entry = entry->next;
        }

        pthread_mutex_unlock(&manager->scheduler_mutex);
    }

    pthread_exit(NULL);
}

static void __load_scheduled_tasks_from_db(void) {
    array_t* tasks = scheduled_task_get_all_enabled();
    if (tasks == NULL) return;

    pthread_mutex_lock(&__manager->scheduler_mutex);

    for (size_t i = 0; i < array_size(tasks); i++) {
        scheduled_task_t* db_task = array_get(tasks, i);
        const char* name = scheduled_task_name(db_task);

        scheduled_task_entry_t* entry = __manager->scheduled_tasks;
        while (entry != NULL) {
            if (strcmp(entry->name, name) == 0) {
                entry->last_run = scheduled_task_last_run_at(db_task);
                entry->next_run = scheduled_task_next_run_at(db_task);
                entry->enabled = scheduled_task_is_enabled(db_task);
                break;
            }
            entry = entry->next;
        }

        scheduled_task_free(db_task);
    }

    pthread_mutex_unlock(&__manager->scheduler_mutex);

    array_free(tasks);
}

int taskmanager_init(const char* dbid) {
    if (__manager != NULL) return 1;

    __manager = malloc(sizeof(taskmanager_t));
    if (__manager == NULL) return 0;

    memset(__manager, 0, sizeof(taskmanager_t));

    __manager->dbid = dbid;
    __manager->async_queue = cqueue_create();
    __manager->scheduled_tasks = NULL;

    if (__manager->async_queue == NULL) {
        free(__manager);
        __manager = NULL;
        return 0;
    }

    scheduled_task_set_dbid(dbid);

    pthread_mutex_init(&__manager->async_mutex, NULL);
    pthread_cond_init(&__manager->async_cond, NULL);
    pthread_mutex_init(&__manager->scheduler_mutex, NULL);

    atomic_store(&__manager->running, 1);

    if (pthread_create(&__manager->async_thread, NULL, __async_worker, __manager) != 0) {
        log_error("taskmanager_init: failed to create async worker thread\n");
        taskmanager_shutdown();
        return 0;
    }
    pthread_setname_np(__manager->async_thread, "TM-Async");

    if (pthread_create(&__manager->scheduler_thread, NULL, __scheduler_worker, __manager) != 0) {
        log_error("taskmanager_init: failed to create scheduler thread\n");
        taskmanager_shutdown();
        return 0;
    }
    pthread_setname_np(__manager->scheduler_thread, "TM-Scheduler");

    __load_scheduled_tasks_from_db();

    log_info("taskmanager: initialized\n");

    return 1;
}

void taskmanager_shutdown(void) {
    if (__manager == NULL) return;

    atomic_store(&__manager->running, 0);

    pthread_mutex_lock(&__manager->async_mutex);
    pthread_cond_signal(&__manager->async_cond);
    pthread_mutex_unlock(&__manager->async_mutex);

    pthread_join(__manager->async_thread, NULL);
    pthread_join(__manager->scheduler_thread, NULL);

    cqueue_freecb(__manager->async_queue, __task_free);

    scheduled_task_entry_t* entry = __manager->scheduled_tasks;
    while (entry != NULL) {
        scheduled_task_entry_t* next = entry->next;
        free(entry);
        entry = next;
    }

    pthread_mutex_destroy(&__manager->async_mutex);
    pthread_cond_destroy(&__manager->async_cond);
    pthread_mutex_destroy(&__manager->scheduler_mutex);

    free(__manager);
    __manager = NULL;

    log_info("taskmanager: shutdown complete\n");
}

int taskmanager_async(task_fn_t run, void* data) {
    return taskmanager_async_with_free(run, data, NULL);
}

int taskmanager_async_with_free(task_fn_t run, void* data, task_free_fn_t free_fn) {
    if (__manager == NULL) return 0;
    if (run == NULL) return 0;

    task_t* task = __task_create(run, data, free_fn);
    if (task == NULL) return 0;

    pthread_mutex_lock(&__manager->async_mutex);
    cqueue_append(__manager->async_queue, task);
    pthread_cond_signal(&__manager->async_cond);
    pthread_mutex_unlock(&__manager->async_mutex);

    return 1;
}

int taskmanager_schedule(const char* name, int interval, task_fn_t run) {
    return taskmanager_schedule_with_data(name, interval, run, NULL);
}

int taskmanager_schedule_with_data(const char* name, int interval, task_fn_t run, void* data) {
    if (__manager == NULL) return 0;
    if (name == NULL || run == NULL) return 0;

    pthread_mutex_lock(&__manager->scheduler_mutex);

    scheduled_task_entry_t* entry = __manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            pthread_mutex_unlock(&__manager->scheduler_mutex);
            log_error("taskmanager: task '%s' already exists\n", name);
            return 0;
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(scheduled_task_entry_t));
    if (entry == NULL) {
        pthread_mutex_unlock(&__manager->scheduler_mutex);
        return 0;
    }

    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->name[sizeof(entry->name) - 1] = '\0';
    entry->run = run;
    entry->data = data;
    entry->interval = interval;
    entry->enabled = 1;
    entry->schedule_type = SCHEDULE_INTERVAL;
    entry->schedule_day = 0;
    entry->schedule_hour = 0;
    entry->schedule_min = 0;

    time_t now = time(NULL);
    entry->last_run = 0;
    entry->next_run = now + interval;

    entry->next = __manager->scheduled_tasks;
    __manager->scheduled_tasks = entry;

    pthread_mutex_unlock(&__manager->scheduler_mutex);

    scheduled_task_t* db_task = scheduled_task_get_by_name(name);
    if (db_task) {
        entry->last_run = scheduled_task_last_run_at(db_task);
        entry->next_run = scheduled_task_next_run_at(db_task);
        entry->enabled = scheduled_task_is_enabled(db_task);
        scheduled_task_free(db_task);
    } else {
        db_task = scheduled_task_instance();
        if (db_task) {
            scheduled_task_set_name(db_task, name);
            scheduled_task_set_interval(db_task, interval);
            scheduled_task_set_next_run_at(db_task, entry->next_run);
            scheduled_task_set_enabled(db_task, 1);
            scheduled_task_create(db_task);
            scheduled_task_free(db_task);
        }
    }

    log_info("taskmanager: scheduled task '%s' every %d seconds\n", name, interval);

    return 1;
}

int taskmanager_schedule_weekly(const char* name, weekday_e weekday, int hour, int minute, task_fn_t run) {
    return taskmanager_schedule_weekly_with_data(name, weekday, hour, minute, run, NULL);
}

int taskmanager_schedule_weekly_with_data(const char* name, weekday_e weekday, int hour, int minute, task_fn_t run, void* data) {
    if (__manager == NULL) return 0;
    if (name == NULL || run == NULL) return 0;
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return 0;

    pthread_mutex_lock(&__manager->scheduler_mutex);

    scheduled_task_entry_t* entry = __manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            pthread_mutex_unlock(&__manager->scheduler_mutex);
            log_error("taskmanager: task '%s' already exists\n", name);
            return 0;
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(scheduled_task_entry_t));
    if (entry == NULL) {
        pthread_mutex_unlock(&__manager->scheduler_mutex);
        return 0;
    }

    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->name[sizeof(entry->name) - 1] = '\0';
    entry->run = run;
    entry->data = data;
    entry->interval = 0;
    entry->enabled = 1;
    entry->schedule_type = SCHEDULE_WEEKLY;
    entry->schedule_day = weekday;
    entry->schedule_hour = hour;
    entry->schedule_min = minute;

    entry->last_run = 0;
    entry->next_run = __calc_next_weekly(weekday, hour, minute);

    entry->next = __manager->scheduled_tasks;
    __manager->scheduled_tasks = entry;

    pthread_mutex_unlock(&__manager->scheduler_mutex);

    scheduled_task_t* db_task = scheduled_task_get_by_name(name);
    if (db_task) {
        entry->last_run = scheduled_task_last_run_at(db_task);
        entry->next_run = scheduled_task_next_run_at(db_task);
        entry->enabled = scheduled_task_is_enabled(db_task);
        scheduled_task_free(db_task);
    } else {
        db_task = scheduled_task_instance();
        if (db_task) {
            scheduled_task_set_name(db_task, name);
            scheduled_task_set_schedule_type(db_task, SCHEDULE_WEEKLY);
            scheduled_task_set_schedule_day(db_task, weekday);
            scheduled_task_set_schedule_hour(db_task, hour);
            scheduled_task_set_schedule_min(db_task, minute);
            scheduled_task_set_next_run_at(db_task, entry->next_run);
            scheduled_task_set_enabled(db_task, 1);
            scheduled_task_create(db_task);
            scheduled_task_free(db_task);
        }
    }

    static const char* weekday_names[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
    log_info("taskmanager: scheduled task '%s' every %s at %02d:%02d\n", name, weekday_names[weekday], hour, minute);

    return 1;
}

int taskmanager_schedule_monthly(const char* name, int day, int hour, int minute, task_fn_t run) {
    return taskmanager_schedule_monthly_with_data(name, day, hour, minute, run, NULL);
}

int taskmanager_schedule_monthly_with_data(const char* name, int day, int hour, int minute, task_fn_t run, void* data) {
    if (__manager == NULL) return 0;
    if (name == NULL || run == NULL) return 0;
    if (day < 1 || day > 31) return 0;
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return 0;

    pthread_mutex_lock(&__manager->scheduler_mutex);

    scheduled_task_entry_t* entry = __manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            pthread_mutex_unlock(&__manager->scheduler_mutex);
            log_error("taskmanager: task '%s' already exists\n", name);
            return 0;
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(scheduled_task_entry_t));
    if (entry == NULL) {
        pthread_mutex_unlock(&__manager->scheduler_mutex);
        return 0;
    }

    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->name[sizeof(entry->name) - 1] = '\0';
    entry->run = run;
    entry->data = data;
    entry->interval = 0;
    entry->enabled = 1;
    entry->schedule_type = SCHEDULE_MONTHLY;
    entry->schedule_day = day;
    entry->schedule_hour = hour;
    entry->schedule_min = minute;

    entry->last_run = 0;
    entry->next_run = __calc_next_monthly(day, hour, minute);

    entry->next = __manager->scheduled_tasks;
    __manager->scheduled_tasks = entry;

    pthread_mutex_unlock(&__manager->scheduler_mutex);

    scheduled_task_t* db_task = scheduled_task_get_by_name(name);
    if (db_task) {
        entry->last_run = scheduled_task_last_run_at(db_task);
        entry->next_run = scheduled_task_next_run_at(db_task);
        entry->enabled = scheduled_task_is_enabled(db_task);
        scheduled_task_free(db_task);
    } else {
        db_task = scheduled_task_instance();
        if (db_task) {
            scheduled_task_set_name(db_task, name);
            scheduled_task_set_schedule_type(db_task, SCHEDULE_MONTHLY);
            scheduled_task_set_schedule_day(db_task, day);
            scheduled_task_set_schedule_hour(db_task, hour);
            scheduled_task_set_schedule_min(db_task, minute);
            scheduled_task_set_next_run_at(db_task, entry->next_run);
            scheduled_task_set_enabled(db_task, 1);
            scheduled_task_create(db_task);
            scheduled_task_free(db_task);
        }
    }

    log_info("taskmanager: scheduled task '%s' on day %d at %02d:%02d\n", name, day, hour, minute);

    return 1;
}

int taskmanager_unschedule(const char* name) {
    if (__manager == NULL || name == NULL) return 0;

    pthread_mutex_lock(&__manager->scheduler_mutex);

    scheduled_task_entry_t* prev = NULL;
    scheduled_task_entry_t* entry = __manager->scheduled_tasks;

    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            if (prev == NULL) {
                __manager->scheduled_tasks = entry->next;
            } else {
                prev->next = entry->next;
            }
            free(entry);

            pthread_mutex_unlock(&__manager->scheduler_mutex);

            scheduled_task_t* db_task = scheduled_task_get_by_name(name);
            if (db_task) {
                scheduled_task_delete(db_task);
                scheduled_task_free(db_task);
            }

            log_info("taskmanager: unscheduled task '%s'\n", name);
            return 1;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&__manager->scheduler_mutex);
    return 0;
}

int taskmanager_trigger(const char* name) {
    if (__manager == NULL || name == NULL) return 0;

    pthread_mutex_lock(&__manager->scheduler_mutex);

    scheduled_task_entry_t* entry = __manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            entry->next_run = time(NULL) - 1;
            pthread_mutex_unlock(&__manager->scheduler_mutex);
            return 1;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&__manager->scheduler_mutex);
    return 0;
}

int taskmanager_enable(const char* name) {
    if (__manager == NULL || name == NULL) return 0;

    pthread_mutex_lock(&__manager->scheduler_mutex);

    scheduled_task_entry_t* entry = __manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            entry->enabled = 1;
            pthread_mutex_unlock(&__manager->scheduler_mutex);

            scheduled_task_t* db_task = scheduled_task_get_by_name(name);
            if (db_task) {
                scheduled_task_set_enabled(db_task, 1);
                scheduled_task_update(db_task);
                scheduled_task_free(db_task);
            }

            return 1;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&__manager->scheduler_mutex);
    return 0;
}

int taskmanager_disable(const char* name) {
    if (__manager == NULL || name == NULL) return 0;

    pthread_mutex_lock(&__manager->scheduler_mutex);

    scheduled_task_entry_t* entry = __manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            entry->enabled = 0;
            pthread_mutex_unlock(&__manager->scheduler_mutex);

            scheduled_task_t* db_task = scheduled_task_get_by_name(name);
            if (db_task) {
                scheduled_task_set_enabled(db_task, 0);
                scheduled_task_update(db_task);
                scheduled_task_free(db_task);
            }

            return 1;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&__manager->scheduler_mutex);
    return 0;
}

scheduled_task_entry_t* taskmanager_get(const char* name) {
    if (__manager == NULL || name == NULL) return NULL;

    pthread_mutex_lock(&__manager->scheduler_mutex);

    scheduled_task_entry_t* entry = __manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            pthread_mutex_unlock(&__manager->scheduler_mutex);
            return entry;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&__manager->scheduler_mutex);
    return NULL;
}
