#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "appconfig.h"
#include "taskmanager.h"
#include "signal/signal.h"
#include "log.h"

static inline taskmanager_t* __manager(void) {
    appconfig_t* config = appconfig();
    return config ? config->taskmanager : NULL;
}

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

    if (task->free_data && task->data)
        task->free_data(task->data);

    free(task);
}

static void* __async_worker(void* arg) {
    signal_block_usr1();

    appconfig_t* config = arg;
    taskmanager_t* manager = config->taskmanager;

    appconfg_threads_increment(config);

    while (!atomic_load(&config->shutdown)) {
        struct timeval now;
        gettimeofday(&now, NULL);
        struct timespec timeToWait = {
            .tv_sec = now.tv_sec + 1,
            .tv_nsec = 0
        };

        pthread_mutex_lock(&manager->async_mutex);
        pthread_cond_timedwait(&manager->async_cond, &manager->async_mutex, &timeToWait);
        task_t* task = cqueue_pop(manager->async_queue);
        pthread_mutex_unlock(&manager->async_mutex);

        if (task != NULL) {
            task->status = TASK_STATUS_RUNNING;

            if (task->run)
                task->run(task->data);

            task->status = TASK_STATUS_COMPLETED;
            __task_free(task);
        }
    }

    appconfg_threads_decrement(config);

    pthread_exit(NULL);
}

// Обёртки для внутреннего использования (с текущим временем)
static time_t __calc_next_daily(int hour, int minute) {
    return taskmanager_calc_next_daily(0, hour, minute);
}

static time_t __calc_next_weekly(int weekday, int hour, int minute) {
    return taskmanager_calc_next_weekly(0, weekday, hour, minute);
}

static time_t __calc_next_monthly(int day, int hour, int minute) {
    return taskmanager_calc_next_monthly(0, day, hour, minute);
}

// Вычисление следующего запуска
static time_t __calc_next_run(scheduled_task_entry_t* entry) {
    time_t now = time(NULL);

    switch (entry->schedule_type) {
        case SCHEDULE_DAILY:
            return __calc_next_daily(entry->schedule_hour, entry->schedule_min);

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
    log_info("taskmanager: executing scheduled task '%s'\n", entry->name);

    if (entry->run)
        entry->run(entry->data);

    entry->last_run = time(NULL);
    entry->next_run = __calc_next_run(entry);
}

static void* __scheduler_worker(void* arg) {
    signal_block_usr1();

    appconfig_t* config = arg;
    taskmanager_t* manager = config->taskmanager;

    appconfg_threads_increment(config);

    while (!atomic_load(&config->shutdown)) {
        sleep(1);

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

    appconfg_threads_decrement(config);

    pthread_exit(NULL);
}


taskmanager_t* taskmanager_init(void) {
    taskmanager_t* manager = malloc(sizeof * manager);
    if (manager == NULL) return NULL;

    memset(manager, 0, sizeof(taskmanager_t));

    manager->async_queue = cqueue_create();
    manager->scheduled_tasks = NULL;

    if (manager->async_queue == NULL) {
        cqueue_free(manager->async_queue);
        free(manager);
        return NULL;
    }

    pthread_mutex_init(&manager->async_mutex, NULL);
    pthread_cond_init(&manager->async_cond, NULL);
    pthread_mutex_init(&manager->scheduler_mutex, NULL);

    log_info("taskmanager: initialized\n");

    return manager;
}

int taskmanager_create_threads(appconfig_t* config) {
    if (config == NULL || config->taskmanager == NULL) {
        log_info("taskmanager_init: taskmanager not initialized\n");
        return 1;
    }

    taskmanager_t* manager = config->taskmanager;

    if (pthread_create(&manager->async_thread, NULL, __async_worker, config) != 0) {
        log_error("taskmanager_init: failed to create async worker thread\n");
        return 0;
    }
    pthread_detach(manager->async_thread);
    pthread_setname_np(manager->async_thread, "Server async");

    if (pthread_create(&manager->scheduler_thread, NULL, __scheduler_worker, config) != 0) {
        log_error("taskmanager_init: failed to create scheduler thread\n");
        return 0;
    }
    pthread_detach(manager->scheduler_thread);
    pthread_setname_np(manager->scheduler_thread, "Server sched");

    return 1;
}

void taskmanager_free(taskmanager_t* manager) {
    if (manager == NULL) return;

    pthread_mutex_lock(&manager->async_mutex);
    pthread_cond_signal(&manager->async_cond);
    pthread_mutex_unlock(&manager->async_mutex);

    pthread_mutex_lock(&manager->scheduler_mutex);

    scheduled_task_entry_t* entry = manager->scheduled_tasks;
    while (entry != NULL) {
        scheduled_task_entry_t* next = entry->next;
        free(entry);
        entry = next;
    }

    pthread_mutex_unlock(&manager->scheduler_mutex);

    cqueue_freecb(manager->async_queue, __task_free);

    pthread_mutex_destroy(&manager->async_mutex);
    pthread_cond_destroy(&manager->async_cond);
    pthread_mutex_destroy(&manager->scheduler_mutex);

    free(manager);
}

int taskmanager_async(task_fn_t run, void* data) {
    return taskmanager_async_with_free(run, data, NULL);
}

int taskmanager_async_with_free(task_fn_t run, void* data, task_free_fn_t free_fn) {
    taskmanager_t* manager = __manager();
    if (manager == NULL) return 0;
    if (run == NULL) return 0;

    task_t* task = __task_create(run, data, free_fn);
    if (task == NULL) return 0;

    pthread_mutex_lock(&manager->async_mutex);
    cqueue_append(manager->async_queue, task);
    pthread_cond_signal(&manager->async_cond);
    pthread_mutex_unlock(&manager->async_mutex);

    return 1;
}

int taskmanager_schedule(taskmanager_t* manager, const char* name, int interval, task_fn_t run) {
    return taskmanager_schedule_with_data(manager, name, interval, run, NULL);
}

int taskmanager_schedule_with_data(taskmanager_t* manager, const char* name, int interval, task_fn_t run, void* data) {
    if (manager == NULL) return 0;
    if (name == NULL || run == NULL) return 0;

    pthread_mutex_lock(&manager->scheduler_mutex);

    scheduled_task_entry_t* entry = manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            pthread_mutex_unlock(&manager->scheduler_mutex);
            log_error("taskmanager: task '%s' already exists\n", name);
            return 0;
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(scheduled_task_entry_t));
    if (entry == NULL) {
        pthread_mutex_unlock(&manager->scheduler_mutex);
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

    entry->next = manager->scheduled_tasks;
    manager->scheduled_tasks = entry;

    pthread_mutex_unlock(&manager->scheduler_mutex);

    log_info("taskmanager: scheduled task '%s' every %d seconds\n", name, interval);

    return 1;
}

int taskmanager_schedule_daily(taskmanager_t* manager, const char* name, int hour, int minute, task_fn_t run) {
    return taskmanager_schedule_daily_with_data(manager, name, hour, minute, run, NULL);
}

int taskmanager_schedule_daily_with_data(taskmanager_t* manager, const char* name, int hour, int minute, task_fn_t run, void* data) {
    if (manager == NULL) return 0;
    if (name == NULL || run == NULL) return 0;
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return 0;

    pthread_mutex_lock(&manager->scheduler_mutex);

    scheduled_task_entry_t* entry = manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            pthread_mutex_unlock(&manager->scheduler_mutex);
            log_error("taskmanager: task '%s' already exists\n", name);
            return 0;
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(scheduled_task_entry_t));
    if (entry == NULL) {
        pthread_mutex_unlock(&manager->scheduler_mutex);
        return 0;
    }

    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->name[sizeof(entry->name) - 1] = '\0';
    entry->run = run;
    entry->data = data;
    entry->interval = 0;
    entry->enabled = 1;
    entry->schedule_type = SCHEDULE_DAILY;
    entry->schedule_day = 0;
    entry->schedule_hour = hour;
    entry->schedule_min = minute;

    entry->last_run = 0;
    entry->next_run = __calc_next_daily(hour, minute);

    entry->next = manager->scheduled_tasks;
    manager->scheduled_tasks = entry;

    pthread_mutex_unlock(&manager->scheduler_mutex);

    log_info("taskmanager: scheduled task '%s' daily at %02d:%02d\n", name, hour, minute);

    return 1;
}

int taskmanager_schedule_weekly(taskmanager_t* manager, const char* name, weekday_e weekday, int hour, int minute, task_fn_t run) {
    return taskmanager_schedule_weekly_with_data(manager, name, weekday, hour, minute, run, NULL);
}

int taskmanager_schedule_weekly_with_data(taskmanager_t* manager, const char* name, weekday_e weekday, int hour, int minute, task_fn_t run, void* data) {
    if (manager == NULL) return 0;
    if (name == NULL || run == NULL) return 0;
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return 0;

    pthread_mutex_lock(&manager->scheduler_mutex);

    scheduled_task_entry_t* entry = manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            pthread_mutex_unlock(&manager->scheduler_mutex);
            log_error("taskmanager: task '%s' already exists\n", name);
            return 0;
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(scheduled_task_entry_t));
    if (entry == NULL) {
        pthread_mutex_unlock(&manager->scheduler_mutex);
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

    entry->next = manager->scheduled_tasks;
    manager->scheduled_tasks = entry;

    pthread_mutex_unlock(&manager->scheduler_mutex);

    static const char* weekday_names[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
    log_info("taskmanager: scheduled task '%s' every %s at %02d:%02d\n", name, weekday_names[weekday], hour, minute);

    return 1;
}

int taskmanager_schedule_monthly(taskmanager_t* manager, const char* name, int day, int hour, int minute, task_fn_t run) {
    return taskmanager_schedule_monthly_with_data(manager, name, day, hour, minute, run, NULL);
}

int taskmanager_schedule_monthly_with_data(taskmanager_t* manager, const char* name, int day, int hour, int minute, task_fn_t run, void* data) {
    if (manager == NULL) return 0;
    if (name == NULL || run == NULL) return 0;
    if (day < 1 || day > 31) return 0;
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return 0;

    pthread_mutex_lock(&manager->scheduler_mutex);

    scheduled_task_entry_t* entry = manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            pthread_mutex_unlock(&manager->scheduler_mutex);
            log_error("taskmanager: task '%s' already exists\n", name);
            return 0;
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(scheduled_task_entry_t));
    if (entry == NULL) {
        pthread_mutex_unlock(&manager->scheduler_mutex);
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

    entry->next = manager->scheduled_tasks;
    manager->scheduled_tasks = entry;

    pthread_mutex_unlock(&manager->scheduler_mutex);

    log_info("taskmanager: scheduled task '%s' on day %d at %02d:%02d\n", name, day, hour, minute);

    return 1;
}

int taskmanager_unschedule(taskmanager_t* manager, const char* name) {
    if (manager == NULL || name == NULL) return 0;

    pthread_mutex_lock(&manager->scheduler_mutex);

    scheduled_task_entry_t* prev = NULL;
    scheduled_task_entry_t* entry = manager->scheduled_tasks;

    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            if (prev == NULL) {
                manager->scheduled_tasks = entry->next;
            } else {
                prev->next = entry->next;
            }
            free(entry);

            pthread_mutex_unlock(&manager->scheduler_mutex);

            log_info("taskmanager: unscheduled task '%s'\n", name);
            return 1;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&manager->scheduler_mutex);
    return 0;
}

int taskmanager_trigger(taskmanager_t* manager, const char* name) {
    if (manager == NULL || name == NULL) return 0;

    pthread_mutex_lock(&manager->scheduler_mutex);

    scheduled_task_entry_t* entry = manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            entry->next_run = time(NULL) - 1;
            pthread_mutex_unlock(&manager->scheduler_mutex);
            return 1;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&manager->scheduler_mutex);
    return 0;
}

int taskmanager_enable(taskmanager_t* manager, const char* name) {
    if (manager == NULL || name == NULL) return 0;

    pthread_mutex_lock(&manager->scheduler_mutex);

    scheduled_task_entry_t* entry = manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            entry->enabled = 1;
            pthread_mutex_unlock(&manager->scheduler_mutex);
            return 1;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&manager->scheduler_mutex);
    return 0;
}

int taskmanager_disable(taskmanager_t* manager, const char* name) {
    if (manager == NULL || name == NULL) return 0;

    pthread_mutex_lock(&manager->scheduler_mutex);

    scheduled_task_entry_t* entry = manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            entry->enabled = 0;
            pthread_mutex_unlock(&manager->scheduler_mutex);
            return 1;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&manager->scheduler_mutex);
    return 0;
}

scheduled_task_entry_t* taskmanager_get(taskmanager_t* manager, const char* name) {
    if (manager == NULL || name == NULL) return NULL;

    pthread_mutex_lock(&manager->scheduler_mutex);

    scheduled_task_entry_t* entry = manager->scheduled_tasks;
    while (entry != NULL) {
        if (strcmp(entry->name, name) == 0) {
            pthread_mutex_unlock(&manager->scheduler_mutex);
            return entry;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&manager->scheduler_mutex);
    return NULL;
}
