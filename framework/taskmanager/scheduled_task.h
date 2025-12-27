#ifndef __MODEL_SCHEDULED_TASK__
#define __MODEL_SCHEDULED_TASK__

#include "model.h"

typedef struct {
    model_t base;
    struct {
        mfield_t id;
        mfield_t name;
        mfield_t interval_sec;
        mfield_t schedule_type;   // 0=interval, 1=weekly, 2=monthly
        mfield_t schedule_day;    // день недели (0-6) или день месяца (1-31)
        mfield_t schedule_hour;   // час (0-23)
        mfield_t schedule_min;    // минута (0-59)
        mfield_t last_run_at;
        mfield_t next_run_at;
        mfield_t enabled;
        mfield_t created_at;
        mfield_t updated_at;
    } field;
    char table[64];
    char* primary_key[1];
} scheduled_task_t;

void scheduled_task_set_dbid(const char* dbid);

void* scheduled_task_instance(void);

scheduled_task_t* scheduled_task_get(array_t* params);
scheduled_task_t* scheduled_task_get_by_name(const char* name);
array_t* scheduled_task_get_all_enabled(void);
int scheduled_task_create(scheduled_task_t* task);
int scheduled_task_update(scheduled_task_t* task);
int scheduled_task_delete(scheduled_task_t* task);
void scheduled_task_free(scheduled_task_t* task);

void scheduled_task_set_name(scheduled_task_t* task, const char* name);
void scheduled_task_set_interval(scheduled_task_t* task, int interval_sec);
void scheduled_task_set_schedule_type(scheduled_task_t* task, int type);
void scheduled_task_set_schedule_day(scheduled_task_t* task, int day);
void scheduled_task_set_schedule_hour(scheduled_task_t* task, int hour);
void scheduled_task_set_schedule_min(scheduled_task_t* task, int min);
void scheduled_task_set_last_run_at(scheduled_task_t* task, time_t last_run);
void scheduled_task_set_last_run_at_now(scheduled_task_t* task);
void scheduled_task_set_next_run_at(scheduled_task_t* task, time_t next_run);
void scheduled_task_set_enabled(scheduled_task_t* task, short enabled);
void scheduled_task_set_updated_at_now(scheduled_task_t* task);

long long scheduled_task_id(scheduled_task_t* task);
const char* scheduled_task_name(scheduled_task_t* task);
int scheduled_task_interval(scheduled_task_t* task);
int scheduled_task_schedule_type(scheduled_task_t* task);
int scheduled_task_schedule_day(scheduled_task_t* task);
int scheduled_task_schedule_hour(scheduled_task_t* task);
int scheduled_task_schedule_min(scheduled_task_t* task);
time_t scheduled_task_last_run_at(scheduled_task_t* task);
time_t scheduled_task_next_run_at(scheduled_task_t* task);
int scheduled_task_is_enabled(scheduled_task_t* task);
int scheduled_task_is_due(scheduled_task_t* task);

#endif
