#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "db.h"
#include "scheduled_task.h"

static const char* __dbid = NULL;

static mfield_t* __first_field(void* arg);
static int __fields_count(void* arg);
static const char* __table(void* arg);
static const char** __unique_fields(void* arg);
static int __primary_key_count(void* arg);

void scheduled_task_set_dbid(const char* dbid) {
    __dbid = dbid;
}

void* scheduled_task_instance(void) {
    scheduled_task_t* task = malloc(sizeof *task);
    if (task == NULL) return NULL;

    scheduled_task_t st = {
        .base = {
            .fields_count = __fields_count,
            .primary_key_count = __primary_key_count,
            .first_field = __first_field,
            .table = __table,
            .primary_key = __unique_fields
        },
        .field = {
            mfield_bigint(id, NULL),
            mfield_varchar(name, NULL),
            mfield_int(interval_sec, 0),
            mfield_smallint(schedule_type, 0),
            mfield_smallint(schedule_day, 0),
            mfield_smallint(schedule_hour, 0),
            mfield_smallint(schedule_min, 0),
            mfield_timestamp(last_run_at, NULL),
            mfield_timestamp(next_run_at, NULL),
            mfield_bool(enabled, 1),
            mfield_timestamp(created_at, NOW),
            mfield_timestamp(updated_at, NOW),
        },
        .table = "scheduled_tasks",
        .primary_key = { "id" }
    };

    memcpy(task, &st, sizeof st);

    return task;
}

scheduled_task_t* scheduled_task_get(array_t* params) {
    if (__dbid == NULL) return NULL;
    return model_get(__dbid, scheduled_task_instance, params);
}

scheduled_task_t* scheduled_task_get_by_name(const char* name) {
    if (name == NULL || __dbid == NULL) return NULL;

    array_t* params = array_create();
    if (params == NULL) return NULL;

    mparams_fill_array(params,
        mparam_varchar(name, name)
    );

    scheduled_task_t* task = scheduled_task_get(params);
    array_free(params);

    return task;
}

array_t* scheduled_task_get_all_enabled(void) {
    if (__dbid == NULL) return NULL;

    return model_list(__dbid, scheduled_task_instance,
        "SELECT * FROM scheduled_tasks WHERE enabled = TRUE",
        NULL
    );
}

int scheduled_task_create(scheduled_task_t* task) {
    if (__dbid == NULL) return 0;
    return model_create(__dbid, task);
}

int scheduled_task_update(scheduled_task_t* task) {
    if (__dbid == NULL) return 0;
    scheduled_task_set_updated_at_now(task);
    return model_update(__dbid, task);
}

int scheduled_task_delete(scheduled_task_t* task) {
    if (__dbid == NULL) return 0;
    return model_delete(__dbid, task);
}

void scheduled_task_free(scheduled_task_t* task) {
    if (task == NULL) return;
    model_free(task);
}

void scheduled_task_set_name(scheduled_task_t* task, const char* name) {
    model_set_varchar(&task->field.name, name);
}

void scheduled_task_set_interval(scheduled_task_t* task, int interval_sec) {
    model_set_int(&task->field.interval_sec, interval_sec);
}

void scheduled_task_set_schedule_type(scheduled_task_t* task, int type) {
    model_set_smallint(&task->field.schedule_type, type);
}

void scheduled_task_set_schedule_day(scheduled_task_t* task, int day) {
    model_set_smallint(&task->field.schedule_day, day);
}

void scheduled_task_set_schedule_hour(scheduled_task_t* task, int hour) {
    model_set_smallint(&task->field.schedule_hour, hour);
}

void scheduled_task_set_schedule_min(scheduled_task_t* task, int min) {
    model_set_smallint(&task->field.schedule_min, min);
}

void scheduled_task_set_last_run_at(scheduled_task_t* task, time_t last_run) {
    tm_t tm;
    localtime_r(&last_run, &tm);
    model_set_timestamp(&task->field.last_run_at, &tm);
}

void scheduled_task_set_last_run_at_now(scheduled_task_t* task) {
    model_set_timestamp_now(&task->field.last_run_at);
}

void scheduled_task_set_next_run_at(scheduled_task_t* task, time_t next_run) {
    tm_t tm;
    localtime_r(&next_run, &tm);
    model_set_timestamp(&task->field.next_run_at, &tm);
}

void scheduled_task_set_enabled(scheduled_task_t* task, short enabled) {
    model_set_bool(&task->field.enabled, enabled);
}

void scheduled_task_set_updated_at_now(scheduled_task_t* task) {
    model_set_timestamp_now(&task->field.updated_at);
}

long long scheduled_task_id(scheduled_task_t* task) {
    return model_bigint(&task->field.id);
}

const char* scheduled_task_name(scheduled_task_t* task) {
    return str_get(model_varchar(&task->field.name));
}

int scheduled_task_interval(scheduled_task_t* task) {
    return model_int(&task->field.interval_sec);
}

int scheduled_task_schedule_type(scheduled_task_t* task) {
    return model_smallint(&task->field.schedule_type);
}

int scheduled_task_schedule_day(scheduled_task_t* task) {
    return model_smallint(&task->field.schedule_day);
}

int scheduled_task_schedule_hour(scheduled_task_t* task) {
    return model_smallint(&task->field.schedule_hour);
}

int scheduled_task_schedule_min(scheduled_task_t* task) {
    return model_smallint(&task->field.schedule_min);
}

time_t scheduled_task_last_run_at(scheduled_task_t* task) {
    if (task->field.last_run_at.is_null) return 0;

    tm_t tm = model_timestamp(&task->field.last_run_at);
    return mktime(&tm);
}

time_t scheduled_task_next_run_at(scheduled_task_t* task) {
    if (task->field.next_run_at.is_null) return 0;

    tm_t tm = model_timestamp(&task->field.next_run_at);
    return mktime(&tm);
}

int scheduled_task_is_enabled(scheduled_task_t* task) {
    return model_bool(&task->field.enabled);
}

int scheduled_task_is_due(scheduled_task_t* task) {
    if (!scheduled_task_is_enabled(task)) return 0;
    return time(NULL) >= scheduled_task_next_run_at(task);
}


mfield_t* __first_field(void* arg) {
    scheduled_task_t* task = arg;
    if (task == NULL) return NULL;

    return (void*)&task->field;
}

int __fields_count(void* arg) {
    scheduled_task_t* task = arg;
    if (task == NULL) return 0;

    return sizeof(task->field) / sizeof(mfield_t);
}

const char* __table(void* arg) {
    scheduled_task_t* task = arg;
    if (task == NULL) return NULL;

    return task->table;
}

const char** __unique_fields(void* arg) {
    scheduled_task_t* task = arg;
    if (task == NULL) return NULL;

    return (const char**)&task->primary_key[0];
}

int __primary_key_count(void* arg) {
    scheduled_task_t* task = arg;
    if (task == NULL) return 0;

    return sizeof(task->primary_key) / sizeof(task->primary_key[0]);
}
