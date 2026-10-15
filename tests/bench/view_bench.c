/* Template engine throughput: render() of a cached view from several threads.
 *
 * Not a unit test and not registered with CTest: the numbers only mean
 * something in a Release build without sanitizers, and a pass/fail threshold
 * would depend on the machine. Run it by hand before and after a change.
 *
 *   ./exec/view_bench                 4 threads, 5 runs of 1 s per scenario
 *   ./exec/view_bench -t 8 -d 2 -r 3  8 threads, 3 runs of 2 s
 *   ./exec/view_bench -s loop         only scenarios whose name contains "loop"
 *   ./exec/view_bench -s loop -p      print what the scenario renders, no timing
 *
 * Every scenario is measured on 1 thread and on -t threads, so the scaling
 * column shows contention (the viewstore lock, malloc) rather than raw speed.
 * Templates are parsed once before measuring: this is the cached render path
 * a running server takes on every request after the first.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/limits.h>

#include "appconfig.h"
#include "json.h"
#include "storagefs.h"
#include "view.h"
#include "viewstore.h"

#define BENCH_STORAGE "view_bench"
#define BENCH_MAX_THREADS 256
#define BENCH_MAX_RUNS 99

typedef struct {
    const char* name;
    const char* path;
    view_escape_e escape;
    const char* description;
} bench_scenario_t;

typedef struct {
    pthread_barrier_t* barrier;
    atomic_int* stop;
    const bench_scenario_t* scenario;
    json_doc_t* document;
    const char* expected;
    unsigned long long renders;
    double seconds;
    int failed;
} bench_worker_t;

typedef struct {
    double renders_per_sec;
    double ns_per_render;
    double mb_per_sec;
} bench_result_t;

static char bench_root[PATH_MAX];

static const bench_scenario_t bench_scenarios[] = {
    { "static",    "/static.tpl",    VIEW_ESCAPE, "16 KB of text, no tags" },
    { "variables", "/variables.tpl", VIEW_ESCAPE, "60 {{ }} with paths, escaping" },
    { "loop",      "/loop.tpl",      VIEW_ESCAPE, "for over 100 items, if, modifiers" },
    { "loop_raw",  "/loop.tpl",      VIEW_RAW,    "same as loop, VIEW_RAW" },
    { "layout",    "/layout.tpl",    VIEW_ESCAPE, "includes + nested loops" },
};

static double bench_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void bench_sleep(double seconds) {
    struct timespec ts;
    ts.tv_sec = (time_t)seconds;
    ts.tv_nsec = (long)((seconds - (double)ts.tv_sec) * 1e9);
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

// ============================================================================
// Fixtures
// ============================================================================

static int bench_write(const char* name, const char* content) {
    char path[PATH_MAX + NAME_MAX + 2];
    snprintf(path, sizeof(path), "%s/%s", bench_root, name);

    FILE* f = fopen(path, "w");
    if (f == NULL) return 0;

    const size_t size = strlen(content);
    const size_t written = fwrite(content, 1, size, f);
    fclose(f);

    return written == size;
}

static void bench_remove_fixtures(void) {
    static const char* names[] = {
        "static.tpl", "variables.tpl", "loop.tpl", "layout.tpl",
        "header.tpl", "footer.tpl", "config.json"
    };

    char path[PATH_MAX + NAME_MAX + 2];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", bench_root, names[i]);
        unlink(path);
    }
    rmdir(bench_root);
}

static int bench_write_static(void) {
    static const char line[] =
        "<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
        "tempor incididunt ut labore et dolore magna aliqua.</p>\n";

    const size_t count = 16 * 1024 / (sizeof(line) - 1) + 1;
    char* content = malloc(count * (sizeof(line) - 1) + 1);
    if (content == NULL) return 0;

    char* p = content;
    for (size_t i = 0; i < count; i++) {
        memcpy(p, line, sizeof(line) - 1);
        p += sizeof(line) - 1;
    }
    *p = 0;

    const int ok = bench_write("static.tpl", content);
    free(content);

    return ok;
}

static int bench_write_fixtures(void) {
    if (!bench_write_static()) return 0;

    // 6 fields x 10 rows: plain, nested, indexed and escaped values
    char variables[16384];
    size_t pos = (size_t)snprintf(variables, sizeof(variables),
                                  "<html><head><title>{{ title }}</title></head><body>\n");
    for (int i = 0; i < 10; i++)
        pos += (size_t)snprintf(variables + pos, sizeof(variables) - pos,
            "<div class=\"row\"><b>{{ user.name }}</b> <i>{{ user.email }}</i> "
            "<span>{{ user.address.city }}</span> <em>{{ tags[%d] }}</em> "
            "<p>{{ note }}</p> <s>{{ count }}</s></div>\n", i % 5);
    snprintf(variables + pos, sizeof(variables) - pos, "</body></html>\n");

    static const char loop[] =
        "<table>\n"
        "{% for p, i in products %}"
        "<tr class=\"{% if i % 2 == 0 %}even{% else %}odd{% endif %}\">"
        "<td>{{ i + 1 }}</td>"
        "<td>{{ p.name | upper }}</td>"
        "<td>{{ p.description | truncate(40) }}</td>"
        "<td>{{ p.price | number(2, '.', ' ') }}</td>"
        "<td>{% if p.stock > 0 %}{{ p.stock }} in stock{% else %}sold out{% endif %}</td>"
        "</tr>\n"
        "{% endfor %}"
        "</table>\n";

    static const char header[] =
        "<header><h1>{{ title }}</h1><nav>"
        "{% for item in menu %}<a href=\"{{ item.url }}\">{{ item.label }}</a>{% endfor %}"
        "</nav></header>\n";

    static const char footer[] =
        "<footer>&copy; {{ year }} {{ title }}</footer>\n";

    static const char layout[] =
        "<!doctype html><html><head><title>{{ title }}</title></head><body>\n"
        "{* include /header.tpl *}"
        "<main>\n"
        "{% for c in categories %}"
        "<section><h2>{{ c.name }}</h2><ul>"
        "{% for p in c.items %}<li>{{ p.name }} - {{ p.price }}</li>{% endfor %}"
        "</ul></section>\n"
        "{% endfor %}"
        "</main>\n"
        "{* include /footer.tpl *}"
        "</body></html>\n";

    return bench_write("variables.tpl", variables)
        && bench_write("loop.tpl", loop)
        && bench_write("header.tpl", header)
        && bench_write("footer.tpl", footer)
        && bench_write("layout.tpl", layout);
}

static json_doc_t* bench_document(void) {
    const size_t capacity = 256 * 1024;
    char* json = malloc(capacity);
    if (json == NULL) return NULL;

    size_t pos = (size_t)snprintf(json, capacity,
        "{\"title\":\"Shop <Benchmark> & \\\"Co\\\"\",\"year\":2026,\"count\":42,"
        "\"note\":\"a < b && c > d, 'quoted'\","
        "\"user\":{\"name\":\"Alex\",\"email\":\"alex@example.com\","
        "\"address\":{\"city\":\"Singapore\"}},"
        "\"tags\":[\"one\",\"two\",\"three\",\"four\",\"five\"],"
        "\"menu\":[");
    for (int i = 0; i < 8; i++)
        pos += (size_t)snprintf(json + pos, capacity - pos,
            "%s{\"url\":\"/section/%d\",\"label\":\"Section %d\"}", i ? "," : "", i, i);

    pos += (size_t)snprintf(json + pos, capacity - pos, "],\"products\":[");
    for (int i = 0; i < 100; i++)
        pos += (size_t)snprintf(json + pos, capacity - pos,
            "%s{\"name\":\"product %d\",\"description\":\"A long description of product %d "
            "that is longer than forty characters\",\"price\":%d.%02d,\"stock\":%d}",
            i ? "," : "", i, i, 100 + i * 7, i % 100, i % 3 == 0 ? 0 : i);

    pos += (size_t)snprintf(json + pos, capacity - pos, "],\"categories\":[");
    for (int c = 0; c < 10; c++) {
        pos += (size_t)snprintf(json + pos, capacity - pos,
            "%s{\"name\":\"Category %d\",\"items\":[", c ? "," : "", c);
        for (int i = 0; i < 10; i++)
            pos += (size_t)snprintf(json + pos, capacity - pos,
                "%s{\"name\":\"item <%d.%d>\",\"price\":%d}", i ? "," : "", c, i, c * 10 + i);
        pos += (size_t)snprintf(json + pos, capacity - pos, "]}");
    }
    snprintf(json + pos, capacity - pos, "]}");

    json_doc_t* document = json_parse(json);
    free(json);

    return document;
}

static int bench_env_init(void) {
    snprintf(bench_root, sizeof(bench_root), "/tmp/cwfr_view_bench_XXXXXX");
    if (mkdtemp(bench_root) == NULL) {
        perror("mkdtemp");
        return 0;
    }

    // appconfig_create only checks that the file exists; nothing reads it
    if (!bench_write("config.json", "{}\n") || !bench_write_fixtures()) {
        fprintf(stderr, "failed to write fixtures to %s\n", bench_root);
        return 0;
    }

    char config_path[PATH_MAX + NAME_MAX + 2];
    snprintf(config_path, sizeof(config_path), "%s/config.json", bench_root);

    appconfig_t* config = appconfig_create(config_path);
    if (config == NULL) return 0;

    config->viewstore = viewstore_create();
    config->storages = (storage_t*)storage_create_fs(BENCH_STORAGE, bench_root);
    if (config->viewstore == NULL || config->storages == NULL) {
        appconfig_free(config);
        fprintf(stderr, "failed to create the view store or storage\n");
        return 0;
    }

    appconfig_set(config);
    appconfig_free(config);

    return 1;
}

// ============================================================================
// Measurement
// ============================================================================

static void* bench_worker(void* arg) {
    bench_worker_t* worker = arg;

    pthread_barrier_wait(worker->barrier);

    const double start = bench_now();
    unsigned long long renders = 0;

    while (!atomic_load_explicit(worker->stop, memory_order_relaxed)) {
        char* result = render(worker->document, worker->scenario->escape,
                              BENCH_STORAGE, worker->scenario->path);
        if (result == NULL) {
            worker->failed = 1;
            break;
        }

        free(result);
        renders++;
    }

    worker->seconds = bench_now() - start;
    worker->renders = renders;

    return NULL;
}

static int bench_run(const bench_scenario_t* scenario, json_doc_t* document,
                     size_t output_size, int threads, double seconds,
                     bench_result_t* result) {
    pthread_t ids[BENCH_MAX_THREADS];
    bench_worker_t workers[BENCH_MAX_THREADS];
    pthread_barrier_t barrier;
    atomic_int stop;

    atomic_init(&stop, 0);
    if (pthread_barrier_init(&barrier, NULL, (unsigned)threads + 1) != 0)
        return 0;

    for (int i = 0; i < threads; i++) {
        workers[i] = (bench_worker_t){
            .barrier = &barrier, .stop = &stop, .scenario = scenario, .document = document,
        };
        // the barrier counts on every thread: it can never be released short of one
        if (pthread_create(&ids[i], NULL, bench_worker, &workers[i]) != 0) {
            fprintf(stderr, "pthread_create failed after %d threads\n", i);
            exit(1);
        }
    }

    pthread_barrier_wait(&barrier);
    bench_sleep(seconds);
    atomic_store(&stop, 1);

    int ok = 1;
    double renders_per_sec = 0;
    for (int i = 0; i < threads; i++) {
        pthread_join(ids[i], NULL);
        if (workers[i].failed) ok = 0;
        if (workers[i].seconds > 0)
            renders_per_sec += (double)workers[i].renders / workers[i].seconds;
    }

    pthread_barrier_destroy(&barrier);
    if (!ok) return 0;

    result->renders_per_sec = renders_per_sec;
    result->ns_per_render = renders_per_sec > 0 ? 1e9 * threads / renders_per_sec : 0;
    result->mb_per_sec = renders_per_sec * (double)output_size / (1024.0 * 1024.0);

    return 1;
}

static int bench_compare(const void* a, const void* b) {
    const double x = ((const bench_result_t*)a)->renders_per_sec;
    const double y = ((const bench_result_t*)b)->renders_per_sec;
    return (x > y) - (x < y);
}

// Median of `runs` runs by throughput, after a discarded warm-up run.
static int bench_measure(const bench_scenario_t* scenario, json_doc_t* document,
                         size_t output_size, int threads, double seconds, int runs,
                         bench_result_t* median) {
    bench_result_t results[BENCH_MAX_RUNS];

    if (!bench_run(scenario, document, output_size, threads, seconds / 4, &results[0]))
        return 0;

    for (int i = 0; i < runs; i++)
        if (!bench_run(scenario, document, output_size, threads, seconds, &results[i]))
            return 0;

    qsort(results, (size_t)runs, sizeof(results[0]), bench_compare);
    *median = results[runs / 2];

    return 1;
}

static void* bench_check_worker(void* arg) {
    bench_worker_t* worker = arg;

    pthread_barrier_wait(worker->barrier);

    for (int i = 0; i < 100; i++) {
        char* result = render(worker->document, worker->scenario->escape,
                              BENCH_STORAGE, worker->scenario->path);
        if (result == NULL || strcmp(result, worker->expected) != 0)
            worker->failed = 1;
        free(result);
        if (worker->failed) break;
    }

    return NULL;
}

// Renders from every thread at once and compares with the single-threaded output.
static int bench_check_threads(const bench_scenario_t* scenario, json_doc_t* document,
                               const char* expected, int threads) {
    pthread_t ids[BENCH_MAX_THREADS];
    bench_worker_t workers[BENCH_MAX_THREADS];
    pthread_barrier_t barrier;

    if (pthread_barrier_init(&barrier, NULL, (unsigned)threads) != 0)
        return 0;

    for (int i = 0; i < threads; i++) {
        workers[i] = (bench_worker_t){
            .barrier = &barrier, .scenario = scenario, .document = document, .expected = expected,
        };
        if (pthread_create(&ids[i], NULL, bench_check_worker, &workers[i]) != 0) {
            fprintf(stderr, "pthread_create failed after %d threads\n", i);
            exit(1);
        }
    }

    int ok = 1;
    for (int i = 0; i < threads; i++) {
        pthread_join(ids[i], NULL);
        if (workers[i].failed) ok = 0;
    }

    pthread_barrier_destroy(&barrier);

    return ok;
}

// ============================================================================
// main
// ============================================================================

static void bench_usage(const char* argv0) {
    fprintf(stderr,
        "usage: %s [-t threads] [-d seconds] [-r runs] [-s scenario] [-p]\n"
        "  -t  worker threads (default 4)\n"
        "  -d  seconds per run (default 1)\n"
        "  -r  runs per measurement, the median is reported (default 5, odd)\n"
        "  -s  only scenarios whose name contains this string\n"
        "  -p  print the rendered output of the scenarios instead of timing them\n", argv0);
}

int main(int argc, char* argv[]) {
    int threads = 4;
    double seconds = 1.0;
    int runs = 5;
    const char* filter = NULL;
    int print = 0;

    int opt;
    while ((opt = getopt(argc, argv, "t:d:r:s:ph")) != -1) {
        switch (opt) {
        case 't': threads = atoi(optarg); break;
        case 'd': seconds = atof(optarg); break;
        case 'r': runs = atoi(optarg); break;
        case 's': filter = optarg; break;
        case 'p': print = 1; break;
        default:
            bench_usage(argv[0]);
            return opt == 'h' ? 0 : 2;
        }
    }

    if (threads < 1 || threads > BENCH_MAX_THREADS || seconds <= 0
        || runs < 1 || runs > BENCH_MAX_RUNS || runs % 2 == 0) {
        bench_usage(argv[0]);
        return 2;
    }

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
    fprintf(stderr, "warning: built with a sanitizer, the numbers are not representative\n");
#endif
#ifndef NDEBUG
    fprintf(stderr, "warning: not a Release build, the numbers are not representative\n");
#endif

    if (!bench_env_init()) {
        bench_remove_fixtures();
        return 1;
    }

    json_doc_t* document = bench_document();
    if (document == NULL) {
        fprintf(stderr, "failed to build the JSON document\n");
        appconfig_set(NULL);
        bench_remove_fixtures();
        return 1;
    }

    if (!print) {
        printf("view_bench: %d thread(s) vs 1, median of %d x %.2f s, cpus online %ld\n\n",
               threads, runs, seconds, sysconf(_SC_NPROCESSORS_ONLN));
        printf("%-10s %9s %14s %13s %11s %11s %14s %8s\n",
               "scenario", "out, B", "1 thr, r/s", "1 thr, ns/r",
               "N thr, r/s", "N thr, MB/s", "N thr, ns/r", "scaling");
    }

    int status = 0;
    for (size_t i = 0; i < sizeof(bench_scenarios) / sizeof(bench_scenarios[0]); i++) {
        const bench_scenario_t* scenario = &bench_scenarios[i];
        if (filter != NULL && strstr(scenario->name, filter) == NULL) continue;

        char* expected = render(document, scenario->escape, BENCH_STORAGE, scenario->path);
        if (expected == NULL) {
            fprintf(stderr, "%s: render failed\n", scenario->name);
            status = 1;
            continue;
        }

        const size_t size = strlen(expected);

        if (print) {
            printf("===== %s (%zu bytes) =====\n%s\n", scenario->name, size, expected);
            free(expected);
            continue;
        }

        if (!bench_check_threads(scenario, document, expected, threads)) {
            fprintf(stderr, "%s: output differs between threads\n", scenario->name);
            free(expected);
            status = 1;
            continue;
        }
        free(expected);

        bench_result_t single;
        bench_result_t multi;
        if (!bench_measure(scenario, document, size, 1, seconds, runs, &single)
            || !bench_measure(scenario, document, size, threads, seconds, runs, &multi)) {
            fprintf(stderr, "%s: render failed during measurement\n", scenario->name);
            status = 1;
            continue;
        }

        printf("%-10s %9zu %14.0f %13.0f %11.0f %11.1f %14.0f %7.2fx\n",
               scenario->name, size,
               single.renders_per_sec, single.ns_per_render,
               multi.renders_per_sec, multi.mb_per_sec, multi.ns_per_render,
               multi.renders_per_sec / single.renders_per_sec);
    }

    if (print) goto done;

    printf("\nns/r is wall time per render on one thread; ideal scaling is %dx.\n", threads);
    for (size_t i = 0; i < sizeof(bench_scenarios) / sizeof(bench_scenarios[0]); i++)
        printf("  %-10s %s\n", bench_scenarios[i].name, bench_scenarios[i].description);

done:
    json_free(document);
    appconfig_set(NULL);
    bench_remove_fixtures();

    return status;
}
