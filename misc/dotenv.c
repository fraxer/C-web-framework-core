#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "dotenv.h"
#include "file.h"
#include "log.h"

/* Leading/trailing blanks and \r (CRLF files) off. */
static char* __dotenv_trim(char* s) {
    while (*s == ' ' || *s == '\t') s++;

    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r'))
        s[--len] = '\0';

    return s;
}

static int __dotenv_line(char** cursor, char** line) {
    if (**cursor == '\0') return 0;

    *line = *cursor;

    char* next = strchr(*cursor, '\n');
    if (next != NULL) *next = '\0';
    *cursor = next == NULL ? *line + strlen(*line) : next + 1;

    return 1;
}

char* dotenv_load(const char* path) {
    file_t file = file_open(path, O_RDONLY);
    if (!file.ok) {
        log_error("dotenv_load: cannot open %s\n", path);
        return NULL;
    }

    char* data = file.content(&file);
    file.close(&file);
    if (data == NULL)
        log_error("dotenv_load: file_read error %s\n", path);

    return data;
}

int dotenv_parse(char* data, const char* name, dotenv_pair_fn fn, void* userdata) {
    int count = 0;
    int lineno = 0;

    char* cursor = data;
    char* line = NULL;

    while (__dotenv_line(&cursor, &line)) {
        lineno++;

        char* key = __dotenv_trim(line);

        /* Blank line, comment. */
        if (*key == '\0' || *key == '#') continue;

        /* Optional `export` prefix, as in shell syntax. */
        if (strncmp(key, "export ", 7) == 0)
            key = __dotenv_trim(key + 7);

        char* eq = strchr(key, '=');
        if (eq == NULL || eq == key) {
            if (name != NULL)
                log_error("dotenv_parse: malformed line %d in %s\n", lineno, name);
            else
                log_error("dotenv_parse: malformed line %d\n", lineno);
            continue;
        }
        *eq = '\0';
        __dotenv_trim(key);

        char* value = __dotenv_trim(eq + 1);

        /* Matching surrounding quotes mean string; a bare value may carry a
         * trailing comment. */
        int quoted = 0;
        const size_t vlen = strlen(value);
        if (vlen >= 2 && (value[0] == '"' || value[0] == '\'') && value[vlen - 1] == value[0]) {
            value[vlen - 1] = '\0';
            value++;
            quoted = 1;
        }
        else {
            for (char* p = value; *p != '\0'; p++) {
                if (*p == '#' && p > value && (p[-1] == ' ' || p[-1] == '\t')) {
                    *p = '\0';
                    __dotenv_trim(value);
                    break;
                }
            }
        }

        if (fn != NULL && !fn(key, value, quoted, userdata))
            return -1;

        count++;
    }

    return count;
}
