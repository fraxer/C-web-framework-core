#!/usr/bin/env bash

# Конфигурация с ключом "storage" на маршруте: что принимается и что обязано
# завалить старт.
#
# Имя хранилища нельзя проверить там же, где разбирается маршрут: servers
# грузятся раньше storages, а __storage_find смотрит в активную конфигурацию,
# то есть при reload — в предыдущее поколение. Поэтому проверка живёт отдельным
# проходом после загрузки storages, и этот тест существует, чтобы проход не
# потерялся.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/storage_routes_config.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-storage-routes-config}
SERVER="$BUILD_DIR/exec/cwfr"
PORT=${STORAGE_CONFIG_PORT:-18510}

if [ ! -x "$SERVER" ]; then
    printf 'storage routes config: server is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/www" "$WORK_DIR/assets"
printf 'index\n' > "$WORK_DIR/www/index.html"
printf 'asset\n' > "$WORK_DIR/assets/a.txt"

failed=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failed=1; }

# $1 имя конфига, $2 тело секции routes
write_config() {
    local name=$1 routes=$2

    cat > "$WORK_DIR/$name.json" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" }
    },
    "servers": {
        "s1": {
            "domains": ["localhost", "127.0.0.1"], "ip": "127.0.0.1", "port": $PORT,
            "root": "$WORK_DIR/www", "index": "index.html",
            "http": { "routes": $routes }
        }
    },
    "storages": {
        "assets": { "type": "filesystem", "root": "$WORK_DIR/assets" }
    },
    "mimetypes": { "text/html": ["html"], "text/plain": ["txt"] }
}
JSON
}

# $1 имя конфига, $2 описание
expect_failure() {
    local name=$1 what=$2

    timeout 30 "$SERVER" -c "$WORK_DIR/$name.json" -f > "$WORK_DIR/$name.log" 2>&1
    local status=$?

    if [ "$status" -eq 124 ]; then
        fail "$what never returned"
    elif [ "$status" -eq 0 ]; then
        cat "$WORK_DIR/$name.log" >&2
        fail "$what exited 0"
    else
        printf 'ok: %s exits %d\n' "$what" "$status"
    fi

    pkill -f "cwfr -c $WORK_DIR/$name.json" 2>/dev/null
}

# $1 имя конфига, $2 описание
expect_start() {
    local name=$1 what=$2

    timeout 30 "$SERVER" -c "$WORK_DIR/$name.json" -f > "$WORK_DIR/$name.log" 2>&1 &
    local pid=$!
    sleep 2

    if kill -0 "$pid" 2>/dev/null; then
        printf 'ok: %s started\n' "$what"
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    else
        cat "$WORK_DIR/$name.log" >&2
        fail "$what did not start"
    fi
}

write_config good '{ "/assets/(.*)": { "GET": { "static_file": "{1}", "storage": "assets" } } }'
expect_start good 'a route bound to an existing storage'

write_config unknown '{ "/assets/(.*)": { "GET": { "static_file": "{1}", "storage": "nosuch" } } }'
expect_failure unknown 'a route bound to an unknown storage'

write_config nostatic '{ "/assets/(.*)": { "GET": { "storage": "assets" } } }'
expect_failure nostatic 'a storage without static_file'

write_config withhandler '{ "/assets/(.*)": { "GET": { "static_file": "{1}", "storage": "assets", "file": "lib_x.so", "function": "x" } } }'
expect_failure withhandler 'a storage together with a handler'

write_config emptyname '{ "/assets/(.*)": { "GET": { "static_file": "{1}", "storage": "" } } }'
expect_failure emptyname 'an empty storage name'

if [ "$failed" -ne 0 ]; then
    printf 'storage routes config: FAILED\n' >&2
    exit 1
fi

printf 'storage routes config: OK\n'
