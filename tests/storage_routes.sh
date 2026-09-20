#!/usr/bin/env bash

# Маршрут, привязанный к файловому хранилищу, отдаёт файлы оттуда, а не из
# server.root, и ведёт себя как обычная статика: ETag, Range, gzip_static.
#
# Два случая здесь — про то, чего у статики от server.root нет и не было: путь
# storage-маршрута раскрывается из пути запроса, так что шаблон "*" и
# нерегулярный файл — это входные данные клиента, а не конфигурация.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/storage_routes.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-storage-routes}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
PORT=${STORAGE_ROUTES_PORT:-18511}
BASE="http://127.0.0.1:$PORT"

if [ ! -x "$SERVER" ]; then
    printf 'storage routes: server is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/www" "$WORK_DIR/assets/sub"
printf 'from server root\n' > "$WORK_DIR/www/index.html"
printf 'hello from storage' > "$WORK_DIR/assets/a.txt"
printf 'nested' > "$WORK_DIR/assets/sub/b.txt"
# Больше HTTP_GZIP_MIN_SIZE (1 КБ): ниже порога gzip_static не срабатывает и
# у себя, поэтому маленький файл проверял бы не то.
{ printf '<html><body>\n'
  for _ in $(seq 1 60); do printf '<p>compressible content that is worth compressing</p>\n'; done
  printf '</body></html>\n'; } > "$WORK_DIR/assets/page.html"
gzip -kf "$WORK_DIR/assets/page.html"
mkfifo "$WORK_DIR/assets/pipe.txt"

failed=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failed=1; }
ok() { printf 'ok: %s\n' "$1"; }

cat > "$WORK_DIR/config.json" <<JSON
{
    "main": {
        "workers": 1, "threads": 4, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "/tmp", "gzip": ["text/html"],
        "env": { "gzip_static": true },
        "log": { "enabled": true, "level": "error" }
    },
    "servers": {
        "s1": {
            "domains": ["localhost", "127.0.0.1"], "ip": "127.0.0.1", "port": $PORT,
            "root": "$WORK_DIR/www", "index": "index.html",
            "http": {
                "routes": {
                    "/assets/(.*)": { "GET": { "static_file": "{1}", "storage": "assets" } },
                    "/local/(.*)": { "GET": { "static_file": "{1}" } }
                }
            }
        }
    },
    "storages": {
        "assets": { "type": "filesystem", "root": "$WORK_DIR/assets" }
    },
    "mimetypes": { "text/html": ["html"], "text/plain": ["txt"], "application/octet-stream": ["bin"] }
}
JSON

"$SERVER" -c "$WORK_DIR/config.json" -f > "$WORK_DIR/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null' EXIT
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat "$WORK_DIR/server.log" >&2
    printf 'storage routes: server did not start\n' >&2
    exit 1
fi

status() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }

# 1: файл из хранилища
body=$(curl -s --max-time 10 "$BASE/assets/a.txt")
[ "$body" = "hello from storage" ] && ok 'a file comes from the storage' \
    || fail "a file from the storage: got '$body'"

# 2: вложенный путь
body=$(curl -s --max-time 10 "$BASE/assets/sub/b.txt")
[ "$body" = "nested" ] && ok 'a nested path resolves' || fail "nested path: got '$body'"

# 3: ETag есть и 304 работает
etag=$(curl -s -D - -o /dev/null --max-time 10 "$BASE/assets/a.txt" | grep -i '^etag:' | tr -d '\r')
[ -n "$etag" ] && ok 'ETag is present' || fail 'ETag is missing'
value=${etag#*: }
code=$(status -H "If-None-Match: $value" "$BASE/assets/a.txt")
[ "$code" = "304" ] && ok 'If-None-Match gives 304' || fail "If-None-Match: got $code"

# 4: Range
part=$(curl -s --max-time 10 -H 'Range: bytes=0-4' "$BASE/assets/a.txt")
[ "$part" = "hello" ] && ok 'Range serves the slice' || fail "Range: got '$part'"

# 5: gzip_static отдаёт .gz-двойника
encoding=$(curl -s -D - -o /dev/null --max-time 10 -H 'Accept-Encoding: gzip' \
    "$BASE/assets/page.html" | grep -i '^content-encoding:' | tr -d '\r')
printf '%s' "$encoding" | grep -qi gzip && ok 'gzip_static serves the .gz twin' \
    || fail "gzip_static: got '$encoding'"

# 6: glob не раскрывается
code=$(status "$BASE/assets/*")
[ "$code" = "404" ] && ok 'a glob path is refused' || fail "glob path: got $code"

# 7: нерегулярный файл не отдаётся и не вешает воркер
code=$(status "$BASE/assets/pipe.txt")
[ "$code" = "404" ] && ok 'a fifo is refused' || fail "fifo: got $code"

# 8: обход каталога. Парсер URI отбивает "../" ещё до маршрутизации (400);
# если он когда-нибудь перестанет, отказать обязан резолв пути (404). Тест
# спрашивает про отказ, а не про то, кто именно его вынес.
code=$(status --path-as-is "$BASE/assets/../www/index.html")
{ [ "$code" = "400" ] || [ "$code" = "404" ]; } && ok "traversal is refused ($code)" \
    || fail "traversal: got $code"

# 9: регресс — маршрут без storage по-прежнему от server.root
body=$(curl -s --max-time 10 "$BASE/local/index.html")
[ "$body" = "from server root" ] && ok 'a route without storage is unchanged' \
    || fail "route without storage: got '$body'"

# 10: сервер пережил всё это
kill -0 "$SERVER_PID" 2>/dev/null && ok 'the server is still running' \
    || fail 'the server died during the run'

if [ "$failed" -ne 0 ]; then
    printf 'storage routes: FAILED\n' >&2
    exit 1
fi

printf 'storage routes: OK\n'
