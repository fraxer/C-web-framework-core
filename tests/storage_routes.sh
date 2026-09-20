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

# grep -q в конвейере под `set -o pipefail` врёт: grep закрывает канал на первом
# совпадении, producer получает SIGPIPE, статус конвейера — 141, и проверка
# молча становится ложной. Сравнение делаем без конвейера.
contains() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        *"$2"*) return 0 ;;
        *) return 1 ;;
    esac
}

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
contains "$encoding" gzip && ok 'gzip_static serves the .gz twin' \
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


# ---- S3 ----
#
# Стенд поднимается, только если MinIO доступен: гейт не должен падать на
# машине, где его нет. REQUIRE_S3=1 делает недоступность ошибкой.
#
# Клиент S3 берётся контейнерным (minio/mc), чтобы стенд не требовал ничего
# установленного, кроме docker.

S3_ENDPOINT=${STORAGE_S3_ENDPOINT:-127.0.0.1:9000}
S3_KEY=${STORAGE_S3_KEY:-minioadmin}
S3_SECRET=${STORAGE_S3_SECRET:-minioadmin}
S3_BUCKET=${STORAGE_S3_BUCKET:-cwfr-test}
S3_OBJECT_SIZE=${STORAGE_S3_OBJECT_SIZE:-20971520}

mc_run() {
    docker run --rm --network host -v "$WORK_DIR:/work" --entrypoint /bin/sh quay.io/minio/mc -c "$1" > /dev/null 2>&1
}

if ! curl -s --max-time 2 -o /dev/null "http://$S3_ENDPOINT/minio/health/live"; then
    if [ "${REQUIRE_S3:-0}" = "1" ]; then
        fail "MinIO is not reachable at $S3_ENDPOINT and REQUIRE_S3=1"
    else
        printf 'skip: MinIO is not reachable at %s, the S3 branch is not exercised\n' "$S3_ENDPOINT"
    fi
elif ! command -v docker > /dev/null; then
    if [ "${REQUIRE_S3:-0}" = "1" ]; then
        fail 'docker is required for the S3 part and REQUIRE_S3=1'
    else
        printf 'skip: no docker, the S3 branch is not exercised\n'
    fi
else
    head -c "$S3_OBJECT_SIZE" /dev/urandom > "$WORK_DIR/video.bin"
    mc_run "mc alias set stand http://$S3_ENDPOINT $S3_KEY $S3_SECRET && \
            mc mb --ignore-existing stand/$S3_BUCKET && \
            mc cp /work/video.bin stand/$S3_BUCKET/video.bin"

    PORT_S3=$((PORT + 1))
    cat > "$WORK_DIR/config-s3.json" <<JSON
{
    "main": {
        "workers": 1, "threads": 4, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 16777216,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" }
    },
    "servers": {
        "s1": {
            "domains": ["localhost", "127.0.0.1"], "ip": "127.0.0.1", "port": $PORT_S3,
            "root": "$WORK_DIR/www", "index": "index.html",
            "http": {
                "routes": {
                    "/media/(.*)": {
                        "GET": { "static_file": "{1}", "storage": "media" },
                        "HEAD": { "static_file": "{1}", "storage": "media" }
                    }
                }
            }
        }
    },
    "storages": {
        "media": {
            "type": "s3", "access_id": "$S3_KEY", "access_secret": "$S3_SECRET",
            "protocol": "http", "host": "${S3_ENDPOINT%%:*}", "port": "${S3_ENDPOINT##*:}",
            "bucket": "$S3_BUCKET", "region": "us-east-1"
        }
    },
    "mimetypes": { "text/html": ["html"], "application/octet-stream": ["bin"] }
}
JSON

    "$SERVER" -c "$WORK_DIR/config-s3.json" -f > "$WORK_DIR/server-s3.log" 2>&1 &
    S3_PID=$!
    sleep 2

    S3BASE="http://127.0.0.1:$PORT_S3"
    s3status() { curl -s -o /dev/null -w '%{http_code}' --max-time 120 "$@"; }

    if ! kill -0 "$S3_PID" 2>/dev/null; then
        cat "$WORK_DIR/server-s3.log" >&2
        fail 'the S3 server did not start'
    else

    # 1: объект целиком, побайтово совпадает
    curl -s --max-time 180 -o "$WORK_DIR/got.bin" "$S3BASE/media/video.bin"
    cmp -s "$WORK_DIR/video.bin" "$WORK_DIR/got.bin" \
        && ok 'a whole S3 object is served byte for byte' \
        || fail 'a whole S3 object differs from the source'

    # 2: диапазон совпадает с вырезкой
    curl -s --max-time 60 -H 'Range: bytes=100-199' -o "$WORK_DIR/part.bin" "$S3BASE/media/video.bin"
    dd if="$WORK_DIR/video.bin" of="$WORK_DIR/expect.bin" bs=1 skip=100 count=100 status=none
    cmp -s "$WORK_DIR/part.bin" "$WORK_DIR/expect.bin" \
        && ok 'a byte range matches the source slice' \
        || fail 'a byte range differs from the source slice'

    # 3: 206 и Content-Range
    headers=$(curl -s -D - -o /dev/null --max-time 60 -H 'Range: bytes=100-199' "$S3BASE/media/video.bin")
    contains "$headers" ' 206' && ok 'a ranged request answers 206' \
        || fail 'a ranged request did not answer 206'
    contains "$headers" "content-range: bytes 100-199/$S3_OBJECT_SIZE" \
        && ok 'Content-Range names the slice and the total' \
        || fail "Content-Range is wrong: $(printf '%s' "$headers" | grep -i content-range)"

    # 4: открытый конец клипуется размером порции (8 МБ)
    length=$(curl -s -D - -o /dev/null --max-time 180 -H 'Range: bytes=0-' "$S3BASE/media/video.bin" \
        | grep -i '^content-length:' | tr -dc '0-9')
    [ "$length" = "8388608" ] && ok 'an open-ended range is clipped to the chunk size' \
        || fail "an open-ended range gave Content-Length $length"

    # 5: суффиксная форма
    curl -s --max-time 60 -H 'Range: bytes=-100' -o "$WORK_DIR/suffix.bin" "$S3BASE/media/video.bin"
    tail -c 100 "$WORK_DIR/video.bin" > "$WORK_DIR/expect-suffix.bin"
    cmp -s "$WORK_DIR/suffix.bin" "$WORK_DIR/expect-suffix.bin" \
        && ok 'a suffix range serves the tail' || fail 'a suffix range is wrong'

    # 6: диапазон за концом объекта
    code=$(s3status -H 'Range: bytes=99999999-' "$S3BASE/media/video.bin")
    [ "$code" = "416" ] && ok 'a range past the end answers 416' || fail "range past the end: got $code"

    # 7: multi-range. Объект тянется целиком, дальше его режет обычный
    # range-фильтр — выходит настоящий multipart/byteranges.
    headers=$(curl -s -D - -o "$WORK_DIR/multi.bin" --max-time 180 \
        -H 'Range: bytes=0-1,5-10' "$S3BASE/media/video.bin")
    contains "$headers" ' 206' && ok 'a multi-range request answers 206' \
        || fail 'a multi-range request did not answer 206'
    contains "$headers" 'content-type: multipart/byteranges' \
        && ok 'a multi-range request is served as multipart/byteranges' \
        || fail "multi-range content type: $(printf '%s' "$headers" | grep -i content-type)"

    # 7a: If-Range с чужим валидатором — Range игнорируется целиком (RFC 9110
    # §13.1.5), и фильтр не должен нарезать ответ вместо нас
    headers=$(curl -s -D - -o /dev/null --max-time 180 \
        -H 'Range: bytes=100-199' -H 'If-Range: "stale-validator"' "$S3BASE/media/video.bin")
    contains "$headers" ' 200' && ok 'a stale If-Range serves the whole object' \
        || fail "stale If-Range: $(printf '%s' "$headers" | head -1)"

    # 8: условный запрос
    etag=$(curl -s -I --max-time 30 "$S3BASE/media/video.bin" | grep -i '^etag:' | tr -d '\r')
    value=${etag#*: }
    code=$(s3status -H "If-None-Match: $value" "$S3BASE/media/video.bin")
    [ "$code" = "304" ] && ok 'If-None-Match against an S3 object gives 304' || fail "If-None-Match: got $code"

    # 9: HEAD не качает тело — на 20 МБ это видно по времени
    started=$(date +%s)
    length=$(curl -s -I --max-time 30 "$S3BASE/media/video.bin" | grep -i '^content-length:' | tr -dc '0-9')
    elapsed=$(( $(date +%s) - started ))
    [ "$length" = "$S3_OBJECT_SIZE" ] && ok 'HEAD reports the full size' || fail "HEAD Content-Length: $length"
    [ "$elapsed" -lt 5 ] && ok 'HEAD does not download the body' || fail "HEAD took ${elapsed}s"

    # 10: отсутствующий объект
    code=$(s3status "$S3BASE/media/nosuch.bin")
    [ "$code" = "404" ] && ok 'a missing object answers 404' || fail "missing object: got $code"

    # 11: перемотки не растят потребление. Мерить надо после прогрева: до этого
    # места процесс уже скачал объект целиком дважды, и остывающие арены
    # аллокатора попали бы в окно измерения вместо самих перемоток.
    #
    # На санитизированной сборке измерение бессмысленно: редзоны и карантин
    # ASan дают десятки мегабайт там, где обычная сборка стоит на месте
    # (проверено: 30 диапазонных запросов — рост 24 КБ). ci.sh гоняет этот
    # скрипт на -DSANITIZE=none, где проверка и работает.
    seek_round() {
        for offset in 0 1000000 5000000 9000000 15000000 19000000; do
            curl -s -o /dev/null --max-time 60 \
                -H "Range: bytes=$offset-$((offset + 65535))" "$S3BASE/media/video.bin"
        done
    }

    asan=$(ldd "$SERVER" 2>/dev/null | grep -c libasan || true)
    if [ "${asan:-0}" -gt 0 ]; then
        printf 'skip: sanitized build, the seek memory check measures ASan quarantine\n'
    else
        # Замер по рабочему процессу: $S3_PID — родитель, память растёт не в нём
        worker=$(pgrep -x cwfr | sort -n | tail -1)

        seek_round
        rss_before=$(awk '/VmRSS/ {print $2}' "/proc/$worker/status")
        seek_round
        seek_round
        rss_after=$(awk '/VmRSS/ {print $2}' "/proc/$worker/status")
        growth=$(( rss_after - rss_before ))
        [ "$growth" -lt 4096 ] && ok "seeking grew RSS by ${growth} KB" \
            || fail "seeking grew RSS by ${growth} KB"
    fi

    # 12: та же ветка на h2 и h3. Смысл не в протоколе, а в очереди: h2 и h3
    # раздают её элементы по воркерам (fan-out), чего у h1.1 нет.
    #
    # Нужен TLS: h2 без ALPN клиенты не согласуют, а h3 живёт только поверх
    # QUIC. Секцию http3 конфиг принимает лишь от сборки с -DINCLUDE_HTTP3=yes,
    # поэтому она и добавляется только к ней.
    PORT_TLS=$((PORT + 2))

    framework=$(ls "$BUILD_DIR"/core/framework_shared/libcwfr_framework.so* 2>/dev/null | head -1)
    h3_section=""
    symbols=$(nm -D --defined-only "$framework" 2>/dev/null | grep -c quic || true)
    if [ -n "$framework" ] && [ "${symbols:-0}" -gt 0 ]; then
        h3_section=", \"http3\": { \"enabled\": true, \"port\": $PORT_TLS }"
    fi
    cat > "$WORK_DIR/config-s3-tls.json" <<JSON
{
    "main": {
        "workers": 1, "threads": 4, "reload": "hard",
        "buffer_size": 16384, "client_max_body_size": 16777216,
        "tmp": "/tmp", "gzip": ["text/html"],
        "log": { "enabled": true, "level": "error" }
    },
    "servers": {
        "s1": {
            "domains": ["localhost", "127.0.0.1"], "ip": "127.0.0.1", "port": $PORT_TLS,
            "root": "$WORK_DIR/www", "index": "index.html",
            "tls": {
                "fullchain": "$CORE_DIR/tests/data/quic_test_cert.pem",
                "private": "$CORE_DIR/tests/data/quic_test_key.pem",
                "ciphers": "TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256"
            }$h3_section,
            "http": {
                "routes": {
                    "/media/(.*)": { "GET": { "static_file": "{1}", "storage": "media" } }
                }
            }
        }
    },
    "storages": {
        "media": {
            "type": "s3", "access_id": "$S3_KEY", "access_secret": "$S3_SECRET",
            "protocol": "http", "host": "${S3_ENDPOINT%%:*}", "port": "${S3_ENDPOINT##*:}",
            "bucket": "$S3_BUCKET", "region": "us-east-1"
        }
    },
    "mimetypes": { "text/html": ["html"], "application/octet-stream": ["bin"] }
}
JSON

    "$SERVER" -c "$WORK_DIR/config-s3-tls.json" -f > "$WORK_DIR/server-s3-tls.log" 2>&1 &
    TLS_PID=$!
    sleep 2

    if ! kill -0 "$TLS_PID" 2>/dev/null; then
        cat "$WORK_DIR/server-s3-tls.log" >&2
        fail 'the TLS server did not start'
    else
        TLSBASE="https://localhost:$PORT_TLS"

        code=$(curl -sk --http2 -o /dev/null -w '%{http_code}' --max-time 120 \
            -H 'Range: bytes=100-199' "$TLSBASE/media/video.bin")
        [ "$code" = "206" ] && ok 'the S3 branch answers a ranged request over h2' \
            || fail "h2 ranged request: got $code"

        curl_h3=$(curl -V | grep -c HTTP3 || true)
        if [ -n "$h3_section" ] && [ "${curl_h3:-0}" -gt 0 ]; then
            code=$(curl -sk --http3 -o /dev/null -w '%{http_code}' --max-time 120 \
                -H 'Range: bytes=100-199' "$TLSBASE/media/video.bin")
            [ "$code" = "206" ] && ok 'the S3 branch answers a ranged request over h3' \
                || fail "h3 ranged request: got $code"
        elif [ -z "$h3_section" ]; then
            printf 'skip: the build has no HTTP/3, the h3 smoke is not run\n'
        else
            printf 'skip: curl has no HTTP/3 support, the h3 smoke is not run\n'
        fi
    fi

    kill "$TLS_PID" 2>/dev/null
    wait "$TLS_PID" 2>/dev/null

    fi

    kill "$S3_PID" 2>/dev/null
    wait "$S3_PID" 2>/dev/null
fi

if [ "$failed" -ne 0 ]; then
    printf 'storage routes: FAILED\n' >&2
    exit 1
fi

printf 'storage routes: OK\n'
