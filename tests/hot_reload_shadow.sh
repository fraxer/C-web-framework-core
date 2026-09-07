#!/usr/bin/env bash

# End-to-end gate for docs/hotreload/00-shadow-copy.md §6.
#
# A handler rebuilt at the same path is picked up by SIGUSR1; a handler with a
# private dependency next to it still resolves that dependency through $ORIGIN
# after the rebuild; the copies survive the reload and are gone once the process
# exits; repeated rebuild-and-reload does not accumulate mappings; and a reload
# with a broken `main.modules` path is refused while the server keeps serving.
#
# And the second half of the story (docs/hotreload/01-soname-per-generation.md
# §5): the application module itself is picked up in place, the handlers of the
# new generation call the *new* module, old generations are unloaded, a handler
# that does not depend on the module is not copied for its sake, and a `soft`
# reload that swaps the module never stops answering.

set -u -o pipefail

BUILD_DIR=${1:?usage: tests/hot_reload_shadow.sh BUILD_DIR [WORK_DIR]}
WORK_DIR=${2:-/tmp/cwfr-hot-reload-shadow}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER="$BUILD_DIR/exec/cwfr"
FRAMEWORK=$(find "$BUILD_DIR" -name libcwfr_framework.so -print -quit)
PORT=${HOT_RELOAD_SHADOW_PORT:-18461}

if [ ! -x "$SERVER" ] || [ -z "$FRAMEWORK" ]; then
    printf 'hot reload: cwfr or libcwfr_framework.so is missing in %s\n' "$BUILD_DIR" >&2
    exit 2
fi

# The framework's headers include each other by bare name, so a handler compiled
# outside the build system needs every directory that holds one. This is what
# `find_package(cwfr)` flattens into one directory at install time.
mapfile -t INCLUDES < <(find "$CORE_DIR/src" "$CORE_DIR/misc" "$CORE_DIR/framework" \
    "$CORE_DIR/protocols" -name '*.h' -printf '-I%h\n' | sort -u)

failures=0
step() { printf '\n== %s\n' "$1"; }
ok()   { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else fail "$1: expected '$3', got '$2'"; fi; }

HANDLER_DIR="$WORK_DIR/handlers"
rm -rf "$WORK_DIR"
mkdir -p "$HANDLER_DIR" "$WORK_DIR/root"
printf 'root\n' > "$WORK_DIR/root/index.html"

# A private library in the handler's own directory, reached only through the
# $ORIGIN in the handler's RPATH -- which is the whole reason a shadow copy is
# made next to the original instead of in a temporary directory.
cat > "$WORK_DIR/private.c" <<'EOF'
const char* private_greeting(void) { return "private"; }
EOF
gcc -shared -fPIC -o "$HANDLER_DIR/libprivate.so" "$WORK_DIR/private.c" \
    -Wl,-soname,libprivate.so || exit 2

build_handler() { # <version>
    cat > "$WORK_DIR/handler.c" <<EOF
#include <stdio.h>
#include "http.h"

const char* private_greeting(void);

void get(httpctx_t* ctx) {
    char body[64];
    snprintf(body, sizeof body, "v$1 %s", private_greeting());
    ctx->response->send_data(ctx->response, body);
}
EOF
    gcc -shared -fPIC -o "$WORK_DIR/handler.staging.so" "$WORK_DIR/handler.c" \
        -DPCRE2_CODE_UNIT_WIDTH=8 "${INCLUDES[@]}" "$FRAMEWORK" \
        -L"$HANDLER_DIR" -lprivate -Wl,-rpath,'$ORIGIN' -Wl,-soname,lib_handler.so || return 1
    # Published the way a linker does: a new inode under the same name.
    mv "$WORK_DIR/handler.staging.so" "$HANDLER_DIR/lib_handler.so"
}

# The application module: it exports something a handler calls, and it registers
# the context destructors -- whose address differs between builds, which is what
# used to make a module reload impossible to accept at all.
build_module() { # <version>
    cat > "$WORK_DIR/module.c" <<EOF
#include <stdlib.h>
#include "httpcontext.h"
#include "wscontext.h"
#include "middleware_registry.h"

const char* module_tag(void) { return "m$1"; }

static void payload_free_$1(void* payload) { free(payload); }

static int mw_base(httpctx_t* ctx) { (void)ctx; return 1; }

/* Only from the second build on. A route may name it in the very reload that
 * brings this build, which is the case the validation pass has to be able to
 * resolve -- it runs this app_init(), not the previous one. */
static int mw_added(httpctx_t* ctx) {
    ctx->response->add_header(ctx->response, "X-Added", "yes");
    return 1;
}

int app_init(void) {
    if (!httpctx_set_user_data_free(payload_free_$1)) return 0;
    if (!wsctx_set_user_data_free(payload_free_$1)) return 0;
    if (!middleware_registry_register("mw_base", (middleware_fn_p)mw_base)) return 0;
    if ($1 > 1 && !middleware_registry_register("mw_added", (middleware_fn_p)mw_added)) return 0;
    return 1;
}
EOF
    gcc -shared -fPIC -o "$WORK_DIR/module.staging.so" "$WORK_DIR/module.c" \
        -DPCRE2_CODE_UNIT_WIDTH=8 "${INCLUDES[@]}" "$FRAMEWORK" \
        -Wl,-soname,libtestmodule.so || return 1
    mv "$WORK_DIR/module.staging.so" "$WORK_DIR/libtestmodule.so"
}

# A handler that calls into the module, so it records it in DT_NEEDED -- the
# dependency the whole SONAME-per-generation exercise is about.
build_module_handler() {
    cat > "$WORK_DIR/modhandler.c" <<'EOF'
#include <stdio.h>
#include "http.h"

const char* module_tag(void);

void get(httpctx_t* ctx) {
    char body[64];
    snprintf(body, sizeof body, "handler+%s", module_tag());
    ctx->response->send_data(ctx->response, body);
}
EOF
    gcc -shared -fPIC -o "$HANDLER_DIR/lib_modhandler.so" "$WORK_DIR/modhandler.c" \
        -DPCRE2_CODE_UNIT_WIDTH=8 "${INCLUDES[@]}" "$FRAMEWORK" \
        "$WORK_DIR/libtestmodule.so" -Wl,-soname,lib_modhandler.so || return 1
}

build_module 1 || exit 2
build_module_handler || exit 2

CONFIG="$WORK_DIR/config.json"
RELOAD_MODE=hard
MIDDLEWARES='"mw_base"'
write_config() { # <module path>
    cat > "$CONFIG.next" <<JSON
{
    "main": {
        "workers": 1, "threads": 2, "reload": "$RELOAD_MODE",
        "buffer_size": 16384, "client_max_body_size": 1048576,
        "tmp": "$WORK_DIR", "gzip": ["text/html"],
        "modules": ["$1"],
        "log": { "enabled": true, "level": "info" }
    },
    "servers": {
        "s1": {
            "domains": ["localhost"],
            "ip": "127.0.0.1", "port": $PORT,
            "root": "$WORK_DIR/root", "index": "index.html",
            "http": {
                "middlewares": [$MIDDLEWARES],
                "routes": {
                    "/hello":  { "GET": { "file": "$HANDLER_DIR/lib_handler.so",    "function": "get" } },
                    "/module": { "GET": { "file": "$HANDLER_DIR/lib_modhandler.so", "function": "get" } }
                }
            }
        }
    },
    "mimetypes": { "text/html": ["html"] }
}
JSON
    mv "$CONFIG.next" "$CONFIG"
}

server_pid=
cleanup() {
    if [ -n "$server_pid" ]; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

fetch() { curl -s --max-time 5 -H "Host: localhost" "http://127.0.0.1:$PORT/$1" 2>/dev/null; }
body() { fetch hello; }
module_body() { fetch module; }

wait_for() { # <path> <expected>
    for _ in $(seq 1 100); do
        [ "$(fetch "$1")" = "$2" ] && return 0
        sleep 0.1
    done
    return 1
}

wait_for_body() { wait_for hello "$1"; }

shadow_files() { find "$HANDLER_DIR" -name '.cwfr-shadow-*' | wc -l; }
plain_handler_copies() { find "$HANDLER_DIR" -name '.cwfr-shadow-*lib_handler.so' | wc -l; }
module_objects() {
    grep -oE '[^ ]*libtestmodule[^ ]*' "/proc/$server_pid/maps" 2>/dev/null | sort -u | wc -l
}
handler_maps() { grep -c 'lib_handler.so\|cwfr-shadow' "/proc/$server_pid/maps" 2>/dev/null || echo 0; }

build_handler 1 || exit 2
write_config "$WORK_DIR/libtestmodule.so"

step "the server starts and serves the handler"
"$SERVER" -c "$CONFIG" -f > "$WORK_DIR/server.log" 2>&1 &
server_pid=$!
if wait_for_body "v1 private"; then ok "v1 answers"; else fail "server did not come up"; cat "$WORK_DIR/server.log"; exit 1; fi
check "the module-dependent handler answers"  "$(module_body)" "handler+m1"
check "no copies before anything is rebuilt" "$(shadow_files)" "0"

step "a handler rebuilt in place is picked up by SIGUSR1"
build_handler 2 || exit 2
kill -USR1 "$server_pid"
if wait_for_body "v2 private"; then
    ok "the rebuilt handler answers, and its \$ORIGIN dependency still resolves"
else
    fail "SIGUSR1 did not pick up the rebuilt handler (got '$(body)')"
fi
check "the reload left one copy behind" "$(shadow_files)" "1"

step "repeated rebuild and reload does not accumulate mappings"
for version in 3 4 5 6; do
    build_handler "$version" || exit 2
    kill -USR1 "$server_pid"
    wait_for_body "v$version private" || fail "reload to v$version did not take"
done
# An old generation is unloaded by its last thread, which is not the thread that
# answered the request the loop above waited for -- so the count is read once it
# has settled, not the moment the new generation starts serving.
maps_after=$(handler_maps)
for _ in $(seq 1 40); do
    [ "$maps_after" -le 10 ] && break
    sleep 0.5
    maps_after=$(handler_maps)
done
# Five text/data/relro/bss mappings per loaded object is the usual shape; two
# generations may overlap while the old one drains, so allow for two and no more.
if [ "$maps_after" -le 10 ]; then
    ok "$maps_after handler mappings after five reloads -- old generations unloaded"
else
    fail "handler mappings grew to $maps_after; old generations are not being unloaded"
fi

step "the application module is picked up when it is rebuilt in place"
copies_before=$(shadow_files)
build_module 2 || exit 2
# The same reload introduces a middleware that only this build registers: the
# name is in no registry until the new module's app_init() has run, so the
# validation pass has to run it rather than check against the running one.
MIDDLEWARES='"mw_base", "mw_added"'
write_config "$WORK_DIR/libtestmodule.so"
kill -USR1 "$server_pid"
if wait_for module "handler+m2"; then
    ok "the handler of the new generation calls the rebuilt module"
else
    fail "a rebuilt module was not picked up (got '$(module_body)')"
fi
check "the handler that does not need the module is unaffected" "$(body)" "v6 private"
added=$(curl -s -D- -o /dev/null --max-time 5 -H "Host: localhost" \
    "http://127.0.0.1:$PORT/module" 2>/dev/null | tr -d '\r' | grep -ci '^X-Added: yes')
check "a middleware introduced by that same build is in force" "$added" "1"
# It has to gain no copy of its own: only what actually names the module in
# DT_NEEDED is copied for the module's sake.
check "and was not copied for the module's sake" "$(plain_handler_copies)" "$copies_before"

for version in 3 4; do
    build_module "$version" || exit 2
    kill -USR1 "$server_pid"
    wait_for module "handler+m$version" || fail "module reload to m$version did not take"
done
objects=$(module_objects)
for _ in $(seq 1 40); do
    [ "$objects" -le 2 ] && break
    sleep 0.5
    objects=$(module_objects)
done
if [ "$objects" -le 2 ]; then
    ok "$objects module object(s) after three swaps -- old generations unloaded"
else
    fail "$objects module objects are mapped; old generations are not being unloaded"
fi

step "a soft reload that swaps the module never stops answering"
RELOAD_MODE=soft
write_config "$WORK_DIR/libtestmodule.so"
kill -USR1 "$server_pid"
sleep 1
build_module 5 || exit 2
kill -USR1 "$server_pid"
refused=0
for _ in $(seq 1 40); do
    case "$(module_body)" in
        handler+m*) ;;
        *) refused=$((refused + 1)) ;;
    esac
done
check "every request during the swap was answered" "$refused" "0"
if wait_for module "handler+m5"; then
    ok "and the new module is what answers once the reload has landed"
else
    fail "the soft reload did not pick the rebuilt module up (got '$(module_body)')"
fi
RELOAD_MODE=hard
write_config "$WORK_DIR/libtestmodule.so"
kill -USR1 "$server_pid"
sleep 1

step "a reload with a broken main.modules path is refused, and serving continues"
write_config "$WORK_DIR/does-not-exist.so"
kill -USR1 "$server_pid"
sleep 1
check "the old configuration keeps serving" "$(body)" "v6 private"
if grep -q 'app_modules_check' "$WORK_DIR/server.log"; then
    ok "the module check said why"
else
    fail "nothing in the log explains the refusal"
fi
write_config "$WORK_DIR/libtestmodule.so"

step "the copies are gone once the process exits"
kill -TERM "$server_pid"
wait "$server_pid" 2>/dev/null
server_pid=
sleep 0.5
check "no copies left in the handler directory" "$(shadow_files)" "0"

printf '\n'
if [ "$failures" -eq 0 ]; then
    printf 'hot reload (shadow copies): PASS\n'
    exit 0
fi

printf 'hot reload (shadow copies): FAIL (%d)\n' "$failures"
exit 1
