#!/usr/bin/env bash
# Isolated real-transport correctness/resource scenario; no throughput benchmark.
set -euo pipefail
BUILD_DIR=${1:?usage: tests/body_memory_integration.sh BUILD_DIR [WORK_DIR]}
BUILD_DIR=$(cd "$BUILD_DIR" && pwd)
WORK_DIR=${2:-$(mktemp -d /tmp/cwfr-body-integration-XXXXXX)}
CORE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$WORK_DIR/tmp" "$WORK_DIR/www"
WORK_DIR=$(cd "$WORK_DIR" && pwd)
for fixture in "$BUILD_DIR/exec/cwfr" "$BUILD_DIR/exec/body_memory_h3" \
    "$BUILD_DIR/exec/handlers/tests/libbody_memory_module.so"; do
    [ -f "$fixture" ] || { echo "missing fixture: $fixture" >&2; exit 2; }
done
python3 -c 'import h2.connection' || { echo 'python-h2 is required' >&2; exit 2; }
PORT=$(python3 - <<'PY'
import socket
with socket.socket() as s:
 s.bind(('127.0.0.1',0));print(s.getsockname()[1])
PY
)
python3 - "$WORK_DIR" "$CORE_DIR" "$BUILD_DIR" "$PORT" <<'PY'
import json,sys,os
work,core,build,port=sys.argv[1:]
module=build+'/exec/handlers/tests/libbody_memory_module.so'
routes={path:{'POST':{'file':module,'function':'body_check'}} for path in ['/body','/file','/json','/form']}
routes['/stats']={'GET':{'file':module,'function':'body_stats'}}
routes['/ws']={'GET':{'file':module,'function':'body_upgrade'}}
config={'main':{'workers':1,'threads':8,'reload':'hard','buffer_size':16384,'client_max_body_size':4194304,'tmp':work+'/tmp','gzip':[],
 'log':{'enabled':True,'level':'error'},'env':{'http3_idle_timeout_sec':2,'http3_handshake_rate':0}},
 'servers':{'s1':{'domains':['localhost','127.0.0.1'],'ip':'127.0.0.1','port':int(port),'root':work+'/www','index':'index.html',
 'tls':{'fullchain':core+'/tests/data/quic_test_cert.pem','private':core+'/tests/data/quic_test_key.pem','ciphers':'TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256'},
 'http3':{'enabled':True,'port':int(port)},'http':{'routes':routes},
 'websockets':{'default':{'file':module,'function':'body_ws'},'routes':{'/body':{'POST':{'file':module,'function':'body_ws'}}}}}},
 'mimetypes':{'text/html':['html']}}
body_store = {}
if 'BODY_STORE_MODE' in os.environ: body_store['mode'] = os.environ['BODY_STORE_MODE']
if 'BODY_FILE_THRESHOLD' in os.environ: body_store['file_threshold'] = int(os.environ['BODY_FILE_THRESHOLD'])
if body_store: config['main']['body_store'] = body_store
if 'BODY_STORE_CONFIG' in os.environ: config['main']['body_store'] = json.loads(os.environ['BODY_STORE_CONFIG'])
open(work+'/config.json','w').write(json.dumps(config,indent=2)+'\n')
PY
server_pid=
cleanup() {
    if [ -n "$server_pid" ]; then
        kill -TERM -- "-$server_pid" 2>/dev/null || true
        for ((i=0;i<50;i++)); do kill -0 "$server_pid" 2>/dev/null || break; sleep .1; done
        kill -KILL -- "-$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
setsid bash -c 'ulimit -n "$1"; exec "$2" -c "$3" -f' body-memory \
    "${BODY_FD_LIMIT:-128}" "$BUILD_DIR/exec/cwfr" "$WORK_DIR/config.json" > "$WORK_DIR/server.log" 2>&1 &
server_pid=$!
python3 "$CORE_DIR/tests/body_memory_probe.py" "$PORT" "$server_pid" "$WORK_DIR" "$BUILD_DIR"
# Complete graceful shutdown before checking sanitizer diagnostics.
cleanup
server_pid=
python3 - "$WORK_DIR/server.log" <<'PY_LOG'
import re,sys
text=open(sys.argv[1]).read()
assert not re.search(r'ERROR: (AddressSanitizer|LeakSanitizer)|runtime error:|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer)',text), text
PY_LOG
