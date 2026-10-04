"""Configured body policies over real transports and startup validation."""
import json
import os
from pathlib import Path
import subprocess
import sys

build = Path(sys.argv[1]).resolve()
work = Path(sys.argv[2]).resolve()
core = Path(__file__).resolve().parent.parent
work.mkdir(parents=True, exist_ok=True)
results = []
policies = [(mode, threshold, {'mode': mode, 'file_threshold': threshold})
            for mode, threshold in [('auto', 0), ('auto', 257), ('auto', 2097152),
                                    ('memory', 1), ('file', 4294967295)]]
policies += [('auto', 1048576, {}), ('memory', 1048576, {'mode': 'memory'}),
             ('auto', 1024, {'file_threshold': 1024})]
for mode, threshold, policy in policies:
    case = work / f'{mode}-{threshold}'
    env = {**os.environ, 'BODY_STORE_MODE': mode, 'BODY_FILE_THRESHOLD': str(threshold),
           'BODY_STORE_CONFIG': json.dumps(policy), 'BODY_POLICY_ONLY': '1'}
    case.mkdir(exist_ok=True)
    with (case / 'probe.log').open('w') as log:
        subprocess.run([str(core / 'tests/body_memory_integration.sh'), str(build), str(case)],
                       env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
    results.append(json.loads((case / 'results.json').read_text()))

base = json.loads((case / 'config.json').read_text())
base['main']['body_store'] = {'mode': 'auto', 'file_threshold': 1048576}
invalid = [('mode', v) for v in [None, False, 0, 'MEMORY', 'unknown', 'auto\x00file', {}]]
invalid += [('file_threshold', v) for v in [None, False, '10', -1, .5, 1.5, 4294967296, 1e100]]
invalid += [('body_store', v) for v in [None, False, 1, 'auto', []]]
for index, (key, value) in enumerate(invalid):
    config = json.loads(json.dumps(base))
    if key == 'body_store': config['main'][key] = value
    else: config['main']['body_store'][key] = value
    path = work / f'invalid-{index}.json'
    path.write_text(json.dumps(config))
    for foreground in (True, False):
        proc = subprocess.run([str(build / 'exec/cwfr'), '-c', str(path), *(['-f'] if foreground else [])],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
        (work / f'invalid-{index}-{foreground}.log').write_text(proc.stdout)
        assert proc.returncode != 0 and key in proc.stdout, (key, value, foreground, proc.returncode, proc.stdout)
summary = {'status': 'PASS', 'policy_cases': len(results),
           'validated_handler_calls': sum(r['validated_handler_calls'] for r in results),
           'invalid_startups': 2*len(invalid)}
(work / 'results.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps(summary, indent=2))
