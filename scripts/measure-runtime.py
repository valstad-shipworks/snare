import argparse
import hashlib
import json
import os
import platform
import random
import statistics
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser(
    description='Compare snare runtime probe executables serially on macOS.'
)
parser.add_argument('--before', required=True, type=Path)
parser.add_argument(
    '--after', type=Path, default=Path('target/release/examples/performance_probe')
)
parser.add_argument('--output', type=Path, default=Path('target/performance'))
parser.add_argument('--repeats', type=int, default=5)
parser.add_argument(
    '--suite', choices=['runtime', 'send-recv', 'recvmsg', 'udp32'], default='runtime'
)
parser.add_argument(
    '--payloads', type=int, nargs='+',
    help='payload bytes for send-recv or recvmsg; each must be between 1 and 8192',
)
args = parser.parse_args()
if platform.system() != 'Darwin':
    parser.error('this matrix currently targets macOS')
if args.repeats < 1:
    parser.error('--repeats must be positive')
if args.payloads is not None:
    if args.suite not in ['send-recv', 'recvmsg']:
        parser.error('--payloads requires --suite send-recv or recvmsg')
    if any(size < 1 or size > 8192 for size in args.payloads):
        parser.error('--payloads must be between 1 and 8192 bytes')
    args.payloads = list(dict.fromkeys(args.payloads))
for executable in [args.before, args.after]:
    if not executable.is_file():
        parser.error(f'executable missing: {executable}')

root = args.output
root.mkdir(parents=True, exist_ok=True)
executables = {
    'before': str(args.before.resolve()),
    'after': str(args.after.resolve()),
}
matrix = []
for mode in ['plain', 'det', 'host']:
    for size, iterations in [(1, 20000), (64, 5000), (1024, 300)]:
        matrix.append((mode, 'poll', size, iterations))
    for payload in [4, 1024, 8192]:
        matrix.append((mode, f'poll_ready_{payload}', 128, 100))
    for case, iterations in [
        ('clock', 1000000),
        ('yield', 200000),
        ('empty', 100000),
        ('udp', 20000),
        ('tcp', 10000),
        ('mutex', 2000000),
        ('sleep', 50000),
        ('spawn', 1000),
    ]:
        matrix.append((mode, case, 2, iterations))
for mode in ['plain', 'host']:
    for size in [100, 200, 400, 800, 1600]:
        for case in ['explicit_bind', 'ephemeral_bind']:
            matrix.append((mode, case, size, 1))
for mode in ['plain', 'det']:
    for size in [1000, 2000, 4000, 8000]:
        for case in ['timer_register', 'timer_cancel_reverse']:
            matrix.append((mode, case, size, 1))

if args.suite == 'send-recv':
    matrix = []
    for mode in ['plain', 'det', 'host']:
        for size in [2, 64, 1024]:
            for payload in args.payloads or [4, 1024, 8192]:
                for prefix in ['udp', 'udp_connected']:
                    matrix.append((mode, f'{prefix}_{payload}', size, 50000))
        for payload in args.payloads or [64, 1024, 8192]:
            matrix.append((mode, f'tcp_{payload}', 2, 20000))
        matrix.append((mode, 'empty', 2, 100000))
elif args.suite == 'recvmsg':
    matrix = []
    for mode in ['plain', 'det', 'host']:
        for protocol in ['udp', 'tcp']:
            for payload in args.payloads or [4, 1024, 8192]:
                for prefix in ['recvmsg', 'recvmsg_vectored']:
                    matrix.append((mode, f'{protocol}_{prefix}_{payload}', 2, 50000))
elif args.suite == 'udp32':
    matrix = []
    for mode in ['plain', 'det', 'host']:
        for case in [
            'udp_128', 'udp_connected_128', 'udp_mesh_128',
            'udp_mesh_connected_128', 'udp_burst_128', 'udp_burst_connected_128',
            'udp_threaded_128',
        ]:
            iterations = (
                1000 if case.startswith('udp_threaded_')
                else 10000 if case.startswith('udp_burst_') else 300000
            )
            matrix.append((mode, case, 32, iterations))
metadata = dict(
    uname=list(platform.uname()),
    cpu_count=os.cpu_count(),
    load_before=os.getloadavg(),
    clock=time.strftime('%Y-%m-%dT%H:%M:%S%z'),
    repeats=args.repeats,
    paired=True,
    suite=args.suite,
    payloads=args.payloads,
    executables={
        version: dict(
            path=exe,
            sha256=hashlib.sha256(Path(exe).read_bytes()).hexdigest(),
        )
        for version, exe in executables.items()
    },
    rustc=subprocess.check_output(['rustc', '--version'], text=True).strip(),
)

rows = []
with (root / 'macos-comparison-samples.jsonl').open('w') as log:
    for repeat in range(args.repeats):
        jobs = matrix.copy()
        rng = random.Random(9044 + repeat)
        rng.shuffle(jobs)
        for index, (mode, case, size, iterations) in enumerate(jobs):
            versions = list(executables)
            rng.shuffle(versions)
            for version in versions:
                try:
                    result = subprocess.run(
                        [executables[version], mode, case, str(size), str(iterations)],
                        text=True,
                        capture_output=True,
                        timeout=45,
                    )
                    row = (
                        json.loads(result.stdout.strip().splitlines()[-1])
                        if result.returncode == 0
                        else dict(error=result.stderr[-2000:], exit=result.returncode)
                    )
                except Exception as error:
                    row = dict(error=str(error))
                row.update(
                    version=version,
                    repeat=repeat,
                    mode=mode,
                    case=case,
                    size=size,
                    iterations=iterations,
                )
                rows.append(row)
                log.write(json.dumps(row) + '\n')
                log.flush()
                if 'error' in row:
                    print(row, flush=True)
            if index % 10 == 0:
                print(repeat + 1, index + 1, '/', len(jobs), mode, case, size, flush=True)

summary = []
for mode, case, size, iterations in matrix:
    row = dict(mode=mode, case=case, size=size, iterations=iterations)
    for version in executables:
        matched = [
            r
            for r in rows
            if r['version'] == version
            and (r['mode'], r['case'], r['size'], r['iterations'])
            == (mode, case, size, iterations)
            and 'error' not in r
        ]
        values = [r['ns_per_operation'] for r in matched]
        row[version] = dict(
            samples=len(values),
            median_ns=statistics.median(values) if values else None,
            min_ns=min(values) if values else None,
            max_ns=max(values) if values else None,
        )
    if row['before']['median_ns'] and row['after']['median_ns']:
        row['speedup'] = row['before']['median_ns'] / row['after']['median_ns']
        ratios = []
        for repeat in range(args.repeats):
            pair = {
                r['version']: r['ns_per_operation']
                for r in rows
                if r['repeat'] == repeat
                and (r['mode'], r['case'], r['size'], r['iterations'])
                == (mode, case, size, iterations)
                and 'error' not in r
            }
            if pair.get('before') and pair.get('after'):
                ratios.append(pair['before'] / pair['after'])
        row['paired_speedup_median'] = (
            statistics.median(ratios) if ratios else None
        )
    summary.append(row)

(root / 'macos-comparison-summary.json').write_text(json.dumps(summary, indent=2))
metadata['load_after'] = os.getloadavg()
(root / 'macos-comparison-environment.json').write_text(json.dumps(metadata, indent=2))
print(
    'done', len(rows), 'samples', sum('error' in r for r in rows), 'errors', flush=True
)
if any('error' in row for row in rows):
    raise SystemExit(1)
