#!/usr/bin/env python3 -I
"""Parse measure2.sh's runs (RUNS/*.{json,err,time}) into RESULTS (JSON) and print the summary
table (medians over the runs of each config and variant).

usage: python3 -I parse2.py RUNS RESULTS   (RESULTS must not exist: published results are never
overwritten; RESULTS-2.md's table is this script's output over its runs2/)"""
import json, re, glob, os, statistics, collections, sys

if len(sys.argv) != 3:
    sys.exit(__doc__)
RUNS, RESULTS = sys.argv[1], sys.argv[2]
if os.path.exists(RESULTS):
    sys.exit(f'{RESULTS} exists: not overwritten')
TIMING = re.compile(r'^vci: timing: (.*): ([0-9.]+)s$')

def parse_err(path):
    steps = {}
    store = []
    lines = []
    verdict_threads = {}
    objects = None
    warnings = []
    rss = None
    for line in open(path, errors='replace'):
        line = line.rstrip('\n')
        m = TIMING.match(line)
        if m:
            label, secs = m.group(1), float(m.group(2))
            steps[label] = secs
            if label.startswith('store: '):
                store.append((label, secs))
            continue
        if line.startswith('vci: timing: objects:'):
            objects = line[len('vci: timing: '):]
            continue
        mv = re.match(r'^vci: timing: (\S+): verdicts: (\d+) candidate\(s\) checked, (\d+) rehashed; thread-seconds: (.*)$', line)
        if mv:
            d = {'checked': int(mv.group(2)), 'rehashed': int(mv.group(3))}
            for part in mv.group(4).split(', '):
                k, v = part.rsplit(' ', 1)
                d[k] = float(v)
            verdict_threads[mv.group(1)] = d
            continue
        if line.startswith('vci: warning') or line.startswith('vci: error') or 'error' in line.lower() and line.startswith('vci:'):
            warnings.append(line[:300])
        mr = re.match(r'^\s*(\d+)\s+maximum resident set size', line)
        if mr:
            rss = int(mr.group(1))
        mt = re.match(r'^\s*([0-9.]+) real\s+([0-9.]+) user\s+([0-9.]+) sys', line)
        if mt:
            steps['_time_real'] = float(mt.group(1)); steps['_time_user'] = float(mt.group(2)); steps['_time_sys'] = float(mt.group(3))
    # Store requests and bytes out of the store lines.
    req = 0; mb = 0.0; values = 0; listed = 0
    for label, secs in store:
        r = re.search(r'(\d+) request\(s\)', label)
        if r: req += int(r.group(1))
        b = re.search(r'([0-9.]+) MB', label)
        if b: mb += float(b.group(1))
        v = re.search(r'(\d+) value\(s\)', label)
        if v: values += int(v.group(1))
        l = re.search(r'list (\d+) unit', label)
        if l: listed = int(l.group(1))
    return {'steps': steps, 'store_lines': store, 'store_requests': req, 'store_mb': round(mb, 2), 'store_values': values,
            'listed': listed, 'verdicts': verdict_threads, 'objects': objects, 'warnings': warnings, 'max_rss_bytes': rss}

def parse_json(path):
    try:
        d = json.load(open(path))
    except Exception as e:
        return {'error': str(e)[:200]}
    files = d.get('files', [])
    by_proj = collections.defaultdict(lambda: {'skip': 0, 'run': 0})
    reasons = collections.Counter()
    for f in files:
        by_proj[f['project']]['skip' if f.get('skip') else 'run'] += 1
        if not f.get('skip'):
            reasons[re.sub(r'\(\d+ candidates', '(N candidates', f.get('reason', ''))[:110]] += 1
    return {'files': len(files), 'skip': sum(v['skip'] for v in by_proj.values()), 'run': sum(v['run'] for v in by_proj.values()),
            'by_project': dict(by_proj), 'reasons': reasons.most_common(8), 'runAll': d.get('runAll')}

def main():
    runs = []
    for t in sorted(glob.glob(RUNS + '/*.time')):
        base = t[:-5]
        name = os.path.basename(base)
        rest, n = name.rsplit('-', 1)
        cfg = next(c for c in ('before-f3', 'before-f1', 'fix1-f3', 'after-f3', 'after-f1', '281-f1') if rest.startswith(c + '-'))
        variant = rest[len(cfg) + 1:]
        tm = dict(kv.split('=') for kv in open(t).read().split())
        r = {'config': cfg, 'variant': variant, 'n': int(n), 'exit': int(tm['exit']), 'wall': float(tm['wall']), 'probes_after_exit': int(tm.get('probes_after_exit', 0))}
        r.update(parse_err(base + '.err'))
        r['plan'] = parse_json(base + '.json')
        runs.append(r)
    # Medians per (config, variant).
    groups = collections.defaultdict(list)
    for r in runs:
        groups[(r['config'], r['variant'])].append(r)
    keys = ['read the base commit\'s policy and signers', 'vex-api: resolve toolchain and externals', 'fetch the stored values the plan reads',
            'read the candidates', 'load the verdict objects', 'verdicts (rehash inputs, check candidates)', 'plan total']
    def med(xs):
        xs = [x for x in xs if x is not None]
        return statistics.median(xs) if xs else None
    rows = []
    for (cfg, variant), rs in sorted(groups.items()):
        row = {'config': cfg, 'variant': variant, 'runs': len(rs), 'wall_median': med([r['wall'] for r in rs]),
               'wall_all': [r['wall'] for r in rs], 'user_median': med([r['steps'].get('_time_user') for r in rs]),
               'rss_mb_median': med([r['max_rss_bytes'] / 1e6 for r in rs if r['max_rss_bytes']]),
               'store_requests_median': med([r['store_requests'] for r in rs]), 'store_mb_median': med([r['store_mb'] for r in rs]),
               'skip': med([r['plan'].get('skip') for r in rs]), 'run': med([r['plan'].get('run') for r in rs]),
               'exit': [r['exit'] for r in rs], 'probes_after_exit': sum(r['probes_after_exit'] for r in rs),
               'wall_min': min(r['wall'] for r in rs), 'wall_max': max(r['wall'] for r in rs)}
        for k in keys:
            row[k] = med([r['steps'].get(k) for r in rs])
        vt = collections.defaultdict(list)
        for r in rs:
            for proj, d in r['verdicts'].items():
                for kk, v in d.items():
                    vt[(proj, kk)].append(v)
        row['verdict_threads_median'] = {f'{p}.{k}': med(v) for (p, k), v in vt.items()}
        rows.append(row)
    json.dump({'runs': runs, 'summary': rows}, open(RESULTS, 'x'), indent=1, default=str)
    def f(x, w=6):
        return ('%*.2f' % (w, x)) if isinstance(x, (int, float)) else ' ' * (w - 1) + '-'
    print('| config | variant | runs | wall s (median) | wall min..max | plan total s | resolve toolchain s | fetch values s | read cands s | load objects s | verdicts s | store req | store MB | skip | run | RSS MB |')
    print('|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
    for row in rows:
        print('| %s | %s | %d | %s | %.1f..%.1f | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |' % (
            row['config'], row['variant'], row['runs'], f(row['wall_median']), min(row['wall_all']), max(row['wall_all']), f(row['plan total']), f(row["vex-api: resolve toolchain and externals"]), f(row['fetch the stored values the plan reads']),
            f(row['read the candidates']), f(row['load the verdict objects']), f(row['verdicts (rehash inputs, check candidates)']),
            f(row['store_requests_median'], 3), f(row['store_mb_median']), f(row['skip'], 4), f(row['run'], 4), f(row['rss_mb_median'])))
    print()
    for row in rows:
        print(row['config'], row['variant'], 'walls', row['wall_all'], 'exit', row['exit'], 'probes left after exit', row['probes_after_exit'])
        print('   verdict thread-seconds (median):', {k: v for k, v in row['verdict_threads_median'].items() if v})
    for (cfg, variant), rs in sorted(groups.items()):
        r = rs[0]
        print(cfg, variant, 'objects:', r['objects'])
        print('   store lines:', r['store_lines'])
        print('   reasons:', r['plan'].get('reasons'))
        print('   warnings:', r['warnings'][:4])

main()
