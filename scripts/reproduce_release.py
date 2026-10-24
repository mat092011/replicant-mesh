"""Reproduce the candidate in a fresh local clone with isolated lab resources."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import uuid

from check_release import ROOT, source_files, tree_digest


SERVICES = ('prepare', 'tests', 'benchmark', 'worker-1', 'worker-2', 'worker-3',
            'remote-check', 'coordinator-check', 'coordinator', 'pipeline-benchmark',
            'service-check', 'replica-1', 'replica-2', 'replica-3', 'replica-4',
            'matched-control-check')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / '.lab/release/reproduction')
    args = parser.parse_args()
    identity = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    output = args.output.resolve() / identity
    output.mkdir(parents=True)
    source = output / 'source'
    project = 'replicant-mesh-release-' + identity.lower()
    image = 'replicant-mesh-release:' + identity.lower()
    names = source_files(ROOT)
    runtime_names = [name for name in names if not name.endswith('.md') and (
        name.startswith(('src/', 'lab/', 'tests/', 'scripts/', 'docker/'))
        or name == 'compose.pytorch.yaml')]
    report = {'schema_version': 1, 'identity': identity,
              'source_kind': 'fresh local clone of HEAD plus uncommitted candidate overlay',
              'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'source_digest': tree_digest(ROOT, names), 'source_files': len(names),
              'runtime_source_digest': tree_digest(ROOT, runtime_names),
              'build_cache_allowed': True, 'fresh_model_volumes': True,
              'independent_device': False, 'project': project, 'steps': []}

    def run(name, command, cwd=source):
        started = datetime.now(timezone.utc).isoformat()
        with (output / (name + '.log')).open('w', encoding='utf-8') as log:
            result = subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
        report['steps'].append({'name': name, 'exit_code': result.returncode,
                                'started_at_utc': started,
                                'ended_at_utc': datetime.now(timezone.utc).isoformat()})
        print(f'{name}: exit {result.returncode}', flush=True)
        if result.returncode:
            raise RuntimeError(f'{name} failed; evidence retained')

    compose = ['docker', 'compose', '-p', project, '-f', 'compose.pytorch.yaml',
               '-f', 'compose.release.json']
    configured = False
    try:
        run('clone', ['git', 'clone', '--quiet', '--no-hardlinks', str(ROOT), str(source)], ROOT)
        old_names = source_files(source)
        for name in old_names:
            if name not in names and (source / name).is_file():
                (source / name).unlink()
        for name in names:
            candidate = ROOT / name
            if not candidate.exists():
                continue
            if candidate.is_symlink() or not candidate.resolve().is_relative_to(ROOT):
                raise RuntimeError(f'Unsupported source path: {name}')
            destination = source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate, destination)
        if tree_digest(source, names) != report['source_digest']:
            raise RuntimeError('Candidate export digest mismatch')
        results = source / '.lab/pytorch-results'
        results.mkdir(parents=True)
        override = {'services': {service: {'image': image} for service in SERVICES}}
        (source / 'compose.release.json').write_text(json.dumps(override), encoding='utf-8')
        configured = True
        run('compose-config', compose + ['config', '--quiet'])
        run('build', compose + ['build', '--pull', 'prepare'])
        report['image'] = subprocess.check_output(['docker', 'image', 'inspect', image,
                                                  '--format', '{{.Id}}'], text=True).strip()
        run('prepare', compose + ['run', '--rm', 'prepare'])
        run('tests', compose + ['run', '--rm', 'tests'])
        run('start', compose + ['up', '-d', '--wait', 'worker-1', 'worker-2',
                               'worker-3', 'coordinator', 'pipeline-benchmark'])
        run('service-check', compose + ['run', '--rm', '--no-deps', 'service-check'])
        run('smoke', compose + ['exec', '-T', 'pipeline-benchmark', 'python', '-m',
                               'lab.benchmark', 'bench', '--backend', 'pipeline',
                               '--coordinator', 'coordinator:50052', '--prompt-tokens',
                               '128', '--new-tokens', '8', '--concurrency', '3',
                               '--requests', '6', '--label', 'release-reproduction'])
        report['success'] = True
    except Exception as error:
        report['success'] = False
        report['error'] = str(error)
    finally:
        if configured:
            try:
                run('cleanup', compose + ['down', '--volumes', '--remove-orphans'])
            except Exception as error:
                report['success'] = False
                report['cleanup_error'] = str(error)
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(f'Evidence: {output}', flush=True)
    return int(not report.get('success'))


if __name__ == '__main__':
    raise SystemExit(main())
