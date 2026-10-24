"""Scan reachable/reflog Git history and the intended source tree with Gitleaks."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

from check_release import ROOT, source_files


VERSION = '8.30.1'
ARCHIVES = {
    'Windows': ('windows_x64.zip', 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e'),
    'Linux': ('linux_x64.tar.gz', '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'),
}


def scanner(root):
    if platform.machine().lower() not in {'amd64', 'x86_64'}:
        raise RuntimeError('Pinned scanner supports x64 Windows/Linux only')
    suffix, expected = ARCHIVES[platform.system()]
    cache = root / '.lab' / 'release-tools'
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / f'gitleaks_{VERSION}_{suffix}'
    if not archive.exists():
        url = f'https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/{archive.name}'
        with urllib.request.urlopen(url, timeout=120) as response:
            archive.write_bytes(response.read())
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise RuntimeError('Scanner archive SHA256 mismatch; refusing execution')
    executable_name = 'gitleaks.exe' if platform.system() == 'Windows' else 'gitleaks'
    directory = cache / f'gitleaks-{VERSION}'
    directory.mkdir(exist_ok=True)
    executable = directory / executable_name
    if suffix.endswith('.zip'):
        with zipfile.ZipFile(archive) as bundle:
            executable.write_bytes(bundle.read(executable_name))
    else:
        with tarfile.open(archive) as bundle:
            with bundle.extractfile(executable_name) as member:
                executable.write_bytes(member.read())
        executable.chmod(0o755)
    return executable, expected


def scan(executable, mode, target, report, config, ignore):
    command = [str(executable), mode, str(target), '--no-banner', '--no-color',
               '--redact=100', '--ignore-gitleaks-allow', '--config', str(config),
               '--gitleaks-ignore-path', str(ignore), '--max-target-megabytes=0',
               '--max-archive-depth=3', '--max-decode-depth=5', '--timeout=600',
               '--report-format=json', '--report-path', str(report)]
    if mode == 'git':
        command.append('--log-opts=--all --reflog --full-history')
    result = subprocess.run(command, cwd=target, capture_output=True, text=True)
    report.with_suffix('.log').write_text(result.stdout + result.stderr, encoding='utf-8')
    if result.returncode not in {0, 1} or not report.is_file():
        raise RuntimeError(f'{mode} scan failed; inspect redacted log {report.name}')
    findings = json.loads(report.read_text(encoding='utf-8')) or []
    if result.returncode == 1 and not findings:
        raise RuntimeError(f'{mode} scan failed without a findings report')
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / '.lab/release/security')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    executable, archive_digest = scanner(ROOT)
    config = ROOT / '.gitleaks.toml'
    ignore = output / 'empty.ignore'
    ignore.write_text('', encoding='utf-8')
    with tempfile.TemporaryDirectory(prefix='replicant-mesh-scanner-control-') as directory:
        control = Path(directory)
        synthetic = 'ghp_' + '0123456789abcdefghijklmnopqrstuvABCD'
        (control / 'control.txt').write_text('token = ' + synthetic + '\n', encoding='utf-8')
        detected = scan(executable, 'dir', control, output / 'positive-control.json', config, ignore)
        if not detected or any(synthetic in json.dumps(item) for item in detected):
            raise RuntimeError('Scanner detection/redaction positive control failed')
    names = source_files(ROOT)
    history = scan(executable, 'git', ROOT, output / 'history.json', config, ignore)
    with tempfile.TemporaryDirectory(prefix='replicant-mesh-source-scan-') as directory:
        snapshot = Path(directory)
        for name in names:
            source = ROOT / name
            if not source.exists():
                continue
            if source.is_symlink() or not source.resolve().is_relative_to(ROOT):
                raise RuntimeError(f'Refusing source symlink or escaped path: {name}')
            destination = snapshot / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        current = scan(executable, 'dir', snapshot, output / 'source.json', config, ignore)
    commit_count = subprocess.check_output(
        ['git', 'rev-list', '--all', '--reflog', '--count'], cwd=ROOT, text=True).strip()
    summary = {'scanner': 'gitleaks', 'version': VERSION, 'archive_sha256': archive_digest,
               'history_scope': 'all local refs and reflogs; fetch intended remote refs before scanning',
               'history_commits': int(commit_count), 'source_files': len(names),
               'history_findings': len(history), 'source_findings': len(current),
               'rules': dict(Counter(item['RuleID'] for item in history + current)),
               'redacted': True,
               'allowlist': 'exact public artifact identities and reviewed synthetic test/code markers',
               'inline_allow_comments_disabled': True, 'positive_control_passed': True}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))
    return int(bool(history or current))


if __name__ == '__main__':
    raise SystemExit(main())
