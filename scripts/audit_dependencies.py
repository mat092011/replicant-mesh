"""Record installed dependency provenance and license files inside a lab image."""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import subprocess


def canonical(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def inventory(root, stack):
    lock = root / 'docker/pytorch/requirements.lock'
    expected = {canonical(name): version for name, version in re.findall(
        r'^# ([A-Za-z0-9_.-]+)==(\S+)$', lock.read_text(), re.MULTILINE)} if stack == 'owned' else {}
    packages = []
    notice_texts = {}
    errors = []
    for distribution in sorted(importlib.metadata.distributions(),
                               key=lambda item: canonical(item.metadata['Name'])):
        name = distribution.metadata['Name']
        metadata = distribution.metadata
        licenses = []
        for file in distribution.files or []:
            basename = Path(str(file)).name.lower()
            if not re.match(r'^(licen[cs]e|copying|notice|copyright)([._-]|$)', basename):
                continue
            path = Path(distribution.locate_file(file))
            if not path.is_file():
                continue
            data = path.read_bytes()
            key = name + '/' + str(file)
            licenses.append({'path': str(file), 'sha256': hashlib.sha256(data).hexdigest(),
                             'bytes': len(data)})
            notice_texts[key] = data.decode('utf-8', errors='replace')
        direct_text = distribution.read_text('direct_url.json')
        direct = json.loads(direct_text) if direct_text else None
        version = distribution.version
        if canonical(name) in expected and expected[canonical(name)] != version:
            errors.append(f'Installed version differs from lock: {name}')
        packages.append({'name': name, 'version': version,
                         'license_expression': metadata.get('License-Expression'),
                         'license_metadata': metadata.get('License'),
                         'license_classifiers': [value for value in metadata.get_all('Classifier', [])
                                                 if value.startswith('License ::')],
                         'direct_url': direct, 'license_files': licenses,
                         'locked': canonical(name) in expected})
    installed = {canonical(package['name']) for package in packages}
    errors.extend('Locked distribution missing: ' + name for name in expected.keys() - installed)
    operating_system = []
    result = subprocess.run(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\n'],
                            capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        name, version, architecture = line.split('\t')
        copyright_path = Path('/usr/share/doc') / name.split(':')[0] / 'copyright'
        operating_system.append({'name': name, 'version': version, 'architecture': architecture,
                                  'copyright_sha256': hashlib.sha256(copyright_path.read_bytes()).hexdigest()
                                  if copyright_path.is_file() else None})
    return {'schema_version': 1, 'stack': stack,
            'lock_sha256': hashlib.sha256(lock.read_bytes()).hexdigest() if expected else None,
            'locked_packages': len(expected), 'packages': packages,
            'os_packages': operating_system, 'errors': errors}, notice_texts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/review'))
    parser.add_argument('--stack', choices=('owned', 'legacy'), default='owned')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--notices-output', type=Path, required=True)
    args = parser.parse_args()
    report, notices = inventory(args.root, args.stack)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    args.notices_output.write_text(json.dumps(notices, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({'stack': args.stack, 'packages': len(report['packages']),
                      'locked_packages': report['locked_packages'], 'notice_files': len(notices),
                      'os_packages': len(report['os_packages']), 'errors': report['errors']}))
    return int(bool(report['errors']))


if __name__ == '__main__':
    raise SystemExit(main())
