"""Dependency-free source-release checks; does not run model validation."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {'.safetensors', '.bin', '.pt', '.pth', '.pkl', '.pem', '.key'}


def source_files(root):
    result = subprocess.run(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
        cwd=root, check=True, capture_output=True)
    return sorted({name for name in result.stdout.decode('utf-8').split('\0') if name})


def check_files(root, names):
    errors = []
    links = 0
    markdown_files = 0
    for name in names:
        path = root / name
        if not path.exists():
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            errors.append(f'{name}: symlink or path outside source root')
            continue
        if path.suffix.lower() in FORBIDDEN_SUFFIXES or path.name == '.env':
            errors.append(f'{name}: artifact or credential file in source release')
        if path.stat().st_size > 1_000_000:
            errors.append(f'{name}: exceeds source-release file size limit')
        try:
            content = path.read_text(encoding='utf-8-sig')
        except UnicodeError:
            errors.append(f'{name}: unexpected binary source file')
            continue
        if content and not content.endswith('\n'):
            errors.append(f'{name}: missing final newline')
        for number, line in enumerate(content.splitlines(), 1):
            if line.rstrip() != line:
                errors.append(f'{name}:{number}: trailing whitespace')
        if path.suffix.lower() != '.md':
            continue
        markdown_files += 1
        for target in re.findall(r'(?<!!)\[[^\]]+\]\(([^)]+)\)', content):
            target = target.strip().strip('<>')
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith('#'):
                continue
            links += 1
            if not (path.parent / unquote(parsed.path)).exists():
                errors.append(f'{name}: missing local link {target}')
    return {'files': len(names), 'markdown_files': markdown_files,
            'local_links': links, 'errors': errors}


def tree_digest(root, names):
    digest = hashlib.sha256()
    for name in names:
        path = root / name
        if path.is_file():
            digest.update(name.encode('utf-8') + b'\0')
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.root.resolve()
    names = source_files(root)
    report = check_files(root, names)
    report['source_digest'] = tree_digest(root, names)
    print(json.dumps(report, indent=2))
    return int(bool(report['errors']))


if __name__ == '__main__':
    raise SystemExit(main())
