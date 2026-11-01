#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Offline checks for the documentation-stage repository; no runtime test claims."""

from pathlib import Path
import ast
import re
import sys
import subprocess
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def check(root: Path) -> list[str]:
    errors = []
    # Inspect tracked files: ignore rules alone do not protect already tracked secrets.
    tracked = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'],
                             capture_output=True, check=True).stdout
    private_key = re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----')
    for raw_name in tracked.split(b'\0'):
        if not raw_name:
            continue
        name = raw_name.decode('utf-8')
        path = root / name
        if not path.is_file() or path.is_symlink():
            continue
        env_file = path.name == '.env' or (path.name.startswith('.env.') and path.name != '.env.example')
        if env_file or path.name in {'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa'} or path.suffix.lower() in {'.key', '.p12', '.pfx'}:
            errors.append(f'Sensitive file must not be tracked: {name}')
        if private_key.search(path.read_bytes()):
            errors.append(f'Private key marker detected: {name}; remove the key and rotate it if real')
    required = [
        'README.md', 'AGENTS.md', 'CONTRIBUTING.md', 'LICENSE',
        'docs/DECISIONS.md', 'docs/LICENSING.md',
        '.github/dependabot.yml', '.github/workflows/ci.yml',
    ]
    for name in required:
        if not (root / name).is_file():
            errors.append(f'Missing required file: {name}')
    license_path = root / 'LICENSE'
    if license_path.is_file() and 'GNU AFFERO GENERAL PUBLIC LICENSE' not in license_path.read_text():
        errors.append('LICENSE must identify the GNU AGPL')
    for path in sorted(root.rglob('*')):
        if any(part in {'.git', '.venv', 'node_modules', '__pycache__', 'target', 'local', 'private'}
               for part in path.relative_to(root).parts):
            continue
        if path.suffix not in {'.md', '.py', '.yml', '.yaml'} or not path.is_file():
            continue
        if path.is_symlink():
            errors.append(f'Symlink requires explicit review: {path.relative_to(root)}')
            continue
        text = path.read_text(encoding='utf-8')
        if path.suffix == '.py':
            try:
                ast.parse(text, filename=str(path))
            except SyntaxError as exc:
                errors.append(f'{path.relative_to(root)}:{exc.lineno}: {exc.msg}')
        if path.suffix == '.md':
            # Current docs use inline Markdown links. Strip fenced examples first.
            prose = re.sub(r'^```.*?^```[^\n]*$', '', text, flags=re.M | re.S)
            for target in re.findall(r'\]\(([^\s)]+)\)', prose):
                target = target.strip('<>')
                parts = urlsplit(target)
                if parts.scheme or parts.netloc or not parts.path:
                    continue
                dest = (path.parent / unquote(parts.path)).resolve()
                if not dest.is_relative_to(root) or not dest.exists():
                    errors.append(f'{path.relative_to(root)}: missing or escaping link {target}')
        if path.parent == root / '.github/workflows':
            for action in re.findall(r'^\s*(?:-\s*)?uses:\s*([^\s#]+)', text, re.M):
                if not action.startswith('./') and not re.fullmatch(r'[^@]+@[0-9a-f]{40}', action):
                    errors.append(f'{path.relative_to(root)}: action must use a full commit SHA: {action}')
    return errors


if __name__ == '__main__':
    failures = check(ROOT)
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        raise SystemExit(1)
    print('Repository checks passed (documents, local file links, Python syntax, Action pins).')
