#!/usr/bin/env python3
"""Build a source-only handoff for a new repository, excluding local state."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MODULES = ('muk_mcp', 'muk_mcp_access', 'muk_web_utils',
           'muk_mcp_oauth21', 'muk_mcp_feishu')
TOP_FILES = ('LICENSE', '.gitignore',
             'README.oauth-feishu.md' if (ROOT / 'README.oauth-feishu.md').exists() else 'README.md')
IGNORED_PARTS = {'.git', '.local', '__pycache__', '.pytest_cache', 'node_modules',
                 '.ruff_cache', '.mypy_cache', '.venv'}
SENSITIVE_SUFFIXES = {'.key', '.pem', '.pyc', '.pyo'}


def source_files():
    for name in TOP_FILES:
        path = ROOT / name
        if path.is_file():
            yield path
    for name in (*MODULES, 'tests', 'scripts', 'skills'):
        for path in sorted((ROOT / name).rglob('*')):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(ROOT)
            if any(part in IGNORED_PARTS for part in relative.parts):
                continue
            if path.suffix.lower() in SENSITIVE_SUFFIXES or path.name.startswith('.env'):
                continue
            yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=ROOT / '.local/odoo-mcp-oauth-feishu-source.zip')
    args = parser.parse_args()
    destination = args.output.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    paths = list(source_files())
    # Literal long bearer tokens do not belong in distributable source. Dynamic
    # credentials and named placeholders are unaffected by this narrow check.
    for path in paths:
        content = path.read_bytes()
        if re.search(rb'Bearer [A-Za-z0-9_-]{30,}', content):
            raise SystemExit('Review a credential-like literal before packaging: ' + str(path.relative_to(ROOT)))
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            relative = path.relative_to(ROOT)
            name = Path('README.md') if relative == Path('README.oauth-feishu.md') else relative
            archive.write(path, name)
    print(f'Source files: {len(paths)}')
    print(f'Archive: {destination}')
    print(f'SHA-256: {hashlib.sha256(destination.read_bytes()).hexdigest()}')


if __name__ == '__main__':
    main()
