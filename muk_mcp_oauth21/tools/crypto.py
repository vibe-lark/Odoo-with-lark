"""Encrypt provider credentials with a key kept outside the database."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

try:
    import fcntl
except ImportError:  # Windows deployments must provide their shared key explicitly.
    fcntl = None


def _fernet():
    from odoo.tools import config
    value = os.environ.get('MCP_OAUTH_ENCRYPTION_KEY') or config.get('mcp_oauth_encryption_key')
    if value:
        return Fernet(value.encode() if isinstance(value, str) else value)
    if fcntl is None:
        raise RuntimeError('Set MCP_OAUTH_ENCRYPTION_KEY on platforms without POSIX file locking.')
    directory = Path(config['data_dir']) / 'mcp_oauth'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / 'master.key'
    descriptor = os.open(directory / 'master.lock', os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, 'wb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not path.exists():
            descriptor, staging = tempfile.mkstemp(prefix='.master-', dir=directory)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(Fernet.generate_key())
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(staging, path)
            finally:
                Path(staging).unlink(missing_ok=True)
        if path.is_symlink() or path.stat().st_uid != os.getuid():
            raise RuntimeError('OAuth encryption key must be an owned regular file.')
        if path.stat().st_mode & 0o077:
            raise RuntimeError('OAuth encryption key must only be readable by its owner.')
        value = path.read_bytes().strip()
    return Fernet(value)


def encrypt(value):
    return _fernet().encrypt(value.encode()).decode() if value else ''


def decrypt(value):
    try:
        return _fernet().decrypt(value.encode()).decode() if value else ''
    except InvalidToken:
        raise RuntimeError('Cannot decrypt OAuth credentials; restore the original encryption key.') from None
