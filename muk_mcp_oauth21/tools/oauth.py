"""Protocol primitives without any Odoo or HTTP dependency."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

COOKIE_NAME = 'mcp_oauth_browser'
VERIFIER = re.compile(r'^[A-Za-z0-9._~-]{43,128}$')
CHALLENGE = re.compile(r'^[A-Za-z0-9_-]{43}$')
SCOPE_SET = frozenset(('mcp:read', 'mcp:write'))


class OAuthError(Exception):
    def __init__(self, error, description, status=400):
        self.error, self.description, self.status = error, description, status
        super().__init__(description)


def secret(prefix=''):
    return prefix + secrets.token_urlsafe(32)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode()


def verify_pkce(verifier, expected):
    return bool(isinstance(verifier, str) and VERIFIER.fullmatch(verifier)
                and hmac.compare_digest(challenge(verifier), expected or ''))


def normalize_scopes(value, allowed=SCOPE_SET):
    if not isinstance(value, str):
        raise OAuthError('invalid_scope', 'Scope must be a space-separated string.')
    scopes = set(value.split())
    if not scopes or not scopes <= set(allowed):
        raise OAuthError('invalid_scope', 'Unsupported scope requested.')
    if 'mcp:write' in scopes:
        scopes.add('mcp:read')
    return ' '.join(sorted(scopes))


def redirect_uri(value):
    if not isinstance(value, str) or len(value) > 2048 or '\\' in value or any(ord(c) < 33 for c in value):
        raise OAuthError('invalid_redirect_uri', 'Invalid redirect URI.')
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise OAuthError('invalid_redirect_uri', 'Invalid redirect URI.') from None
    if not parsed.hostname or '@' in parsed.netloc or '#' in value:
        raise OAuthError('invalid_redirect_uri', 'Redirect URI must not contain credentials or a fragment.')
    loopback = parsed.hostname.lower() == 'localhost'
    try:
        loopback = loopback or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        pass
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and loopback):
        raise OAuthError('invalid_redirect_uri', 'Use HTTPS, or HTTP on the loopback interface.')
    return value


def add_query(url, values):
    parsed = urlsplit(url)
    query = list(parse_qsl(parsed.query, keep_blank_values=True))
    # Never allow preexisting authorization response parameters to shadow ours.
    names = {'code', 'error', 'error_description', 'state', 'iss'}
    query = [(key, value) for key, value in query if key not in names]
    query.extend((key, value) for key, value in values.items() if value is not None)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ''))
