"""Verify a real authorization GET commits before an independent SQL read.

Run only against a disposable loopback test process. Redirects are deliberately
not followed, so this probe never visits Feishu or prints browser nonces.
"""
from hashlib import sha256
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit
import argparse
import base64
import ipaddress
import json
import time

import psycopg2
import requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    base = urlsplit(args.base_url)
    fixture = json.loads(args.fixture.read_text())
    if (not fixture['database'].startswith('mcp_oauth_test_') or base.scheme != 'http'
            or not ipaddress.ip_address(base.hostname).is_loopback or base.username or base.password
            or base.path not in ('', '/') or base.port != fixture['http_port']):
        raise RuntimeError('Authorization probes require an isolated loopback test server and database')
    if args.fixture.stat().st_mode & 0o077:
        raise RuntimeError('Restrict test fixture permissions to its owner')
    session = requests.Session()
    session.trust_env = False
    session.headers.update({'X-Forwarded-Host': urlsplit(fixture['resource']).netloc,
                            'X-Forwarded-Proto': 'https'})
    endpoint = args.base_url.rstrip('/')
    for _ in range(75):
        try:
            if session.get(endpoint + '/web/login', allow_redirects=False, timeout=2).status_code == 200:
                break
        except requests.RequestException:
            pass
        time.sleep(0.2)
    else:
        raise RuntimeError('The isolated test process did not become ready')
    verifier = 'independent-client-verifier-' + 'v' * 48
    challenge = base64.urlsafe_b64encode(sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    params = {'client_id': fixture['client_id'], 'redirect_uri': fixture['redirect_uri'],
              'response_type': 'code', 'code_challenge': challenge, 'code_challenge_method': 'S256',
              'scope': 'mcp:read', 'resource': fixture['resource']}
    response = session.get(endpoint + '/mcp/oauth/authorize', params=params, allow_redirects=False, timeout=15)
    if response.status_code != 302:
        raise AssertionError('Authorization GET did not redirect directly')
    from urllib.parse import parse_qs
    location = urlsplit(response.headers.get('Location', ''))
    query = parse_qs(location.query)
    if location.scheme != 'https' or location.hostname != 'accounts.feishu.cn':
        raise AssertionError('Authorization GET did not target the fixed Feishu origin')
    if query.get('code_challenge_method') != ['S256'] or len(query.get('code_challenge', [''])[0]) != 43:
        raise AssertionError('The direct redirect lost PKCE')
    if set(query.get('scope', [''])[0].split()) != {'offline_access', 'contact:user.email:readonly'}:
        raise AssertionError('The direct redirect lost requested identity scopes')
    provider_state = query.get('state', [''])[0]
    cookies = SimpleCookie()
    for header in response.raw.headers.getlist('Set-Cookie'):
        cookies.load(header)
    browser = cookies.get('mcp_oauth_browser')
    if not browser or not browser['secure'] or not browser['httponly'] or browser['samesite'].lower() != 'lax':
        raise AssertionError('The direct redirect did not set a hardened browser cookie')
    provider_hash = sha256(provider_state.encode()).hexdigest()
    browser_hash = sha256(browser.value.encode()).hexdigest()
    # This connection is independent of Odoo's request cursor and is opened only
    # after the real response completed. No HttpCase/test_cursor is involved.
    with psycopg2.connect(dbname=fixture['database'], host=fixture['database_socket'],
                          port=fixture['database_port'], user=fixture['database_user']) as database:
        with database.cursor() as cursor:
            cursor.execute("SELECT f.state, f.expires_at > NOW() AT TIME ZONE 'UTC', "
                           "f.browser_hash=%s, f.provider_verifier IS NOT NULL "
                           "FROM mcp_oauth_flow f JOIN mcp_oauth_client c ON c.id=f.client_id "
                           "WHERE f.provider_state_hash=%s AND c.client_id=%s",
                           [browser_hash, provider_hash, fixture['client_id']])
            rows = cursor.fetchall()
    if rows != [('redirected', True, True, True)]:
        raise AssertionError('Redirect state was not committed and browser-bound across transactions')
    post = session.post(endpoint + '/mcp/oauth/authorize', data={'decision': 'approve'},
                        allow_redirects=False, timeout=15)
    if post.status_code != 405:
        raise AssertionError('The removed confirmation POST still accepts submissions')
    invalid = session.get(endpoint + '/mcp/oauth/authorize',
                          params={key: value for key, value in params.items() if key != 'code_challenge'},
                          allow_redirects=False, timeout=15)
    if invalid.status_code != 400 or 'Location' in invalid.headers:
        raise AssertionError('A missing PKCE challenge was allowed to redirect')
    report = {'isolated_database': fixture['database'], 'authorization_get_status': response.status_code,
              'direct_feishu_redirect': True, 'flow_committed_across_transactions': True,
              'flow_redirected_and_browser_bound': True, 'secure_httponly_samesite_cookie': True,
              'pkce_and_identity_scopes_preserved': True, 'legacy_post_status': post.status_code,
              'missing_pkce_status': invalid.status_code, 'test_cursor_used': False,
              'provider_redirect_followed': False, 'passed': True}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
