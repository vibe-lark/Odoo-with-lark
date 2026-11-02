"""Race a one-use authorization code and file URL against an isolated test server.

The fixture must be generated in a disposable database by the companion Odoo
fixture function. This client refuses non-loopback transports and never prints
the private token, code, download URL, headers, or response body.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener
import argparse
import ipaddress
import json
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    parsed = urlsplit(args.base_url)
    if not (parsed.scheme == 'http' and ipaddress.ip_address(parsed.hostname).is_loopback
            and not parsed.username and not parsed.password and parsed.path in ('', '/')):
        raise RuntimeError('Concurrency probes require an isolated loopback HTTP backend')
    fixture = json.loads(args.fixture.read_text())
    if not fixture['database'].startswith('mcp_oauth_test_'):
        raise RuntimeError('Refusing a fixture for a non-test database')
    if args.fixture.stat().st_mode & 0o077:
        raise RuntimeError('The fixture contains private test credentials; restrict its permissions')
    headers = {'X-Forwarded-Host': urlsplit(fixture['resource']).netloc, 'X-Forwarded-Proto': 'https'}
    # Start the races only after the isolated worker has finished loading its
    # registry. A failed connection must not ambiguously consume half a race.
    ready = False
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with build_opener(ProxyHandler({})).open(args.base_url.rstrip('/') + '/web/login', timeout=2) as response:
                ready = response.status == 200
        except (OSError, HTTPError):
            pass
        if ready:
            break
        time.sleep(0.2)
    if not ready:
        raise RuntimeError('The isolated test server did not become ready')

    def race(path, data=None):
        barrier = Barrier(2)

        def invoke(_):
            opener = build_opener(ProxyHandler({}))
            request_headers = dict(headers)
            if data is not None:
                request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
            request = Request(args.base_url.rstrip('/') + path,
                              data=urlencode(data).encode() if data is not None else None,
                              headers=request_headers)
            barrier.wait(timeout=10)
            try:
                with opener.open(request, timeout=30) as response:
                    response.read()
                    return response.status
            except HTTPError as exc:
                exc.read()
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            return sorted(pool.map(invoke, range(2)))

    code_statuses = race('/mcp/oauth/token', fixture['token_request'])
    file_statuses = race(urlsplit(fixture['download_url']).path)
    report = {'isolated_database': fixture['database'], 'parallel_requests': 2,
              'authorization_code_statuses': code_statuses, 'file_redemption_statuses': file_statuses,
              'authorization_code_consumed_once': code_statuses == [200, 400],
              'file_consumed_once': file_statuses == [200, 404]}
    report['passed'] = report['authorization_code_consumed_once'] and report['file_consumed_once']
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    assert report['passed'], 'One-use credentials were not consumed atomically'


if __name__ == '__main__':
    main()
