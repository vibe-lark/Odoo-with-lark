"""Run with ``python -m unittest discover -s tests -p test_oauth_primitives.py``.

These protocol boundary checks run without an Odoo database. The PKCE vector is
RFC 7636 Appendix B; model and HTTP integration checks live in the test addon.
"""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import unittest
import logging


SOURCE = Path(__file__).resolve().parents[1] / 'muk_mcp_oauth21/tools/oauth.py'
SPEC = spec_from_file_location('mcp_oauth_protocol_primitives', SOURCE)
oauth = module_from_spec(SPEC)
SPEC.loader.exec_module(oauth)
LOG_SPEC = spec_from_file_location('mcp_oauth_protocol_logging', SOURCE.with_name('logging.py'))
oauth_logging = module_from_spec(LOG_SPEC)
LOG_SPEC.loader.exec_module(oauth_logging)


class TestOAuthProtocolPrimitives(unittest.TestCase):
    def test_pkce_rfc7636_vector_and_mutated_verifier(self):
        verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
        self.assertEqual(oauth.challenge(verifier), challenge)
        self.assertTrue(oauth.verify_pkce(verifier, challenge))
        self.assertFalse(oauth.verify_pkce(verifier[:-1] + 'y', challenge))

    def test_pkce_rejects_missing_short_long_and_non_ascii_verifiers(self):
        expected = oauth.challenge('v' * 64)
        for value in (None, '', 'v' * 42, 'v' * 129, 'é' * 64, 'v' * 63 + ' '):
            with self.subTest(value=repr(value)):
                self.assertFalse(oauth.verify_pkce(value, expected))

    def test_redirects_allow_https_and_native_loopback(self):
        for uri in ('https://client.example/callback', 'http://127.0.0.1:34567/callback',
                    'http://[::1]:34567/callback'):
            self.assertEqual(oauth.redirect_uri(uri), uri)

    def test_redirects_reject_open_redirect_and_header_injection_shapes(self):
        for uri in ('javascript:alert(1)', 'http://client.example/callback',
                    'https://user:pass@client.example/callback',
                    'https://@client.example/callback', 'https://client.example\\evil.example/callback',
                    'https://client.example/callback#fragment', '//client.example/callback',
                    'https://client.example/callback#',
                    'https://client.example/callback\r\nLocation: https://evil.example',
                    'https://client.example:invalid/callback'):
            with self.subTest(uri=repr(uri)), self.assertRaises(oauth.OAuthError):
                oauth.redirect_uri(uri)

    def test_scope_normalization_and_unsupported_scope(self):
        self.assertEqual(oauth.normalize_scopes('mcp:write'), 'mcp:read mcp:write')
        self.assertEqual(oauth.normalize_scopes('mcp:read mcp:read'), 'mcp:read')
        for value in ('', 'openid', 'mcp:read mcp:admin', ['mcp:read']):
            with self.subTest(value=value), self.assertRaises(oauth.OAuthError):
                oauth.normalize_scopes(value)

    def test_authorization_response_cannot_be_shadowed_by_callback_query(self):
        result = oauth.add_query('https://client.example/callback?code=attacker&state=bad&keep=ok',
                                 {'code': 'real', 'state': 'expected', 'iss': 'https://odoo.example'})
        from urllib.parse import parse_qs, urlsplit
        self.assertEqual(parse_qs(urlsplit(result).query), {
            'code': ['real'], 'state': ['expected'], 'iss': ['https://odoo.example'], 'keep': ['ok'],
        })

    def test_logs_redact_authorization_query_and_one_use_file_paths(self):
        self.assertEqual(oauth_logging.redact_http_message('GET /mcp/oauth/feishu/callback?code=secret&state=nonce HTTP/1.1'),
                         'GET /mcp/oauth/feishu/callback?<redacted> HTTP/1.1')
        self.assertEqual(oauth_logging.redact_http_message('GET /mcp/transfer/one-use-secret?extra=private HTTP/1.1'),
                         'GET /mcp/transfer/<redacted> HTTP/1.1')
        ordinary = 'GET /web/login?redirect=/odoo HTTP/1.1'
        self.assertEqual(oauth_logging.redact_http_message(ordinary), ordinary)

    def test_logging_filter_handles_format_arguments_and_installs_once(self):
        record = logging.LogRecord('odoo.http.server', logging.INFO, __file__, 1,
                                   '%s %s %s', ('GET', '/mcp/oauth/token?code=secret', '200'), None)
        self.assertTrue(oauth_logging.SensitiveOAuthURLFilter().filter(record))
        self.assertNotIn('secret', record.getMessage())
        self.assertEqual(record.args, ())
        oauth_logging.install_log_filter()
        oauth_logging.install_log_filter()
        for name in ('odoo.http.server', 'werkzeug'):
            installed = [item for item in logging.getLogger(name).filters if getattr(item, '_mcp_oauth_sensitive_urls', False)]
            self.assertEqual(len(installed), 1)

    def test_logging_filter_covers_odoo20_colored_and_header_extra_fields(self):
        record = logging.LogRecord('odoo.http.server', logging.INFO, __file__, 1,
                                   'GET /mcp/oauth/feishu/callback?code=private-code HTTP/1.1', (), None)
        record.http_request_line = 'GET /mcp/oauth/feishu/callback?code=private-code HTTP/1.1'
        record.http_headers = "[(b'authorization', b'Bearer private-token'), (b'cookie', b'private-cookie')]"
        record.colored_message = record.getMessage() + '\n' + record.http_headers
        oauth_logging.SensitiveOAuthURLFilter().filter(record)
        for value in (record.getMessage(), record.http_request_line, record.colored_message, str(record.http_headers)):
            self.assertNotIn('private-code', value)
            self.assertNotIn('private-token', value)
            self.assertNotIn('private-cookie', value)
        self.assertIn('<redacted>', record.http_request_line)


if __name__ == '__main__':
    unittest.main()
