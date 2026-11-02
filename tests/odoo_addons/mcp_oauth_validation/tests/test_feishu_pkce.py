"""Verify the exact upstream PKCE wire format without contacting Feishu."""
import json
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

import requests

from odoo.tests import HttpCase, TransactionCase, tagged

from odoo.addons.muk_mcp_feishu.models.config import APP_TOKEN_URL, TOKEN_URL, USER_TOKEN_URL
from odoo.addons.muk_mcp_feishu.models.trial import TRIAL_COOKIE
from odoo.addons.muk_mcp_oauth21.tools.crypto import decrypt
from odoo.addons.muk_mcp_oauth21.tools.oauth import COOKIE_NAME, OAuthError, challenge, digest

def assert_feishu_scopes(testcase, location):
    query = urlsplit(location).query
    scopes = parse_qs(query).get('scope')
    testcase.assertEqual(len(scopes), 1)
    testcase.assertEqual(set(scopes[0].split()), {'contact:user.email:readonly', 'offline_access'})
    testcase.assertEqual(len(scopes[0].split()), 2)
    encoded_scope = next(item.partition('=')[2] for item in query.split('&') if item.startswith('scope='))
    testcase.assertIn('%20', encoded_scope)
    testcase.assertNotIn('+', encoded_scope)


@tagged('post_install', '-at_install')
class TestFeishuPkceWireAcceptance(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.config = cls.env['mcp.feishu.config']._get_config()
        cls.env['ir.config_parameter'].set_str('mcp_oauth.public_base_url', 'https://odoo.example')
        cls.config.write({'app_id': 'cli_pkce_wire', 'app_secret': 'test-only-pkce-secret'})

    def _capture_request(self, wire):
        def capture(method, url, **kwargs):
            wire.append(requests.Request(method, url, data=kwargs.get('data'), json=kwargs.get('json'),
                                         headers=kwargs.get('headers')).prepare())
            response = Mock(status_code=200)
            response.json.return_value = {'access_token': 'test-only-provider-access', 'expires_in': 3600}
            return response
        return capture

    def _enable_application(self):
        fingerprint = self.config._fingerprint()
        self.config.write({'credentials_fingerprint': fingerprint, 'login_fingerprint': fingerprint})
        self.config.enabled = True

    def test_user_and_application_token_endpoints_are_explicitly_separate(self):
        self.assertEqual(USER_TOKEN_URL, 'https://open.feishu.cn/open-apis/authen/v2/oauth/token')
        self.assertEqual(APP_TOKEN_URL, 'https://accounts.feishu.cn/oauth/v3/token')
        self.assertEqual(TOKEN_URL, USER_TOKEN_URL)
        self.assertNotEqual(USER_TOKEN_URL, APP_TOKEN_URL)

    def test_token_scope_diagnostics_use_exact_space_delimited_names_without_raw_values(self):
        marker = 'sensitive-scope-or-token@example.invalid'
        cases = (
            ('offline_access contact:user.email:readonly', True, True, True),
            ('contact:user.email:readonly\n\toffline_access ' + marker, True, True, True),
            ('contact:user.email:readonly,offline_access', True, False, False),
            ('offline_access contact:user.email:readonly,' + marker, True, False, True),
            ('contact:user.email:readonly-suffix offline_access', True, False, True),
            ('', True, False, False),
            (None, False, None, None),
            ({'unknown': marker}, False, None, None),
        )
        for scope, returned, email, offline in cases:
            payload = {'access_token': marker, 'refresh_token': marker, 'scope': scope}
            with self.subTest(scope_type=type(scope).__name__, email=email, offline=offline), patch.object(
                    type(self.config), '_request_json', return_value=payload), self.assertLogs(
                    'odoo.addons.muk_mcp_feishu.models.config', level='INFO') as captured:
                result = self.config._request_token({'grant_type': 'refresh_token', 'refresh_token': marker})
            self.assertEqual(result, payload)
            self.assertEqual(len(captured.output), 1)
            message = captured.output[0]
            self.assertIn('grant_type=refresh_token', message)
            self.assertIn(f'scope_returned={returned} email_scope_granted={email} offline_access_granted={offline}', message)
            self.assertNotIn(marker, message)
            self.assertNotIn('contact:user.email:readonly', message)

    def test_userinfo_diagnostics_record_only_field_presence_and_email_validity(self):
        cases = (
            ({'email': 'private-contact@example.invalid', 'enterprise_email': 'private-company@example.invalid'},
             (True, True, True, True)),
            ({'enterprise_email': 'private-company@example.invalid'}, (False, False, True, True)),
            ({'email': '', 'enterprise_email': None}, (True, False, True, False)),
            ({'email': 'sensitive_invalid_contact', 'enterprise_email': {'private': 'not-for-logs'}},
             (True, False, True, False)),
        )
        for email_fields, expected in cases:
            info = {'open_id': 'ou_do_not_log_identity',
                    'name': 'Private Test Person', 'mobile': 'sensitive-mobile-marker', **email_fields}
            with self.subTest(expected=expected), patch.object(type(self.config), '_request_json', return_value=info), self.assertLogs(
                    'odoo.addons.muk_mcp_feishu.models.config', level='INFO') as captured:
                result = self.config._user_info('sensitive-user-access-token')
            self.assertEqual(result, info)
            self.assertEqual(len(captured.output), 1)
            message = captured.output[0]
            self.assertIn('email_present=%s email_valid=%s enterprise_email_present=%s enterprise_email_valid=%s' % expected, message)
            for value in ('ou_do_not_log_identity', 'tenant-do-not-log', 'Private Test Person',
                          'sensitive-mobile-marker', 'private-contact@example.invalid',
                          'private-company@example.invalid', 'sensitive_invalid_contact',
                          'not-for-logs', 'sensitive-user-access-token'):
                self.assertNotIn(value, message)

    def test_code_exchange_json_preserves_verifier_and_expected_s256(self):
        for verifier in ('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
                         'a' * 60 + '._~-', 'v' * 128):
            wire = []
            code = 'test-only-code-._~+/%'
            expected = challenge(verifier)
            with self.subTest(length=len(verifier)), patch(
                    'odoo.addons.muk_mcp_feishu.models.config.requests.request', side_effect=self._capture_request(wire)), self.assertLogs(
                    'odoo.addons.muk_mcp_feishu.models.config', level='INFO') as captured:
                self.config._exchange_code(code, verifier, expected)
            self.assertEqual(len(wire), 1)
            prepared = wire[0]
            self.assertEqual(prepared.method, 'POST')
            self.assertEqual(prepared.url, 'https://open.feishu.cn/open-apis/authen/v2/oauth/token')
            self.assertEqual(prepared.headers['Content-Type'], 'application/json')
            payload = json.loads(prepared.body)
            self.assertEqual(payload['grant_type'], 'authorization_code')
            self.assertEqual(payload['code_verifier'], verifier)
            self.assertEqual(challenge(payload['code_verifier']), expected)
            self.assertEqual(payload['code'], code)
            self.assertEqual(payload['redirect_uri'], 'https://odoo.example/mcp/oauth/feishu/callback')
            self.assertEqual(payload['client_id'], 'cli_pkce_wire')
            self.assertNotIn(verifier, '\n'.join(captured.output))
            self.assertNotIn(code, '\n'.join(captured.output))
            self.assertNotIn(expected, '\n'.join(captured.output))

    def test_refresh_uses_json_while_application_check_keeps_form_encoding(self):
        for kind in ('refresh_token', 'client_credentials'):
            wire = []
            values = {'grant_type': kind}
            if kind == 'refresh_token':
                values['refresh_token'] = 'test-only-refresh-._~+/%'
            with self.subTest(grant_type=kind), patch(
                    'odoo.addons.muk_mcp_feishu.models.config.requests.request', side_effect=self._capture_request(wire)):
                self.config._request_token(values)
            self.assertEqual(len(wire), 1)
            self.assertEqual(wire[0].method, 'POST')
            if kind == 'refresh_token':
                self.assertEqual(wire[0].url, 'https://open.feishu.cn/open-apis/authen/v2/oauth/token')
                self.assertEqual(wire[0].headers['Content-Type'], 'application/json')
                self.assertEqual(json.loads(wire[0].body)['refresh_token'], values['refresh_token'])
            else:
                self.assertEqual(wire[0].url, 'https://accounts.feishu.cn/oauth/v3/token')
                self.assertEqual(wire[0].headers['Content-Type'], 'application/x-www-form-urlencoded')
                body = wire[0].body.decode() if isinstance(wire[0].body, bytes) else wire[0].body
                self.assertEqual(parse_qs(body)['grant_type'], ['client_credentials'])

    def test_invalid_verifier_or_changed_challenge_is_blocked_before_http(self):
        verifier = 'v' * 64
        cases = ((verifier, challenge('w' * 64)), ('short', challenge(verifier)),
                 (verifier + ' ', challenge(verifier)), ('é' * 64, challenge(verifier)))
        for supplied, expected in cases:
            with self.subTest(verifier_length=len(supplied)), patch(
                    'odoo.addons.muk_mcp_feishu.models.config.requests.request') as outbound, self.assertRaises(OAuthError):
                self.config._exchange_code('test-only-code', supplied, expected)
            outbound.assert_not_called()

    def test_prepared_request_cannot_silently_replace_the_verifier(self):
        original_prepare = requests.Request.prepare

        def corrupt_prepare(request):
            prepared = original_prepare(request)
            payload = json.loads(prepared.body)
            payload['code_verifier'] = 'changed-on-wire-' + 'v' * 48
            prepared.body = json.dumps(payload).encode()
            return prepared

        verifier = 'v' * 64
        with patch.object(requests.Request, 'prepare', new=corrupt_prepare), patch(
                'odoo.addons.muk_mcp_feishu.models.config.requests.request') as outbound, self.assertRaises(OAuthError):
            self.config._exchange_code('test-only-code', verifier, challenge(verifier))
        outbound.assert_not_called()

    def test_trial_changed_persisted_challenge_blocks_upstream_code_exchange(self):
        admin = self.env.ref('base.user_admin')
        admin.active = True
        self.config.credentials_fingerprint = self.config._fingerprint()
        url, cookie = self.env['mcp.feishu.trial'].with_user(admin)._start()
        state = parse_qs(urlsplit(url).query)['state'][0]
        trial = self.env['mcp.feishu.trial'].search([('state_hash', '=', digest(state))])
        trial.code_challenge = challenge('mismatched-verifier-' + 'v' * 48)
        with patch('odoo.addons.muk_mcp_feishu.models.config.requests.request') as outbound, self.assertRaises(OAuthError):
            self.env['mcp.feishu.trial']._complete({'state': state, 'code': 'test-only-code'}, cookie, admin.id)
        outbound.assert_not_called()

    def test_mcp_login_keeps_upstream_challenge_separate_from_client_pkce(self):
        self._enable_application()
        admin = self.env.ref('base.user_admin')
        admin.write({'active': True, 'email': 'pkce-admin@example.invalid', 'mcp_oauth_enabled': True})
        client = self.env['mcp.oauth.client'].create({
            'name': 'PKCE Client', 'redirect_uris': ['https://client.example/callback'], 'auth_method': 'none',
        })
        client_challenge = challenge('client-verifier-' + 'v' * 48)
        flow, _flow_id, _csrf, _cookie = self.env['mcp.oauth.service']._start_flow({
            'client_id': client.client_id, 'redirect_uri': client.redirect_uris[0],
            'response_type': 'code', 'code_challenge_method': 'S256', 'code_challenge': client_challenge,
            'scope': 'mcp:read', 'resource': 'https://odoo.example/api/mcp',
        })
        provider = self.env['mcp.oauth.provider']
        redirect = provider._begin_login(flow)
        assert_feishu_scopes(self, redirect)
        query = parse_qs(urlsplit(redirect).query)
        upstream_challenge = flow.provider_data['code_challenge']
        self.assertEqual(flow.provider_data['config_fingerprint'], self.config._fingerprint())
        self.assertNotIn('tenant_key', flow.provider_data)
        self.assertEqual(query['code_challenge_method'], ['S256'])
        self.assertEqual(query['code_challenge'], [upstream_challenge])
        self.assertEqual(challenge(decrypt(flow.provider_verifier)), upstream_challenge)
        self.assertEqual(flow.code_challenge, client_challenge)
        self.assertNotEqual(upstream_challenge, client_challenge)
        token = {'access_token': 'test-only-upstream-access', 'expires_in': 3600}
        info = {'open_id': 'ou_pkce_wire', 'email': admin.email}
        with patch.object(type(self.config), '_exchange_code', return_value=token) as exchange, patch.object(
                type(self.config), '_user_info', return_value=info):
            user, provider_data = provider._complete_login(flow, {'code': 'test-only-upstream-code'})
        exchange.assert_called_once_with('test-only-upstream-code', decrypt(flow.provider_verifier), upstream_challenge)
        binding = self.env['mcp.feishu.binding'].browse(provider_data['binding_id'])
        self.assertEqual(user, admin)
        self.assertEqual(binding.odoo_user_id, admin)
        self.assertEqual(binding.state, 'confirmed')
        self.assertEqual(provider_data['binding_version'], binding.auth_version)
        self.assertNotIn('tenant_key', provider_data)

    def test_mcp_login_rejects_configuration_changed_after_identity_redirect(self):
        self._enable_application()
        client = self.env['mcp.oauth.client'].create({
            'name': 'Changed Config Client', 'redirect_uris': ['https://client.example/callback'],
            'auth_method': 'none',
        })
        flow, _flow_id, _csrf, _cookie = self.env['mcp.oauth.service']._start_flow({
            'client_id': client.client_id, 'redirect_uri': client.redirect_uris[0], 'response_type': 'code',
            'code_challenge_method': 'S256', 'code_challenge': challenge('v' * 64),
            'scope': 'mcp:read', 'resource': 'https://odoo.example/api/mcp',
        })
        provider = self.env['mcp.oauth.provider']
        provider._begin_login(flow)
        fingerprint = flow.provider_data['config_fingerprint']
        self.config.app_secret = 'changed-test-only-application-secret'
        self._enable_application()
        self.assertNotEqual(fingerprint, self.config._fingerprint())
        with patch.object(type(self.config), '_exchange_code') as exchange, self.assertRaises(OAuthError):
            provider._complete_login(flow, {'code': 'test-only-upstream-code'})
        exchange.assert_not_called()


@tagged('post_install', '-at_install')
class TestFeishuTrialRedirectAcceptance(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.config = cls.env['mcp.feishu.config']._get_config()
        cls.env['ir.config_parameter'].set_str('mcp_oauth.public_base_url', 'https://odoo.example')
        cls.config.write({'app_id': 'cli_pkce_redirect', 'app_secret': 'test-only-pkce-secret'})
        cls.config.credentials_fingerprint = cls.config._fingerprint()
        cls.admin = cls.env.ref('base.user_admin')
        cls.admin.active = True

    def url_open(self, *args, headers=None, **kwargs):
        merged = {'X-Forwarded-Host': 'odoo.example', 'X-Forwarded-Proto': 'https', **(headers or {})}
        return super().url_open(*args, headers=merged, **kwargs)

    def test_real_trial_redirect_keeps_s256_and_the_persisted_challenge(self):
        self.authenticate(self.admin.login, 'unused-test-password')
        with patch('odoo.addons.muk_mcp_feishu.models.config.requests.request') as outbound:
            response = self.url_open('/mcp/oauth/feishu/trial/start', allow_redirects=False)
        outbound.assert_not_called()
        self.assertEqual(response.status_code, 302)
        target = urlsplit(response.headers['Location'])
        assert_feishu_scopes(self, response.headers['Location'])
        self.assertEqual(target.scheme, 'https')
        self.assertEqual(target.hostname, 'accounts.feishu.cn')
        query = parse_qs(target.query)
        self.assertEqual(query['code_challenge_method'], ['S256'])
        self.assertEqual(len(query['code_challenge'][0]), 43)
        self.assertEqual(query['client_id'], ['cli_pkce_redirect'])
        state = query['state'][0]
        trial = self.env['mcp.feishu.trial'].search([('state_hash', '=', digest(state))])
        self.assertTrue(trial)
        self.assertEqual(trial.code_challenge, query['code_challenge'][0])
        self.assertEqual(challenge(decrypt(trial.verifier)), trial.code_challenge)
        self.assertTrue(response.cookies.get(TRIAL_COOKIE))
        cookie = response.headers['Set-Cookie']
        self.assertIn('Secure', cookie)
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Lax', cookie)
        self.assertIn('no-store', response.headers['Cache-Control'])

    def test_real_mcp_authorize_get_redirect_keeps_email_and_offline_scope(self):
        fingerprint = self.config._fingerprint()
        self.config.write({'credentials_fingerprint': fingerprint, 'login_fingerprint': fingerprint})
        self.config.enabled = True
        client = self.env['mcp.oauth.client'].create({
            'name': 'Scope Redirect Client', 'redirect_uris': ['https://client.example/callback'],
            'auth_method': 'none',
        })
        params = {'client_id': client.client_id, 'redirect_uri': client.redirect_uris[0],
                  'response_type': 'code', 'scope': 'mcp:read', 'code_challenge_method': 'S256',
                  'code_challenge': challenge('scope-client-verifier-' + 'v' * 48),
                  'resource': 'https://odoo.example/api/mcp'}
        with patch('odoo.addons.muk_mcp_feishu.models.config.requests.request') as outbound:
            response = self.url_open('/mcp/oauth/authorize?' + urlencode(params), allow_redirects=False)
        outbound.assert_not_called()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(urlsplit(response.headers['Location']).hostname, 'accounts.feishu.cn')
        self.assertTrue(response.cookies.get(COOKIE_NAME))
        self.assertIn('Secure', response.headers['Set-Cookie'])
        self.assertIn('HttpOnly', response.headers['Set-Cookie'])
        self.assertIn('SameSite=Lax', response.headers['Set-Cookie'])
        assert_feishu_scopes(self, response.headers['Location'])
        self.assertEqual(parse_qs(urlsplit(response.headers['Location']).query)['code_challenge_method'], ['S256'])

    def test_trial_redirect_rejects_missing_or_weakened_pkce(self):
        self.authenticate(self.admin.login, 'unused-test-password')
        with patch.object(type(self.config), '_authorize_url', return_value=(
                'https://accounts.feishu.cn/open-apis/authen/v1/authorize?code_challenge=too-short&code_challenge_method=plain')):
            response = self.url_open('/mcp/oauth/feishu/trial/start', allow_redirects=False)
        self.assertEqual(response.status_code, 500)
        self.assertIn('PKCE', response.text)
        self.assertFalse(response.cookies.get(TRIAL_COOKIE))
