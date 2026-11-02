"""Accept OAuth at the real MuK HTTP endpoint, preserving employee permissions."""
from datetime import timedelta
import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from odoo import fields
from odoo.exceptions import AccessError
from odoo.tests import HttpCase, new_test_user, tagged

from odoo.addons.muk_mcp_oauth21.tools.crypto import encrypt
from odoo.addons.muk_mcp_oauth21.tools.oauth import COOKIE_NAME, OAuthError, challenge, digest


@tagged('post_install', '-at_install')
class TestOAuthAcceptance(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.service = cls.env['mcp.oauth.service']
        cls.owner = new_test_user(
            cls.env, login='oauth_acceptance_employee', email='oauth-employee@example.invalid',
            groups='base.group_user,base.group_partner_manager,base.group_allow_export',
        )
        cls.owner.write({'mcp_oauth_enabled': True, 'mcp_oauth_scope': 'write', 'mcp_oauth_rate_limit': 0})
        cls.env['ir.config_parameter'].set_str('mcp_oauth.public_base_url', 'https://odoo.example')
        cls.env['ir.config_parameter'].set_str('web.base.url', cls.base_url())
        cls.env['ir.config_parameter'].set_bool('muk_mcp.allow_any_origin', False)
        cls.partner = cls.env['res.partner'].create({'name': 'OAuth Export Fixture'})
        cls.env['muk_mcp.tool'].create({
            'name': 'oauth_acceptance_identity', 'description': 'Check caller identity.',
            'code': 'result = {"uid": env.uid, "superuser": env.su}\n',
        })
        provider = type(cls.env['mcp.oauth.provider'])
        cls.enterClassContext(patch.object(provider, '_enabled', return_value=True))
        cls.enterClassContext(patch.object(provider, '_validate_grant', return_value=True))
        cls.enterClassContext(patch.object(provider, '_refresh_grant', return_value=None))
        cls.enterClassContext(patch.object(provider, '_token_deadlines', side_effect=lambda _data: {
            'access_expires_at': fields.Datetime.now() + timedelta(hours=1),
            'refresh_expires_at': fields.Datetime.now() + timedelta(days=1),
        }))

    def url_open(self, *args, headers=None, **kwargs):
        # Only the isolated loopback test process enables proxy_mode. Model the
        # same TLS-terminating proxy as the real deployment, without disabling
        # the application's HTTPS checks.
        merged = {'X-Forwarded-Host': 'odoo.example', 'X-Forwarded-Proto': 'https', **(headers or {})}
        return super().url_open(*args, headers=merged, **kwargs)

    def _authorization_code(self, scope='mcp:read', user=None):
        registered = self.service._register_client({
            'client_name': 'Acceptance Client', 'redirect_uris': ['https://client.example/callback'],
            'grant_types': ['authorization_code', 'refresh_token'], 'token_endpoint_auth_method': 'none',
        })
        verifier = 'v' * 64
        flow, _flow_id, _csrf, _cookie = self.service._start_flow({
            'client_id': registered['client_id'], 'redirect_uri': registered['redirect_uris'][0],
            'response_type': 'code', 'code_challenge': challenge(verifier),
            'code_challenge_method': 'S256', 'scope': scope, 'resource': self.service._resource(),
            'state': 'acceptance-client-state',
        })
        response_url = self.service._complete_flow(flow, user or self.owner, {})
        code = parse_qs(urlsplit(response_url).query)['code'][0]
        params = {'grant_type': 'authorization_code', 'client_id': registered['client_id'],
                  'redirect_uri': registered['redirect_uris'][0], 'code': code,
                  'code_verifier': verifier, 'resource': self.service._resource()}
        return params

    def _new_authorization(self, scope='mcp:read', user=None):
        params = self._authorization_code(scope, user)
        return self.service._exchange(params), params

    def _post(self, path, payload=None, token=None, form=None):
        headers = {}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if form is not None:
            return self.url_open(path, data=form, headers=headers, method='POST')
        headers['Content-Type'] = 'application/json'
        return self.url_open(path, data=json.dumps(payload or {}), headers=headers, method='POST')

    def _tool(self, token, name, arguments=None):
        return self._post('/api/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                    'params': {'name': name, 'arguments': arguments or {}}}, token=token)

    @staticmethod
    def _result(response):
        result = response.json()['result']
        return json.loads(next(item['text'] for item in result['content'] if item['type'] == 'text'))

    def test_oauth_token_executes_as_employee_and_is_not_a_legacy_key(self):
        tokens, _params = self._new_authorization()
        response = self._tool(tokens['access_token'], 'oauth_acceptance_identity')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._result(response), {'uid': self.owner.id, 'superuser': False})
        self.assertFalse(self.env['muk_mcp.key'].sudo().authenticate(tokens['access_token']))

    def test_read_scope_refuses_write_with_http_scope_challenge(self):
        tokens, _params = self._new_authorization()
        response = self._tool(tokens['access_token'], 'create_records', {
            'model': 'res.partner', 'values': {'name': 'Must not exist OAuth acceptance'},
        })
        self.assertEqual(response.status_code, 403)
        self.assertIn('insufficient_scope', response.headers['WWW-Authenticate'])
        self.assertFalse(self.env['res.partner'].search([('name', '=', 'Must not exist OAuth acceptance')]))

    def test_oauth_file_link_and_revocation(self):
        tokens, _params = self._new_authorization()
        response = self._tool(tokens['access_token'], 'export_records', {
            'model': 'res.partner', 'ids': [self.partner.id], 'fields': ['name'], 'delivery': 'link',
        })
        self.assertEqual(response.status_code, 200)
        result = self._result(response)
        self.assertIn('download_url', result)
        self.assertNotIn('content_base64', result)
        self.assertTrue(result['download_url'].startswith('https://odoo.example/mcp/transfer/'))
        path = urlsplit(result['download_url']).path
        download = self.url_open(path)
        self.assertEqual(download.status_code, 200)
        self.assertIn(b'OAuth Export Fixture', download.content)
        self.assertEqual(self.url_open(path).status_code, 404)
        # A newly issued link must also die when its OAuth authorization is revoked.
        result = self._result(self._tool(tokens['access_token'], 'export_records', {
            'model': 'res.partner', 'ids': [self.partner.id], 'fields': ['name'], 'delivery': 'link',
        }))
        self.service._authenticate_token(tokens['access_token']).action_revoke()
        self.assertEqual(self.url_open(urlsplit(result['download_url']).path).status_code, 404)
        self.assertEqual(self._tool(tokens['access_token'], 'whoami').status_code, 401)

    def test_oauth_file_link_requires_https_without_consuming_on_plain_http(self):
        tokens, _params = self._new_authorization()
        result = self._result(self._tool(tokens['access_token'], 'export_records', {
            'model': 'res.partner', 'ids': [self.partner.id], 'fields': ['name'], 'delivery': 'link',
        }))
        path = urlsplit(result['download_url']).path
        self.assertEqual(super().url_open(path).status_code, 404)
        self.assertEqual(self.url_open(path).status_code, 200)
        self.assertEqual(self.url_open(path).status_code, 404)

    def test_employee_disable_blocks_existing_access_and_file_link(self):
        tokens, _params = self._new_authorization()
        result = self._result(self._tool(tokens['access_token'], 'export_records', {
            'model': 'res.partner', 'ids': [self.partner.id], 'fields': ['name'], 'delivery': 'link',
        }))
        self.owner.mcp_oauth_enabled = False
        self.assertEqual(self._tool(tokens['access_token'], 'whoami').status_code, 401)
        self.assertEqual(self.url_open(urlsplit(result['download_url']).path).status_code, 404)
        self.owner.mcp_oauth_enabled = True
        self.assertEqual(self._tool(tokens['access_token'], 'whoami').status_code, 401)
        self.assertEqual(self.url_open(urlsplit(result['download_url']).path).status_code, 404)

    def test_refresh_rotation_replay_revokes_over_real_token_route(self):
        tokens, params = self._new_authorization()
        refresh = {'grant_type': 'refresh_token', 'client_id': params['client_id'],
                   'refresh_token': tokens['refresh_token'], 'resource': params['resource']}
        response = self._post('/mcp/oauth/token', form=refresh)
        self.assertEqual(response.status_code, 200)
        replacement = response.json()
        self.assertNotEqual(replacement['refresh_token'], tokens['refresh_token'])
        replay = self._post('/mcp/oauth/token', form=refresh)
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.json()['error'], 'invalid_grant')
        self.assertEqual(self._tool(replacement['access_token'], 'whoami').status_code, 401)

    def test_employee_cannot_escalate_own_mcp_permissions_or_read_tokens(self):
        with self.assertRaises(AccessError):
            self.owner.with_user(self.owner).write({'mcp_oauth_scope': 'write'})
        with self.assertRaises(AccessError):
            self.env['mcp.oauth.token'].with_user(self.owner).search([])

    def test_expired_access_is_rejected_with_resource_discovery(self):
        tokens, _params = self._new_authorization()
        grant = self.service._authenticate_token(tokens['access_token'])
        self.env['mcp.oauth.token'].search([('grant_id', '=', grant.id), ('kind', '=', 'access')]).expires_at = (
            fields.Datetime.now() - timedelta(seconds=1)
        )
        response = self._tool(tokens['access_token'], 'whoami')
        self.assertEqual(response.status_code, 401)
        self.assertIn('oauth-protected-resource/api/mcp', response.headers['WWW-Authenticate'])

    def test_real_oauth_routes_bind_cookie_pkce_code_and_employee_identity(self):
        response = self._post('/mcp/oauth/register', {
            'client_name': 'HTTP Acceptance Client', 'redirect_uris': ['https://client.example/callback'],
            'grant_types': ['authorization_code', 'refresh_token'], 'token_endpoint_auth_method': 'none',
        })
        self.assertEqual(response.status_code, 201)
        client = response.json()
        verifier = 'r' * 64
        params = {'client_id': client['client_id'], 'redirect_uri': client['redirect_uris'][0],
                  'response_type': 'code', 'code_challenge': challenge(verifier),
                  'code_challenge_method': 'S256', 'scope': 'mcp:read',
                  'resource': self.service._resource(), 'state': 'original-client-state'}
        provider = type(self.env['mcp.oauth.provider'])

        def begin_login(_provider, flow):
            flow.write({'provider_state_hash': digest('external-identity-state'),
                        'provider_verifier': encrypt('f' * 64)})
            return 'https://accounts.feishu.cn/open-apis/authen/v1/authorize?state=external-identity-state'

        with patch.object(provider, '_begin_login', new=begin_login), patch.object(provider, '_complete_login', return_value=(self.owner, {})):
            redirect = self.url_open('/mcp/oauth/authorize?' + urlencode(params), allow_redirects=False)
            self.assertEqual(redirect.status_code, 302, redirect.text)
            self.assertIn('no-store', redirect.headers['Cache-Control'])
            self.assertTrue(redirect.headers['Location'].startswith('https://accounts.feishu.cn/'))
            browser = redirect.cookies.get(COOKIE_NAME)
            self.assertTrue(browser)
            # HttpCase uses loopback HTTP with trusted proxy headers. The real
            # process probe separately checks persisted state without test_cursor.
            cookies = {COOKIE_NAME: browser}
            callback_path = '/mcp/oauth/feishu/callback?state=external-identity-state&code=upstream-code'
            wrong_browser = self.url_open(callback_path, cookies={COOKIE_NAME: 'different-browser'}, allow_redirects=False)
            self.assertEqual(wrong_browser.status_code, 400)
            self.assertIn('different browser', wrong_browser.text)
            callback = self.url_open(callback_path, cookies=cookies, allow_redirects=False)
            self.assertEqual(callback.status_code, 302)
        result = parse_qs(urlsplit(callback.headers['Location']).query)
        self.assertEqual(result['state'], ['original-client-state'])
        self.assertEqual(result['iss'], ['https://odoo.example'])
        exchange = {'grant_type': 'authorization_code', 'client_id': client['client_id'],
                    'redirect_uri': client['redirect_uris'][0], 'code': result['code'][0],
                    'code_verifier': 'wrong-verifier', 'resource': self.service._resource()}
        invalid = self._post('/mcp/oauth/token', form=exchange)
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()['error'], 'invalid_grant')
        exchange['code_verifier'] = verifier
        token = self._post('/mcp/oauth/token', form=exchange)
        self.assertEqual(token.status_code, 200)
        self.assertIn('no-store', token.headers['Cache-Control'])
        self.assertEqual(self._result(self._tool(token.json()['access_token'], 'oauth_acceptance_identity')),
                         {'uid': self.owner.id, 'superuser': False})
        self.assertEqual(self._post('/mcp/oauth/token', form=exchange).status_code, 400)

    def test_direct_authorize_get_rejects_invalid_pkce_and_redirect_before_provider_login(self):
        registered = self.service._register_client({
            'client_name': 'Direct Redirect Validation', 'redirect_uris': ['https://client.example/callback'],
            'token_endpoint_auth_method': 'none',
        })
        params = {'client_id': registered['client_id'], 'redirect_uri': registered['redirect_uris'][0],
                  'response_type': 'code', 'code_challenge': challenge('v' * 64),
                  'code_challenge_method': 'S256', 'scope': 'mcp:read', 'resource': self.service._resource()}
        cases = (({'code_challenge': None}, 400, 'invalid_request'),
                 ({'code_challenge_method': None}, 400, 'invalid_request'),
                 ({'code_challenge_method': 'plain'}, 400, 'invalid_request'),
                 ({'redirect_uri': 'https://other.example/callback'}, 400, 'invalid_request'),
                 ({'client_id': 'mcp_client_missing'}, 401, 'invalid_client'),
                 ({'resource': 'https://other.example/api/mcp'}, 400, 'invalid_target'),
                 ({'scope': 'mcp:admin'}, 400, 'invalid_scope'),
                 ({'response_type': 'token'}, 400, 'unsupported_response_type'))
        provider = type(self.env['mcp.oauth.provider'])
        for changed, status, error in cases:
            query = {key: value for key, value in {**params, **changed}.items() if value is not None}
            with self.subTest(changed=list(changed)), patch.object(provider, '_begin_login') as begin:
                response = self.url_open('/mcp/oauth/authorize?' + urlencode(query), allow_redirects=False)
            self.assertEqual(response.status_code, status)
            self.assertEqual(response.json()['error'], error)
            self.assertNotIn('Location', response.headers)
            begin.assert_not_called()

    def test_legacy_authorize_post_is_method_not_allowed(self):
        response = self.url_open('/mcp/oauth/authorize', data={'decision': 'approve'}, method='POST',
                                 allow_redirects=False)
        self.assertEqual(response.status_code, 405)

    def test_metadata_discovery_and_unknown_token_challenge(self):
        metadata = self.url_open('/.well-known/oauth-protected-resource/api/mcp').json()
        self.assertEqual(metadata['resource'], 'https://odoo.example/api/mcp')
        auth = self.url_open('/.well-known/oauth-authorization-server').json()
        self.assertEqual(auth['code_challenge_methods_supported'], ['S256'])
        self.assertTrue(auth['authorization_response_iss_parameter_supported'])
        rejected = self._tool('mcp_at_not-a-real-token', 'whoami')
        self.assertEqual(rejected.status_code, 401)
        self.assertIn('resource_metadata=', rejected.headers['WWW-Authenticate'])
        self.assertIn('WWW-Authenticate', rejected.headers.get('Access-Control-Expose-Headers', ''))

    def test_browser_preflight_exposes_post_and_authorization_headers(self):
        response = self.url_open('/api/mcp', method='OPTIONS', headers={
            'Origin': 'https://odoo.example', 'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Authorization,MCP-Protocol-Version',
        })
        self.assertEqual(response.status_code, 204)
        self.assertIn('POST', response.headers.get('Access-Control-Allow-Methods', ''))
        self.assertIn('Authorization', response.headers.get('Access-Control-Allow-Headers', ''))
        self.assertIn('MCP-Protocol-Version', response.headers.get('Access-Control-Allow-Headers', ''))

    def test_oauth_credentials_are_not_accepted_over_plain_http(self):
        response = super().url_open('/mcp/oauth/register', json={
            'client_name': 'Plain HTTP Client', 'redirect_uris': ['https://client.example/callback'],
            'token_endpoint_auth_method': 'none',
        }, method='POST')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_request')
        response = super().url_open('/mcp/oauth/token', data={'grant_type': 'authorization_code'}, method='POST')
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('access_token', response.json())

    def test_authorization_code_is_bound_to_client_redirect_resource_and_pkce(self):
        params = self._authorization_code()
        other = self.service._register_client({
            'client_name': 'Other Client', 'redirect_uris': ['https://other.example/callback'],
            'token_endpoint_auth_method': 'none',
        })
        for changed, expected in (({'client_id': other['client_id']}, 'invalid_grant'),
                                  ({'redirect_uri': 'https://client.example/other'}, 'invalid_grant'),
                                  ({'resource': 'https://other.example/api/mcp'}, 'invalid_target'),
                                  ({'code_verifier': 'wrong'}, 'invalid_grant')):
            with self.subTest(changed=list(changed)):
                try:
                    self.service._exchange({**params, **changed})
                except OAuthError as exc:
                    self.assertEqual(exc.error, expected)
                else:
                    self.fail('An authorization-code binding was bypassed')
        self.assertTrue(self.service._exchange(params)['access_token'])
        with self.assertRaises(OAuthError):
            self.service._exchange(params)

    def test_wrong_client_cannot_revoke_another_clients_refresh_family(self):
        pair, params = self._new_authorization()
        other = self.service._register_client({
            'client_name': 'Unrelated Client', 'redirect_uris': ['https://other.example/callback'],
            'grant_types': ['authorization_code', 'refresh_token'], 'token_endpoint_auth_method': 'none',
        })
        with self.assertRaises(OAuthError):
            self.service._exchange({'grant_type': 'refresh_token', 'client_id': other['client_id'],
                                    'refresh_token': pair['refresh_token'], 'resource': params['resource']})
        self.assertTrue(self.service._authenticate_token(pair['access_token']))
        refreshed = self.service._exchange({'grant_type': 'refresh_token', 'client_id': params['client_id'],
                                            'refresh_token': pair['refresh_token'], 'resource': params['resource']})
        self.assertTrue(refreshed['access_token'])

    def test_disabling_api_key_mode_invalidates_already_issued_file_links(self):
        _key, raw = self.env['muk_mcp.key'].with_user(self.owner)._generate('Acceptance Legacy Key', 'read', 0)
        result = self._result(self._tool(raw, 'export_records', {
            'model': 'res.partner', 'ids': [self.partner.id], 'fields': ['name'], 'delivery': 'link',
        }))
        self.env['ir.config_parameter'].set_bool('mcp_oauth.allow_api_keys', False)
        self.assertEqual(self.url_open(urlsplit(result['download_url']).path).status_code, 404)

    def test_downscoping_a_grant_invalidates_existing_upload_links(self):
        self.env['mcp.feishu.config']._get_config().allow_write_scope = True
        pair, params = self._new_authorization('mcp:read mcp:write')
        response = self._tool(pair['access_token'], 'authorize_upload', {'name': 'downscope-fixture.txt'})
        self.assertEqual(response.status_code, 200)
        upload = self._result(response)
        self.service._exchange({'grant_type': 'refresh_token', 'client_id': params['client_id'],
                                'refresh_token': pair['refresh_token'], 'resource': params['resource'],
                                'scope': 'mcp:read'})
        result = self.url_open(urlsplit(upload['upload_url']).path, data=b'not accepted', method='PUT')
        self.assertEqual(result.status_code, 404)
