"""Create finite, committed fixtures ONLY in a disposable mcp_oauth_test_* DB."""
import json
import secrets
import time
from urllib.parse import parse_qs, urlsplit

from odoo import Command
from odoo.tools import BinaryBytes

from odoo.addons.muk_mcp_oauth21.tools.crypto import encrypt
from odoo.addons.muk_mcp_oauth21.tools.oauth import challenge, digest


def create_fixture(env):
    if not env.cr.dbname.startswith('mcp_oauth_test_'):
        raise RuntimeError('Refusing a non-test database')
    config = env['mcp.feishu.config']._get_config()
    config.write({'app_id': 'cli_concurrency_fixture', 'app_secret': 'fake-provider-secret-for-local-tests'})
    fingerprint = config._fingerprint()
    config.write({'credentials_fingerprint': fingerprint, 'login_fingerprint': fingerprint})
    config.enabled = True
    nonce = secrets.token_hex(4)
    employee = env['res.users'].with_context(no_reset_password=True).create({
        'name': 'OAuth Concurrency Fixture', 'login': 'oauth_concurrency_fixture_' + nonce,
        'email': 'oauth-concurrency-' + nonce + '@example.invalid', 'mcp_oauth_enabled': True,
        'mcp_oauth_rate_limit': 0,
        'group_ids': [Command.link(env.ref('base.group_user').id),
                      Command.link(env.ref('base.group_partner_manager').id)],
    })
    binding = env['mcp.feishu.binding'].create({
        'name': employee.name, 'app_id': config.app_id,
        'open_id': 'ou_concurrency_fixture_' + nonce, 'email_normalized': employee.email,
        'odoo_user_id': employee.id,
    })
    binding.action_enable()
    service = env['mcp.oauth.service']
    registration = service._register_client({
        'client_name': 'Concurrency Fixture', 'redirect_uris': ['https://client.example/callback'],
        'token_endpoint_auth_method': 'none', 'grant_types': ['authorization_code', 'refresh_token'],
    })
    verifier = 'concurrency-verifier-' + 'v' * 48
    flow, _flow_id, _csrf, _cookie = service._start_flow({
        'client_id': registration['client_id'], 'redirect_uri': registration['redirect_uris'][0],
        'response_type': 'code', 'code_challenge': challenge(verifier), 'code_challenge_method': 'S256',
        'scope': 'mcp:read', 'resource': service._resource(),
    })
    response_url = service._complete_flow(flow, employee, {
        'provider': 'feishu', 'app_id': config.app_id,
        'binding_id': binding.id, 'binding_version': binding.auth_version,
        'credentials': encrypt(json.dumps({'access_token': 'unused-fake-upstream-token',
                                          'expires_at': int(time.time()) + 3600,
                                          'refresh_token': 'unused-fake-upstream-refresh',
                                          'refresh_expires_at': int(time.time()) + 172800})),
    })
    code = parse_qs(urlsplit(response_url).query)['code'][0]
    grant = env['mcp.oauth.code'].search([('code_hash', '=', digest(code))]).grant_id
    attachment = env['ir.attachment'].with_user(employee).create({
        'name': 'concurrency-fixture.txt', 'raw': BinaryBytes(b'One successful reader only'),
    })
    _transfer, url = env['muk_mcp.transfer'].with_user(employee)._issue(
        'download', uri=f'odoo://attachment/{attachment.id}', oauth_grant_id=grant.id,
    )
    return {'database': env.cr.dbname, 'resource': service._resource(), 'download_url': url,
            'token_request': {'grant_type': 'authorization_code', 'client_id': registration['client_id'],
                              'redirect_uri': registration['redirect_uris'][0], 'code': code,
                              'code_verifier': verifier, 'resource': service._resource()}}
