"""Probe real PostgreSQL locks outside Odoo's shared HttpCase test cursor."""
from unittest.mock import patch

from psycopg2.errors import LockNotAvailable

from odoo import api, SUPERUSER_ID
from odoo.tools import mute_logger

from odoo.addons.muk_mcp_oauth21.tools.oauth import OAuthError, digest
from .concurrency_fixture import create_fixture


def probe_grant_lock(env):
    if not env.cr.dbname.startswith('mcp_oauth_test_'):
        raise RuntimeError('Refusing a non-test database')
    fixture = create_fixture(env)
    grant = env['mcp.oauth.code'].search([('code_hash', '=', digest(fixture['token_request']['code']))]).grant_id
    service = env['mcp.oauth.service']
    pair = service._new_token_pair(grant)
    grant.last_used = False
    env.cr.commit()  # The second connection must be able to see the fixture.
    report = {'isolated_database': env.cr.dbname, 'provider_network_requests': 0}

    def verify_lock_before_provider(_provider, locked_grant):
        with env.registry.cursor() as other:
            try:
                other.execute('SELECT id FROM mcp_oauth_grant WHERE id=%s FOR UPDATE NOWAIT', [locked_grant.id])
            except LockNotAvailable:
                other.rollback()
                report['grant_locked_before_provider_refresh'] = True
            else:
                other.rollback()
                raise AssertionError('Provider refresh ran before acquiring the grant lock')

    provider = type(env['mcp.oauth.provider'])
    with patch.object(provider, '_refresh_grant', new=verify_lock_before_provider):
        service._exchange({'grant_type': 'refresh_token', 'client_id': grant.client_id.client_id,
                           'refresh_token': pair['refresh_token'], 'resource': grant.resource})
    # Keep the primary transaction's grant lock held while another request
    # authenticates its already-committed access token.
    with env.registry.cursor() as other:
        other.execute("SET LOCAL lock_timeout = '100ms'")
        second_env = api.Environment(other, SUPERUSER_ID, {})
        authenticated = second_env['mcp.oauth.service']._authenticate_token(pair['access_token'])
        report['access_authentication_skips_locked_last_used'] = authenticated.id == grant.id
        other.rollback()
    report['passed'] = bool(report.get('grant_locked_before_provider_refresh')
                            and report.get('access_authentication_skips_locked_last_used'))
    assert report['passed'], 'The grant refresh lock boundary failed'
    return report


def probe_binding_disable_lock_skip(env):
    """Disable while another real connection holds the grant row lock."""
    if not env.cr.dbname.startswith('mcp_oauth_test_'):
        raise RuntimeError('Refusing a non-test database')
    fixture = create_fixture(env)
    grant = env['mcp.oauth.code'].search([('code_hash', '=', digest(fixture['token_request']['code']))]).grant_id
    binding = env['mcp.feishu.binding'].browse(grant.provider_data['binding_id'])
    pair = env['mcp.oauth.service']._new_token_pair(grant)
    env.cr.commit()
    report = {'isolated_database': env.cr.dbname, 'provider_network_requests': 0}
    with env.registry.cursor() as locked:
        locked.execute('SELECT id FROM mcp_oauth_grant WHERE id=%s FOR UPDATE', [grant.id])
        env.cr.execute("SET LOCAL lock_timeout = '500ms'")
        binding.action_disable()
        env.cr.commit()
        binding.action_enable()
        env.cr.commit()
        with env.registry.cursor() as other:
            other.execute('SELECT revoked_at IS NULL FROM mcp_oauth_grant WHERE id=%s', [grant.id])
            report['locked_grant_revocation_was_skipped'] = bool(other.fetchone()[0])
            second_env = api.Environment(other, SUPERUSER_ID, {})
            report['old_access_denied_after_reenable'] = not bool(
                second_env['mcp.oauth.service']._authenticate_token(pair['access_token']))
            other.rollback()
        locked.rollback()
    with env.registry.cursor() as other:
        second_env = api.Environment(other, SUPERUSER_ID, {})
        provider = type(second_env['mcp.oauth.provider'])
        with patch.object(provider, '_refresh_grant') as refresh:
            try:
                second_env['mcp.oauth.service']._exchange({
                    'grant_type': 'refresh_token', 'client_id': grant.client_id.client_id,
                    'refresh_token': pair['refresh_token'], 'resource': grant.resource,
                })
            except OAuthError as exc:
                report['old_refresh_denied_before_provider'] = exc.error == 'invalid_grant' and not refresh.called
            else:
                report['old_refresh_denied_before_provider'] = False
        other.rollback()
    report['passed'] = all(report.get(key) for key in (
        'locked_grant_revocation_was_skipped', 'old_access_denied_after_reenable',
        'old_refresh_denied_before_provider'))
    if not report['passed']:
        raise AssertionError('Binding version did not protect a grant skipped during revocation')
    return report


def probe_provider_refresh_locks_binding(env):
    """Verify both rows are locked before an upstream one-use refresh call."""
    if not env.cr.dbname.startswith('mcp_oauth_test_'):
        raise RuntimeError('Refusing a non-test database')
    fixture = create_fixture(env)
    grant = env['mcp.oauth.code'].search([('code_hash', '=', digest(fixture['token_request']['code']))]).grant_id
    binding = env['mcp.feishu.binding'].browse(grant.provider_data['binding_id'])
    pair = env['mcp.oauth.service']._new_token_pair(grant)
    env.cr.commit()
    report = {'isolated_database': env.cr.dbname, 'provider_network_requests': 0}

    def verify_locks(_config, values):
        if values.get('grant_type') != 'refresh_token':
            raise AssertionError('Unexpected provider token request in lock probe')
        with env.registry.cursor() as other, mute_logger('odoo.sql_db'):
            other.execute("SET LOCAL lock_timeout = '100ms'")
            try:
                api.Environment(other, SUPERUSER_ID, {})['mcp.feishu.binding']._lock_identity(
                    binding.app_id, binding.open_id)
            except LockNotAvailable:
                other.rollback()
                report['identity_advisory_locked_before_upstream_refresh'] = True
            else:
                other.rollback()
                raise AssertionError('The identity advisory lock was missing before upstream refresh')
            for table, row_id, result_key in (
                    ('mcp_oauth_grant', grant.id, 'grant_locked_before_upstream_refresh'),
                    ('mcp_feishu_binding', binding.id, 'binding_locked_before_upstream_refresh')):
                try:
                    other.execute('SELECT id FROM ' + table + ' WHERE id=%s FOR UPDATE NOWAIT', [row_id])
                except LockNotAvailable:
                    other.rollback()
                    report[result_key] = True
                else:
                    other.rollback()
                    raise AssertionError('An identity row was not locked before upstream refresh')
        return {'access_token': 'fake-refreshed-access', 'expires_in': 3600,
                'refresh_token': 'fake-refreshed-refresh', 'refresh_token_expires_in': 86400}

    config_model = type(env['mcp.feishu.config'])
    info = {'open_id': binding.open_id, 'email': grant.user_id.email}
    with patch.object(config_model, '_request_token', new=verify_locks), patch.object(
            config_model, '_user_info', return_value=info):
        env['mcp.oauth.service']._exchange({
            'grant_type': 'refresh_token', 'client_id': grant.client_id.client_id,
            'refresh_token': pair['refresh_token'], 'resource': grant.resource,
        })
    report['passed'] = bool(report.get('grant_locked_before_upstream_refresh')
                            and report.get('binding_locked_before_upstream_refresh')
                            and report.get('identity_advisory_locked_before_upstream_refresh'))
    if not report['passed']:
        raise AssertionError('Refresh row-lock protection failed')
    return report
