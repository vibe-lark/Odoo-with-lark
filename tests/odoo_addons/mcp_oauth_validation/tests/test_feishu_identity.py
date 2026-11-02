"""Unique emails map automatically while disabled access and stable users persist."""
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import json
import time
from psycopg2.errors import UniqueViolation

from odoo import fields
from odoo.exceptions import AccessError, UserError
from odoo.tests import TransactionCase, new_test_user, tagged
from odoo.modules.module import get_module_path
from odoo.tools import mute_logger

from odoo.addons.muk_mcp_oauth21.tools.crypto import decrypt, encrypt
from odoo.addons.muk_mcp_oauth21.tools.oauth import OAuthError, digest
from odoo.addons.muk_mcp_feishu.controllers.login import error_response
from odoo.addons.muk_mcp_feishu.models.config import APP_TOKEN_URL, USER_TOKEN_URL
from odoo.addons.muk_mcp_feishu.tools.errors import FeishuRequestError


@tagged('post_install', '-at_install')
class TestFeishuIdentityAcceptance(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.config = cls.env['mcp.feishu.config']._get_config()
        cls.env['ir.config_parameter'].set_str('mcp_oauth.public_base_url', 'https://odoo.example')
        cls.config.write({'app_id': 'cli_acceptance', 'app_secret': 'test-only-application-secret'})
        cls.employee = new_test_user(cls.env, login='feishu_acceptance_employee', email='feishu@example.invalid')
        cls.employee.mcp_oauth_enabled = True
        cls.admin = cls.env.ref('base.user_admin')
        cls.admin.active = True
        cls.bindings = cls.env['mcp.feishu.binding']

    def _info(self, **overrides):
        return {'name': 'Test Employee', 'open_id': 'ou_acceptance_employee',
                'email': 'feishu@example.invalid', **overrides}

    def _resolve(self, **overrides):
        return self.bindings._resolve_identity(self._info(**overrides), 'cli_acceptance')

    def _propose_pending(self, **overrides):
        # Odoo's assertRaises rolls its savepoint back. OAuth controllers catch
        # this non-database error and commit the unmatched identity for display.
        try:
            self._resolve(**overrides)
        except OAuthError as exc:
            self.assertEqual(exc.error, 'access_denied')
        else:
            self.fail('An unresolved email match unexpectedly authenticated')
        binding = self.bindings.search([('app_id', '=', 'cli_acceptance'),
                                        ('open_id', '=', overrides.get('open_id', 'ou_acceptance_employee'))])
        self.assertEqual(binding.state, 'pending')
        self.assertEqual(binding.status, 'unmatched')

    def test_unique_email_binds_automatically_without_creating_a_legacy_key(self):
        key_count = self.env['muk_mcp.key'].sudo().search_count([])
        user, binding = self._resolve()
        self.assertEqual(binding.state, 'confirmed')
        self.assertEqual(binding.odoo_user_id, self.employee)
        self.assertEqual(user, self.employee)
        self.assertTrue(self.employee.mcp_oauth_enabled)
        self.assertEqual(self.env['muk_mcp.key'].sudo().search_count([]), key_count)

    def test_automatic_login_cannot_restore_disabled_user_mcp_permission(self):
        self.employee.mcp_oauth_enabled = False
        policy = self.employee.read(['mcp_oauth_scope', 'mcp_oauth_rate_limit', 'group_ids'])[0]
        try:
            self._resolve()
        except OAuthError as exc:
            self.assertEqual(exc.error, 'access_denied')
        else:
            self.fail('Automatic email matching granted disabled MCP access')
        self.assertFalse(self.employee.mcp_oauth_enabled)
        self.assertEqual(self.employee.read(['mcp_oauth_scope', 'mcp_oauth_rate_limit', 'group_ids'])[0], policy)
        binding = self.bindings.search([('open_id', '=', 'ou_acceptance_employee')])
        self.assertTrue(binding)
        self.assertEqual(binding.state, 'confirmed')
        self.assertEqual(binding.status, 'disabled')
        binding.action_enable()
        self.assertTrue(self.employee.mcp_oauth_enabled)
        self.assertEqual(self.employee.read(['mcp_oauth_scope', 'mcp_oauth_rate_limit', 'group_ids'])[0], policy)
        self.assertEqual(self._resolve()[0], self.employee)
        self.assertEqual(binding.status, 'enabled')

    def test_portal_account_is_not_automatically_matched_or_enabled(self):
        portal = new_test_user(self.env, login='feishu_portal_account', email='portal@example.invalid',
                               groups='base.group_portal')
        self.assertTrue(portal.share)
        self._propose_pending(open_id='ou_portal_identity', email=portal.email)
        binding = self.bindings.search([('open_id', '=', 'ou_portal_identity')])
        self.assertFalse(binding.odoo_user_id)
        with self.assertRaises(UserError):
            binding.action_enable()
        self.assertFalse(portal.mcp_oauth_enabled)

    def test_missing_email_or_openid_cannot_propose_binding(self):
        for info in ({'email': ''}, {'open_id': ''}):
            with self.subTest(info=info), self.assertRaises(OAuthError):
                self._resolve(**info)
        self.assertFalse(self.bindings.search([('open_id', '=', 'ou_acceptance_employee')]))

    def test_missing_or_changed_tenant_reuses_the_same_app_openid_binding(self):
        _user, binding = self._resolve()
        for info in ({}, {'tenant_key': None}, {'tenant_key': 'a_different_legacy_tenant'}):
            with self.subTest(info=info):
                self.assertEqual(self._resolve(**info), (self.employee, binding))
        self.assertEqual(self.bindings.search_count([('app_id', '=', 'cli_acceptance'),
                                                    ('open_id', '=', 'ou_acceptance_employee')]), 1)
        self.assertFalse(binding.tenant_key)

    def test_new_openid_gets_a_distinct_automatic_binding_for_the_same_unique_employee(self):
        _user, first = self._resolve()
        user, second = self._resolve(open_id='ou_second_identity')
        self.assertEqual(second.state, 'confirmed')
        self.assertEqual(second.odoo_user_id, self.employee)
        self.assertEqual(user, self.employee)
        self.assertNotEqual(first, second)

    def test_database_uniqueness_uses_app_and_openid_independently_of_legacy_tenant(self):
        self.env.cr.execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                            "WHERE conrelid='mcp_feishu_binding'::regclass AND contype='u'")
        self.assertIn('UNIQUE (app_id, open_id)', [row[0] for row in self.env.cr.fetchall()])
        self.env.cr.execute("SELECT attnotnull FROM pg_attribute "
                            "WHERE attrelid='mcp_feishu_binding'::regclass AND attname='tenant_key'")
        self.assertFalse(self.env.cr.fetchone()[0])
        self._resolve()
        with mute_logger('odoo.sql_db'), self.assertRaises(UniqueViolation), self.env.cr.savepoint():
            self.env.cr.execute("INSERT INTO mcp_feishu_binding "
                                "(app_id, open_id, tenant_key, email_normalized, state) VALUES (%s,%s,%s,%s,%s)",
                                ['cli_acceptance', 'ou_acceptance_employee', 'different_legacy_tenant',
                                 self.employee.email, 'pending'])
        other_app = self.bindings.create({'app_id': 'cli_other_application', 'open_id': 'ou_acceptance_employee',
                                         'email_normalized': self.employee.email, 'odoo_user_id': self.employee.id})
        with self.assertRaises(UserError):
            other_app.action_enable()

    def _migration_hook(self, phase, version='20.0.1.2.0'):
        path = Path(get_module_path('muk_mcp_feishu')) / 'migrations' / version / (phase + '-migration.py')
        spec = spec_from_file_location('feishu_migration_' + version.replace('.', '_') + '_' + phase, path)
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.migrate

    def test_pre_migration_rejects_legacy_duplicates_without_merging_accounts(self):
        migrate = self._migration_hook('pre')
        self.env.cr.execute('SAVEPOINT legacy_duplicate_probe')
        try:
            self.env.cr.execute('ALTER TABLE mcp_feishu_binding DROP CONSTRAINT mcp_feishu_binding_identity_unique')
            for tenant, uid in (('legacy_one', self.employee.id), ('legacy_two', self.admin.id)):
                self.env.cr.execute("INSERT INTO mcp_feishu_binding "
                                    "(app_id,open_id,tenant_key,email_normalized,state,odoo_user_id) "
                                    "VALUES (%s,%s,%s,%s,%s,%s)",
                                    ['cli_duplicate_migration', 'ou_duplicate', tenant,
                                     self.employee.email, 'pending', uid])
            self.env.cr.execute("SELECT id,tenant_key,odoo_user_id FROM mcp_feishu_binding "
                                "WHERE app_id='cli_duplicate_migration' ORDER BY id")
            original = self.env.cr.fetchall()
            with self.assertRaisesRegex(RuntimeError, 'Duplicate Feishu application identities'):
                migrate(self.env.cr, '20.0.1.1.4')
            self.env.cr.execute("SELECT id,tenant_key,odoo_user_id FROM mcp_feishu_binding "
                                "WHERE app_id='cli_duplicate_migration' ORDER BY id")
            self.assertEqual(self.env.cr.fetchall(), original)
        finally:
            self.env.cr.execute('ROLLBACK TO SAVEPOINT legacy_duplicate_probe')
            self.env.cr.execute('RELEASE SAVEPOINT legacy_duplicate_probe')
            self.env.invalidate_all(flush=False)

    def test_migration_hooks_require_the_real_postgresql_unique_constraint(self):
        self._migration_hook('pre')(self.env.cr, '20.0.1.1.4')
        migrate = self._migration_hook('post')
        migrate(self.env.cr, '20.0.1.1.4')
        self.env.cr.execute('SAVEPOINT missing_constraint_probe')
        try:
            self.env.cr.execute('ALTER TABLE mcp_feishu_binding DROP CONSTRAINT mcp_feishu_binding_identity_unique')
            with self.assertRaisesRegex(RuntimeError, 'unique constraint was not installed'):
                migrate(self.env.cr, '20.0.1.1.4')
        finally:
            self.env.cr.execute('ROLLBACK TO SAVEPOINT missing_constraint_probe')
            self.env.cr.execute('RELEASE SAVEPOINT missing_constraint_probe')
            self.env.invalidate_all(flush=False)

    def _legacy_binding(self, open_id, **changes):
        return self.bindings.create({'app_id': self.config.app_id, 'open_id': open_id,
                                     'email_normalized': self.employee.email, 'odoo_user_id': self.employee.id,
                                     'active': True, 'state': 'pending', **changes})

    def test_automatic_binding_migration_preserves_user_permissions_and_legacy_keys(self):
        eligible = self._legacy_binding('ou_legacy_auto_match', approved_by=self.admin.id,
                                        approved_at=fields.Datetime.now() - timedelta(days=30))
        historical_approval = eligible.read(['approved_by', 'approved_at'])[0]
        disabled_user = new_test_user(self.env, login='migration_mcp_disabled', email='migration-disabled@example.invalid')
        disabled = self._legacy_binding('ou_legacy_permission_disabled', email_normalized=disabled_user.email,
                                        odoo_user_id=disabled_user.id)
        key, raw = self.env['muk_mcp.key'].with_user(self.employee)._generate('Migration Existing Key', 'read', 0)
        fields_to_read = ['mcp_oauth_enabled', 'mcp_oauth_scope', 'mcp_oauth_rate_limit', 'group_ids']
        policies = (self.employee | disabled_user).read(fields_to_read)
        key_count = self.env['muk_mcp.key'].sudo().search_count([])
        self._migration_hook('post', '20.0.1.3.0')(self.env.cr, '20.0.1.2.0')
        self.assertEqual(eligible.state, 'confirmed')
        self.assertEqual(eligible.status, 'enabled')
        self.assertEqual(eligible.read(['approved_by', 'approved_at'])[0], historical_approval)
        self.assertEqual(disabled.state, 'confirmed')
        self.assertEqual(disabled.status, 'disabled')
        self.assertFalse(disabled_user.mcp_oauth_enabled)
        self.assertEqual((self.employee | disabled_user).read(fields_to_read), policies)
        self.assertEqual(self.env['muk_mcp.key'].sudo().search_count([]), key_count)
        self.assertEqual(self.env['muk_mcp.key'].sudo().authenticate(raw), key)
        with self.assertRaises(OAuthError):
            self._resolve(open_id=disabled.open_id, email=disabled_user.email)
        self.assertFalse(disabled_user.mcp_oauth_enabled)
        self.assertFalse(hasattr(self.bindings, 'action_approve'))
        self.assertFalse(hasattr(self.bindings, 'action_review'))

    def test_automatic_binding_migration_skips_blocked_archived_unmatched_or_changed_email(self):
        records = self._legacy_binding('ou_migration_blocked', state='blocked')
        records |= self._legacy_binding('ou_migration_archived', active=False)
        records |= self._legacy_binding('ou_migration_email_changed', pending_email='pending-change@example.invalid')
        records |= self._legacy_binding('ou_migration_unmatched', odoo_user_id=False)
        records |= self._legacy_binding('ou_migration_wrong_uid', odoo_user_id=self.admin.id)
        records |= self._legacy_binding('ou_migration_other_app', app_id='cli_other_application')
        before = records.read(['state', 'active', 'odoo_user_id', 'email_normalized', 'pending_email'])
        self._migration_hook('post', '20.0.1.3.0')(self.env.cr, '20.0.1.2.0')
        self.assertEqual(records.read(['state', 'active', 'odoo_user_id', 'email_normalized', 'pending_email']), before)

    def test_automatic_binding_migration_does_not_resolve_ambiguous_email(self):
        new_test_user(self.env, login='migration_duplicate_employee', email=self.employee.email)
        binding = self._legacy_binding('ou_migration_duplicate')
        self._migration_hook('post', '20.0.1.3.0')(self.env.cr, '20.0.1.2.0')
        self.assertEqual(binding.state, 'pending')
        self.assertEqual(binding.status, 'unmatched')
        self.assertEqual(binding.odoo_user_id, self.employee)

    def test_unmatched_or_duplicate_email_recovers_automatically_after_correction(self):
        duplicate = new_test_user(self.env, login='feishu_duplicate_employee', email='feishu@example.invalid')
        self._propose_pending()
        binding = self.bindings.search([('open_id', '=', 'ou_acceptance_employee')])
        self.assertFalse(binding.odoo_user_id)
        with self.assertRaises(UserError):
            binding.action_enable()
        duplicate.active = False
        self.assertEqual(self._resolve(), (self.employee, binding))
        self.assertEqual(binding.state, 'confirmed')
        self._propose_pending(open_id='ou_unknown_employee', email='unknown@example.invalid')
        self.assertFalse(self.bindings.search([('open_id', '=', 'ou_unknown_employee')]).odoo_user_id)
        newcomer = new_test_user(self.env, login='feishu_new_matching_employee', email='unknown@example.invalid')
        newcomer.mcp_oauth_enabled = True
        user, matched = self._resolve(open_id='ou_unknown_employee', email='unknown@example.invalid')
        self.assertEqual(user, newcomer)
        self.assertEqual(matched.state, 'confirmed')

    def test_disabled_employee_and_changed_email_do_not_silently_rebind(self):
        _user, binding = self._resolve()
        with self.assertRaises(OAuthError):
            self._resolve(email='someone-else@example.invalid')
        self.assertEqual(binding.odoo_user_id, self.employee)
        self.employee.active = False
        with self.assertRaises(OAuthError):
            self._resolve()

    def test_employee_cannot_enable_or_disable_bindings_or_read_application_secret(self):
        _user, binding = self._resolve()
        with self.assertRaises(AccessError):
            binding.with_user(self.employee).action_enable()
        with self.assertRaises(AccessError):
            binding.with_user(self.employee).action_disable()
        with self.assertRaises(AccessError):
            self.config.with_user(self.employee).read(['app_secret', 'secret_ciphertext'])
        with self.assertRaises(AccessError):
            self.env['mcp.feishu.trial'].with_user(self.employee)._start()
        with self.assertRaises(AccessError):
            self.config.with_user(self.employee).write({'enabled': True})
        with self.assertRaises(AccessError):
            self.config.with_user(self.employee).write({'login_fingerprint': self.config._fingerprint()})

    def test_application_secret_is_encrypted_and_not_read_back(self):
        self.config.invalidate_recordset()
        self.assertTrue(self.config.secret_is_set)
        self.assertFalse(self.config.app_secret)
        self.assertNotIn('test-only-application-secret', self.config.secret_ciphertext)
        self.assertEqual(self.config._secret(), 'test-only-application-secret')

    def _assert_settings_reload(self, action):
        self.assertEqual(action['type'], 'ir.actions.client')
        self.assertEqual(action['tag'], 'display_notification')
        self.assertEqual(action['params']['type'], 'success')
        self.assertEqual(action['params']['next'], {'type': 'ir.actions.client', 'tag': 'reload'})

    def test_credentials_check_refreshes_state_and_exposes_trial_login(self):
        self.assertEqual(self.config.state, 'unchecked')
        with patch.object(type(self.config), '_request_token', return_value={'access_token': 'test-application-token'}) as request_token:
            action = self.config.action_check_credentials()
        request_token.assert_called_once_with({'grant_type': 'client_credentials'})
        self.assertTrue(self.config.credentials_checked_at)
        self.assertEqual(self.config.credentials_fingerprint, self.config._fingerprint())
        self.assertEqual(self.config.state, 'checked')
        self._assert_settings_reload(action)
        trial_action = self.config.action_trial_login()
        self.assertEqual(trial_action, {
            'type': 'ir.actions.act_url',
            'url': 'https://odoo.example/mcp/oauth/feishu/trial/start',
            'target': 'self',
        })

    def test_upstream_errors_preserve_safe_codes_without_echoing_provider_secrets(self):
        raw = 'must-not-leak-test-authorization-token'
        cases = (
            (USER_TOKEN_URL, 400, {'error': 'invalid_grant', 'error_description': raw, 'access_token': raw}, 'invalid_grant'),
            (USER_TOKEN_URL, 200, {'code': 20003, 'msg': raw, 'refresh_token': raw}, '20003'),
            (APP_TOKEN_URL, 200, {'code': 20003, 'msg': raw, 'refresh_token': raw}, '20003'),
            (USER_TOKEN_URL, 400, {'code': 20049, 'msg': raw}, '20049'),
            (USER_TOKEN_URL, 400, {'error': raw, 'code': raw, 'error_description': raw}, '未返回错误码'),
        )
        for endpoint, status, payload, safe_code in cases:
            response = Mock(status_code=status)
            response.json.return_value = payload
            with self.subTest(endpoint=endpoint, status=status, safe_code=safe_code), patch(
                    'odoo.addons.muk_mcp_feishu.models.config.requests.request', return_value=response), self.assertLogs(
                    'odoo.addons.muk_mcp_feishu.tools.errors', level='WARNING') as captured:
                try:
                    self.config._request_json('POST', endpoint, data={'client_secret': raw})
                except FeishuRequestError as exc:
                    rejection = exc
                else:
                    self.fail('A provider error response was accepted as successful')
            self.assertIn(f'HTTP {status}', rejection.description)
            self.assertIn('令牌接口', rejection.description)
            self.assertIn(safe_code, rejection.description)
            if safe_code == '20049':
                self.assertIn('PKCE', rejection.description)
            self.assertNotIn(raw, rejection.description)
            self.assertNotIn(raw, '\n'.join(captured.output))
            with patch.object(type(self.config), '_request_token', side_effect=rejection), self.assertRaises(UserError) as raised:
                self.config.action_check_credentials()
            self.assertIn(safe_code, str(raised.exception))
            self.assertNotIn(raw, str(raised.exception))

    def test_trial_provider_error_page_does_not_misdiagnose_employee_binding(self):
        exc = FeishuRequestError('invalid_grant', '飞书未接受本次请求（接口：令牌接口；HTTP 400；错误码：invalid_grant）。')
        response = error_response(exc, browser=True, trial=True)
        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 400)
        self.assertIn('飞书登录验证未完成', page)
        self.assertIn('尚未进入员工邮箱绑定', page)
        self.assertIn('接口：令牌接口', page)
        self.assertIn('invalid_grant', page)
        self.assertIn('返回飞书设置', page)
        self.assertNotIn('检查授权、账号绑定或 MCP 使用权限', page)
        self.assertIn('no-store', response.headers['Cache-Control'])
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')

    def test_administrator_trial_without_tenant_enables_readiness_without_issuing_mcp_grants(self):
        self.config.write({'credentials_fingerprint': self.config._fingerprint()})
        grant_count = self.env['mcp.oauth.grant'].sudo().search_count([])
        url, cookie = self.env['mcp.feishu.trial'].with_user(self.admin)._start()
        state = parse_qs(urlsplit(url).query)['state'][0]
        config_model = type(self.config)
        token = {'access_token': 'test-provider-access', 'refresh_token': 'test-provider-refresh', 'expires_in': 3600}
        with patch.object(config_model, '_exchange_code', return_value=token) as exchange, patch.object(config_model, '_user_info', return_value=self._info()):
            self.env['mcp.feishu.trial']._complete({'state': state, 'code': 'test-code'}, cookie, self.admin.id)
        trial = self.env['mcp.feishu.trial'].search([('state_hash', '=', digest(state))])
        exchange.assert_called_once_with('test-code', decrypt(trial.verifier), trial.code_challenge)
        self.assertEqual(self.env['mcp.oauth.grant'].sudo().search_count([]), grant_count)
        self.assertEqual(self.config.state, 'login_ok')
        self.assertTrue(self.config.can_enable_oauth)
        self.assertFalse(self.config.enabled)
        self.config.enabled = True
        self.assertTrue(self.config.enabled)
        self.assertEqual(self.config.state, 'enabled')
        self.assertFalse(hasattr(self.config, 'action_confirm_tenant'))

    def _ready_oauth_settings(self):
        fingerprint = self.config._fingerprint()
        self.config.write({'credentials_fingerprint': fingerprint, 'login_fingerprint': fingerprint,
                           'pending_trial_user_id': self.admin.id})
        self.assertTrue(self.config.can_enable_oauth)

    def test_enable_error_identifies_the_first_incomplete_setup_step(self):
        self.assertFalse(self.config.can_enable_oauth)
        with self.assertRaises(UserError) as raised:
            self.config.enabled = True
        self.assertIn('检查', str(raised.exception))
        self.assertIn('凭证', str(raised.exception))
        self.config.credentials_fingerprint = self.config._fingerprint()
        self.assertFalse(self.config.can_enable_oauth)
        with self.assertRaises(UserError) as raised:
            self.config.enabled = True
        self.assertIn('试用', str(raised.exception))
        self.assertIn('登录', str(raised.exception))

    def test_legacy_tenant_values_do_not_gate_oauth_enablement(self):
        self._ready_oauth_settings()
        self.config.with_context(mcp_confirm_tenant=True).write({
            'allowed_tenant_key': 'legacy_tenant_one', 'pending_tenant_key': 'legacy_tenant_two'})
        self.assertTrue(self.config.can_enable_oauth)
        self.config.enabled = True
        self.assertTrue(self.config.enabled)

    def test_changing_application_secret_disables_oauth_and_invalidates_setup(self):
        self._ready_oauth_settings()
        self.config.enabled = True
        self.config.app_secret = 'new-test-only-application-secret'
        self.assertFalse(self.config.enabled)
        self.assertFalse(self.config.can_enable_oauth)
        self.assertFalse(self.config.credentials_fingerprint)
        self.assertFalse(self.config.login_fingerprint)
        with self.assertRaises(UserError) as raised:
            self.config.enabled = True
        self.assertIn('凭证', str(raised.exception))

    def test_changing_application_id_requires_new_credentials_and_administrator_login(self):
        self._ready_oauth_settings()
        self.config.enabled = True
        self.config.app_id = 'cli_changed_acceptance'
        self.assertFalse(self.config.enabled)
        self.assertFalse(self.config.can_enable_oauth)
        self.assertFalse(self.config.credentials_fingerprint)
        self.assertFalse(self.config.login_fingerprint)

    def test_enabled_oauth_can_still_be_turned_off_when_setup_becomes_invalid(self):
        self._ready_oauth_settings()
        self.config.enabled = True
        self.config.login_fingerprint = False
        self.assertFalse(self.config.can_enable_oauth)
        self.assertTrue(self.config.enabled)
        self.config.enabled = False
        self.assertFalse(self.config.enabled)

    def test_trial_callback_cannot_use_a_different_browser_or_employee_session(self):
        self.config.write({'credentials_fingerprint': self.config._fingerprint()})
        url, cookie = self.env['mcp.feishu.trial'].with_user(self.admin)._start()
        state = parse_qs(urlsplit(url).query)['state'][0]
        for supplied_cookie, uid in (('incorrect-cookie', self.admin.id), (cookie, self.employee.id)):
            with self.subTest(uid=uid), self.assertRaises(OAuthError):
                self.env['mcp.feishu.trial']._complete({'state': state, 'code': 'test-code'}, supplied_cookie, uid)
        self.assertFalse(self.config.login_fingerprint)
        self.assertFalse(self.config.can_enable_oauth)

    def test_trial_missing_email_distinguishes_user_consent_from_contact_details(self):
        self.config.credentials_fingerprint = self.config._fingerprint()
        url, cookie = self.env['mcp.feishu.trial'].with_user(self.admin)._start()
        state = parse_qs(urlsplit(url).query)['state'][0]
        grant_count = self.env['mcp.oauth.grant'].search_count([])
        token = {'access_token': 'test-only-provider-access', 'expires_in': 3600}
        with patch.object(type(self.config), '_exchange_code', return_value=token), patch.object(
                type(self.config), '_user_info', return_value=self._info(email='')), self.assertRaises(OAuthError) as raised:
            self.env['mcp.feishu.trial']._complete({'state': state, 'code': 'test-only-code'}, cookie, self.admin.id)
        self.assertIn('本次用户授权', raised.exception.description)
        self.assertIn('联系方式', raised.exception.description)
        self.assertFalse(self.config.login_fingerprint)
        self.assertFalse(self.config.can_enable_oauth)
        self.assertEqual(self.env['mcp.oauth.grant'].search_count([]), grant_count)

    def test_disabled_or_archived_binding_is_not_automatically_restored(self):
        _user, binding = self._resolve()
        binding.action_disable()
        self.assertEqual(binding.status, 'disabled')
        for info in ({}, {'tenant_key': 'changed_tenant'}):
            with self.subTest(info=info), self.assertRaises(OAuthError):
                self._resolve(**info)
        binding.action_enable()
        self.assertEqual(self._resolve()[0], self.employee)
        self.assertEqual(binding.status, 'enabled')
        binding.active = False
        self.assertEqual(binding.status, 'disabled')
        with self.assertRaises(OAuthError):
            self._resolve(tenant_key='another_tenant')
        binding.action_enable()
        user, _ = self._resolve()
        self.assertEqual(user, self.employee)

    def test_email_change_updates_the_same_unique_user_but_cannot_switch_accounts(self):
        _user, binding = self._resolve()
        self.employee.email = 'renamed-feishu@example.invalid'
        self.assertEqual(self._resolve(email='renamed-feishu@example.invalid')[0], self.employee)
        self.assertEqual(binding.state, 'confirmed')
        self.assertFalse(binding.pending_email)
        self.assertEqual(binding.email_normalized, 'renamed-feishu@example.invalid')
        self.assertEqual(binding.odoo_user_id, self.employee)
        # A later email claim matching another user must never take over that account.
        new_test_user(self.env, login='feishu_different_account', email='other-employee@example.invalid')
        try:
            self._resolve(email='other-employee@example.invalid')
        except OAuthError:
            pass
        else:
            self.fail('Email matching a different Odoo user authenticated')
        self.assertEqual(binding.pending_email, 'other-employee@example.invalid')
        with self.assertRaises(UserError):
            binding.action_enable()
        self.assertEqual(binding.odoo_user_id, self.employee)

    def test_rotated_upstream_refresh_is_retained_if_userinfo_temporarily_fails(self):
        _user, binding = self._resolve()
        fingerprint = self.config._fingerprint()
        self.config.write({'credentials_fingerprint': fingerprint, 'login_fingerprint': fingerprint})
        self.config.enabled = True
        client = self.env['mcp.oauth.client'].create({
            'name': 'Provider Refresh Acceptance', 'redirect_uris': ['https://client.example/callback'],
            'grant_types': ['authorization_code', 'refresh_token'], 'auth_method': 'none',
        })
        grant = self.env['mcp.oauth.grant'].sudo().create({
            'client_id': client.id, 'user_id': self.employee.id, 'scope': 'read',
            'resource': 'https://odoo.example/api/mcp', 'expires_at': fields.Datetime.now() + timedelta(hours=1),
            'provider_data': {'provider': 'feishu', 'app_id': 'cli_acceptance',
                              'tenant_key': 'tenant_acceptance', 'binding_id': binding.id,
                              'credentials': encrypt(json.dumps({'access_token': 'initial_provider_access',
                                  'expires_at': int(time.time()) + 60, 'refresh_token': 'old_provider_refresh',
                                  'refresh_expires_at': int(time.time()) + 60}))},
        })
        service = self.env['mcp.oauth.service']
        pair = service._new_token_pair(grant)
        expired_bundle = json.loads(decrypt(grant.provider_data['credentials']))
        expired_bundle['expires_at'] = int(time.time()) - 30
        grant.provider_data = {**grant.provider_data, 'credentials': encrypt(json.dumps(expired_bundle))}
        params = {'grant_type': 'refresh_token', 'client_id': client.client_id,
                  'refresh_token': pair['refresh_token'], 'resource': grant.resource}
        next_bundle = {'access_token': 'new_provider_access', 'refresh_token': 'new_provider_refresh',
                       'expires_in': 3600, 'refresh_token_expires_in': 7200}
        config_model = type(self.config)
        with patch.object(config_model, '_request_token', return_value=next_bundle) as refresh, patch.object(
                config_model, '_user_info', side_effect=OAuthError('temporarily_unavailable', 'Retry identity lookup', 502)):
            try:
                service._exchange(params)
            except OAuthError as exc:
                self.assertEqual(exc.error, 'temporarily_unavailable')
            else:
                self.fail('A temporary user-info failure unexpectedly completed refresh')
            self.assertEqual(refresh.call_count, 1)
        stored = json.loads(decrypt(grant.provider_data['credentials']))
        self.assertEqual(stored['refresh_token'], 'new_provider_refresh')
        self.assertGreater(stored['refresh_expires_at'], expired_bundle['refresh_expires_at'])
        self.assertEqual(grant.expires_at, datetime.fromtimestamp(stored['refresh_expires_at'], timezone.utc).replace(tzinfo=None))
        token = self.env['mcp.oauth.token'].sudo().search([('token_hash', '=', digest(pair['refresh_token']))])
        self.assertFalse(token.used_at)
        self.assertFalse(grant.revoked_at)
        self.assertEqual(token.expires_at, grant.expires_at)
        # The old upstream refresh credential has expired by the retry time.
        # The already-rotated bundle and the unconsumed MCP RT remain usable.
        after_old_deadline = datetime.fromtimestamp(expired_bundle['refresh_expires_at'], timezone.utc).replace(tzinfo=None) + timedelta(seconds=30)
        with patch.object(fields.Datetime, 'now', return_value=after_old_deadline), patch(
                'odoo.addons.muk_mcp_feishu.models.provider.time.time', return_value=after_old_deadline.timestamp()), patch.object(
                config_model, '_request_token') as refresh, patch.object(config_model, '_user_info', return_value=self._info()):
            replacement = service._exchange(params)
            self.assertEqual(refresh.call_count, 0)
        self.assertTrue(replacement['access_token'])
        self.assertTrue(token.used_at)
