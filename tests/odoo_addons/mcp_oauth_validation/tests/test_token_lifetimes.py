"""The upstream authorization deadlines, rather than local knobs, bound MCP."""
from datetime import datetime, timedelta, timezone
import json
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from psycopg2.errors import SerializationFailure

from odoo import fields
from odoo.tests import TransactionCase, new_test_user, tagged

from odoo.addons.muk_mcp_feishu.models.provider import credential_bundle
from odoo.addons.muk_mcp_oauth21.tools.crypto import decrypt, encrypt
from odoo.addons.muk_mcp_oauth21.tools.oauth import OAuthError, challenge, digest


def utc_datetime(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).replace(tzinfo=None)


@tagged('post_install', '-at_install')
class TestAutomaticTokenLifetimes(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.enterClassContext(patch('odoo.addons.muk_mcp_feishu.models.config.requests.request',
                                    side_effect=AssertionError('External provider HTTP is disabled in this test')))
        cls.service = cls.env['mcp.oauth.service']
        cls.config = cls.env['mcp.feishu.config']._get_config()
        cls.env['ir.config_parameter'].set_str('mcp_oauth.public_base_url', 'https://odoo.example')
        cls.config.write({'app_id': 'cli_lifetime_acceptance', 'app_secret': 'test-only-expiry-secret'})
        fingerprint = cls.config._fingerprint()
        cls.config.write({'credentials_fingerprint': fingerprint, 'login_fingerprint': fingerprint})
        cls.config.enabled = True
        cls.employee = new_test_user(cls.env, login='oauth_lifetime_employee', email='expiry@example.invalid')
        cls.binding = cls.env['mcp.feishu.binding'].create({
            'name': 'Expiry Employee', 'app_id': cls.config.app_id,
            'open_id': 'ou_lifetime_employee', 'email_normalized': cls.employee.email,
            'odoo_user_id': cls.employee.id,
        })
        cls.binding.action_enable()

    def _info(self):
        return {'name': 'Expiry Employee', 'open_id': 'ou_lifetime_employee',
                'email': self.employee.email}

    def _provider_data(self, bundle):
        return {'provider': 'feishu', 'app_id': self.config.app_id,
                'binding_id': self.binding.id, 'binding_version': self.binding.auth_version,
                'credentials': encrypt(json.dumps(bundle))}

    def _authorization(self, bundle):
        registered = self.service._register_client({
            'client_name': 'Expiry Acceptance', 'redirect_uris': ['https://client.example/callback'],
            'grant_types': ['authorization_code', 'refresh_token'], 'token_endpoint_auth_method': 'none',
        })
        verifier = 'l' * 64
        flow, _flow_id, _csrf, _cookie = self.service._start_flow({
            'client_id': registered['client_id'], 'redirect_uri': registered['redirect_uris'][0],
            'response_type': 'code', 'code_challenge': challenge(verifier),
            'code_challenge_method': 'S256', 'scope': 'mcp:read', 'resource': self.service._resource(),
        })
        callback = self.service._complete_flow(flow, self.employee, self._provider_data(bundle))
        raw_code = parse_qs(urlsplit(callback).query)['code'][0]
        grant = self.env['mcp.oauth.code'].search([('code_hash', '=', digest(raw_code))]).grant_id
        pair = self.service._exchange({
            'grant_type': 'authorization_code', 'client_id': registered['client_id'],
            'redirect_uri': registered['redirect_uris'][0], 'code': raw_code,
            'code_verifier': verifier, 'resource': self.service._resource(),
        })
        return pair, grant

    def _bundle(self, access_seconds=7200, refresh_seconds=20 * 86400):
        now = int(time.time())
        bundle = {'access_token': 'test-upstream-access', 'expires_at': now + access_seconds}
        if refresh_seconds is not None:
            bundle.update(refresh_token='test-upstream-refresh', refresh_expires_at=now + refresh_seconds)
        return bundle

    def _token(self, raw):
        return self.env['mcp.oauth.token'].search([('token_hash', '=', digest(raw))])

    def _refresh(self, pair, grant):
        return self.service._exchange({'grant_type': 'refresh_token', 'client_id': grant.client_id.client_id,
                                       'refresh_token': pair['refresh_token'], 'resource': grant.resource})

    def _expire_provider_access(self, grant):
        bundle = json.loads(decrypt(grant.provider_data['credentials']))
        bundle['expires_at'] = int(time.time()) - 60
        grant.provider_data = self._provider_data(bundle)
        return bundle

    def test_manual_lifetime_fields_and_view_controls_are_removed(self):
        views = self.env['ir.ui.view'].search([('model', '=', 'mcp.feishu.config')])
        self.assertTrue(views)
        for name in ('access_token_minutes', 'grant_days'):
            self.assertNotIn(name, self.config._fields)
            for view in views:
                self.assertNotIn(name, view.arch_db)
        self.assertFalse(hasattr(self.config, '_check_oauth_lifetimes'))

    def test_old_parameters_are_ignored_and_tokens_follow_actual_provider_deadlines(self):
        parameters = self.env['ir.config_parameter']
        parameters.set_str('mcp_oauth.access_token_minutes', 'not-a-number')
        parameters.set_str('mcp_oauth.grant_days', '1')
        bundle = self._bundle()
        pair, grant = self._authorization(bundle)
        self.assertEqual(self._token(pair['access_token']).expires_at, utc_datetime(bundle['expires_at']))
        self.assertEqual(grant.expires_at, utc_datetime(bundle['refresh_expires_at']))
        self.assertEqual(self._token(pair['refresh_token']).expires_at, grant.expires_at)
        self.assertGreater(pair['expires_in'], 7100)
        self.assertGreater(grant.expires_at, fields.Datetime.now() + timedelta(days=19))

    def test_legacy_tenant_values_do_not_affect_grants_but_app_id_still_does(self):
        pair, grant = self._authorization(self._bundle())
        self.assertNotIn('tenant_key', grant.provider_data)
        grant.provider_data = {**grant.provider_data, 'tenant_key': 'legacy_grant_tenant'}
        self.binding.tenant_key = 'different_legacy_binding_tenant'
        self.config.with_context(mcp_confirm_tenant=True).write({
            'allowed_tenant_key': 'another_legacy_tenant', 'pending_tenant_key': 'unrelated_legacy_tenant'})
        self.assertEqual(self.service._authenticate_token(pair['access_token']), grant)
        response = {'access_token': 'legacy-compatible-test-access', 'expires_in': 3600,
                    'refresh_token': 'legacy-compatible-test-refresh', 'refresh_token_expires_in': 86400}
        with patch.object(type(self.config), '_request_token', return_value=response), patch.object(
                type(self.config), '_user_info', return_value=self._info()):
            replacement = self._refresh(pair, grant)
        self.assertEqual(self.service._authenticate_token(replacement['access_token']), grant)
        grant.provider_data = {**grant.provider_data, 'app_id': 'cli_wrong_application'}
        self.assertFalse(self.service._authenticate_token(replacement['access_token']))
        grant.provider_data = {**grant.provider_data, 'app_id': self.config.app_id, 'tenant_key': 'changed_again'}
        self.binding.active = False
        self.assertFalse(self.service._authenticate_token(replacement['access_token']))

    def test_conflicting_email_refresh_revokes_grant_without_switching_users(self):
        pair, grant = self._authorization(self._bundle())
        other = new_test_user(self.env, login='lifetime_other_employee', email='other-lifetime@example.invalid')
        other.mcp_oauth_enabled = True
        info = {**self._info(), 'email': other.email}
        response = {'access_token': 'conflicting-email-test-access', 'expires_in': 3600,
                    'refresh_token': 'conflicting-email-test-refresh', 'refresh_token_expires_in': 86400}
        with patch.object(type(self.config), '_request_token', return_value=response), patch.object(
                type(self.config), '_user_info', return_value=info):
            try:
                self._refresh(pair, grant)
            except OAuthError as exc:
                self.assertEqual(exc.error, 'access_denied')
            else:
                self.fail('A refresh switched the stable identity to another account')
        self.assertEqual(self.binding.odoo_user_id, self.employee)
        self.assertEqual(self.binding.pending_email, other.email)
        self.assertTrue(grant.revoked_at)
        self.assertFalse(self.service._authenticate_token(pair['access_token']))
        other.email = 'no-longer-conflicting@example.invalid'
        self.employee.email = info['email']
        user, binding = self.env['mcp.feishu.binding']._resolve_identity(info, self.config.app_id)
        self.assertEqual(user, self.employee)
        self.assertEqual(binding, self.binding)
        self.assertFalse(binding.pending_email)
        self.assertFalse(self.service._authenticate_token(pair['access_token']))

    def test_matching_email_becoming_ambiguous_revokes_access_and_recovers_same_user(self):
        pair, grant = self._authorization(self._bundle())
        duplicate = new_test_user(self.env, login='duplicate_after_binding', email=self.employee.email)
        try:
            self.env['mcp.feishu.binding']._resolve_identity(self._info(), self.config.app_id)
        except OAuthError as exc:
            self.assertEqual(exc.error, 'access_denied')
        else:
            self.fail('A newly ambiguous email remained usable')
        self.assertEqual(self.binding.state, 'pending')
        self.assertEqual(self.binding.odoo_user_id, self.employee)
        self.assertFalse(self.service._authenticate_token(pair['access_token']))
        duplicate.active = False
        user, binding = self.env['mcp.feishu.binding']._resolve_identity(self._info(), self.config.app_id)
        self.assertEqual((user, binding), (self.employee, self.binding))
        self.assertEqual(binding.state, 'confirmed')
        self.assertFalse(self.service._authenticate_token(pair['access_token']))

    def test_binding_version_blocks_old_tokens_even_if_grant_revocation_was_skipped(self):
        pair, grant = self._authorization(self._bundle())
        version = self.binding.auth_version
        with patch.object(type(self.binding), '_revoke_grants'):
            self.binding.action_disable()
            self.binding.action_enable()
        self.assertGreater(self.binding.auth_version, version)
        self.assertFalse(grant.revoked_at)
        self.assertFalse(self.service._authenticate_token(pair['access_token']))
        with self.assertRaises(OAuthError):
            self._refresh(pair, grant)

    def test_revocation_serialization_preserves_disabled_state_and_version(self):
        pair, grant = self._authorization(self._bundle())
        version = self.binding.auth_version
        with patch.object(type(grant), '_revoke', side_effect=SerializationFailure()):
            self.binding.action_disable()
        self.env.cr.execute('SELECT state, auth_version FROM mcp_feishu_binding WHERE id=%s', [self.binding.id])
        state, current_version = self.env.cr.fetchone()
        self.assertEqual(state, 'blocked')
        self.assertGreater(current_version, version)
        self.assertFalse(grant.revoked_at)
        self.binding.action_enable()
        self.assertFalse(self.service._authenticate_token(pair['access_token']))
        with self.assertRaises(OAuthError):
            self._refresh(pair, grant)

    def test_access_only_authorization_has_no_refresh_token_or_unbounded_grant(self):
        bundle = self._bundle(access_seconds=1200, refresh_seconds=None)
        pair, grant = self._authorization(bundle)
        self.assertNotIn('refresh_token', pair)
        self.assertEqual(grant.expires_at, utc_datetime(bundle['expires_at']))
        self.assertEqual(self._token(pair['access_token']).expires_at, grant.expires_at)

    def test_shorter_refresh_deadline_does_not_truncate_valid_provider_access(self):
        bundle = self._bundle(access_seconds=3600, refresh_seconds=600)
        pair, grant = self._authorization(bundle)
        self.assertEqual(grant.expires_at, utc_datetime(bundle['expires_at']))
        self.assertEqual(self._token(pair['access_token']).expires_at, grant.expires_at)
        self.assertEqual(self._token(pair['refresh_token']).expires_at,
                         utc_datetime(bundle['refresh_expires_at']))

    def test_refresh_without_known_positive_deadline_cannot_create_mcp_refresh_token(self):
        bundle = credential_bundle({'access_token': 'test-access-with-finite-lifetime', 'expires_in': 1200,
                                    'refresh_token': 'test-refresh-without-deadline'})
        pair, grant = self._authorization(bundle)
        self.assertNotIn('refresh_token', pair)
        self.assertEqual(grant.expires_at, utc_datetime(bundle['expires_at']))

    def test_missing_or_invalid_provider_access_lifetime_is_rejected(self):
        for ttl in (None, 0, -1, True, 'NaN', float('inf'), 1.5):
            response = {'access_token': 'test-upstream-access'}
            if ttl is not None:
                response['expires_in'] = ttl
            with self.subTest(ttl=ttl), self.assertRaises(OAuthError):
                credential_bundle(response)

    def test_refresh_rotation_follows_new_upstream_expiry_in_both_directions(self):
        for initial_days, rotated_days in ((1, 30), (30, 5)):
            with self.subTest(initial_days=initial_days, rotated_days=rotated_days):
                pair, grant = self._authorization(self._bundle(refresh_seconds=initial_days * 86400))
                old_expiry = grant.expires_at
                self._expire_provider_access(grant)
                response = {'access_token': 'rotated-test-access', 'expires_in': 3600,
                            'refresh_token': 'rotated-test-refresh',
                            'refresh_token_expires_in': rotated_days * 86400}
                with patch.object(type(self.config), '_request_token', return_value=response) as refresh, patch.object(
                        type(self.config), '_user_info', return_value=self._info()):
                    replacement = self._refresh(pair, grant)
                refresh.assert_called_once()
                stored = json.loads(decrypt(grant.provider_data['credentials']))
                self.assertEqual(grant.expires_at, utc_datetime(stored['refresh_expires_at']))
                self.assertEqual(self._token(replacement['refresh_token']).expires_at, grant.expires_at)
                self.assertEqual(self._token(replacement['access_token']).expires_at,
                                 utc_datetime(stored['expires_at']))
                if rotated_days > initial_days:
                    self.assertGreater(grant.expires_at, old_expiry)
                else:
                    self.assertLess(grant.expires_at, old_expiry)

    def test_early_mcp_refresh_rotates_upstream_before_access_expiry(self):
        pair, grant = self._authorization(self._bundle(access_seconds=300))
        old_access_expiry = self._token(pair['access_token']).expires_at
        response = {'access_token': 'early-rotation-test-access', 'expires_in': 3600,
                    'refresh_token': 'early-rotation-test-refresh', 'refresh_token_expires_in': 30 * 86400}
        with patch.object(type(self.config), '_request_token', return_value=response) as refresh, patch.object(
                type(self.config), '_user_info', return_value=self._info()):
            replacement = self._refresh(pair, grant)
        refresh.assert_called_once()
        self.assertGreater(replacement['expires_in'], 3500)
        self.assertGreater(self._token(replacement['access_token']).expires_at, old_access_expiry)

    def test_authorization_can_refresh_after_seven_days_while_feishu_refresh_is_valid(self):
        pair, grant = self._authorization(self._bundle(refresh_seconds=20 * 86400))
        future = fields.Datetime.now() + timedelta(days=8)
        response = {'access_token': 'day-eight-test-access', 'expires_in': 7200,
                    'refresh_token': 'day-eight-test-refresh', 'refresh_token_expires_in': 30 * 86400}
        with patch.object(fields.Datetime, 'now', return_value=future), patch(
                'odoo.addons.muk_mcp_feishu.models.provider.time.time', return_value=future.timestamp()), patch.object(
                type(self.config), '_request_token', return_value=response) as refresh, patch.object(
                type(self.config), '_user_info', return_value=self._info()):
            replacement = self._refresh(pair, grant)
            self.assertTrue(self.service._authenticate_token(replacement['access_token']))
        refresh.assert_called_once()
        self.assertGreater(grant.expires_at, future + timedelta(days=29))

    def test_provider_following_deadlines_do_not_override_revocation_or_employee_disable(self):
        pair, grant = self._authorization(self._bundle())
        grant._revoke()
        grant.provider_data = {**grant.provider_data, 'tenant_key': 'changed_after_revocation'}
        self.assertFalse(self.service._authenticate_token(pair['access_token']))
        with self.assertRaises(OAuthError):
            self._refresh(pair, grant)
        pair, grant = self._authorization(self._bundle())
        self.employee.mcp_oauth_enabled = False
        self.employee.mcp_oauth_enabled = True
        self.assertTrue(grant.revoked_at)
        self.assertFalse(self.service._authenticate_token(pair['access_token']))
        with self.assertRaises(OAuthError):
            self._refresh(pair, grant)

    def test_existing_grants_sync_provider_deadlines_without_extending_access_or_spent_refresh(self):
        bundle = self._bundle(access_seconds=600)
        pair, grant = self._authorization(bundle)
        expired_local_cap = fields.Datetime.now() - timedelta(days=1)
        grant.expires_at = expired_local_cap
        self._token(pair['refresh_token']).expires_at = expired_local_cap
        self._token(pair['access_token']).expires_at = fields.Datetime.now() + timedelta(minutes=15)
        spent = self.env['mcp.oauth.token'].create({
            'token_hash': digest('spent-migration-test-refresh'), 'kind': 'refresh',
            'grant_id': grant.id, 'used_at': fields.Datetime.now(), 'expires_at': expired_local_cap,
        })
        outcome = self.service._sync_provider_lifetimes(grant)
        self.assertEqual(outcome, {'updated': 1, 'revoked': 0})
        self.assertEqual(grant.expires_at, utc_datetime(bundle['refresh_expires_at']))
        self.assertEqual(self._token(pair['refresh_token']).expires_at, grant.expires_at)
        self.assertEqual(self._token(pair['access_token']).expires_at, utc_datetime(bundle['expires_at']))
        self.assertEqual(spent.expires_at, expired_local_cap)
        # A short, already-issued MCP AT is never silently extended by migration.
        shortened = fields.Datetime.now() + timedelta(minutes=1)
        self._token(pair['access_token']).expires_at = shortened
        self.service._sync_provider_lifetimes(grant)
        self.assertEqual(self._token(pair['access_token']).expires_at, shortened)

    def test_deadline_sync_preserves_revocation_and_revokes_missing_provider_validity(self):
        pair, grant = self._authorization(self._bundle())
        grant._revoke()
        revoked = grant.revoked_at
        self.assertEqual(self.service._sync_provider_lifetimes(grant), {'updated': 0, 'revoked': 0})
        self.assertEqual(grant.revoked_at, revoked)
        self.assertFalse(self.service._authenticate_token(pair['access_token']))
        with self.assertRaises(OAuthError):
            self._refresh(pair, grant)
        _pair, invalid = self._authorization(self._bundle())
        invalid.provider_data = self._provider_data({'access_token': 'missing-expiry-test-access'})
        self.assertEqual(self.service._sync_provider_lifetimes(invalid), {'updated': 0, 'revoked': 1})
        self.assertTrue(invalid.revoked_at)
