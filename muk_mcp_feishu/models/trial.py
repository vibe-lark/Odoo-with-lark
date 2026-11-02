from __future__ import annotations

import hmac
import secrets
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import AccessError
from odoo.tools import email_normalize

from odoo.addons.muk_mcp_oauth21.tools.crypto import decrypt, encrypt
from odoo.addons.muk_mcp_oauth21.tools.oauth import digest, OAuthError
from .provider import challenge, credential_bundle

TRIAL_COOKIE = 'mcp_feishu_trial_browser'


class FeishuTrial(models.Model):
    """Administrator-only login validation; never signs an MCP code or grant."""

    _name = 'mcp.feishu.trial'
    _description = 'MCP Feishu Administrator Login Test'

    state_hash = fields.Char(required=True, index=True, copy=False)
    browser_hash = fields.Char(required=True, copy=False)
    verifier = fields.Text(required=True, copy=False)
    code_challenge = fields.Char(readonly=True, copy=False)
    admin_id = fields.Many2one('res.users', required=True, ondelete='cascade')
    config_fingerprint = fields.Char(required=True, copy=False)
    expires_at = fields.Datetime(required=True, index=True)
    consumed = fields.Boolean(default=False)

    @api.model
    def _start(self):
        if not self.env.user.has_group('base.group_system') or not self.env.user.active:
            raise AccessError(self.env._('An active system administrator must start this test.'))
        config = self.env['mcp.feishu.config']._get_config()
        if config.credentials_fingerprint != config._fingerprint():
            raise OAuthError('access_denied', 'Check the application credentials before testing login.', 403)
        state = 'trial_' + secrets.token_urlsafe(32)
        cookie = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        self.sudo().create({
            'state_hash': digest(state), 'browser_hash': digest(cookie),
            'verifier': encrypt(verifier), 'code_challenge': challenge(verifier), 'admin_id': self.env.uid,
            'config_fingerprint': config._fingerprint(),
            'expires_at': fields.Datetime.now() + timedelta(minutes=10),
        })
        return config._authorize_url(state, challenge(verifier)), cookie

    @api.model
    def _complete(self, params, browser_cookie, session_uid):
        state = params.get('state', '')
        trial = self.sudo().search([('state_hash', '=', digest(state))], limit=1)
        if not trial:
            raise OAuthError('invalid_request', 'Unknown administrator login test.')
        self.env.cr.execute('SELECT id FROM mcp_feishu_trial WHERE id = %s FOR UPDATE', (trial.id,))
        trial.invalidate_recordset()
        if (trial.consumed or trial.expires_at <= fields.Datetime.now()
                or session_uid != trial.admin_id.id or not browser_cookie
                or not hmac.compare_digest(trial.browser_hash, digest(browser_cookie))
                or not trial.admin_id.active or not trial.admin_id.has_group('base.group_system')):
            raise OAuthError('access_denied', 'Restart the administrator login test in the same signed-in browser.', 403)
        trial.write({'consumed': True})
        config = self.env['mcp.feishu.config']._get_config()
        self.env.cr.execute('SELECT id FROM mcp_feishu_config WHERE id = %s FOR UPDATE', (config.id,))
        config.invalidate_recordset()
        if trial.config_fingerprint != config._fingerprint():
            raise OAuthError('invalid_request', 'The application configuration changed. Start the login test again.')
        if params.get('error'):
            raise OAuthError('access_denied', 'The Feishu login was cancelled.', 403)
        if not params.get('code'):
            raise OAuthError('invalid_request', 'Feishu did not return an authorization code.')
        if not trial.code_challenge:
            raise OAuthError('invalid_request', '请重新发起飞书登录验证，此次验证的 PKCE 状态已失效。')
        response = config._exchange_code(params['code'], decrypt(trial.verifier), trial.code_challenge)
        info = config._user_info(credential_bundle(response)['access_token'])
        raw_email = info.get('email')
        if not isinstance(raw_email, str) or not email_normalize(raw_email):
            raise OAuthError('access_denied', '飞书已完成登录，但没有返回有效的联系邮箱（email）。请核对本次用户授权是否包含 contact:user.email:readonly，以及当前登录账号的联系方式是否填写邮箱。', 403)
        config.with_user(trial.admin_id).sudo().write({
            'pending_trial_user_id': trial.admin_id.id,
            'pending_trial_at': fields.Datetime.now(), 'login_fingerprint': config._fingerprint(),
        })
        return '/odoo/mcp-feishu-settings'

    @api.autovacuum
    def _cleanup_trials(self):
        self.sudo().search([('expires_at', '<', fields.Datetime.now() - timedelta(days=1))]).unlink()
