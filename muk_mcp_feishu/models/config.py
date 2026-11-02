from __future__ import annotations

import hashlib
import hmac
import json
import logging
from urllib.parse import quote, urlencode, urlsplit

import requests

from odoo import api, fields, models
from odoo.exceptions import AccessError, UserError, ValidationError
from odoo.tools import email_normalize

from odoo.addons.muk_mcp_oauth21.tools.crypto import decrypt, encrypt
from odoo.addons.muk_mcp_oauth21.tools.oauth import OAuthError
from odoo.addons.muk_mcp_oauth21.tools.oauth import VERIFIER, challenge
from ..tools.errors import rejected_request

AUTHORIZE_URL = 'https://accounts.feishu.cn/open-apis/authen/v1/authorize'
USER_TOKEN_URL = 'https://open.feishu.cn/open-apis/authen/v2/oauth/token'
APP_TOKEN_URL = 'https://accounts.feishu.cn/oauth/v3/token'
TOKEN_URL = USER_TOKEN_URL
USERINFO_URL = 'https://open.feishu.cn/open-apis/authen/v1/user_info'
CALLBACK_PATH = '/mcp/oauth/feishu/callback'
FEISHU_SCOPES = 'offline_access contact:user.email:readonly'
_logger = logging.getLogger(__name__)


class FeishuConfig(models.Model):
    """One database-wide application, editable only by system administrators.

    Application credentials are not employee credentials. The secret input is
    write-only, and encryption uses the OAuth module's external master key.
    """

    _name = 'mcp.feishu.config'
    _description = 'MCP Feishu Application'
    _rec_name = 'name'

    name = fields.Char(default='飞书与 OAuth', required=True)
    app_id = fields.Char(string='App ID', copy=False)
    app_secret = fields.Char(
        string='更新 App Secret', compute='_compute_secret_input',
        inverse='_inverse_secret_input', groups='base.group_system',
    )
    secret_ciphertext = fields.Text(copy=False, groups='base.group_system')
    secret_is_set = fields.Boolean(string='App Secret 已设置', compute='_compute_secret_input')
    enabled = fields.Boolean(string='启用飞书 OAuth', default=False)
    can_enable_oauth = fields.Boolean(compute='_compute_can_enable_oauth')
    # Kept only to preserve upgrade history. Neither field controls access.
    allowed_tenant_key = fields.Char(string='旧版企业标识（不再使用）', readonly=True, copy=False)
    pending_tenant_key = fields.Char(string='旧版试用企业标识（不再使用）', readonly=True, copy=False)
    pending_trial_user_id = fields.Many2one(
        'res.users', string='试用登录管理员', readonly=True, ondelete='set null',
    )
    pending_trial_at = fields.Datetime(string='最近试用登录', readonly=True)
    credentials_checked_at = fields.Datetime(string='凭证检查时间', readonly=True)
    credentials_fingerprint = fields.Char(readonly=True, copy=False)
    login_fingerprint = fields.Char(readonly=True, copy=False)
    public_base_url = fields.Char(string='HTTPS 服务地址', compute='_compute_urls', inverse='_inverse_base_url')
    callback_url = fields.Char(string='飞书登录回调地址', compute='_compute_urls')
    mcp_url = fields.Char(string='MCP 连接地址', compute='_compute_urls')
    state = fields.Selection([
        ('unconfigured', '未配置'), ('unchecked', '待检查'),
        ('checked', '应用配置检查通过'), ('login_ok', '试用登录通过'),
        ('enabled', '已启用'),
    ], string='配置状态', compute='_compute_state')
    default_scope = fields.Selection(
        [('read', '只读'), ('write', '读取与写入')], default='read', required=True,
        string='默认授权范围',
    )
    allow_write_scope = fields.Boolean(string='允许申请写入授权', default=False)
    allow_api_keys = fields.Boolean(string='兼容已有 API Key', default=True)
    binding_ids = fields.Many2many('mcp.feishu.binding', compute='_compute_management_records', string='员工身份绑定')
    grant_ids = fields.Many2many('mcp.oauth.grant', compute='_compute_management_records', string='已授权的客户端')

    def _compute_management_records(self):
        for record in self:
            record.binding_ids = self.env['mcp.feishu.binding'].search([])
            record.grant_ids = self.env['mcp.oauth.grant'].search([])

    @api.model
    def _get_config(self):
        return self.env.ref('muk_mcp_feishu.config_main').sudo()

    def _require_admin(self):
        if not self.env.user.has_group('base.group_system'):
            raise AccessError(self.env._('Only system administrators can configure Feishu MCP.'))

    @api.depends('secret_ciphertext')
    def _compute_secret_input(self):
        for record in self:
            record.app_secret = False
            record.secret_is_set = bool(record.secret_ciphertext)

    def _inverse_secret_input(self):
        self._require_admin()
        for record in self:
            if record.app_secret:
                record.secret_ciphertext = encrypt(record.app_secret.strip())

    def _secret(self):
        self.ensure_one()
        if not self.secret_ciphertext:
            raise OAuthError('server_error', 'The Feishu application secret is not configured.', 500)
        return decrypt(self.secret_ciphertext)

    def _base_url(self):
        params = self.env['ir.config_parameter'].sudo()
        base = params.get_str('mcp_oauth.public_base_url') or params.get_str('web.base.url')
        parsed = urlsplit(base or '')
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
                or parsed.password or parsed.path not in ('', '/')
                or parsed.query or parsed.fragment):
            raise UserError(self.env._('Set the MCP public base URL to an HTTPS origin.'))
        return base.rstrip('/')

    def _compute_urls(self):
        for record in self:
            try:
                base = record._base_url()
            except UserError:
                base = ''
            record.public_base_url = base
            record.callback_url = base + CALLBACK_PATH if base else ''
            record.mcp_url = base + '/api/mcp' if base else ''

    def _inverse_base_url(self):
        self._require_admin()
        for record in self:
            value = (record.public_base_url or '').strip().rstrip('/')
            parsed = urlsplit(value)
            if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
                    or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
                raise ValidationError(self.env._('The public URL must be an HTTPS origin.'))
            self.env['ir.config_parameter'].sudo().set_str('mcp_oauth.public_base_url', value)
            record.write({'enabled': False, 'credentials_fingerprint': False, 'login_fingerprint': False})

    def _fingerprint(self):
        self.ensure_one()
        return hashlib.sha256('\0'.join((self.app_id or '', self.secret_ciphertext or '', self._base_url())).encode()).hexdigest()

    def _enable_oauth_error(self):
        self.ensure_one()
        if not self.app_id or not self.secret_ciphertext:
            return self.env._('请先填写飞书 App ID 和 App Secret，再检查应用凭证。')
        try:
            fingerprint = self._fingerprint()
        except UserError:
            return self.env._('请先配置有效的 HTTPS 服务地址，再检查应用凭证。')
        if self.credentials_fingerprint != fingerprint:
            return self.env._('请先完成第 1 步「检查应用凭证」，应用配置变更后需要重新检查。')
        if self.login_fingerprint != fingerprint:
            return self.env._('请先完成第 2 步「试用飞书登录」，验证登录和邮箱权限。')
        return False

    @api.depends('app_id', 'secret_ciphertext', 'credentials_fingerprint', 'login_fingerprint')
    def _compute_can_enable_oauth(self):
        for record in self:
            record.can_enable_oauth = not record._enable_oauth_error()

    @api.depends('app_id', 'secret_ciphertext', 'enabled', 'credentials_fingerprint', 'login_fingerprint')
    def _compute_state(self):
        for record in self:
            if record.enabled:
                record.state = 'enabled'
            elif not record.app_id or not record.secret_ciphertext:
                record.state = 'unconfigured'
            elif record.login_fingerprint:
                record.state = 'login_ok'
            elif record.credentials_fingerprint:
                record.state = 'checked'
            else:
                record.state = 'unchecked'

    @api.constrains('app_id', 'default_scope', 'allow_write_scope')
    def _check_config(self):
        for record in self:
            if record.app_id and (not record.app_id.startswith('cli_') or any(ch.isspace() for ch in record.app_id)):
                raise ValidationError(self.env._('Enter the App ID of a Feishu enterprise self-built application.'))
            if record.default_scope == 'write' and not record.allow_write_scope:
                raise ValidationError(self.env._('Enable write-scope requests before granting write access by default.'))

    def write(self, values):
        self._require_admin()
        if {'allowed_tenant_key', 'pending_tenant_key'} & values.keys() and not self.env.context.get('mcp_confirm_tenant'):
            raise AccessError(self.env._('旧版企业字段不再使用，不能手动修改。'))
        if {'app_id', 'secret_ciphertext'} & values.keys():
            values = dict(values, enabled=False, credentials_fingerprint=False, login_fingerprint=False)
            if 'app_id' in values and any(record.app_id != values['app_id'] for record in self):
                values.update(pending_trial_user_id=False, pending_trial_at=False)
        if values.get('enabled'):
            for record in self:
                error = record._enable_oauth_error()
                if error:
                    raise UserError(error)
        result = super().write(values)
        params = self.env['ir.config_parameter'].sudo()
        if 'allow_api_keys' in values:
            params.set_str('mcp_oauth.allow_api_keys', str(values['allow_api_keys']))
        return result

    def unlink(self):
        raise UserError(self.env._('Disable Feishu OAuth instead of deleting its shared configuration.'))

    @api.model_create_multi
    def create(self, values_list):
        self._require_admin()
        if self.search_count([]):
            raise ValidationError(self.env._('Only one Feishu application configuration is supported per database.'))
        if len(values_list) != 1 or any(values.get('enabled') for values in values_list):
            raise ValidationError(self.env._('Create an unconfigured application, then verify the application and login.'))
        return super().create(values_list)

    def _request_json(self, method, url, *, data=None, json_payload=None, token=None):
        """Call fixed official endpoints without following redirects or logging secrets."""
        headers = {'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        try:
            response = requests.request(method, url, data=data, json=json_payload, headers=headers,
                                        timeout=(5, 20), allow_redirects=False)
            if response.status_code >= 500 or response.status_code == 429:
                raise OAuthError('temporarily_unavailable', 'Feishu is temporarily unavailable. Please authorize again later.', 502)
            result = response.json()
        except (requests.RequestException, ValueError):
            raise OAuthError('temporarily_unavailable', 'Cannot obtain a valid response from Feishu.', 502) from None
        if (response.status_code != 200 or not isinstance(result, dict)
                or result.get('code', 0) != 0 or result.get('error')):
            endpoint = '令牌接口' if url in (USER_TOKEN_URL, APP_TOKEN_URL) else '用户身份接口'
            raise rejected_request(endpoint, response.status_code, result)
        payload = result.get('data', result)
        if not isinstance(payload, dict):
            raise OAuthError('temporarily_unavailable', 'Feishu returned an invalid response payload.', 502)
        return payload

    def _request_token(self, values):
        self.ensure_one()
        payload = {
            'client_id': self.app_id, 'client_secret': self._secret(), **values,
        }
        if values.get('grant_type') in ('authorization_code', 'refresh_token'):
            # Feishu v2 user-token requests use JSON; application credential
            # checks use the separate v3 client-credentials endpoint below.
            # Prepare the exact wire representation before sending it, so a
            # missing/misencoded PKCE field cannot silently reach the provider.
            prepared = requests.Request('POST', USER_TOKEN_URL, json=payload).prepare()
            transmitted = json.loads(prepared.body)
            if values.get('grant_type') == 'authorization_code':
                verifier = values.get('code_verifier')
                if (not isinstance(verifier, str) or not VERIFIER.fullmatch(verifier)
                        or transmitted.get('code_verifier') != verifier):
                    raise OAuthError('server_error', '服务端 PKCE 请求参数校验失败，请重新发起飞书登录。', 500)
                _logger.info('Feishu PKCE token request: verifier_present=True verifier_length=%s encoding=json', len(verifier))
            result = self._request_json('POST', USER_TOKEN_URL, json_payload=payload)
            # Record only the status of the two requested permissions, never
            # tokens, unknown scope strings or provider response bodies.
            scope = result.get('scope')
            granted = set(scope.split()) if isinstance(scope, str) else None
            _logger.info(
                'Feishu user-token permissions: grant_type=%s scope_returned=%s '
                'email_scope_granted=%s offline_access_granted=%s',
                values['grant_type'], granted is not None,
                'contact:user.email:readonly' in granted if granted is not None else None,
                'offline_access' in granted if granted is not None else None,
            )
            return result
        return self._request_json('POST', APP_TOKEN_URL, data=payload)

    def _exchange_code(self, code, verifier, expected_challenge=None):
        if (not isinstance(verifier, str) or not VERIFIER.fullmatch(verifier)
                or (expected_challenge and not hmac.compare_digest(challenge(verifier), expected_challenge))):
            raise OAuthError('server_error', '服务端 PKCE 登录状态校验失败，请重新发起飞书登录。', 500)
        _logger.info('Feishu PKCE callback: verifier_length=%s original_challenge_matches=%s',
                     len(verifier), bool(expected_challenge))
        return self._request_token({'grant_type': 'authorization_code', 'code': code,
                                    'redirect_uri': self._base_url() + CALLBACK_PATH,
                                    'code_verifier': verifier})

    def _user_info(self, access_token):
        info = self._request_json('GET', USERINFO_URL, token=access_token)
        if (not isinstance(info, dict)
                or not isinstance(info.get('open_id'), str) or not info['open_id']
                or len(info['open_id']) > 200):
            raise OAuthError('temporarily_unavailable', 'Feishu did not return the required user identity.', 502)
        # Field availability helps distinguish missing user consent from an
        # empty directory email, without recording personal information.
        _logger.info(
            'Feishu user-info email fields: email_present=%s email_valid=%s '
            'enterprise_email_present=%s enterprise_email_valid=%s',
            'email' in info,
            bool(email_normalize(info['email'])) if isinstance(info.get('email'), str) else False,
            'enterprise_email' in info,
            bool(email_normalize(info['enterprise_email'])) if isinstance(info.get('enterprise_email'), str) else False,
        )
        return info

    def _authorize_url(self, state, challenge):
        return AUTHORIZE_URL + '?' + urlencode({
            'client_id': self.app_id, 'redirect_uri': self._base_url() + CALLBACK_PATH,
            'response_type': 'code', 'scope': FEISHU_SCOPES, 'state': state,
            'code_challenge': challenge, 'code_challenge_method': 'S256',
        }, quote_via=quote)

    def action_check_credentials(self):
        self._require_admin()
        self.ensure_one()
        try:
            token = self._request_token({'grant_type': 'client_credentials'})
            if not token.get('access_token'):
                raise OAuthError('server_error', 'Feishu did not return an application token.', 502)
        except OAuthError as exc:
            raise UserError(self.env._(
                '飞书应用凭证检查失败，请核对应用凭证、发布状态及网络连接。\n%(detail)s',
                detail=exc.description,
            )) from None
        self.write({'credentials_checked_at': fields.Datetime.now(), 'credentials_fingerprint': self._fingerprint()})
        return self._notification('应用凭证检查通过', '接下来请试用飞书登录，验证登录和用户邮箱权限。')

    def action_trial_login(self):
        self._require_admin()
        self.ensure_one()
        if self.credentials_fingerprint != self._fingerprint():
            raise UserError(self.env._('Check the application credentials before starting a trial login.'))
        return {'type': 'ir.actions.act_url', 'url': self._base_url() + '/mcp/oauth/feishu/trial/start', 'target': 'self'}

    def _notification(self, title, message):
        return {'type': 'ir.actions.client', 'tag': 'display_notification',
                'params': {'title': title, 'message': message, 'type': 'success', 'sticky': False,
                           'next': {'type': 'ir.actions.client', 'tag': 'reload'}}}

    @api.model
    def action_open_settings(self):
        self._require_admin()
        return {'type': 'ir.actions.act_window', 'name': '飞书与 OAuth',
                'res_model': self._name, 'res_id': self._get_config().id,
                'view_mode': 'form', 'target': 'current'}
