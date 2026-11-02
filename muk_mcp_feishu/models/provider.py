from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
import time
from datetime import datetime, timezone

from odoo import models

from odoo.addons.muk_mcp_oauth21.tools.crypto import decrypt, encrypt
from odoo.addons.muk_mcp_oauth21.tools.oauth import digest, OAuthError


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()


def _positive_seconds(value):
    """Accept only finite, positive whole seconds, never booleans or infinity."""
    if isinstance(value, bool):
        return None
    try:
        numeric = float(value)
        if not math.isfinite(numeric) or numeric <= 0 or not numeric.is_integer():
            return None
        seconds = int(value)
        # This bound is the datetime representation limit, not an auth policy.
        datetime.fromtimestamp(seconds, timezone.utc)
        return seconds
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _utc_deadline(value):
    epoch = _positive_seconds(value)
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError, OSError):
        return None


def credential_bundle(response, previous=None):
    """Use each provider response's actual lifetimes, including RT rotation.

    A rotated refresh token is a new one-use credential. Its returned validity
    replaces the old token's deadline; absent/invalid validity is never treated
    as infinite, and an old refresh token is never silently reused.
    """
    if not isinstance(response, dict):
        raise OAuthError('temporarily_unavailable', 'Feishu returned invalid token data.', 502)
    access = response.get('access_token')
    expires = _positive_seconds(response.get('expires_in'))
    now = int(time.time())
    if (not isinstance(access, str) or not access or not expires
            or _utc_deadline(now + expires) is None):
        raise OAuthError('temporarily_unavailable', 'Feishu did not return a valid access token and lifetime.', 502)
    value = {'access_token': access, 'expires_at': now + expires}
    refresh = response.get('refresh_token')
    if isinstance(refresh, str) and refresh:
        value['refresh_token'] = refresh
        lifetime = response.get('refresh_token_expires_in', response.get('refresh_expires_in'))
        seconds = _positive_seconds(lifetime)
        if seconds and _utc_deadline(now + seconds) is not None:
            value['refresh_expires_at'] = now + seconds
    return value


class FeishuOAuthProvider(models.AbstractModel):
    _inherit = 'mcp.oauth.provider'

    def _enabled(self):
        config = self.env['mcp.feishu.config']._get_config()
        return bool(config.enabled and config.app_id and config.secret_ciphertext)

    def _default_scope(self):
        config = self.env['mcp.feishu.config']._get_config()
        return 'mcp:read mcp:write' if config.default_scope == 'write' and config.allow_write_scope else 'mcp:read'

    def _scopes_supported(self):
        config = self.env['mcp.feishu.config']._get_config()
        return ['mcp:read', 'mcp:write'] if config.allow_write_scope else ['mcp:read']

    def _credential_data(self, provider_data):
        data = provider_data or {}
        if not isinstance(data, dict) or data.get('provider') != 'feishu':
            raise OAuthError('invalid_grant', 'The Feishu authorization is unavailable. Sign in again.')
        try:
            bundle = json.loads(decrypt(data.get('credentials') or ''))
        except (ValueError, TypeError):
            raise OAuthError('invalid_grant', 'The Feishu authorization is unavailable. Sign in again.') from None
        if not isinstance(bundle, dict) or not isinstance(bundle.get('access_token'), str) or not bundle['access_token']:
            raise OAuthError('invalid_grant', 'The Feishu authorization is unavailable. Sign in again.')
        return bundle

    def _token_deadlines(self, provider_data):
        bundle = self._credential_data(provider_data)
        access = _utc_deadline(bundle.get('expires_at'))
        if access is None:
            raise OAuthError('invalid_grant', 'The Feishu access-token validity is unavailable. Sign in again.')
        refresh = None
        if isinstance(bundle.get('refresh_token'), str) and bundle['refresh_token']:
            epoch = _positive_seconds(bundle.get('refresh_expires_at'))
            candidate = _utc_deadline(epoch)
            if candidate and epoch > time.time():
                refresh = candidate
        return {'access_expires_at': access, 'refresh_expires_at': refresh}

    def _begin_login(self, flow):
        config = self.env['mcp.feishu.config']._get_config()
        if not self._enabled():
            raise OAuthError('access_denied', 'Feishu OAuth has not been configured and enabled.', 403)
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        flow.write({'provider_state_hash': digest(state), 'provider_verifier': encrypt(verifier),
                    'provider_data': {'app_id': config.app_id, 'config_fingerprint': config._fingerprint(),
                                      'code_challenge': challenge(verifier)}})
        return config._authorize_url(state, challenge(verifier))

    def _complete_login(self, flow, params):
        config = self.env['mcp.feishu.config']._get_config()
        initial = flow.provider_data or {}
        if (not self._enabled() or initial.get('app_id') != config.app_id
                or initial.get('config_fingerprint') != config._fingerprint()):
            raise OAuthError('access_denied', 'The Feishu application configuration changed. Start authorization again.', 403)
        if not initial.get('code_challenge'):
            raise OAuthError('invalid_request', '请重新连接，此次飞书登录的 PKCE 状态已失效。')
        response = config._exchange_code(params.get('code', ''), decrypt(flow.provider_verifier), initial.get('code_challenge'))
        bundle = credential_bundle(response)
        info = config._user_info(bundle['access_token'])
        user, binding = self.env['mcp.feishu.binding']._resolve_identity(info, config.app_id)
        if 'mcp:write' in flow.scope.split() and not config.allow_write_scope:
            raise OAuthError('invalid_scope', 'The administrator has not enabled write-scope requests.')
        return user, {'provider': 'feishu', 'app_id': config.app_id,
                      'binding_id': binding.id, 'binding_version': binding.auth_version,
                      'credentials': encrypt(json.dumps(bundle))}

    def _validate_grant(self, grant):
        data = grant.provider_data or {}
        if data.get('provider') != 'feishu':
            return False
        config = self.env['mcp.feishu.config']._get_config()
        binding = self.env['mcp.feishu.binding'].sudo().with_context(active_test=False).browse(data.get('binding_id') or 0).exists()
        return bool(self._enabled() and binding and binding.active and binding.state == 'confirmed'
                    and binding.odoo_user_id == grant.user_id and binding.app_id == config.app_id
                    and data.get('app_id') == config.app_id
                    and data.get('binding_version', 0) == binding.auth_version
                    and (grant.scope != 'write' or config.allow_write_scope))

    def _refresh_grant(self, grant):
        if not self._validate_grant(grant):
            raise OAuthError('invalid_grant', 'The employee identity or application authorization is no longer valid.')
        binding = self.env['mcp.feishu.binding'].sudo().browse((grant.provider_data or {})['binding_id'])
        # Lock before rotating a one-use upstream refresh credential. Any
        # repeatable-read retry must happen before that external side effect.
        binding._lock_identity(binding.app_id, binding.open_id)
        binding._lock()
        if not self._validate_grant(grant):
            raise OAuthError('invalid_grant', 'The employee binding is no longer enabled.')
        config = self.env['mcp.feishu.config']._get_config()
        data = dict(grant.provider_data or {})
        bundle = self._credential_data(data)
        deadlines = self._token_deadlines(data)
        access_valid = deadlines['access_expires_at'] > _utc_deadline(int(time.time()))
        pending_validation = bool(data.get('refresh_validation_pending') and access_valid)
        # Explicit MCP refresh must advance the upstream access lifetime even
        # when a client refreshes early. A retry after transient user-info failure
        # reuses the already rotated bundle before consuming another RT.
        if not pending_validation and deadlines['refresh_expires_at']:
            response = config._request_token({'grant_type': 'refresh_token', 'refresh_token': bundle['refresh_token']})
            bundle = credential_bundle(response, bundle)
            # Feishu refresh tokens are one-use. Preserve a successful upstream
            # rotation even when the following user-info call fails transiently;
            # the client can then retry its unconsumed MCP refresh token safely.
            data['credentials'] = encrypt(json.dumps(bundle))
            data['refresh_validation_pending'] = True
            updated = self._token_deadlines(data)
            grant.write({'provider_data': data,
                         'expires_at': self.env['mcp.oauth.service']._grant_deadline(updated)})
        elif not access_valid:
            raise OAuthError('invalid_grant', 'The Feishu authorization expired. Sign in again.')
        info = config._user_info(bundle['access_token'])
        user, binding = self.env['mcp.feishu.binding']._resolve_identity(info, config.app_id)
        if user != grant.user_id or binding.id != data.get('binding_id'):
            raise OAuthError('invalid_grant', 'The Feishu employee identity changed. Sign in again.')
        data['credentials'] = encrypt(json.dumps(bundle))
        data.pop('refresh_validation_pending', None)
        updated = self._token_deadlines(data)
        grant.write({'provider_data': data,
                     'expires_at': self.env['mcp.oauth.service']._grant_deadline(updated)})
