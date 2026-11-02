from __future__ import annotations

import datetime
import hmac
import json

from odoo import api, fields, models
from odoo.exceptions import AccessError, ValidationError

from ..tools.oauth import OAuthError, digest, normalize_scopes, redirect_uri, secret


class OAuthProvider(models.AbstractModel):
    """Identity-provider seam; Feishu implements these hooks in its own addon."""
    _name = 'mcp.oauth.provider'
    _description = 'MCP OAuth Identity Provider'

    @api.model
    def _enabled(self):
        return False

    @api.model
    def _default_scope(self):
        return 'mcp:read'

    @api.model
    def _scopes_supported(self):
        return ['mcp:read', 'mcp:write']

    @api.model
    def _begin_login(self, flow):
        raise OAuthError('temporarily_unavailable', 'No identity provider is configured.', 503)

    @api.model
    def _complete_login(self, flow, params):
        raise OAuthError('temporarily_unavailable', 'No identity provider is configured.', 503)

    @api.model
    def _validate_grant(self, grant):
        return True

    @api.model
    def _refresh_grant(self, grant):
        return None

    @api.model
    def _token_deadlines(self, provider_data):
        """Return authoritative access/refresh deadlines from the identity provider.

        Providers must supply UTC-naive datetimes. A missing refresh deadline
        means this authorization cannot issue renewable MCP credentials.
        """
        raise OAuthError('server_error', 'The identity provider did not supply token validity.', 503)


class OAuthClient(models.Model):
    _name = 'mcp.oauth.client'
    _description = 'MCP OAuth Client'
    _order = 'create_date desc'

    name = fields.Char(required=True)
    client_id = fields.Char(required=True, index=True, copy=False, default=lambda self: secret('mcp_client_'))
    redirect_uris = fields.Json(required=True, default=list)
    grant_types = fields.Json(required=True, default=lambda self: ['authorization_code'])
    auth_method = fields.Selection([
        ('none', 'Public Client'), ('client_secret_basic', 'Client Secret Basic'),
        ('client_secret_post', 'Client Secret Post'),
    ], required=True, default='none')
    secret_hash = fields.Char(copy=False, groups='base.group_system')
    active = fields.Boolean(default=True)
    source = fields.Selection([('registered', 'Registered'), ('cimd', 'Client Metadata URL')], default='registered')
    metadata_checked_at = fields.Datetime()
    grant_ids = fields.One2many('mcp.oauth.grant', 'client_id')
    _client_unique = models.Constraint('UNIQUE(client_id)', 'Client identifiers must be unique.')

    @api.constrains('redirect_uris', 'grant_types')
    def _validate_metadata(self):
        for client in self:
            if not isinstance(client.redirect_uris, list) or not client.redirect_uris:
                raise ValidationError(self.env._('At least one redirect URI is required.'))
            try:
                for uri in client.redirect_uris:
                    redirect_uri(uri)
            except OAuthError as exc:
                raise ValidationError(exc.description) from None
            if (not isinstance(client.grant_types, list)
                    or 'authorization_code' not in client.grant_types
                    or set(client.grant_types) - {'authorization_code', 'refresh_token'}):
                raise ValidationError(self.env._('Unsupported OAuth grant types.'))

    def _authenticate(self, provided_secret):
        self.ensure_one()
        return bool(self.secret_hash and provided_secret and hmac.compare_digest(self.secret_hash, digest(provided_secret)))

    def action_rotate_secret(self):
        self.ensure_one()
        if not self.env.user.has_group('base.group_system'):
            raise AccessError(self.env._('Only a system administrator may generate client credentials.'))
        raw = secret()
        self.write({'secret_hash': digest(raw), 'auth_method': 'client_secret_basic'
                    if self.auth_method == 'none' else self.auth_method})
        self.grant_ids.sudo()._revoke()
        # An unsaved dialog gets the plaintext through default_get; no plaintext is stored.
        return {'type': 'ir.actions.act_window', 'name': self.env._('OAuth Client Secret'),
                'res_model': 'mcp.oauth.client.secret.show', 'views': [(False, 'form')],
                'target': 'new', 'context': {'default_secret': raw}}


class OAuthClientSecretShow(models.TransientModel):
    _name = 'mcp.oauth.client.secret.show'
    _description = 'MCP OAuth Client Secret Display'

    secret = fields.Char(string='Client Secret', readonly=True, store=False)


class OAuthFlow(models.Model):
    _name = 'mcp.oauth.flow'
    _description = 'MCP OAuth Login Flow'
    _order = 'create_date desc'

    client_id = fields.Many2one('mcp.oauth.client', required=True, ondelete='cascade')
    redirect_uri = fields.Char(required=True)
    resource = fields.Char(required=True)
    scope = fields.Char(required=True)
    client_state = fields.Text()
    code_challenge = fields.Char(required=True)
    browser_hash = fields.Char(required=True)
    csrf_hash = fields.Char(required=True)
    flow_hash = fields.Char(required=True, index=True)
    expires_at = fields.Datetime(required=True, index=True)
    state = fields.Selection([
        ('pending', 'Pending Consent'), ('redirected', 'Identity Login'),
        ('completed', 'Completed'), ('failed', 'Failed'),
    ], default='pending', required=True)
    provider_state_hash = fields.Char(index=True)
    provider_verifier = fields.Text()
    provider_data = fields.Json(default=dict)
    _flow_unique = models.Constraint('UNIQUE(flow_hash)', 'Flow identifiers must be unique.')
    _provider_state_unique = models.Constraint('UNIQUE(provider_state_hash)', 'Provider states must be unique.')

    def _lock(self):
        self.ensure_one()
        self.env.cr.execute('SELECT id FROM mcp_oauth_flow WHERE id = %s FOR UPDATE', [self.id])
        self.invalidate_recordset()


class OAuthGrant(models.Model):
    _name = 'mcp.oauth.grant'
    _description = 'MCP OAuth Authorization'
    _order = 'create_date desc'

    name = fields.Char(compute='_compute_name', store=True)
    client_id = fields.Many2one('mcp.oauth.client', required=True, ondelete='cascade')
    user_id = fields.Many2one('res.users', required=True, ondelete='cascade', index=True)
    scope = fields.Selection([('read', 'Read Only'), ('write', 'Read & Write')], required=True)
    resource = fields.Char(required=True)
    expires_at = fields.Datetime(required=True, index=True)
    revoked_at = fields.Datetime(index=True)
    last_used = fields.Datetime()
    provider_data = fields.Json(default=dict, groups='base.group_system')
    key_prefix = fields.Char(compute='_compute_prefix')
    scope_string = fields.Char(compute='_compute_scope_string')

    @api.depends('client_id.name', 'user_id.name')
    def _compute_name(self):
        for grant in self:
            grant.name = '%s / %s' % (grant.user_id.name, grant.client_id.name)

    def _compute_prefix(self):
        for grant in self:
            grant.key_prefix = 'oauth:%s' % grant.id

    @api.depends('scope')
    def _compute_scope_string(self):
        for grant in self:
            grant.scope_string = 'mcp:read mcp:write' if grant.scope == 'write' else 'mcp:read'

    def _mcp_is_active(self):
        self.ensure_one()
        grant = self.sudo()
        if not (grant.exists() and not grant.revoked_at and grant.expires_at > fields.Datetime.now()
                and grant.client_id.active and grant.user_id._mcp_oauth_eligible()
                and self.env['mcp.oauth.provider']._enabled()):
            return False
        if grant.resource != self.env['mcp.oauth.service']._resource():
            return False
        if grant.scope == 'write' and grant.user_id.mcp_oauth_scope != 'write':
            return False
        return bool(self.env['mcp.oauth.provider']._validate_grant(grant))

    def _mcp_transfer_values(self):
        self.ensure_one()
        return {'oauth_grant_id': self.id}

    def _lock(self):
        """Serialize grant mutations before consuming external one-use credentials.

        Odoo uses repeatable-read transactions. A concurrent last-used update
        must cause any serialization retry here, before the provider refresh
        call, rather than after its refresh token has been consumed.
        """
        self.ensure_one()
        self.env.cr.execute('SELECT id FROM mcp_oauth_grant WHERE id = %s FOR UPDATE', [self.id])
        self.invalidate_recordset()

    def _mcp_log_values(self):
        self.ensure_one()
        return {'auth_type': 'oauth', 'oauth_client_id': self.client_id.id, 'oauth_grant_id': self.id}

    def _check_rate_limit(self):
        self.ensure_one()
        limit = max(0, self.sudo().user_id.mcp_oauth_rate_limit)
        if not limit:
            return True
        # One transaction-safe bucket per user/client, shared by every worker and grant.
        self.env.cr.execute('''
            INSERT INTO mcp_oauth_rate (user_id, client_id, window_started, request_count)
            VALUES (%s, %s, date_trunc('minute', NOW() AT TIME ZONE 'UTC'), 1)
            ON CONFLICT (user_id, client_id) DO UPDATE SET
                window_started = EXCLUDED.window_started,
                request_count = CASE WHEN mcp_oauth_rate.window_started = EXCLUDED.window_started
                                    THEN mcp_oauth_rate.request_count + 1 ELSE 1 END
            RETURNING request_count
        ''', [self.user_id.id, self.client_id.id])
        return self.env.cr.fetchone()[0] <= limit

    def action_revoke(self):
        for grant in self:
            if not (self.env.su or self.env.user.has_group('base.group_system') or grant.user_id == self.env.user):
                raise AccessError(self.env._('You may only revoke your own authorization.'))
        self.sudo()._revoke()
        return True

    def _revoke(self):
        self.write({'revoked_at': fields.Datetime.now()})
        return True


class OAuthRate(models.Model):
    _name = 'mcp.oauth.rate'
    _description = 'MCP OAuth Shared Rate Bucket'
    _log_access = False

    user_id = fields.Many2one('res.users', required=True, ondelete='cascade')
    client_id = fields.Many2one('mcp.oauth.client', required=True, ondelete='cascade')
    window_started = fields.Datetime(required=True)
    request_count = fields.Integer(required=True)
    _bucket_unique = models.Constraint('UNIQUE(user_id, client_id)', 'One rate bucket per user and client.')


class OAuthEndpointRate(models.Model):
    _name = 'mcp.oauth.endpoint.rate'
    _description = 'MCP OAuth Public Endpoint Rate Bucket'
    _log_access = False

    bucket_hash = fields.Char(required=True)
    window_started = fields.Datetime(required=True)
    request_count = fields.Integer(required=True)
    _endpoint_bucket_unique = models.Constraint('UNIQUE(bucket_hash)', 'One endpoint rate bucket per caller.')

    @api.model
    def _consume(self, endpoint, caller, limit=120):
        self.env.cr.execute('''
            INSERT INTO mcp_oauth_endpoint_rate (bucket_hash, window_started, request_count)
            VALUES (%s, date_trunc('minute', NOW() AT TIME ZONE 'UTC'), 1)
            ON CONFLICT (bucket_hash) DO UPDATE SET
                window_started = EXCLUDED.window_started,
                request_count = CASE WHEN mcp_oauth_endpoint_rate.window_started = EXCLUDED.window_started
                                    THEN mcp_oauth_endpoint_rate.request_count + 1 ELSE 1 END
            RETURNING request_count
        ''', [digest(endpoint + ':' + caller)])
        return self.env.cr.fetchone()[0] <= limit


class OAuthCode(models.Model):
    _name = 'mcp.oauth.code'
    _description = 'MCP OAuth Authorization Code'

    code_hash = fields.Char(required=True, index=True, copy=False)
    grant_id = fields.Many2one('mcp.oauth.grant', required=True, ondelete='cascade')
    redirect_uri = fields.Char(required=True)
    code_challenge = fields.Char(required=True)
    expires_at = fields.Datetime(required=True, index=True)
    used_at = fields.Datetime()
    _code_unique = models.Constraint('UNIQUE(code_hash)', 'Authorization codes must be unique.')

    def _lock(self):
        self.ensure_one()
        self.env.cr.execute('SELECT id FROM mcp_oauth_code WHERE id = %s FOR UPDATE', [self.id])
        self.invalidate_recordset()


class OAuthToken(models.Model):
    _name = 'mcp.oauth.token'
    _description = 'MCP OAuth Hashed Token'

    token_hash = fields.Char(required=True, index=True, copy=False)
    kind = fields.Selection([('access', 'Access Token'), ('refresh', 'Refresh Token')], required=True)
    grant_id = fields.Many2one('mcp.oauth.grant', required=True, ondelete='cascade', index=True)
    expires_at = fields.Datetime(required=True, index=True)
    used_at = fields.Datetime()
    revoked_at = fields.Datetime()
    _token_unique = models.Constraint('UNIQUE(token_hash)', 'OAuth tokens must be unique.')

    def _lock(self):
        self.ensure_one()
        self.env.cr.execute('SELECT id FROM mcp_oauth_token WHERE id = %s FOR UPDATE', [self.id])
        self.invalidate_recordset()

    @api.autovacuum
    def _gc_oauth(self):
        # Keep spent refresh tokens until the full grant expires, so reuse remains detectable.
        cutoff = fields.Datetime.now() - datetime.timedelta(days=1)
        self.sudo().search([('grant_id.expires_at', '<', cutoff)]).unlink()
        self.env['mcp.oauth.code'].sudo().search([('expires_at', '<', cutoff)]).unlink()
        self.env['mcp.oauth.flow'].sudo().search([('expires_at', '<', cutoff)]).unlink()
        self.env['mcp.oauth.endpoint.rate'].sudo().search([('window_started', '<', cutoff)]).unlink()
