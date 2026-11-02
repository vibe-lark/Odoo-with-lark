"""Persistent OAuth service. All public HTTP input crosses this validation layer."""
from __future__ import annotations

import base64
import datetime
import hmac
import ipaddress
import json
import math
import socket
import ssl
from urllib.parse import unquote_plus, urlsplit

import urllib3

from odoo import api, fields, models

from ..tools.oauth import (
    CHALLENGE, OAuthError, add_query, digest, normalize_scopes, redirect_uri, secret, verify_pkce,
)


class OAuthService(models.AbstractModel):
    _name = 'mcp.oauth.service'
    _description = 'MCP OAuth Protocol Service'

    @api.model
    def _parameter(self, name, default=''):
        return self.env['ir.config_parameter'].sudo().get_str('mcp_oauth.' + name, default)

    @api.model
    def _issuer(self):
        base = (self._parameter('public_base_url') or self.env['ir.config_parameter'].sudo().get_str('web.base.url')).rstrip('/')
        parsed = urlsplit(base)
        try:
            port = parsed.port
        except ValueError:
            raise OAuthError('server_error', 'The public HTTPS origin has an invalid port.', 503) from None
        if (parsed.scheme != 'https' or not parsed.hostname or '@' in parsed.netloc
                or parsed.query or '#' in base or '\\' in base or parsed.path or port == 0):
            raise OAuthError('server_error', 'Configure an HTTPS public base URL without a path.', 503)
        return base

    @api.model
    def _resource(self):
        return self._issuer() + '/api/mcp'

    @api.model
    def _metadata_url(self):
        return self._issuer() + '/.well-known/oauth-protected-resource/api/mcp'

    @api.model
    def _resource_metadata(self):
        return {'resource': self._resource(), 'authorization_servers': [self._issuer()],
                'scopes_supported': self.env['mcp.oauth.provider']._scopes_supported(), 'bearer_methods_supported': ['header']}

    @api.model
    def _metadata(self):
        issuer = self._issuer()
        result = {
            'issuer': issuer,
            'authorization_endpoint': issuer + '/mcp/oauth/authorize',
            'token_endpoint': issuer + '/mcp/oauth/token',
            'revocation_endpoint': issuer + '/mcp/oauth/revoke',
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': ['none', 'client_secret_basic', 'client_secret_post'],
            'revocation_endpoint_auth_methods_supported': ['none', 'client_secret_basic', 'client_secret_post'],
            'scopes_supported': self.env['mcp.oauth.provider']._scopes_supported(),
            'authorization_response_iss_parameter_supported': True,
        }
        if self.env['ir.config_parameter'].sudo().get_bool('mcp_oauth.allow_dynamic_registration', True):
            result['registration_endpoint'] = issuer + '/mcp/oauth/register'
        if self._parameter('cimd_hosts').strip():
            result['client_id_metadata_document_supported'] = True
        return result

    @api.model
    def _require_enabled(self):
        if not self.env['mcp.oauth.provider']._enabled():
            raise OAuthError('temporarily_unavailable', 'OAuth login is not enabled or configured.', 503)

    @api.model
    def _validate_client_metadata(self, data):
        if not isinstance(data, dict):
            raise OAuthError('invalid_client_metadata', 'Client metadata must be an object.')
        uris = data.get('redirect_uris')
        if not isinstance(uris, list) or not 1 <= len(uris) <= 10:
            raise OAuthError('invalid_client_metadata', 'Provide between one and ten redirect URIs.')
        uris = list(dict.fromkeys(redirect_uri(uri) for uri in uris))
        grants = data.get('grant_types', ['authorization_code'])
        if (not isinstance(grants, list) or not all(isinstance(item, str) for item in grants)
                or 'authorization_code' not in grants or set(grants) - {'authorization_code', 'refresh_token'}):
            raise OAuthError('invalid_client_metadata', 'Unsupported grant types.')
        if data.get('response_types', ['code']) != ['code']:
            raise OAuthError('invalid_client_metadata', 'Only the code response type is supported.')
        method = data.get('token_endpoint_auth_method', 'client_secret_basic')
        if method not in ('none', 'client_secret_basic', 'client_secret_post'):
            raise OAuthError('invalid_client_metadata', 'Unsupported token endpoint authentication method.')
        name = data.get('client_name') or 'MCP Client'
        if not isinstance(name, str) or len(name) > 200:
            raise OAuthError('invalid_client_metadata', 'Client name is too long.')
        return {'name': name, 'redirect_uris': uris, 'grant_types': list(dict.fromkeys(grants)), 'auth_method': method}

    @api.model
    def _register_client(self, data):
        self._require_enabled()
        if not self.env['ir.config_parameter'].sudo().get_bool('mcp_oauth.allow_dynamic_registration', True):
            raise OAuthError('access_denied', 'Dynamic registration is disabled.', 403)
        values = self._validate_client_metadata(data)
        raw = secret() if values['auth_method'] != 'none' else None
        if raw:
            values['secret_hash'] = digest(raw)
        client = self.env['mcp.oauth.client'].sudo().create(values)
        result = {'client_id': client.client_id, 'client_name': client.name,
                  'client_id_issued_at': int(client.create_date.replace(tzinfo=datetime.timezone.utc).timestamp()),
                  'redirect_uris': client.redirect_uris, 'grant_types': client.grant_types,
                  'response_types': ['code'], 'token_endpoint_auth_method': client.auth_method}
        if raw:
            result.update(client_secret=raw, client_secret_expires_at=0)
        return result

    @api.model
    def _cimd_metadata(self, client_id):
        """Fetch only approved HTTPS origins, connecting to a validated public IP."""
        parsed = urlsplit(client_id)
        try:
            port = parsed.port or 443
        except ValueError:
            raise OAuthError('invalid_client', 'Invalid metadata URL.', 401) from None
        allowed = {item.strip().lower() for item in self._parameter('cimd_hosts').split(',') if item.strip()}
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.hostname.lower() not in allowed
                or '@' in parsed.netloc or '#' in client_id or '\\' in client_id or port != 443):
            raise OAuthError('invalid_client', 'Client metadata origin has not been approved.', 401)
        try:
            addresses = {record[4][0] for record in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)}
            if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
                raise ValueError('Non-public metadata address')
            ip = sorted(addresses)[0]
            pool = urllib3.HTTPSConnectionPool(
                ip, port=443, server_hostname=parsed.hostname, assert_hostname=parsed.hostname,
                ssl_context=ssl.create_default_context(), maxsize=1,
                timeout=urllib3.Timeout(connect=3, read=5), retries=False,
            )
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            response = pool.request('GET', path, headers={'Host': parsed.hostname, 'Accept': 'application/json'},
                                    redirect=False, preload_content=False)
            try:
                if response.status != 200 or 'application/json' not in response.headers.get('Content-Type', ''):
                    raise ValueError('Invalid metadata response')
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise ValueError('Metadata response too large')
                data = json.loads(raw)
            finally:
                response.release_conn()
                pool.close()
        except Exception:
            raise OAuthError('invalid_client', 'Unable to validate client metadata.', 401) from None
        if not isinstance(data, dict) or data.get('client_id') != client_id:
            raise OAuthError('invalid_client', 'Client metadata identifier does not match.', 401)
        if data.get('token_endpoint_auth_method', 'none') != 'none':
            raise OAuthError('invalid_client', 'Metadata clients must be public clients.', 401)
        return self._validate_client_metadata({**data, 'token_endpoint_auth_method': 'none'})

    @api.model
    def _get_client(self, client_id):
        if not isinstance(client_id, str) or not client_id or len(client_id) > 2048:
            raise OAuthError('invalid_client', 'Unknown OAuth client.', 401)
        clients = self.env['mcp.oauth.client'].sudo()
        client = clients.with_context(active_test=False).search([('client_id', '=', client_id)], limit=1)
        if client and not client.active:
            raise OAuthError('invalid_client', 'Unknown OAuth client.', 401)
        if client_id.startswith('https://'):
            if not client or client.source != 'cimd' or not client.metadata_checked_at or client.metadata_checked_at < fields.Datetime.now() - datetime.timedelta(minutes=15):
                values = self._cimd_metadata(client_id)
                values.update(source='cimd', metadata_checked_at=fields.Datetime.now())
                if client:
                    client.write(values)
                else:
                    client = clients.create({**values, 'client_id': client_id})
        if not client or not client.active:
            raise OAuthError('invalid_client', 'Unknown OAuth client.', 401)
        return client

    @api.model
    def _validate_resource(self, value, expected=None):
        # The default retains compatibility with older single-resource MCP clients.
        resource = value or self._resource()
        if not isinstance(resource, str) or resource != (expected or self._resource()):
            raise OAuthError('invalid_target', 'The resource does not match this MCP service.')
        return resource

    @api.model
    def _start_flow(self, params, browser_cookie=''):
        self._require_enabled()
        client = self._get_client(params.get('client_id'))
        uri = redirect_uri(params.get('redirect_uri'))
        if uri not in client.redirect_uris:
            raise OAuthError('invalid_request', 'The redirect URI is not registered.')
        if params.get('response_type') != 'code':
            raise OAuthError('unsupported_response_type', 'Only authorization codes are supported.')
        challenge = params.get('code_challenge', '')
        if params.get('code_challenge_method') != 'S256' or not CHALLENGE.fullmatch(challenge):
            raise OAuthError('invalid_request', 'PKCE with S256 is required.')
        provider = self.env['mcp.oauth.provider']
        scopes = normalize_scopes(params.get('scope') or provider._default_scope(), provider._scopes_supported())
        resource = self._validate_resource(params.get('resource'))
        state = params.get('state') or ''
        if not isinstance(state, str) or len(state) > 2048:
            raise OAuthError('invalid_request', 'Invalid client state.')
        # Existing cookie values never get trusted as raw flow identifiers.
        cookie = browser_cookie if isinstance(browser_cookie, str) and 32 <= len(browser_cookie) <= 256 else secret()
        flow_id, csrf = secret(), secret()
        flow = self.env['mcp.oauth.flow'].sudo().create({
            'client_id': client.id, 'redirect_uri': uri, 'resource': resource, 'scope': scopes,
            'client_state': state, 'code_challenge': challenge, 'browser_hash': digest(cookie),
            'csrf_hash': digest(csrf), 'flow_hash': digest(flow_id),
            'expires_at': fields.Datetime.now() + datetime.timedelta(minutes=10),
        })
        return flow, flow_id, csrf, cookie

    @api.model
    def _consent(self, flow_id, csrf, decision, browser_cookie):
        self._require_enabled()
        flow = self.env['mcp.oauth.flow'].sudo().search([('flow_hash', '=', digest(flow_id or ''))], limit=1)
        if not flow:
            raise OAuthError('invalid_request', 'Authorization flow is missing or expired.')
        flow._lock()
        if flow.state != 'pending' or flow.expires_at <= fields.Datetime.now():
            raise OAuthError('invalid_request', 'Authorization flow is missing or expired.')
        if (not browser_cookie or not csrf or not hmac.compare_digest(flow.browser_hash, digest(browser_cookie))
                or not hmac.compare_digest(flow.csrf_hash, digest(csrf))):
            raise OAuthError('access_denied', 'The browser or CSRF validation failed.')
        if decision != 'approve':
            flow.state = 'failed'
            return add_query(flow.redirect_uri, {'error': 'access_denied', 'state': flow.client_state or None, 'iss': self._issuer()})
        url = self.env['mcp.oauth.provider']._begin_login(flow)
        flow.state = 'redirected'
        return url

    @api.model
    def _provider_callback(self, params, browser_cookie):
        self._require_enabled()
        state = params.get('state') or ''
        flow = self.env['mcp.oauth.flow'].sudo().search([('provider_state_hash', '=', digest(state))], limit=1)
        if not state or not flow:
            raise OAuthError('invalid_request', 'Identity login flow is missing or expired.')
        flow._lock()
        if flow.state != 'redirected' or flow.expires_at <= fields.Datetime.now():
            raise OAuthError('invalid_request', 'Identity login flow is missing or expired.')
        if not browser_cookie or not hmac.compare_digest(flow.browser_hash, digest(browser_cookie)):
            raise OAuthError('access_denied', 'The identity callback belongs to a different browser.')
        if params.get('error'):
            flow.state = 'failed'
            return add_query(flow.redirect_uri, {'error': 'access_denied', 'state': flow.client_state or None, 'iss': self._issuer()})
        if not params.get('code'):
            raise OAuthError('invalid_request', 'The identity authorization code is missing.')
        try:
            user, values = self.env['mcp.oauth.provider']._complete_login(flow, params)
            return self._complete_flow(flow, user, values)
        except OAuthError:
            flow.state = 'failed'
            # Persist the failure (and any pending employee binding) before the controller responds.
            raise

    @api.model
    def _complete_flow(self, flow, user, provider_data=None):
        self._validate_resource(flow.resource)
        user = user.sudo()
        if not user._mcp_oauth_eligible():
            raise OAuthError('access_denied', 'This Odoo user is not enabled for MCP.', 403)
        write = 'mcp:write' in flow.scope.split()
        if write and user.mcp_oauth_scope != 'write':
            raise OAuthError('access_denied', 'This user may not authorize write access.', 403)
        now = fields.Datetime.now()
        deadlines = self._provider_deadlines(provider_data)
        if deadlines['access_expires_at'] <= now:
            raise OAuthError('invalid_grant', 'The identity access token expired. Sign in again.')
        grant = self.env['mcp.oauth.grant'].sudo().create({
            'client_id': flow.client_id.id, 'user_id': user.id, 'scope': 'write' if write else 'read',
            'resource': flow.resource, 'expires_at': self._grant_deadline(deadlines),
            'provider_data': provider_data or {},
        })
        raw_code = secret('mcp_code_')
        self.env['mcp.oauth.code'].sudo().create({
            'code_hash': digest(raw_code), 'grant_id': grant.id, 'redirect_uri': flow.redirect_uri,
            'code_challenge': flow.code_challenge, 'expires_at': now + datetime.timedelta(minutes=2),
        })
        flow.state = 'completed'
        return add_query(flow.redirect_uri, {'code': raw_code, 'state': flow.client_state or None, 'iss': self._issuer()})

    @api.model
    def _authenticate_client(self, params, authorization=''):
        supplied_id, supplied_secret = params.get('client_id'), params.get('client_secret')
        method = 'client_secret_post' if supplied_secret is not None else 'none'
        if authorization:
            scheme, _, payload = authorization.partition(' ')
            if supplied_secret is not None or scheme.lower() != 'basic' or not payload:
                raise OAuthError('invalid_client', 'Use exactly one client authentication method.', 401)
            try:
                decoded = base64.b64decode(payload, validate=True).decode()
                raw_id, raw_secret = decoded.split(':', 1)
                basic_id, supplied_secret = unquote_plus(raw_id), unquote_plus(raw_secret)
                if supplied_id and supplied_id != basic_id:
                    raise ValueError('Mismatched client id')
                supplied_id, method = basic_id, 'client_secret_basic'
            except (ValueError, UnicodeError):
                raise OAuthError('invalid_client', 'Invalid client credentials.', 401) from None
        client = self._get_client(supplied_id)
        if method != client.auth_method:
            raise OAuthError('invalid_client', 'Client authentication method does not match registration.', 401)
        if method != 'none' and not client._authenticate(supplied_secret):
            raise OAuthError('invalid_client', 'Invalid client credentials.', 401)
        return client

    @api.model
    def _provider_deadlines(self, provider_data):
        """Validate the provider policy without inventing local lifetime limits."""
        deadlines = self.env['mcp.oauth.provider']._token_deadlines(provider_data or {})
        if not isinstance(deadlines, dict):
            raise OAuthError('invalid_grant', 'The identity provider returned invalid token validity.')
        access = deadlines.get('access_expires_at')
        refresh = deadlines.get('refresh_expires_at')
        if (not isinstance(access, datetime.datetime) or access.tzinfo is not None
                or (refresh is not None and (not isinstance(refresh, datetime.datetime) or refresh.tzinfo is not None))):
            raise OAuthError('invalid_grant', 'The identity provider returned invalid token validity.')
        return {'access_expires_at': access, 'refresh_expires_at': refresh}

    @api.model
    def _grant_deadline(self, deadlines):
        # A provider refresh window can end before its current access token.
        # Keep access usable until its own deadline without extending the
        # independently checked refresh credential.
        refresh = deadlines['refresh_expires_at']
        return max(deadlines['access_expires_at'], refresh) if refresh else deadlines['access_expires_at']

    @api.model
    def _new_token_pair(self, grant):
        now = fields.Datetime.now()
        deadlines = self._provider_deadlines(grant.provider_data)
        grant.expires_at = self._grant_deadline(deadlines)
        expires = min(grant.expires_at, deadlines['access_expires_at'])
        if expires <= now:
            raise OAuthError('invalid_grant', 'The identity authorization expired. Sign in again.')
        raw_access = secret('mcp_at_')
        self.env['mcp.oauth.token'].sudo().create({'token_hash': digest(raw_access), 'kind': 'access',
                                                  'grant_id': grant.id, 'expires_at': expires})
        result = {'access_token': raw_access, 'token_type': 'Bearer',
                  'expires_in': max(0, math.floor((expires - now).total_seconds())), 'scope': grant.scope_string}
        refresh_expires = deadlines['refresh_expires_at']
        if ('refresh_token' in grant.client_id.grant_types and refresh_expires
                and refresh_expires > now):
            raw_refresh = secret('mcp_rt_')
            self.env['mcp.oauth.token'].sudo().create({'token_hash': digest(raw_refresh), 'kind': 'refresh',
                                                      'grant_id': grant.id, 'expires_at': refresh_expires})
            result['refresh_token'] = raw_refresh
        return result

    @api.model
    def _exchange(self, params, authorization=''):
        self._require_enabled()
        client = self._authenticate_client(params, authorization)
        kind = params.get('grant_type')
        if kind == 'authorization_code':
            record = self.env['mcp.oauth.code'].sudo().search([('code_hash', '=', digest(params.get('code') or ''))], limit=1)
            if not record:
                raise OAuthError('invalid_grant', 'Invalid or expired authorization code.')
            record._lock()
            grant = record.grant_id
            grant._lock()
            if (record.used_at or record.expires_at <= fields.Datetime.now() or grant.client_id != client
                    or not grant._mcp_is_active()):
                raise OAuthError('invalid_grant', 'Invalid or expired authorization code.')
            if params.get('redirect_uri') != record.redirect_uri:
                raise OAuthError('invalid_grant', 'The redirect URI does not match the authorization request.')
            self._validate_resource(params.get('resource'), grant.resource)
            if not verify_pkce(params.get('code_verifier'), record.code_challenge):
                raise OAuthError('invalid_grant', 'PKCE verification failed.')
            # A short-lived upstream access token can expire while the client
            # is exchanging its (separately bounded) authorization code.
            if self._provider_deadlines(grant.provider_data)['access_expires_at'] <= fields.Datetime.now():
                self.env['mcp.oauth.provider']._refresh_grant(grant)
            record.used_at = fields.Datetime.now()
            return self._new_token_pair(grant)
        if kind == 'refresh_token':
            if 'refresh_token' not in client.grant_types:
                raise OAuthError('unauthorized_client', 'This client is not registered for refresh tokens.')
            record = self.env['mcp.oauth.token'].sudo().search([
                ('token_hash', '=', digest(params.get('refresh_token') or '')), ('kind', '=', 'refresh')], limit=1)
            if not record:
                raise OAuthError('invalid_grant', 'Invalid or expired refresh token.')
            record._lock()
            grant = record.grant_id
            grant._lock()
            # Check ownership before revocation to prevent another client from forcing a logout.
            if grant.client_id != client:
                raise OAuthError('invalid_grant', 'Invalid or expired refresh token.')
            if record.used_at:
                grant.action_revoke()
                raise OAuthError('invalid_grant', 'Refresh token reuse detected; authorization revoked.')
            if record.revoked_at or record.expires_at <= fields.Datetime.now() or not grant._mcp_is_active():
                raise OAuthError('invalid_grant', 'Invalid or expired refresh token.')
            self._validate_resource(params.get('resource'), grant.resource)
            scopes = normalize_scopes(params.get('scope') or grant.scope_string)
            if not set(scopes.split()) <= set(grant.scope_string.split()):
                raise OAuthError('invalid_scope', 'A refresh cannot increase the original scope.')
            try:
                self.env['mcp.oauth.provider']._refresh_grant(grant)
            except OAuthError as exc:
                if exc.error in ('invalid_grant', 'access_denied', 'invalid_token'):
                    grant._revoke()
                elif exc.error == 'temporarily_unavailable' and (grant.provider_data or {}).get('refresh_validation_pending'):
                    # Upstream RT rotation may already have succeeded. Keep
                    # this still-unconsumed MCP retry credential within the
                    # trusted new window, even if the former RT just expired.
                    deadlines = self._provider_deadlines(grant.provider_data)
                    if deadlines['refresh_expires_at']:
                        record.expires_at = deadlines['refresh_expires_at']
                raise
            if not grant._mcp_is_active():
                raise OAuthError('invalid_grant', 'The linked identity is no longer eligible.')
            if 'mcp:write' not in scopes.split():
                grant.scope = 'read'
            record.used_at = fields.Datetime.now()
            return self._new_token_pair(grant)
        raise OAuthError('unsupported_grant_type', 'Unsupported grant type.')

    @api.model
    def _authenticate_token(self, raw):
        if not isinstance(raw, str) or not raw.startswith('mcp_at_') or len(raw) > 1024:
            return self.env['mcp.oauth.grant']
        token = self.env['mcp.oauth.token'].sudo().search([('token_hash', '=', digest(raw)), ('kind', '=', 'access')], limit=1)
        if not token or token.revoked_at or token.expires_at <= fields.Datetime.now():
            return self.env['mcp.oauth.grant']
        grant = token.grant_id
        if grant.resource != self._resource() or not grant._mcp_is_active():
            return self.env['mcp.oauth.grant']
        self.env.cr.execute('''
            UPDATE mcp_oauth_grant SET last_used = NOW() AT TIME ZONE 'UTC'
            WHERE id IN (SELECT id FROM mcp_oauth_grant WHERE id = %s
                AND (last_used IS NULL OR last_used < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 minute')
                FOR NO KEY UPDATE SKIP LOCKED)
        ''', [grant.id])
        return grant

    @api.model
    def _revoke(self, params, authorization=''):
        client = self._authenticate_client(params, authorization)
        token = self.env['mcp.oauth.token'].sudo().search([('token_hash', '=', digest(params.get('token') or ''))], limit=1)
        if token and token.grant_id.client_id == client:
            token.grant_id.action_revoke()
        # RFC 7009 does not reveal whether the token existed.
        return None

    @api.model
    def _sync_provider_lifetimes(self, grants=None):
        """Migrate unrevoked Feishu authorizations away from former local caps.

        Existing access tokens are only shortened. Unspent refresh credentials
        follow the provider's known refresh window; spent credentials remain
        available for reuse detection, and revoked credentials stay revoked.
        """
        if grants is None:
            grants = self.env['mcp.oauth.grant'].sudo().search([('revoked_at', '=', False)])
        now = fields.Datetime.now()
        updated = revoked = 0
        for grant in grants.sudo():
            if grant.revoked_at or (grant.provider_data or {}).get('provider') != 'feishu':
                continue
            grant._lock()
            try:
                deadlines = self._provider_deadlines(grant.provider_data)
            except OAuthError:
                grant._revoke()
                revoked += 1
                continue
            grant.expires_at = self._grant_deadline(deadlines)
            if grant.expires_at <= now:
                grant._revoke()
                revoked += 1
                continue
            tokens = self.env['mcp.oauth.token'].sudo().search([
                ('grant_id', '=', grant.id), ('revoked_at', '=', False),
            ])
            access_deadline = min(grant.expires_at, deadlines['access_expires_at'])
            tokens.filtered(lambda token: token.kind == 'access' and token.expires_at > access_deadline).write({
                'expires_at': access_deadline,
            })
            refresh = tokens.filtered(lambda token: token.kind == 'refresh' and not token.used_at)
            if deadlines['refresh_expires_at'] and deadlines['refresh_expires_at'] > now:
                refresh.write({'expires_at': deadlines['refresh_expires_at']})
            else:
                refresh.write({'revoked_at': now})
            updated += 1
        return {'updated': updated, 'revoked': revoked}
