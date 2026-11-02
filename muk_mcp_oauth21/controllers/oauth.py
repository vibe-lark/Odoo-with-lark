from __future__ import annotations

import json

from odoo import http
from odoo.http import Response, request
from werkzeug.datastructures import WWWAuthenticate

from odoo.addons.muk_mcp.controllers.mcp import MCPController
from odoo.addons.muk_mcp.core.tool import get_tool_index

from ..tools.oauth import COOKIE_NAME, OAuthError

NO_CACHE = {'Cache-Control': 'no-store', 'Pragma': 'no-cache'}


def oauth_json(data, status=200, headers=None):
    return request.make_json_response(data, status=status, headers={**NO_CACHE,
        'Access-Control-Expose-Headers': 'WWW-Authenticate, Retry-After', **(headers or {})})


def oauth_error_response(exc):
    headers = {}
    if exc.error == 'invalid_client' and exc.status == 401:
        headers['WWW-Authenticate'] = 'Basic realm="token"'
    if exc.status == 429:
        headers['Retry-After'] = '60'
    return oauth_json({'error': exc.error, 'error_description': exc.description}, exc.status, headers)


def oauth_redirect(url):
    return Response(status=302, headers={**NO_CACHE, 'Location': url})


def _params(values):
    if any(len(items) != 1 for _, items in values.lists()):
        raise OAuthError('invalid_request', 'Duplicate request parameters are not supported.')
    return values.to_dict(flat=True)


def _public_rate(endpoint, limit=120):
    if not request.env['mcp.oauth.endpoint.rate'].sudo()._consume(endpoint, request.httprequest.remote_addr or 'unknown', limit):
        raise OAuthError('temporarily_unavailable', 'Too many requests; retry later.', 429)


def _require_https():
    if not request.httprequest.is_secure:
        raise OAuthError('invalid_request', 'HTTPS is required for OAuth authorization and credentials.')


class OAuthController(http.Controller):
    @http.route(['/.well-known/oauth-protected-resource/api/mcp', '/.well-known/oauth-protected-resource'],
                type='http', auth='public', methods=['GET'], csrf=False, save_session=False, cors='*')
    def protected_resource(self, **kwargs):
        try:
            return oauth_json(request.env['mcp.oauth.service']._resource_metadata())
        except OAuthError as exc:
            return oauth_error_response(exc)

    @http.route('/.well-known/oauth-authorization-server', type='http', auth='public',
                methods=['GET'], csrf=False, save_session=False, cors='*')
    def metadata(self, **kwargs):
        try:
            return oauth_json(request.env['mcp.oauth.service']._metadata())
        except OAuthError as exc:
            return oauth_error_response(exc)

    @http.route('/mcp/oauth/register', type='http', auth='public', methods=['POST'],
                csrf=False, save_session=False, cors='*')
    def register(self, **kwargs):
        try:
            _require_https()
            _public_rate('register', 20)
            if request.httprequest.mimetype != 'application/json':
                raise OAuthError('invalid_request', 'Use application/json for client registration.')
            raw = request.httprequest.get_data()
            if len(raw) > 16384:
                raise OAuthError('invalid_client_metadata', 'Client metadata is too large.')
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeError):
                raise OAuthError('invalid_client_metadata', 'Invalid client metadata JSON.') from None
            return oauth_json(request.env['mcp.oauth.service']._register_client(data), 201)
        except OAuthError as exc:
            return oauth_error_response(exc)

    @http.route('/mcp/oauth/authorize', type='http', auth='public', methods=['GET'],
                csrf=False, save_session=False)
    def authorize(self, **kwargs):
        try:
            _require_https()
            _public_rate('authorize', 60)
            if len(request.httprequest.query_string) > 8192 or len(request.httprequest.get_data()) > 16384:
                raise OAuthError('invalid_request', 'Authorization request is too large.')
            service = request.env['mcp.oauth.service']
            cookie = request.httprequest.cookies.get(COOKIE_NAME, '')
            values = _params(request.httprequest.args)
            flow, flow_id, csrf, browser = service._start_flow(values, cookie)
            # Start identity login in the same transaction. There is no browser
            # form submission or separate Odoo consent page in this deployment.
            url = service._consent(flow_id, csrf, 'approve', browser)
            response = oauth_redirect(url)
            response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            response.headers['Referrer-Policy'] = 'no-referrer'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.set_cookie(COOKIE_NAME, browser, max_age=600, secure=True, httponly=True, samesite='Lax', path='/')
            return response
        except OAuthError as exc:
            return oauth_error_response(exc)

    @http.route('/mcp/oauth/token', type='http', auth='public', methods=['POST'],
                csrf=False, save_session=False, cors='*')
    def token(self, **kwargs):
        try:
            _require_https()
            _public_rate('token')
            if request.httprequest.mimetype != 'application/x-www-form-urlencoded':
                raise OAuthError('invalid_request', 'Use application/x-www-form-urlencoded.')
            if len(request.httprequest.get_data()) > 16384:
                raise OAuthError('invalid_request', 'Token request is too large.')
            values = _params(request.httprequest.form)
            return oauth_json(request.env['mcp.oauth.service']._exchange(
                values, request.httprequest.headers.get('Authorization', '')))
        except OAuthError as exc:
            # Returning the error preserves replay-triggered revocation in this transaction.
            return oauth_error_response(exc)

    @http.route('/mcp/oauth/revoke', type='http', auth='public', methods=['POST'],
                csrf=False, save_session=False, cors='*')
    def revoke(self, **kwargs):
        try:
            _require_https()
            _public_rate('revoke')
            if len(request.httprequest.get_data()) > 16384:
                raise OAuthError('invalid_request', 'Revocation request is too large.')
            if request.httprequest.mimetype != 'application/x-www-form-urlencoded':
                raise OAuthError('invalid_request', 'Use application/x-www-form-urlencoded.')
            values = _params(request.httprequest.form)
            request.env['mcp.oauth.service']._revoke(values, request.httprequest.headers.get('Authorization', ''))
            return Response(status=200, headers=NO_CACHE)
        except OAuthError as exc:
            return oauth_error_response(exc)


class OAuthMCPController(MCPController):
    def _get_tool_enforce_scope(self):
        scope = super()._get_tool_enforce_scope()
        if request.env.user.sudo().mcp_oauth_scope == 'read':
            return 'read'
        return scope

    def _get_authorization_error(self, data):
        result = super()._get_authorization_error(data)
        grant = getattr(request, '_mcp_oauth_grant', None)
        if result is not None or not grant or data.get('method') != 'tools/call':
            return result
        params = data.get('params') or {}
        if not isinstance(params, dict):
            return None
        entry = get_tool_index(request.env).get(params.get('name'))
        if grant.scope != 'read' or not entry or entry['category'] == 'read':
            return None
        service = request.env['mcp.oauth.service']
        challenge = WWWAuthenticate('bearer', {'error': 'insufficient_scope', 'scope': 'mcp:read mcp:write',
                                              'resource_metadata': service._metadata_url()})
        return oauth_json({'error': 'insufficient_scope', 'error_description': 'Write authorization is required.'},
                          403, {'WWW-Authenticate': str(challenge)})

    @http.route('/api/mcp', type='http', auth='mcp', methods=['GET', 'DELETE'],
                csrf=False, save_session=False, cors='*')
    def unsupported_transport(self, **kwargs):
        return Response(status=405, headers={'Allow': 'POST, OPTIONS'})
