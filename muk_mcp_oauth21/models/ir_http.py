from odoo import models
from odoo.http import request
from werkzeug.datastructures import WWWAuthenticate
from werkzeug.exceptions import Unauthorized

from ..tools.oauth import OAuthError


class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _get_mcp_challenge(cls, token):
        service = request.env['mcp.oauth.service']
        try:
            return WWWAuthenticate('bearer', {'resource_metadata': service._metadata_url(),
                                             'scope': 'mcp:read', 'error': 'invalid_token'})
        except OAuthError:
            return super()._get_mcp_challenge(token)

    @classmethod
    def _handle_error(cls, exception):
        if request.httprequest.path == '/api/mcp' and isinstance(exception, Unauthorized):
            return request.make_json_response(
                {'error': 'invalid_token', 'error_description': 'A valid MCP access token is required.'},
                status=401, headers={'WWW-Authenticate': str(cls._get_mcp_challenge(None)),
                                     'Cache-Control': 'no-store', 'Pragma': 'no-cache',
                                     'Access-Control-Allow-Origin': '*',
                                     'Access-Control-Expose-Headers': 'WWW-Authenticate, Retry-After'},
            )
        return super()._handle_error(exception)

    @classmethod
    def _authenticate_mcp_token(cls, token):
        service = request.env['mcp.oauth.service'].sudo()
        if token.startswith('mcp_at_'):
            if not request.httprequest.is_secure:
                return None
            grant = service._authenticate_token(token)
            if not grant:
                return None
            request.update_env(user=grant.user_id.id)
            request._mcp_principal = grant
            request._mcp_oauth_grant = grant
            return grant.name
        if not request.env['ir.config_parameter'].sudo().get_bool('mcp_oauth.allow_api_keys', True):
            return None
        name = super()._authenticate_mcp_token(token)
        if name and not request.env.user._mcp_oauth_eligible():
            return None
        return name
