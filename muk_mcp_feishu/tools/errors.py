"""Preserve actionable provider codes without exposing OAuth credentials."""
import logging

from odoo.addons.muk_mcp_oauth21.tools.oauth import OAuthError

_logger = logging.getLogger(__name__)
OAUTH_ERRORS = frozenset((
    'invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client',
    'unsupported_grant_type', 'invalid_scope', 'access_denied', 'invalid_token',
    'temporarily_unavailable', 'server_error',
))


class FeishuRequestError(OAuthError):
    provider = 'feishu'


def rejected_request(endpoint, status, payload):
    """Use only numeric codes or known OAuth error names, never raw messages.

    Provider error descriptions can echo codes, tokens or request parameters.
    They must not be copied into application logs or the browser error page.
    """
    payload = payload if isinstance(payload, dict) else {}
    numeric = payload.get('code')
    if (isinstance(numeric, bool) or not isinstance(numeric, (str, int))
            or not str(numeric).isdigit() or len(str(numeric)) > 9):
        numeric = None
    oauth_name = payload.get('error')
    if not isinstance(oauth_name, str) or oauth_name not in OAUTH_ERRORS:
        oauth_name = None
    safe_code = str(numeric) if numeric not in (None, 0, '0') else (oauth_name or '未返回错误码')
    _logger.warning('Feishu OAuth request rejected: endpoint=%s http_status=%s code=%s',
                    endpoint, status, safe_code)
    detail = '飞书未接受本次请求（接口：%s；HTTP %s；错误码：%s）。' % (endpoint, status, safe_code)
    if safe_code == '20049':
        detail += 'PKCE 登录校验失败，请从设置页重新发起飞书登录验证。'
    return FeishuRequestError('invalid_grant', detail)
