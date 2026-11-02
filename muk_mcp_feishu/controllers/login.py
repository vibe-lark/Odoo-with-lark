from __future__ import annotations

from html import escape
import logging
from urllib.parse import parse_qs, urlsplit

from odoo import http
from odoo.http import Response, request

from odoo.addons.muk_mcp_oauth21.tools.oauth import COOKIE_NAME, OAuthError
from ..models.trial import TRIAL_COOKIE

_logger = logging.getLogger(__name__)


def error_response(exc, browser=False, trial=False):
    if browser:
        # Browser callbacks are human-facing; token/protocol endpoints retain
        # the core module's machine-readable OAuth JSON errors.
        upstream = getattr(exc, 'provider', None) == 'feishu'
        title = '飞书登录验证未完成' if trial else 'MCP 授权未完成'
        if upstream:
            guidance = '飞书拒绝了授权凭证或用户身份请求。请根据下方接口与错误码检查飞书应用权限、发布状态和授权流程。此时尚未进入员工邮箱绑定。'
        elif trial:
            guidance = '本次管理员试用登录未完成，请根据下方原因处理后重新发起验证。'
        else:
            guidance = '本次连接未完成，请根据下方原因检查授权、账号绑定或 MCP 使用权限。'
        retry = ('请返回飞书设置重新点击“试用飞书登录”，不要刷新已使用的回调页面。' if trial
                 else '处理完成后，请回到豆包或其他 MCP 客户端重新连接。')
        href = '/odoo/mcp-feishu-settings' if trial else '/odoo'
        label = '返回飞书设置' if trial else '打开 Odoo'
        body = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>%s</title><style>body{font:16px/1.6 system-ui,sans-serif;max-width:640px;margin:10vh auto;padding:24px;color:#30343b}h1{font-size:24px}a{color:#71639e}.detail{color:#666;font-size:14px}</style></head><body><h1>%s</h1><p>%s</p><p class="detail">%s</p><p>%s</p><a href="%s">%s</a></body></html>''' % tuple(escape(value) for value in (title, title, guidance, exc.description, retry, href, label))
        response = Response(body, status=exc.status, content_type='text/html; charset=utf-8')
        response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
        return response
    response = request.make_json_response({'error': exc.error, 'error_description': exc.description}, status=exc.status)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


class FeishuLogin(http.Controller):
    @http.route('/mcp/oauth/feishu/trial/start', type='http', auth='user', methods=['GET'])
    def start_trial(self, **kwargs):
        if not request.env.user.has_group('base.group_system'):
            return error_response(OAuthError('access_denied', 'A system administrator must start this test.', 403), browser=True, trial=True)
        try:
            if not request.httprequest.is_secure:
                # The preserved HTTP Odoo entry is not suitable for Secure
                # authorization cookies. Start on the configured HTTPS origin.
                config = request.env['mcp.feishu.config']._get_config()
                return request.redirect(config._base_url() + '/mcp/oauth/feishu/trial/start', code=302, local=False)
            url, cookie = request.env['mcp.feishu.trial']._start()
            response = request.redirect(url, code=302, local=False)
            original = parse_qs(urlsplit(url).query)
            delivered = parse_qs(urlsplit(response.headers['Location']).query)
            if (delivered.get('code_challenge') != original.get('code_challenge')
                    or delivered.get('code_challenge_method') != ['S256']
                    or len(delivered.get('code_challenge', [''])[0]) != 43):
                raise OAuthError('server_error', '飞书登录跳转缺少有效的 PKCE 参数，请重新发起验证。', 500)
            _logger.info('Feishu PKCE redirect: challenge_present=True challenge_length=43 method=S256')
            response.set_cookie(TRIAL_COOKIE, cookie, max_age=600, secure=True, httponly=True, samesite='Lax', path='/mcp/oauth/feishu')
            response.headers['Cache-Control'] = 'no-store'
            return response
        except OAuthError as exc:
            return error_response(exc, browser=True, trial=True)

    @http.route('/mcp/oauth/feishu/callback', type='http', auth='public', methods=['GET'], save_session=False)
    def callback(self, **kwargs):
        if not request.httprequest.is_secure:
            return error_response(OAuthError('invalid_request', 'HTTPS is required for the identity callback.'), browser=True)
        if any(len(values) != 1 for _, values in request.httprequest.args.lists()):
            return error_response(OAuthError('invalid_request', 'Duplicate callback parameters are not supported.'), browser=True)
        params = request.httprequest.args.to_dict()
        is_trial = (params.get('state') or '').startswith('trial_')
        try:
            if is_trial:
                location = request.env['mcp.feishu.trial']._complete(
                    params, request.httprequest.cookies.get(TRIAL_COOKIE, ''), request.session.uid,
                )
            else:
                location = request.env['mcp.oauth.service']._provider_callback(
                    params, request.httprequest.cookies.get(COOKIE_NAME, ''),
                )
            response = request.redirect(location, code=302, local=is_trial)
            if is_trial:
                response.delete_cookie(TRIAL_COOKIE, path='/mcp/oauth/feishu')
            response.headers['Cache-Control'] = 'no-store'
            response.headers['Pragma'] = 'no-cache'
            return response
        except OAuthError as exc:
            return error_response(exc, browser=True, trial=is_trial)
