"""Remove authorization codes and one-use URLs from HTTP access logs."""
import logging
import re

_OAUTH_QUERY = re.compile(r'(/mcp/oauth/[A-Za-z0-9/_-]+)\?[^\s"\']*')
_TRANSFER_TOKEN = re.compile(r'(/mcp/transfer/)[^\s"\'?#]+(?:\?[^\s"\']*)?')


def redact_http_message(message):
    return _TRANSFER_TOKEN.sub(r'\1<redacted>', _OAUTH_QUERY.sub(r'\1?<redacted>', message))


class SensitiveOAuthURLFilter(logging.Filter):
    _mcp_oauth_sensitive_urls = True

    def filter(self, record):
        original = record.getMessage()
        line = getattr(record, 'http_request_line', '')
        if not isinstance(line, str):
            line = ''
        sensitive = any(path in line or path in original for path in ('/mcp/oauth/', '/mcp/transfer/', '/api/mcp'))
        headers = getattr(record, 'http_headers', None)

        def clean(message):
            message = redact_http_message(message)
            # Odoo 20 preformats the header block before logging. Replace the
            # entire block, not individual headers that pprint may wrap.
            if sensitive and isinstance(headers, str) and headers:
                message = message.replace(headers, '<redacted MCP headers>')
            return message

        redacted = clean(original)
        if redacted != original:
            record.msg, record.args = redacted, ()
        if isinstance(line, str):
            record.http_request_line = redact_http_message(line)
        # Odoo 20's log formatter reads this preformatted extra instead of msg.
        colored = getattr(record, 'colored_message', None)
        if isinstance(colored, str):
            record.colored_message = clean(colored)
        if sensitive and headers is not None:
            record.http_headers = '<redacted MCP headers>'
        return True


def install_log_filter():
    for name in ('odoo.http.server', 'odoo.http.server.headers', 'werkzeug'):
        logger = logging.getLogger(name)
        if not any(getattr(item, '_mcp_oauth_sensitive_urls', False) for item in logger.filters):
            logger.addFilter(SensitiveOAuthURLFilter())
