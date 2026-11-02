from odoo.tools import config

if config.get('test_enable'):
    from . import test_oauth_integration
    from . import test_feishu_identity
    from . import test_token_lifetimes
    from . import test_feishu_pkce
