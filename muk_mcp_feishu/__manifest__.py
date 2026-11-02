{
    'name': 'MCP Feishu SSO',
    'summary': 'Feishu SSO and automatic Odoo identity mapping for MCP OAuth',
    'version': '20.0.1.3.0',
    'license': 'LGPL-3',
    'author': 'Community contributors',
    'category': 'Tools/API',
    'depends': ['muk_mcp_oauth21', 'muk_mcp_access'],
    'external_dependencies': {'python': ['requests', 'cryptography']},
    'data': [
        'security/ir.access.csv',
        'data/config.xml',
        'views/config.xml',
        'views/binding.xml',
        'views/res_users.xml',
        'views/res_config_settings.xml',
        'views/menu.xml',
    ],
    'assets': {
        'web.assets_backend': [
            'muk_mcp_feishu/static/src/scss/config.scss',
        ],
    },
    'installable': True,
    'application': False,
}
