{
    'name': 'MCP OAuth 2.1',
    'summary': 'Persistent OAuth authorization for the MuK MCP server',
    'version': '20.0.1.1.1',
    'license': 'LGPL-3',
    'author': 'Odoo MCP Contributors',
    'depends': ['muk_mcp'],
    'external_dependencies': {'python': ['cryptography', 'requests']},
    'data': ['security/ir.access.csv', 'views/oauth.xml'],
    'post_init_hook': 'post_init_hook',
    'post_load': 'post_load',
    'installable': True,
    'application': False,
}
