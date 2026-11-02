def post_init_hook(env):
    """Keep the owners of existing keys eligible during an opt-in migration."""
    keys = env['muk_mcp.key'].sudo().search([('active', '=', True)])
    users = keys.mapped('user_id')
    users.filtered(lambda user: user.active and not user.share).write({'mcp_oauth_enabled': True})
    keys.filtered(lambda key: key.scope == 'write').mapped('user_id').write({'mcp_oauth_scope': 'write'})


def post_load():
    from .tools.logging import install_log_filter
    install_log_filter()
