"""Seed only an application/client in a disposable direct-redirect test DB."""


def create_authorization_fixture(env):
    if not env.cr.dbname.startswith('mcp_oauth_test_'):
        raise RuntimeError('Refusing a non-test database')
    env['ir.config_parameter'].set_str('mcp_oauth.public_base_url', 'https://odoo.example')
    config = env['mcp.feishu.config']._get_config()
    config.write({'app_id': 'cli_direct_redirect_fixture', 'app_secret': 'test-only-direct-redirect-secret'})
    fingerprint = config._fingerprint()
    config.write({'credentials_fingerprint': fingerprint, 'login_fingerprint': fingerprint})
    config.enabled = True
    registration = env['mcp.oauth.service']._register_client({
        'client_name': 'Independent Transaction Redirect Probe',
        'redirect_uris': ['https://client.example/callback'], 'token_endpoint_auth_method': 'none',
    })
    return {'database': env.cr.dbname, 'database_socket': '/var/run/postgresql', 'database_port': 55433,
            'database_user': 'odoo', 'http_port': 18072, 'resource': 'https://odoo.example/api/mcp',
            'client_id': registration['client_id'], 'redirect_uri': registration['redirect_uris'][0]}
