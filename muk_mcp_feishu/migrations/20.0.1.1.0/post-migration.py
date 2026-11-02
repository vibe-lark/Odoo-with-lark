"""Retire manual lifetimes and align existing grants with provider authority."""
from odoo import api, SUPERUSER_ID


def migrate(cr, version):
    env = api.Environment(cr, SUPERUSER_ID, {})
    env['ir.config_parameter'].sudo().search([
        ('key', 'in', ['mcp_oauth.access_token_minutes', 'mcp_oauth.grant_days']),
    ]).unlink()
    env['mcp.oauth.service']._sync_provider_lifetimes()
