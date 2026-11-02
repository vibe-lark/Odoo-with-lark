"""Activate existing unique matches while preserving explicit user permissions."""
from odoo import api, SUPERUSER_ID


def migrate(cr, version):
    env = api.Environment(cr, SUPERUSER_ID, {})
    env['mcp.feishu.binding']._auto_bind_existing()
