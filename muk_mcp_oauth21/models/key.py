from odoo import api, models
from odoo.exceptions import AccessError


class MCPKey(models.Model):
    _inherit = 'muk_mcp.key'

    @api.model
    def _generate(self, name, scope, rate_limit):
        if not self.env['ir.config_parameter'].sudo().get_bool('mcp_oauth.allow_api_keys', True):
            raise AccessError(self.env._('Manual MCP keys are disabled; connect using OAuth.'))
        user = self.env.user
        if not user._mcp_oauth_eligible():
            raise AccessError(self.env._('MCP access has not been enabled for this user.'))
        if scope == 'write' and user.sudo().mcp_oauth_scope != 'write':
            raise AccessError(self.env._('This user may only create read-only MCP credentials.'))
        return super()._generate(name, scope, rate_limit)
