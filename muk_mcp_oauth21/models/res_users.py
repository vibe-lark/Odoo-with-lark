from odoo import fields, models
from odoo.exceptions import AccessError


class ResUsers(models.Model):
    _inherit = 'res.users'

    mcp_oauth_enabled = fields.Boolean(string='Allow MCP', default=False, groups='base.group_system')
    mcp_oauth_scope = fields.Selection(
        [('read', 'Read Only'), ('write', 'Read & Write')],
        string='Maximum MCP Scope', default='read', required=True, groups='base.group_system',
    )
    mcp_oauth_rate_limit = fields.Integer(string='MCP Requests per Minute', default=60, groups='base.group_system')

    def write(self, values):
        protected = {'mcp_oauth_enabled', 'mcp_oauth_scope', 'mcp_oauth_rate_limit'}
        if protected.intersection(values) and not (self.env.su or self.env.user.has_group('base.group_system')):
            raise AccessError(self.env._('Only a system administrator may change MCP access.'))
        result = super().write(values)
        if values.get('mcp_oauth_enabled') is False or values.get('active') is False:
            self.env['mcp.oauth.grant'].sudo().search([
                ('user_id', 'in', self.ids), ('revoked_at', '=', False),
            ])._revoke()
        return result

    def _mcp_oauth_eligible(self):
        self.ensure_one()
        user = self.sudo()
        return bool(user.active and not user.share and user.mcp_oauth_enabled)
