from odoo import fields, models
from odoo.http import request
from odoo.addons.muk_mcp.tools.auth import get_mcp_principal


class MCPTransfer(models.Model):
    _inherit = 'muk_mcp.transfer'

    oauth_grant_id = fields.Many2one('mcp.oauth.grant', ondelete='cascade', index=True, readonly=True)

    def _get_transfer_base_url(self):
        principal = get_mcp_principal()
        if principal and principal._name == 'mcp.oauth.grant':
            return self.env['mcp.oauth.service']._issuer()
        return super()._get_transfer_base_url()

    def _check_credential(self):
        self.ensure_one()
        if self.oauth_grant_id and request and not request.httprequest.is_secure:
            return False
        if not super()._check_credential():
            return False
        if self.key_id:
            allowed = self.env['ir.config_parameter'].sudo().get_bool('mcp_oauth.allow_api_keys', True)
            user = self.key_id.sudo().user_id
            if not allowed or not user._mcp_oauth_eligible():
                return False
            if self.operation == 'upload' and (self.key_id.scope != 'write' or user.mcp_oauth_scope != 'write'):
                return False
        if self.oauth_grant_id:
            grant = self.oauth_grant_id
            if not grant._mcp_is_active() or self.operation == 'upload' and grant.scope != 'write':
                return False
        return True


class MCPLog(models.Model):
    _inherit = 'muk_mcp.log'

    oauth_client_id = fields.Many2one('mcp.oauth.client', ondelete='set null', readonly=True)
    oauth_grant_id = fields.Many2one('mcp.oauth.grant', ondelete='set null', readonly=True)
