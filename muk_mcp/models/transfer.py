from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from odoo import api, fields, models
from odoo.exceptions import UserError
from odoo.http import Response, request
from odoo.tools import BinaryBytes
from odoo.tools import SQL

from odoo.addons.muk_mcp.tools.common import TRANSFER_MINUTES, TRANSFER_PATH
from odoo.addons.muk_mcp.tools.auth import get_mcp_principal


class MCPTransfer(models.Model):
    """One-time link an MCP client uploads a file to or downloads one from."""

    _name = 'muk_mcp.transfer'
    _description = 'MCP File Transfer'
    _explanation = (
        'A one-time HTTP link for one file, issued to an MCP client by '
        'authorize_upload or authorize_download, so the file travels over plain '
        'HTTP instead of through the conversation.'
    )
    _order = 'id desc'

    # ----------------------------------------------------------
    # Fields
    # ----------------------------------------------------------

    token_hash = fields.Char(
        string='Token Hash',
        required=True,
        index=True,
        copy=False,
    )

    operation = fields.Selection(
        selection=[
            ('upload', 'Upload'),
            ('download', 'Download'),
        ],
        string='Operation',
        required=True,
    )

    key_name = fields.Char(
        string='Key',
        help='The API key the link was issued to.',
    )

    key_id = fields.Many2one(
        comodel_name='muk_mcp.key',
        string='API Key',
        index=True,
        ondelete='cascade',
        help='Credential which authorized this link; revocation disables the link.',
    )

    user_id = fields.Many2one(
        comodel_name='res.users',
        string='User',
        required=True,
        index=True,
        ondelete='cascade',
    )

    attachment_id = fields.Many2one(
        comodel_name='ir.attachment',
        string='Attachment',
        help='The attachment an upload fills or a produced file is served from.',
        ondelete='set null',
    )

    uri = fields.Char(
        string='URI',
        help='The odoo:// resource a download serves.',
    )

    file_size = fields.Integer(
        string='Announced Size',
    )

    sha256 = fields.Char(
        string='Announced SHA-256',
    )

    expires_at = fields.Datetime(
        string='Expires At',
        required=True,
    )

    used = fields.Boolean(
        string='Used',
        default=False,
    )

    # ----------------------------------------------------------
    # Helper
    # ----------------------------------------------------------

    @api.model
    def _get_transfer_base_url(self) -> str:
        """Use a dedicated HTTPS origin when MCP has its own TLS entry point."""
        public_url = self.env['ir.config_parameter'].sudo().get_str('muk_mcp.public_url')
        if public_url:
            parsed = urlsplit(public_url)
            if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
                    or parsed.password or parsed.path not in ('', '/')
                    or parsed.query or parsed.fragment):
                raise UserError(self.env._('The MCP public URL must be an HTTPS origin.'))
            return public_url.rstrip('/')
        return self.get_base_url().rstrip('/')

    def _receive(self, data: bytes) -> dict[str, Any]:
        """Fill the upload's attachment with ``data``, as the link's user.

        :raise UserError: when the data is empty or does not match the announced
            size or digest.
        """
        if not data:
            raise UserError(
                self.env._(
                    'The upload is empty: send the file as the raw request body '
                    '(curl -T) or as a multipart file.'
                ),
            )
        digest = hashlib.sha256(data).hexdigest()
        if self.file_size and len(data) != self.file_size:
            raise UserError(
                self.env._(
                    'The upload has %(got)s bytes, %(want)s were announced.',
                    got=len(data),
                    want=self.file_size,
                ),
            )
        if self.sha256 and digest != self.sha256.lower():
            raise UserError(
                self.env._('The upload does not match the announced SHA-256.')
            )
        attachment = self.attachment_id.with_user(self.user_id)
        attachment.write({'raw': BinaryBytes(data, filename=attachment.name)})
        return {
            'file': f'odoo://attachment/{attachment.id}',
            'file_size': len(data),
            'sha256': digest,
        }

    def _download(self) -> Response:
        """Stream the download's resource, read as the link's user."""
        env = self.env(user=self.user_id)
        record, field = env['muk_mcp.mixin']._resolve_resource_target(self.uri)
        return (
            env['ir.binary']
            ._get_stream_from(record, field)
            .get_response(
                as_attachment=True,
            )
        )

    def _check_credential(self) -> bool:
        """Auth-provider extension point for grant and user revocation."""
        self.ensure_one()
        return bool(self.user_id.active and (not self.key_id or self.key_id._mcp_is_active()))

    # ----------------------------------------------------------
    # Functions
    # ----------------------------------------------------------

    @api.model
    def _issue(self, operation: str, **values: Any) -> tuple[models.Model, str]:
        """Create a link for the current user and return it with its URL."""
        token = secrets.token_urlsafe(32)
        principal = get_mcp_principal()
        credential_values = principal._mcp_transfer_values() if principal else {}
        transfer = self.sudo().create(
            {
                **values,
                **credential_values,
                'operation': operation,
                'token_hash': self.env['muk_mcp.key']._hash_key(token),
                'user_id': self.env.uid,
                'key_name': principal.name if principal else False,
                'expires_at': fields.Datetime.now()
                + timedelta(minutes=TRANSFER_MINUTES),
            },
        )
        return transfer, f'{self._get_transfer_base_url()}{TRANSFER_PATH}/{token}'

    @api.model
    def _redeem(self, token: str, operation: str) -> models.Model:
        """Consume the live, unused link behind ``token``, or return an empty set."""
        transfer = self.sudo().search(
            [
                ('token_hash', '=', self.env['muk_mcp.key']._hash_key(token)),
                ('operation', '=', operation),
                ('used', '=', False),
                ('expires_at', '>', fields.Datetime.now()),
                ('user_id.active', '=', True),
            ],
            limit=1,
        )
        if not transfer or not transfer._check_credential():
            return self.browse()
        # A link can be consumed by only one request, including across workers.
        transfer.flush_recordset(['used'])
        self.env.cr.execute(SQL(
            'UPDATE %s SET used = TRUE WHERE id = %s AND used IS NOT TRUE RETURNING id',
            SQL.identifier(self._table), transfer.id,
        ))
        if not self.env.cr.fetchone():
            return self.browse()
        transfer.invalidate_recordset(['used'])
        return transfer

    # ----------------------------------------------------------
    # Cron
    # ----------------------------------------------------------

    @api.autovacuum
    def _autovacuum_transfers(self) -> None:
        """Drop staged upload files a day past expiry, links with the audit log."""
        transfers = self.sudo()
        transfers.search(
            [
                ('expires_at', '<', fields.Datetime.now() - timedelta(days=1)),
                ('attachment_id.res_model', '=', False),
            ],
        ).attachment_id.unlink()
        limit = self.env['muk_mcp.log']._retention_limit()
        transfers.search([('create_date', '<', limit)]).unlink()
