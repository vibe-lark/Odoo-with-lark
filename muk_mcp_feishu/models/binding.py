from __future__ import annotations

import hashlib

from psycopg2.errors import SerializationFailure, UniqueViolation

from odoo import api, fields, models
from odoo.exceptions import AccessError, UserError
from odoo.tools import email_normalize

from odoo.addons.muk_mcp_oauth21.tools.oauth import OAuthError


class FeishuBinding(models.Model):
    """An app-scoped identity linked to a unique, stable Odoo account."""

    _name = 'mcp.feishu.binding'
    _description = 'MCP Feishu User Binding'
    _rec_name = 'display_name'
    _order = 'create_date desc'

    name = fields.Char(string='飞书姓名', readonly=True)
    app_id = fields.Char(required=True, readonly=True, index=True)
    tenant_key = fields.Char(string='旧版企业标识（不再使用）', readonly=True, index=True)
    open_id = fields.Char(string='飞书用户标识', required=True, readonly=True, index=True)
    email_normalized = fields.Char(string='邮箱', required=True, readonly=True, index=True)
    pending_email = fields.Char(string='最近登录邮箱', readonly=True)
    odoo_user_id = fields.Many2one('res.users', string='Odoo 用户', ondelete='restrict')
    state = fields.Selection([
        ('pending', '未匹配'), ('confirmed', '已绑定'), ('blocked', '已停用'),
    ], string='状态', default='pending', required=True, index=True)
    active = fields.Boolean(default=True)
    status = fields.Selection([
        ('enabled', '已启用'), ('disabled', '已停用'), ('unmatched', '未匹配'),
    ], compute='_compute_status', string='状态')
    auth_version = fields.Integer(default=0, readonly=True, copy=False)
    approved_by = fields.Many2one('res.users', string='确认人', readonly=True, ondelete='set null')
    approved_at = fields.Datetime(string='确认时间', readonly=True)
    user_mcp_enabled = fields.Boolean(related='odoo_user_id.mcp_oauth_enabled', string='允许使用 MCP', readonly=False)
    conflict_reason = fields.Char(string='匹配说明', readonly=True)

    _identity_unique = models.Constraint('UNIQUE(app_id, open_id)', 'This Feishu identity already has a binding.')

    @api.depends('state', 'active', 'odoo_user_id', 'odoo_user_id.active',
                 'odoo_user_id.share', 'odoo_user_id.mcp_oauth_enabled')
    def _compute_status(self):
        for binding in self:
            if not binding.active or binding.state == 'blocked':
                binding.status = 'disabled'
            elif binding.state != 'confirmed' or not binding.odoo_user_id:
                binding.status = 'unmatched'
            elif not binding.odoo_user_id._mcp_oauth_eligible():
                binding.status = 'disabled'
            else:
                binding.status = 'enabled'

    def _lock(self):
        self.ensure_one()
        self.env.cr.execute('SELECT id FROM mcp_feishu_binding WHERE id = %s FOR UPDATE', (self.id,))
        self.invalidate_recordset()

    @api.model
    def _lock_identity(self, app_id, open_id):
        identity_key = int.from_bytes(hashlib.sha256((app_id + '\0' + open_id).encode()).digest()[:8], 'big', signed=True)
        self.env.cr.execute('SELECT pg_advisory_xact_lock(%s)', (identity_key,))

    @api.depends('name', 'email_normalized')
    def _compute_display_name(self):
        for record in self:
            record.display_name = '%s <%s>' % (record.name or 'Feishu user', record.email_normalized or '')

    @api.model
    def _candidate_users(self, email):
        users = self.env['res.users'].sudo().with_context(active_test=False)
        domain = [('active', '=', True), ('share', '=', False)]
        if 'email_normalized' in self.env['res.partner']._fields:
            domain.append(('partner_id.email_normalized', '=', email))
        else:
            domain.append(('email', '=ilike', email))
        return users.search(domain).filtered(lambda user: email_normalize(user.email or '') == email)

    @api.model
    def _create_identity(self, values):
        try:
            with self.env.cr.savepoint():
                return self.sudo().create(values)
        except UniqueViolation:
            # A repeatable-read transaction may retain its pre-lock snapshot.
            # Never reassign an identity or continue on a stale first-login race.
            raise OAuthError('temporarily_unavailable', '另一条连接正在建立此账号绑定，请重新发起连接。', 503) from None

    @api.model
    def _resolve_identity(self, userinfo, app_id):
        """Automatically match email while preserving account and disable boundaries."""
        open_id = userinfo.get('open_id')
        raw_email = userinfo.get('email')
        email = email_normalize(raw_email) if isinstance(raw_email, str) else False
        if (not isinstance(app_id, str) or not app_id or not isinstance(open_id, str)
                or not open_id or not email):
            raise OAuthError('access_denied', 'Feishu did not provide a valid user email. Check the user-email permission.', 403)
        # Serialize first-login creation across workers as well as updates to an
        # existing identity. The database unique constraint remains authoritative.
        self._lock_identity(app_id, open_id)
        binding = self.sudo().with_context(active_test=False).search([
            ('app_id', '=', app_id), ('open_id', '=', open_id),
        ], limit=1)
        if binding:
            try:
                with self.env.cr.savepoint():
                    binding._lock()
            except SerializationFailure:
                # Initial identity codes have already been exchanged. Do not
                # let a framework retry consume that same provider code again.
                raise OAuthError('access_denied', '登录期间账号状态发生变化，请重新发起连接。', 403) from None
            if not binding.active or binding.state == 'blocked':
                raise OAuthError('access_denied', '此账号绑定已停用，请联系管理员启用后重新连接。', 403)
        candidates = self._candidate_users(email)
        wrong_user = bool(binding.odoo_user_id and candidates != binding.odoo_user_id) if binding else False
        if len(candidates) != 1 or wrong_user:
            reason = ('当前邮箱与原绑定的 Odoo 账号不一致，不能自动更换账号' if wrong_user and len(candidates) == 1
                      else '没有启用的内部账号匹配此邮箱' if not candidates
                      else '多个内部账号使用此邮箱，请先处理冲突')
            if binding:
                binding.write({'state': 'pending', 'pending_email': email, 'conflict_reason': reason})
            else:
                self._create_identity({'name': userinfo.get('name') or '', 'app_id': app_id,
                    'open_id': open_id, 'email_normalized': email, 'state': 'pending', 'conflict_reason': reason})
            raise OAuthError('access_denied', reason + '。修正账号邮箱后，请重新连接。', 403)
        user = candidates
        values = {'state': 'confirmed', 'odoo_user_id': user.id, 'email_normalized': email,
                  'pending_email': False, 'conflict_reason': False}
        if binding:
            if any(binding[field] != value for field, value in values.items() if field != 'odoo_user_id') or binding.odoo_user_id != user:
                binding.with_context(mcp_binding_activation=True).write(values)
        else:
            binding = self._create_identity({'name': userinfo.get('name') or '', 'app_id': app_id,
                'open_id': open_id, **values})
        if not user._mcp_oauth_eligible():
            raise OAuthError('access_denied', '此 Odoo 账号未启用 MCP，请联系管理员启用后重新连接。', 403)
        return user, binding

    def _require_admin(self):
        if not (self.env.su or self.env.user.has_group('base.group_system')):
            raise AccessError(self.env._('Only system administrators can manage employee bindings.'))

    def action_enable(self):
        self._require_admin()
        config = self.env['mcp.feishu.config']._get_config()
        for binding in self.sorted('id'):
            # User settings can revoke grants while holding the user row.
            # Never wait for that row while already holding the binding lock.
            candidates = binding._enable_candidate(config)
            if not candidates.mcp_oauth_enabled:
                candidates.write({'mcp_oauth_enabled': True})
            binding._lock()
            email = binding.pending_email or binding.email_normalized
            candidates = binding._enable_candidate(config)
            binding.with_context(mcp_binding_activation=True).write({
                'state': 'confirmed', 'active': True, 'odoo_user_id': candidates.id,
                'conflict_reason': False, 'email_normalized': email, 'pending_email': False,
            })
        return True

    def _enable_candidate(self, config):
        self.ensure_one()
        candidates = self._candidate_users(self.pending_email or self.email_normalized)
        if (config.app_id != self.app_id or len(candidates) != 1
                or (self.odoo_user_id and candidates != self.odoo_user_id)):
            raise UserError(self.env._('邮箱必须唯一匹配一个启用的内部 Odoo 账号，且不能更换已绑定的账号。'))
        return candidates

    def action_disable(self):
        self._require_admin()
        self.write({'state': 'blocked'})
        return True

    def write(self, values):
        self._require_admin()
        if values.get('state') == 'confirmed' and not self.env.context.get('mcp_binding_activation'):
            raise AccessError(self.env._('请使用启用操作管理绑定状态。'))
        result = True
        for binding in self.sorted('id'):
            binding._lock()
            if 'odoo_user_id' in values and binding.odoo_user_id and binding.odoo_user_id.id != values['odoo_user_id']:
                raise UserError(self.env._('已绑定的身份不能更换 Odoo 账号。'))
            invalidate = (values.get('state') == 'blocked' or values.get('active') is False
                          or (values.get('state') == 'pending' and binding.state == 'confirmed'))
            update = dict(values)
            if invalidate:
                update['auth_version'] = binding.auth_version + 1
            result = super(FeishuBinding, binding).write(update) and result
            if invalidate:
                binding._revoke_grants()
        return result

    def _revoke_grants(self):
        # Refresh locks its grant before reading the binding. Do not wait on
        # those rows in the opposite order; auth_version invalidates even an
        # in-flight grant permanently when this binding is enabled again.
        if not self:
            return
        try:
            with self.env.cr.savepoint():
                self.env.cr.execute('''
                    SELECT id FROM mcp_oauth_grant
                    WHERE provider_data->>'provider' = 'feishu'
                      AND provider_data->>'binding_id' = ANY(%s) AND revoked_at IS NULL
                    ORDER BY id FOR UPDATE SKIP LOCKED
                ''', ([str(value) for value in self.ids],))
                self.env['mcp.oauth.grant'].sudo().browse([row[0] for row in self.env.cr.fetchall()])._revoke()
        except SerializationFailure:
            # A completed last-used update can conflict with an older snapshot.
            # Keep the already-written binding version and disable state; they
            # invalidate these grants even when the audit timestamp is skipped.
            return

    @api.model
    def _auto_bind_existing(self):
        """Migrate unambiguous existing matches without granting new user rights."""
        self._require_admin()
        config = self.env['mcp.feishu.config']._get_config()
        activated = self.browse()
        for binding in self.with_context(active_test=False).search([
                ('state', '=', 'pending'), ('active', '=', True), ('app_id', '=', config.app_id)]):
            binding._lock()
            if not binding.odoo_user_id or binding.pending_email:
                continue
            if self._candidate_users(binding.email_normalized) != binding.odoo_user_id:
                continue
            binding.with_context(mcp_binding_activation=True).write({'state': 'confirmed', 'conflict_reason': False})
            activated |= binding
        return activated

    @api.model
    def action_open_bindings(self):
        self._require_admin()
        return {'type': 'ir.actions.act_window', 'name': '用户绑定', 'res_model': self._name,
                'view_mode': 'list,form', 'target': 'current'}
