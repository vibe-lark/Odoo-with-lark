"""Ensure app-scoped identity uniqueness is enforced by PostgreSQL."""


def migrate(cr, version):
    cr.execute('''
        SELECT pg_get_constraintdef(oid) FROM pg_constraint
        WHERE conrelid = 'mcp_feishu_binding'::regclass
          AND conname = 'mcp_feishu_binding_identity_unique' AND contype = 'u'
    ''')
    row = cr.fetchone()
    if not row or row[0] != 'UNIQUE (app_id, open_id)':
        raise RuntimeError('The Feishu application identity unique constraint was not installed.')
