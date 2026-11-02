"""Preserve existing identities without silently merging different accounts."""


def migrate(cr, version):
    cr.execute('''
        SELECT 1 FROM mcp_feishu_binding
        GROUP BY app_id, open_id HAVING count(*) > 1 LIMIT 1
    ''')
    if cr.fetchone():
        raise RuntimeError('Duplicate Feishu application identities need administrator review before upgrade. No bindings were merged.')
