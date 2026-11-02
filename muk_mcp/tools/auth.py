"""Credential-neutral request helpers for API keys and OAuth grants."""
from __future__ import annotations

from odoo.http import request


def get_mcp_principal():
    """Return the credential authenticated by ``auth=mcp``, if in a request.

    The fallback keeps integrations which set the former API-key attribute
    working while authentication providers adopt the principal interface.
    """
    if not request:
        return None
    return getattr(request, '_mcp_principal', None) or getattr(request, '_mcp_key', None)
