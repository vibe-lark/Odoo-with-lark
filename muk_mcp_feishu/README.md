# MCP Feishu SSO

Odoo 20 extension for `muk_mcp_oauth21`. Configure the enterprise self-built
application in **Settings → MCP → 飞书与 OAuth**. Only system administrators can
edit the shared application credentials or employee bindings.

1. Set the Feishu App ID and App Secret. An empty secret input preserves the
   encrypted existing secret; saved plaintext is never returned by the form.
2. Set the public HTTPS origin and register the displayed callback URL in
   Feishu. Publish the application to the intended employees with
   `contact:user.email:readonly` and `offline_access` user permissions.
3. Check the application credentials, then run an administrator trial login.
   The trial requires the initiating Odoo administrator session and an
   independent short-lived browser cookie. It verifies login and user email,
   but **does not issue any MCP grant**.
4. Enable Feishu OAuth after the trial succeeds. There is no enterprise
   confirmation, tenant configuration or tenant allowlist.
5. Employees start the MCP client's OAuth flow. An email that uniquely matches
   an existing active internal Odoo user automatically creates the stable
   `(app_id, open_id)` association. The employee must also have independent
   MCP access enabled; login never grants that permission automatically.
   No Odoo users or legacy API keys are created automatically.

Feishu email is directory contact data. This module uses it for automatic account
matching, so the enterprise should centrally maintain the application's eligible
employees and their Odoo email addresses. Unknown or duplicate emails cannot
sign in. Once an identity is associated with an Odoo user, subsequent email
changes cannot automatically switch it to a different account.

The user-binding page exposes only **启用** (Enable) and **停用** (Disable), with
the statuses **已启用** (Enabled), **已停用** (Disabled), and **未匹配** (Unmatched).
The latest login email and matching explanation help administrators resolve
unknown, duplicate, or conflicting account data. Identity fields and the linked
Odoo user are read-only.

Automatic matching does not change the user's `mcp_oauth_enabled` permission.
An administrator may enable it in the user's MCP access settings or explicitly
open access with the binding's **启用** action. That action still requires a
unique eligible account match and does not bypass identity checks. Administrators
can also disable an unmatched identity; it remains disabled even if a matching
account is created later, until explicitly enabled again.

Legacy tenant fields are retained for upgrade history only and never affect
authorization. Before replacing the unique identity constraint, upgrades reject
duplicate application/open-ID bindings instead of silently merging accounts.

Subsequent logins record the latest email and require it to match the same
original Odoo user uniquely. Unknown or duplicate emails, or an email belonging
to another Odoo account, prevent authorization and display a matching explanation.
The **停用** action revokes the binding's existing grants. Login does not reopen a
disabled binding; after resolving account data, an administrator must explicitly
use **启用**, and the employee authorizes a new client connection.

Tokens and PKCE verifiers are encrypted using the OAuth module's master key,
stored outside the database/repository. Feishu access/refresh tokens remain
server-side. MCP refresh rechecks the stable identity and refreshes the Feishu
credential when necessary; a revoked upstream authorization requires login
again. Odoo account deactivation, MCP access removal, binding suspension and
local grant revocation are checked on each MCP request. Feishu-only account
changes are detected at the next upstream refresh/user-info check, not through
an instantaneous employee event subscription.

The module does not add a Feishu button to the ordinary Odoo password login.
SSO here is the MCP authorization login. OAuth write scope is additionally
restricted by the employee's maximum scope and the existing model allowlist.

See the repository OAuth deployment guide for setup, client discovery, tests
and master-key backup. Keep App Secret and encryption keys out of Git.
