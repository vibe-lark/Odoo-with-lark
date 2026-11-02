# Odoo with Lark / Feishu SSO

为 Odoo Community 20 的 MuK MCP 服务增加 MCP OAuth 2.1 和飞书自建应用 SSO。员工用自己的飞书身份登录，按邮箱自动关联现有 Odoo 内部账号，无需手动生成 MCP Key。

- MCP OAuth 发现、客户端注册、S256 PKCE、令牌自动刷新与撤销。
- 管理员在 Odoo「设置 → MCP → 飞书与 OAuth」集中配置应用。
- 员工权限沿用 Odoo ACL、记录规则、MCP 模型白名单和授权范围。
- 身份自动绑定，支持管理员启用/停用；兼容已有 API Key。
- 通过 Odoo 扩展模块实现，无需修改 Odoo 核心源码。

**[安装、配置和开发说明](README.oauth-feishu.md)** · [OAuth 模块](muk_mcp_oauth21) · [飞书 SSO 模块](muk_mcp_feishu)

本仓库 fork 自 [MuK IT / odoo-modules](https://github.com/muk-it/odoo-modules)，保留上游提交历史、作者声明和 LGPL-3 许可证。本次集成基于上游 `20.0` 分支的 `2e7c56034085a24e6293a90a10d404897e4245d7`。下方保留上游项目说明。

---

## MuK Odoo Modules

[![License LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue?style=flat-square)](LICENSE)
[![Odoo 20.0](https://img.shields.io/badge/Odoo-20.0-714B67?style=flat-square)](https://github.com/muk-it/odoo-modules/tree/20.0)
[![Website mukit.at](https://img.shields.io/badge/Website-mukit.at-243742?style=flat-square)](https://www.mukit.at)
[![Apps Store](https://img.shields.io/badge/Apps-Store-243742?style=flat-square)](https://apps.odoo.com/apps/modules/browse?price=Paid&series=20.0&author=MuK+IT)
[![YouTube](https://img.shields.io/badge/YouTube-Follow-243742?style=flat-square)](https://www.youtube.com/@mukitgmbh)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Follow-243742?style=flat-square)](https://www.linkedin.com/company/mukit)
[![Facebook](https://img.shields.io/badge/Facebook-Follow-243742?style=flat-square)](https://www.facebook.com/mukitgmbh)
[![X](https://img.shields.io/badge/X-Follow-243742?style=flat-square)](https://x.com/mukitgmbh)

Free and open source modules for Odoo 20.0 by MuK IT, an Austrian Odoo partner
in Vienna. Each folder is one module, with its own README.

More modules, with 30 days of support from the date of purchase, are on the
[Odoo Apps Store](https://apps.odoo.com/apps/modules/browse?price=Paid&series=20.0&author=MuK+IT).

## Installation

To install this module, you need to:

Download the module and add it to your Odoo addons folder. Afterward,
log on to your Odoo server and go to the Apps menu. Trigger the debug
mode and update the list by clicking on the "Update Apps List" link. Now
install the module by clicking on the install button.

## Upgrade

To upgrade this module, you need to:

Download the module and add it to your Odoo addons folder. Restart the
server and log on to your Odoo server. Select the Apps menu and upgrade
the module by clicking on the upgrade button.

## Support

Issues and pull requests are welcome. A module built for your process, an
integration or a fix on a deadline is paid work, quoted up front. Maintained by
[MuK IT GmbH](https://www.mukit.at), Vienna. Contact: sale@mukit.at
