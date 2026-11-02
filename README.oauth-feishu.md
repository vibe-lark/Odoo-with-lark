# Odoo MCP：OAuth 2.1 与飞书 SSO

在 MuK MCP 的业务工具上增加 OAuth 授权和飞书企业自建应用登录。员工使用自己的飞书身份连接 MCP，服务通过邮箱唯一匹配并自动关联该员工的 Odoo 用户，无需员工创建或填写 MCP API Key。

本分支面向 Odoo Community 20.0。扩展通过 Odoo 的模型、控制器和视图继承机制实现，所有代码位于本仓库，不需要修改 Odoo 核心源码。

## 模块

| 模块 | 职责 |
| --- | --- |
| `muk_mcp` | 原有工具、协议传输、统一认证主体、审计与一次性文件传输 |
| `muk_mcp_access` | 模型读写白名单和记录范围 |
| `muk_mcp_oauth21` | OAuth 发现、客户端注册、PKCE 授权码、令牌、续期、撤销与员工访问策略 |
| `muk_mcp_feishu` | 飞书应用配置、SSO、员工绑定和管理页面 |

## 授权流程

1. 客户端访问 `/api/mcp`，收到 `401` 和资源发现地址。
2. 客户端通过发现元数据获取授权端点，并注册客户端或使用已登记的客户端。
3. 授权入口校验客户端、回调地址、resource、范围和 S256 后，直接跳转飞书登录，不显示 Odoo 中间确认页。两段授权各自使用独立的 state 和 PKCE S256。
4. 服务从飞书获取登录用户身份，以邮箱唯一匹配一个启用的 Odoo 内部用户并自动建立身份关联。员工还须具备独立的 MCP 使用权限；登录流程不会自动开通该权限。
5. 服务返回一次性 MCP 授权码，客户端携带 PKCE verifier 换取 MCP access/refresh token。
6. 工具调用按映射员工的 Odoo ACL、记录规则、MCP 模型策略和授权范围共同执行。

飞书令牌与 MCP 令牌分别管理。飞书凭证仅保留在服务端，MCP 客户端获得本服务签发的令牌。

## 安装

将本仓库目录加入 Odoo 20 的 `addons_path`。使用 Odoo 已配置的 Python 环境和数据库安装：

```bash
python odoo-bin -c /path/to/odoo.conf -d YOUR_DATABASE \
  -i muk_mcp_feishu,muk_mcp_access --stop-after-init
```

已有 MuK MCP 数据库应同时升级基础模块，使新增的认证与文件字段生效：

```bash
python odoo-bin -c /path/to/odoo.conf -d YOUR_DATABASE \
  -u muk_mcp -i muk_mcp_feishu,muk_mcp_access --stop-after-init
```

完成模块安装后启动 Odoo。先在备份或隔离环境中验证，再安装到实际业务数据库。

## 管理员配置

在 **设置 → MCP → 飞书与 OAuth** 中配置企业自建应用。此配置对当前 Odoo 数据库共享，由系统管理员组维护，不依赖某个固定登录名。

1. 填写 App ID 和 App Secret，设置对外的 HTTPS 服务地址。
2. 将自动生成的飞书回调地址登记到飞书应用的安全设置中，开放用户邮箱与持续授权所需权限，并将应用发布到需要使用的员工范围。
3. 检查应用凭证，再以管理员会话发起试用飞书登录。
4. 试用登录验证成功后，启用飞书 OAuth。
5. 在用户的「MCP 访问」标签中设置允许使用 MCP、最大授权范围和调用限额。员工登录时按邮箱自动关联账号；管理员也可在「用户绑定」中点击「启用」，显式开通已匹配员工的 MCP 使用权限。

顶部以箭头串联「1 检查应用凭证 → 2 试用飞书登录」。已完成步骤显示勾选标记，当前可执行步骤突出显示；窄屏按纵向排列。完成登录验证前，启用开关保持只读并显示下一步提示；已启用时始终可以关闭。服务不配置或校验飞书企业标识，也没有企业确认步骤。

首次安装还需配置 MCP 模型访问规则。上游 `muk_mcp_access` 在白名单为空时允许访问员工原生权限可见的模型；建立显式白名单后，仅开放列出的模型。已有数据库的模型访问规则继续生效。

`App Secret` 是写入式配置：读取页面不返回原密钥，留空保留现有值。应用凭证检查只证明应用身份可用；获取用户邮箱和回调由试用登录验证。检查成功后页面会自动刷新状态与后续操作入口。

飞书应用所需的用户授权范围是 `contact:user.email:readonly offline_access`。应以实际开放平台的权限审批与应用发布状态为准。

## 身份与权限

飞书 `email` 是通讯录联系方式。本实现按已配置应用返回的邮箱自动关联 Odoo 账号，因此应用可用范围和员工邮箱应由企业统一维护。服务仅在邮箱唯一匹配一个启用的内部用户时，建立 `app_id + open_id → Odoo user_id` 的持久关联。未知或重复邮箱、停用账号、门户账号、未开通 MCP 和被停用的绑定均拒绝授权。

用户绑定页仅提供「启用」和「停用」两个操作，展示「已启用」「已停用」「未匹配」三种状态。「最近登录邮箱」记录本次身份匹配所用的邮箱，「匹配说明」提示无法登录的原因。未知或重复邮箱需要先修正 Odoo 账号数据；点击「启用」不会绕过唯一匹配检查。

自动登录和邮箱关联不会更改员工的 `mcp_oauth_enabled` 权限。管理员在用户设置中开通该权限，或在绑定页点击「启用」显式开通；授权范围和调用限额仍由员工的 MCP 访问设置控制。管理员可以提前停用尚未匹配的飞书身份，此后即使出现匹配账号，也须显式点击「启用」才能恢复。

旧版企业字段仅保留历史数据，不再显示或参与鉴权。升级到此身份键时会检查重复的应用用户标识；若存在冲突则中止升级，不会自动合并或更改绑定账号。

实际业务权限为：

```text
员工 Odoo 权限与记录规则 ∩ OAuth 授权范围 ∩ MCP 模型白名单与记录范围
```

OAuth 的 `mcp:write` 不会自动开放模型写权限。管理员仍需在 MCP 模型访问规则中明确配置相关模型。目录中能发现某个工具，也不代表已经获得执行该操作的权限。

管理员可撤销单个客户端授权或停用员工的 MCP 权限；员工可撤销自己的授权。文件链接绑定到签发它的授权，授权撤销或员工被停用后也不能继续兑换。已有 API Key 可以通过兼容开关逐步迁移。

已关联的身份不会自动切换到另一个 Odoo 用户。后续登录邮箱变化时，服务会重新检查邮箱是否仍唯一匹配原账号；未知邮箱、重复邮箱或匹配到其他账号时拒绝授权，并展示最近登录邮箱及匹配说明。停用绑定会撤销其已有授权，后续登录不会自动恢复；修正账号数据后，由管理员点击「启用」恢复访问。

## 接口

| 地址 | 用途 |
| --- | --- |
| `/.well-known/oauth-protected-resource/api/mcp` | RFC 9728 资源发现 |
| `/.well-known/oauth-authorization-server` | RFC 8414 授权服务发现 |
| `/mcp/oauth/register` | RFC 7591 动态注册 |
| `/mcp/oauth/authorize` | 校验授权请求并直接跳转飞书登录（GET） |
| `/mcp/oauth/token` | 授权码兑换与刷新轮换 |
| `/mcp/oauth/revoke` | RFC 7009 撤销 |
| `/mcp/oauth/feishu/callback` | 飞书登录回调 |
| `/api/mcp` | 原有 MCP 工具、资源和提示词 |

授权响应包含 `iss`；授权码和令牌绑定当前 MCP resource、客户端和授权。仅支持授权码流程与 S256 PKCE，不提供密码授权或 implicit flow。公共客户端采用 `none`，机密客户端支持 `client_secret_basic` 与 `client_secret_post`。

MCP 客户端与范围按服务端策略自动校验，没有单独的 Odoo 客户端同意页面；飞书页面负责飞书应用登录授权。客户端注册沿用动态注册开关或管理员预登记配置。员工账号按邮箱自动关联，管理员管理绑定启停、员工 MCP 使用权限和最大授权范围。

CIMD 客户端元数据地址须由管理员批准其 HTTPS 主机。在系统参数 `mcp_oauth.cimd_hosts` 中填写逗号分隔的主机名即可配置允许列表；动态注册可由 `mcp_oauth.allow_dynamic_registration` 控制。实现会验证地址、固定解析到的公共 IP、检查 TLS、限制响应大小且拒绝重定向，避免元数据请求访问内部资源。未配置允许的主机时，不宣称支持 CIMD；可使用动态注册或预登记客户端。

OAuth 授权、令牌、回调及 OAuth 文件链接会检查请求的实际 HTTPS 状态。反向代理部署需启用 Odoo `proxy_mode`、提供可信的 `X-Forwarded-Host` / `X-Forwarded-Proto`，并将 Odoo 后端限制到可信代理。多个数据库应使用明确的数据库筛选与各自的入口，避免一个入口任意切换数据库。

## 凭证和运行状态

授权状态保存于 PostgreSQL，授权码和 MCP token 只保存哈希。授权码兑换、刷新轮换和一次性文件消费使用数据库并发控制。OAuth 调用限额按员工与客户端计数，多个 worker 共享额度，刷新令牌不会重置限额。

飞书应用密钥和用户刷新凭证使用 Fernet 加密。加密主密钥优先从服务环境变量 `MCP_OAUTH_ENCRYPTION_KEY` 或 Odoo 配置 `mcp_oauth_encryption_key` 读取；未指定时，在 Odoo `data_dir/mcp_oauth/master.key` 自动创建仅服务用户可读的密钥文件。多实例必须使用相同的外部主密钥。

数据库备份恢复时须同时恢复该外部主密钥；丢失主密钥后，已有飞书凭证无法解密，需要重新配置应用和授权。真实密钥、令牌、私有配置及本机证书不应加入 Git。

管理员无需配置访问令牌分钟数或授权会话天数。服务按飞书每次返回的 `expires_in` 和 `refresh_token_expires_in` 自动计算 MCP 访问与刷新凭证的期限；刷新后跟随新的飞书期限，不再额外施加固定 7 天上限。缺少可用刷新凭证或可信刷新期限时，仅签发本次访问期限内的凭证，到期后重新授权。

飞书凭证在 MCP 续期时自动轮换并复核用户身份。飞书侧失去授权在后续刷新/身份复核时生效；需要即时同步离职状态时，应另接企业事件同步。Odoo 员工停用、MCP 权限停用和本地授权撤销在后续请求中检查。

飞书用户授权码兑换和刷新使用 `https://open.feishu.cn/open-apis/authen/v2/oauth/token`，以 JSON 传参并保留 S256 PKCE 校验。管理员的 App ID / App Secret 检查单独使用 v3 `client_credentials` 接口。对外的 MCP 授权协议仍为 OAuth 2.1。

飞书登录固定申请 `offline_access contact:user.email:readonly` 两项用户授权，以空格分隔并在 URL 中编码为 `%20`。服务只记录这两项权限是否实际获批、邮箱字段是否存在及格式是否有效，不记录 Token、邮箱值或原始响应。平台后台开通权限与本次用户令牌实际获批的范围须分别核对。

从使用飞书 v3 用户令牌接口的旧版本升级时，已有客户端应重新完成飞书授权，以获得 v2 签发的刷新凭证；不能直接用 v3 刷新凭证请求 v2 续期。

## 客户端接入

在豆包工作中选择 MCP OAuth 2.1，填写当前服务的 HTTPS `/api/mcp` 地址，并按平台的 OAuth 接入约定使用访问令牌。员工点击连接后完成飞书登录及授权。

Codex 使用支持 OAuth 的 HTTP MCP 配置：

```toml
[mcp_servers.odoo]
url = "https://YOUR_MCP_HOST/api/mcp"
```

OAuth 模式由客户端管理令牌，不填写固定 `Authorization`。旧 API Key 模式的 Codex 字段是 `http_headers.Authorization`。

## 开发与发布

本分支以 MuK IT 的 LGPL-3 源码为基础，保留原作者、许可证与上游模块结构。新增模块也采用 LGPL-3。运行数据、连接凭证和测试报告位于 `.local/`，并通过版本化的 `.gitignore` 排除。

代码验证包括独立测试数据库中的 HTTP 授权与权限测试、纯协议安全边界测试及原有 API Key/文件传输回归。真实飞书账号和客户端的端到端联调需要管理员填写应用凭证后进行；模拟上游测试不代表已验证实际应用的权限审批、发布范围或企业网络。

纯协议与日志脱敏测试可直接运行：

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```

Odoo 集成测试单独放在 `tests/odoo_addons/mcp_oauth_validation`。仅在临时测试数据库中，将该目录的父目录加入 `addons_path`，安装测试模块并运行：

```bash
python odoo-bin -c /path/to/isolated-test.conf -d MCP_TEST_DATABASE \
  -i mcp_oauth_validation --test-enable --test-tags /mcp_oauth_validation \
  --without-demo=all --stop-after-init
```

该测试模块通过真实 HTTP 和 ORM 验证发现、注册、浏览器绑定、PKCE、令牌、用户权限和文件功能；只有飞书上游请求采用模拟数据。测试数据库应禁用定时任务并使用不可投递的 SMTP 配置。

准备向另一个仓库交付时可运行：

```bash
python scripts/build_source_archive.py
```

生成的 `.local/odoo-mcp-oauth-feishu-source.zip` 仅包含五个业务扩展、测试、源码文档、许可证和构建脚本，并将本文作为新仓库的 `README.md`。它不带本地连接状态、Devbox 运维资料或开发证书。脚本还会拒绝源码中的长 Bearer 凭证字面量。

参考：[MCP 授权规范](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)、[飞书用户信息](https://open.feishu.cn/document/server-docs/authentication-management/login-state-management/get.md)、[飞书用户令牌 v2](https://open.feishu.cn/document/authentication-management/access-token/get-user-access-token)、[飞书刷新用户令牌](https://open.feishu.cn/document/authentication-management/access-token/refresh-user-access-token)。

飞书拒绝请求时，登录页会标明失败接口、HTTP 状态和安全错误码；不会复制可能含凭证的原始错误描述。管理员试用登录失败时返回设置页处理，员工账号绑定的提示仅用于对应阶段。
