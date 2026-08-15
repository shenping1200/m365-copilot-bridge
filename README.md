# Copilot Bridge

> Microsoft 365 Copilot **ChatHub 网关** —— 把微软 ChatHub（SignalR WebSocket）转成 **OpenAI / Anthropic 兼容 API**，让你手头的任意 OpenAI / Claude 客户端、脚本、Agent 框架都能直接调用 M365 Copilot。

⚠️ **合规说明**：本项目是「互通网关」，**不是**绕过鉴权的工具。你必须使用自己有权限的 Microsoft 账号与租户。上游模型可用性、配额、工具、视觉、生图能力，取决于你的账号与微软服务。

---

## 功能总览

- 💬 **多协议聊天 API**：OpenAI `/v1/chat/completions`、OpenAI Responses `/v1/responses`、Anthropic `/v1/messages`，支持流式 / 多模态 / 工具调用。
- 🔁 **多账号池与轮询**：多个 M365 账号统一调度，按请求 round-robin，自动分散限流；同一对话内锁定账号保证上下文连贯。
- 🌐 **每账号独立 IP 代理**（第三节，重点）：每个账号可配独立出口 IP，进一步降低被关联 / 触发风控概率。
- 🔑 **API Key 与定时有效期**（第四节，重点）：可创建带「永久 / N 天到期」的访问密钥，过期自动失效。
- 📊 **Token 统计估算**（第五节，重点）：在微软不返回 usage 的情况下给出可信的 token 用量参考。
- 🩺 **限流 / 健康自愈**：实时显示每个账号的鉴权 / 限流状态，429 自动冷却并切到健康号。
- 📜 **运行日志 / 设置 / Web 控制台**：内置管理员后台，五页式管理界面，开箱即用。

---

## 一、聊天 API 兼容层

把 ChatHub 私有协议转成业界通用接口，客户端无需关心微软内部实现：

| 接口 | 鉴权 | 说明 |
|---|---|---|
| `POST /v1/chat/completions` | `Bearer` / `X-API-Key` | OpenAI 兼容，支持 `stream` 流式、`session_key` 会话保持、`tools` 工具调用 |
| `POST /v1/responses` | 同上 | OpenAI Responses 兼容 |
| `POST /v1/messages` | `x-api-key` | Anthropic 兼容 |

- **流式输出**：`stream:true` 时按 SSE 逐块返回。
- **多模态**：图文混输随上游账号能力开放。
- **工具调用**：网关层做协议转换，把 OpenAI / Anthropic 工具格式转成 ChatHub 工具调用。
- **会话保持**：稳定传同一个 `session_key` 即可让同一段对话绑定到同一个上游会话（ConversationID / SessionID），刷新页面或换客户端都不丢上下文。

**模型路由**（公开 ID 为网关别名，实际能力由微软侧决定）：

| 公开模型 | 上游口吻 |
|---|---|
| `gpt-5.5` | `Gpt_5_5_Chat` |
| `gpt-5.5-reasoning` | `Gpt_5_5_Reasoning` |
| `gpt-5.6-reasoning` | `Gpt_5_6_Reasoning` |
| `claude-sonnet` | `Claude_Sonnet` |
| `claude-sonnet-reasoning` | `Claude_Sonnet_Reasoning` |

---

## 二、账号池与多账号调度

- **添加账号**：Web 控制台「添加账号」走内置 PKCE OAuth 流程，登录微软即完成授权，令牌缓存到本地 `data/`。
- **刷新令牌 / 删除账号**：每行可手动「刷新令牌」（延长有效期）；「删除」不可撤销，且会**一并清除该账号绑定的所有 `session_key` 会话映射**（避免删号后旧会话永久报错）。
- **多账号轮询**：未指定账号且无会话绑定时，请求在全部在线账号间 **round-robin**；同一 `session_key` 对话内锁定首次选中的账号，避免回答断片。开放客户端每轮都会重发完整 `messages` 历史，即使账号轮换模型也能看到全部上下文。
- **请求次数统计**：每个账号显示请求数，顶部有全账号「请求次数汇总」。计数为内存态，服务重启归零。
- **限流 / 健康状态**：账号表「限流状态」列实时显示 `正常 / 鉴权失败 / 限流冷却(Ns)`。触发限流的账号进入约 2 分钟冷却、自动退出轮询，并切到健康号（429 故障转移 / 自动自愈）。

---

## ⭐ 三、IP 代理（重点）

**用途**：为**每个账号**单独指定出口代理，实现每账号独立 IP。ChatHub 的 WebSocket 与该账号的 token 刷新都走对应代理；**不填则直连**。多账号 + 多 IP 能显著降低被微软关联、触发风控的概率。

### 代理填写规则

在账号行「代理」输入框填写以下任一格式（留空 = 直连）：

| 填写格式 | 说明 |
|---|---|
| `1.2.3.4:1080` | 纯 `host:port`，默认按 **SOCKS5** |
| `socks5://1.2.3.4:1080` | SOCKS5 标准写法 |
| `socks5://user:pass@1.2.3.4:1080` | SOCKS5 带账号密码（标准三段式） |
| `socks5://1.2.3.4:1080:user:pass` | SOCKS5 带账号密码（**非标准四段式**，部分服务商常用） |
| `socks5h://1.2.3.4:1080` | SOCKS5 + 远程 DNS（域名由代理解析） |
| `socks4://1.2.3.4:1080` | SOCKS4（可带 `user:pass@`） |
| `http://1.2.3.4:8080` | HTTP 代理（CONNECT 隧道） |
| `http://user:pass@1.2.3.4:8080` | HTTP 代理带账号密码 |
| `https://1.2.3.4:8443` | HTTPS 代理（真 TLS；仅对「连代理」这一段跳过证书校验，目标站仍正常校验） |

> 协议识别源码见 `internal/proxy/proxy.go`：`http(s)://` 与 `socks5/socks5h/socks4://` 均支持标准三段式 `[user:pass@]host:port` 与非标准四段式 `host:port:user:pass`；无 scheme 默认 SOCKS5。

### ⚠️ 两个易错点

1. **很多标着「HTTPS 代理」的服务，其实只是 HTTP CONNECT 端点** —— 这种应填 `http://`，填 `https://` 反而连不上（`https://` 仅用于真正以 TLS 监听客户端端口的代理）。
2. **密码里含 `@` 或 `:` 时**，标准三段式 `user:pass@host:port` 会解析错；请用四段式 `host:port:user:pass`（user / pass 里别再带 `:`）。

### 连通性测试

- **单账号测试**：填好代理点「测试」，返回出口 IP 与延迟（绿 ✓ / 红 ✗）。
- **一键批量检测**：账号列表「🔍 一键检测」并发探测所有已配代理的账号，每行内联结果，顶部横幅汇总「成功 N / 失败 M」，快速定位失效代理。
- **HTTPS 代理证书**：仅对「连到代理」这一段 `InsecureSkipVerify`（与指纹浏览器行为一致，兼容过期 / 自签代理证书）；目标站（Microsoft / ipify）TLS 仍正常校验。

---

## ⭐ 四、API Key 与定时有效期（重点）

访问密钥是给客户端（OpenAI / Claude SDK、curl、Agent 框架）调用 `/v1/*` 的凭证，支持 `Authorization: Bearer` 或 `X-API-Key` 两种头。

- **创建**：「访问配置」页填名称 + 有效期。`days > 0` = N 天后到期；`days ≤ 0` = **永久有效**。创建后密钥**仅显示一次**，自动复制到剪贴板，请妥善保存。
- **改有效期**：任意时刻可点「改有效期」（`PATCH /api/admin/keys`，`days ≤ 0` 改回永久），立即生效、无需重建。
- **撤销**：点「撤销」即刻失效（不可恢复）。
- **过期行为**：过期 Key 调用任何 `/v1/*` 返回 `401`，但在后台列表仍可见（标「已过期」）。
- **存储安全**：密钥以 **hash** 形式存于 `data/api-keys.json`，明文不落盘。

---

## ⭐ 五、Token 统计估算（重点）

微软 ChatHub 的返回里**没有 `usage` 字段**，拿不到精确 token 数，所以这里给出的是**估算值**（参考社区口径，非账单数字）。

- **估算算法**：
  - 模型名以 `gpt-` 开头 → 用 **o200k_base 真分词器**（tiktoken）逐 token 计数。
  - 其它模型 → 启发式：英文约 **4 字符 = 1 token**、中文 **1 字 = 1 token**（跳过空格），并对整段请求结构（角色 / 内容 / 工具 schema / 协议开销常量）一并计入，比「裸字符数 ÷ 4」准得多。
- **统计范围**：分别估算「发送（输入）」与「接收（输出）」token，账号表与顶部汇总卡均显示；**流式与非流式请求都会记账**（早期版本漏记流式，已修复）。
- **显示单位**：数字过大时用 `k`（千）/ `M`（百万）缩写，便于一眼看懂。
- **说明**：这是**参考用量**，不能当精确账单；若你要严格计费，请以上游微软账单为准。

---

## 六、运行日志

「运行日志」页拉取 `/api/admin/debug/logs`，可按等级（silent / error / warn / info / debug）过滤，显示每条请求的方法、路径、状态码、耗时与请求 ID，便于排查问题。

## 七、设置

「设置」页可在线修改运行参数（标「重启生效」的项需重启服务）：

| 分组 | 项 |
|---|---|
| 工具 | 每轮最大工具调用数、最大工具轮次 |
| 上下文 | 上下文窗口、最大输出 Token |
| 超时 | 聊天超时、图片超时（秒） |
| 日志 | 日志等级、调试日志路径 |
| 运行（重启生效） | 监听地址、账号配置路径、Token 缓存路径、会话缓存路径、OAuth Client ID / Authority / 回调地址 / Scope |

## 八、Web 控制台与登录

内置管理员后台，五页式：**账号池 / 添加账号 / 访问配置 / 运行日志 / 设置**。
- 首次用 `secrets/m365_admin_password` 里的管理员密码登录（Cookie 鉴权，非 token）。
- 根路由 `/` 设了 `Cache-Control: no-cache`，改完前端立即生效、不会卡旧页。

---

## 快速开始（Docker，推荐）

```bash
git clone https://github.com/shenping1200/m365-copilot-bridge.git
cd m365-copilot-bridge
mkdir -p data secrets
printf '%s\n' '换成你自己的长随机管理员密码' > secrets/m365_admin_password
chmod 600 secrets/m365_admin_password
docker compose build
docker compose up -d
```

默认监听 `127.0.0.1:4141` → 浏览器打开 `http://127.0.0.1:4141/` → 登录 → 完成微软授权 → 在「访问配置」创建 Key → 用 Key 调 `/v1`。

```bash
curl http://127.0.0.1:4141/v1/chat/completions \
  -H 'Authorization: Bearer YOUR_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-5.6-reasoning","messages":[{"role":"user","content":"你好"}],"stream":true}'
```

**持久化目录**（务必备份，含凭据）：
`./data/accounts.json`（OAuth 缓存）、`./data/token-cache.json`、`/data/sessions.json`、`/data/api-keys.json`、`secrets/m365_admin_password`。

---

## 配置项（环境变量）

| 变量 | 默认 | 用途 |
|---|---|---|
| `M365_LISTEN` | `127.0.0.1:4141` | 监听地址 |
| `M365_ADMIN_PASSWORD_FILE` | unset | 管理员密码文件 |
| `M365_CHAT_TIMEOUT_SECONDS` | `120` | 聊天超时 |
| `M365_IMAGE_TIMEOUT_SECONDS` | `150` | 图片超时 |
| `M365_MAX_TOOL_ROUNDS` | `16` | 最大工具轮次 |
| `M365_MAX_TOOL_CALLS_PER_TURN` | `1` | 每轮工具调用上限 |
| `M365_CONTEXT_WINDOW` | `128000` | 上下文窗口 |
| `M365_MAX_OUTPUT_TOKENS` | `16384` | 最大输出 token |

（其余路径类见「设置」页与 `.env.example`）

---

## 安全提示

- 默认只绑 localhost；对外暴露前务必加 **TLS 与访问控制层**。
- 首次部署立即改管理员密码。
- `data/`、`secrets/` 含凭据，绝不提交、不贴日志 / 截图。
- 仅使用你有权限的账号与租户。

## License

MIT。
