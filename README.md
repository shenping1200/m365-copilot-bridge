# Copilot Bridge

把你的 Microsoft 365 Copilot 账号，变成一套**标准的 OpenAI / Anthropic 兼容 API**：聊天、流式输出、多模态、工具调用、会话记忆全支持。多账号统一网关，自带 Web 管理后台。

> 本工具只是"互通网关"，不是绕过验证的工具。你只能使用自己有权限的 Microsoft 账号与租户。

## 一句话能力清单

- 对外暴露 `/v1/chat/completions`、`/v1/responses`、`/v1/messages`（Anthropic）等标准接口
- 多账号轮询 + 故障转移，规避微软 per-account 限流
- **每个账号走独立代理 IP**
- 可创建**带有效期**的 API Key
- 实时统计每个账号的 **Token 用量（估算）**

下面重点讲你最关心的三个功能。

---

## 一、IP 代理功能（重点）

**为什么需要**：微软对单个账号有请求频率限制，还会关联同一出口 IP 下的多个账号。给每个账号配独立代理 IP，能分散请求、降低被风控的概率。

**作用范围**：填了代理的账号，其 ChatHub WebSocket 连接和令牌刷新都走该代理。**不填 = 直连**。

### 代理地址填写规则

系统会自动识别以下格式：

| 格式 | 说明 |
|---|---|
| `host:port` | 只写 `IP:端口`、不带协议头 → 默认按 **SOCKS5** |
| `socks5://host:port` | 标准 SOCKS5 |
| `socks5://user:pass@host:port` | SOCKS5 带账号密码（标准写法） |
| `socks5://host:port:user:pass` | SOCKS5 带账号密码（**非标准**，部分服务商常用） |
| `socks5h://host:port` | SOCKS5，由远程代理解析 DNS |
| `socks4://host:port` | SOCKS4 |
| `socks4://user:pass@host:port` | SOCKS4 带账号密码 |
| `http://host:port` | HTTP 代理（明文 CONNECT） |
| `http://user:pass@host:port` | HTTP 代理带账号密码 |
| `http://host:port:user:pass` | HTTP 代理带账号密码（**非标准**，部分服务商常用） |
| `https://host:port` | 真正用 TLS 包裹的代理（如 `12.180.8.60:443`） |

**两个易错点**：

- 很多代理服务商宣传"HTTPS 代理"，实际只是个 HTTP CONNECT 端点 → 请填 `http://`，填 `https://` 反而可能连不上。
- 密码里含 `@`、`:` 等特殊字符时，优先用"非标准四段式" `host:port:user:pass`，避免解析错乱。

**怎么验证**：账号行点「测试」可先验证代理是否可用（返回出口 IP 和延迟）；表格上方「🔍 一键检测」可批量探测所有已配代理的账号。

> 说明：HTTPS 代理只会对"连到代理这一段"跳过证书校验（支持过期/自签证书，和指纹浏览器行为一致），目标站（Microsoft）的 TLS 仍正常校验。

---

## 二、API Key 定时有效期

创建 Key 时可选择：

- **永久有效**：`days` 传 0 或留空
- **自定义天数**：填 N 天，到期时间 = 创建时刻 + N 天

到期后的 Key 在调用任何 `/v1/*` 接口时会返回 `401`，但在后台列表里仍然可见（标注"已过期"）。

后台支持随时改有效期：点「改有效期」→ 填天数 → 保存。`days=0` 即改回永久有效。

> 典型用途：临时给同事/客户开 Key，到期自动失效，不用手动回收。

---

## 三、Token 统计与估算说明

**为什么是"估算"**：微软 ChatHub 的返回结果里**没有 token 用量字段**，不像 OpenAI 那样直接给你 `usage`。所以这里的 Token 数字是我们自己算出来的，是"估算值"，不是官方计数。

**怎么算的**（已尽量贴近真实）：

- 对 `gpt-` 开头的模型，用真正的 **o200k_base** 分词器（词表内嵌、不联网）逐字分词。
- 对 M365 Copilot 等其它模型，用字符启发式：
  - 跳过空格/换行；
  - 英文等 ASCII：约 **4 个字符 = 1 token**（公式 `(长度+3)/4`）；
  - 中文等其它字符：**1 个字符 = 1 token**。
- 还把整段请求结构也算进去：每条消息的 role / content / name / 工具调用，加上工具 schema，再加上协议固定开销（每条消息 4 token、每工具 6 token、回复前缀 3 token 等），最后加上模型回复文本。

这套口径参考了社区通用实现，比单纯"总字数 ÷ 4"准很多，但**仍属估算**，适合看趋势、做配额判断，不要当成精确账单。

**统计口径**：

- 每个账号独立累计「发送 Token / 接收 Token」；
- 顶部汇总「总请求数 / 总发送 / 总接收」；
- 数字过大时自动用 `k` / `M` 单位显示。

---

## 快速开始

```bash
git clone https://github.com/shenping1200/m365-copilot-bridge.git
cd m365-copilot-bridge
docker compose build && docker compose up -d
```

打开 `http://127.0.0.1:4141/` → 登录 → 完成 Microsoft 授权 → 在后台创建 API Key。

调用示例：

```bash
curl http://127.0.0.1:4141/v1/chat/completions \
  -H 'Authorization: Bearer 你的KEY' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-5.6-reasoning","messages":[{"role":"user","content":"你好"}],"stream":true}'
```

## 安全提示

- 默认只监听本地 `127.0.0.1:4141`，对外暴露前务必加 TLS 和访问控制。
- 妥善保管 `secrets/`（管理员密码）与 `data/`（账号、token 缓存），不要提交或外泄。
- 仅使用你有权限的账号。

## License

MIT。
