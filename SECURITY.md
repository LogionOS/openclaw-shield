# LogionOS Shield — Security Model

> "谁来守卫守卫者" (Quis custodiet ipsos custodes?)

Shield 保护 OpenClaw 用户，但如果 Shield 自身被攻破，反而会成为最大突破口。本文档系统性列出 Shield 的自身攻击面及对应防御措施。

---

## 1. 威胁模型总览

```
┌──────────────────────────────────────────────────────────────┐
│                    ATTACKER SURFACE MAP                      │
│                                                              │
│  ① API 连接层          ② Dashboard 层         ③ 运行时层     │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐ │
│  │ MITM/Spoofing│     │ XSS/CSRF     │     │ ReDoS        │ │
│  │ API Redirect │     │ Auth Bypass  │     │ OOM          │ │
│  │ SSRF         │     │ Info Leak    │     │ Fail-Open    │ │
│  │ Key Exposure │     │ Rate Abuse   │     │ Bypass       │ │
│  └──────────────┘     └──────────────┘     └──────────────┘ │
│                                                              │
│  ④ 供应链层            ⑤ 本地数据层           ⑥ 逻辑层       │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐ │
│  │ npm Tamper   │     │ Audit Tamper │     │ Kill Switch  │ │
│  │ Dependency   │     │ Config Leak  │     │ Race Window  │ │
│  │ Code Inject  │     │ PII in Logs  │     │ Policy Gap   │ │
│  └──────────────┘     └──────────────┘     └──────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. 攻击向量 × 防御措施

### ① API 连接层

| 攻击 | 描述 | 防御 | 实现 |
|------|------|------|------|
| **MITM** | 攻击者截取 Shield ↔ LogionOS API 通信 | 强制 TLS | `requireTls()` — enforce/strict 模式下非 localhost 必须 HTTPS |
| **API 欺骗** | 将 API endpoint 指向恶意服务器，返回全部 PASS | 端点验证 + 不跟随重定向 | `validateApiEndpoint()` 阻断 metadata 端点；`redirect: "error"` |
| **SSRF** | 通过 API endpoint 配置访问内网 | 黑名单 + 路径限制 | 阻断 169.254.169.254 等 metadata 端点；强制 `/v1/` 路径前缀 |
| **密钥泄露** | API Key 暴露在日志/错误信息中 | 日志脱敏 | `scrubForLog()` 自动替换 apiKey/token/secret 字段 |
| **DNS Rebinding** | 通过 DNS 重绑定绕过 TLS 检查 | API 端点在启动时验证一次并锁定 | 构造函数中 `validateApiEndpoint()` |

### ② Dashboard 层

| 攻击 | 描述 | 防御 | 实现 |
|------|------|------|------|
| **XSS** | 通过审计数据注入恶意脚本 | CSP 策略 | `Content-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-inline'...` |
| **CSRF** | 诱导管理员浏览器修改 Shield 配置 | CSRF Token | 每次启动生成随机 token，注入 HTML；状态变更 API 验证 `X-CSRF-Token` 头 |
| **点击劫持** | 在 iframe 中嵌入 Dashboard | 框架保护 | `X-Frame-Options: DENY` + `frame-ancestors 'none'` |
| **暴力攻击** | 高频请求 Dashboard API | 速率限制 | `checkDashboardRate()` — 120 请求/分钟/IP |
| **信息泄露** | 响应头暴露服务器信息 | 安全头 | `X-Content-Type-Options: nosniff` + `Referrer-Policy: no-referrer` |
| **CORS 滥用** | 跨域 API 访问 | 移除通配符 CORS | 已删除 `Access-Control-Allow-Origin: *` |

### ③ 运行时层

| 攻击 | 描述 | 防御 | 实现 |
|------|------|------|------|
| **ReDoS** | 精心构造的字符串导致正则引擎指数级回溯 | 输入长度限制 + 迭代上限 | `safeTruncate()` 截断 50K；regex 循环 500 次上限 |
| **Unicode 绕过** | 使用零宽字符/同形字绕过 PII 检测 | Unicode 规范化 | `normalizeInput()` — NFKC 规范化 + 剥离零宽字符 |
| **OOM** | 发送超大文本耗尽内存 | 输入截断 | `MAX_SCAN_LENGTH = 50_000` 字符 |
| **Fail-Open** | Shield 崩溃后请求不经检查直接放行 | 看门狗 + Fail-Closed | `heartbeat()` 每 10s；`isWatchdogHealthy()` 检查 30s 超时；超时则阻断请求 |
| **编码绕过** | Base64/URL encode/分段拆分绕过检测 | 多层检测 | 本地检测 + 远程 API 深度语义分析双保险 |

### ④ 供应链层

| 攻击 | 描述 | 防御 | 实现 |
|------|------|------|------|
| **npm 篡改** | 发布恶意 @logionos/openclaw-shield 包 | npm 2FA + 发布锁定 | npm org 2FA 强制；`package-lock.json` 锁定依赖 |
| **依赖投毒** | Shield 的依赖被注入恶意代码 | 零依赖设计 | Shield 仅依赖 Node.js 内置模块 (crypto, fs, path) |
| **代码篡改** | 运行时 Shield 文件被修改 | 完整性校验 | `computeModuleHash()` 启动时计算关键配置 hash 并记录审计 |

### ⑤ 本地数据层

| 攻击 | 描述 | 防御 | 实现 |
|------|------|------|------|
| **审计篡改** | 修改本地审计 JSONL 文件掩盖攻击痕迹 | 哈希链 | SHA-256 链式哈希——每条记录包含前一条的 hash |
| **配置泄露** | openclaw.json 中 API Key 明文 | 日志脱敏 + 文档警告 | `scrubForLog()` 确保 key 不出现在日志中 |
| **PII 残留** | PII 意外写入日志文件 | 日志脱敏 | `scrubForLog()` 截断 message/query/response 字段 |

### ⑥ 逻辑层

| 攻击 | 描述 | 防御 | 实现 |
|------|------|------|------|
| **Kill Switch 竞态** | 在策略同步间隙绕过封锁 | 短周期同步 + 本地缓存 | 默认 5 分钟同步一次；kill switch 本地缓存 |
| **策略降级** | API 返回空策略导致保护失效 | 本地基线策略 | 本地 PII/blocklist 检测不依赖 API 策略 |
| **渐进探测** | 逐步试探 Shield 检测阈值 | 会话追踪 + 风险累积 | `SessionTracker` 累积每会话风险分；高风险自动升级 |

---

## 3. 防御架构

```
                 Request Flow (Hardened)
                 ═══════════════════════

     User Input
         │
    ┌────▼─────┐
    │ Watchdog  │──── 超时 30s? ──► BLOCK (fail-closed)
    │ Check     │
    └────┬──────┘
         │
    ┌────▼──────────┐
    │ Normalize     │  NFKC + strip zero-width + truncate 50K
    │ (hardening.ts)│
    └────┬──────────┘
         │
    ┌────▼──────────┐
    │ Local Check   │  PII scan (iteration-capped regex)
    │ (pii-scanner) │  Blocklist scan
    └────┬──────────┘
         │
    ┌────▼──────────┐
    │ Remote Check  │  TLS enforced, no-redirect, path-locked
    │ (client.ts)   │  to /v1/* only
    └────┬──────────┘
         │
    ┌────▼──────────┐
    │ Audit Log     │  SHA-256 hash chain
    │ (audit-logger)│  PII scrubbed from logs
    └────┬──────────┘
         │
    ┌────▼──────────┐
    │ Dashboard     │  CSP + CSRF + Rate Limit + No CORS
    │ (serve.ts)    │  X-Frame-Options: DENY
    └───────────────┘
```

---

## 4. 安全配置建议

### 生产环境必须

```json
{
  "@logionos/openclaw-shield": {
    "config": {
      "mode": "enforce",
      "apiEndpoint": "https://api.logionos.com",
      "performance": {
        "failMode": "fail-closed"
      }
    }
  }
}
```

### 检查清单

- [ ] API endpoint 使用 HTTPS
- [ ] API Key 通过环境变量注入，不要硬编码在 openclaw.json
- [ ] 模式设为 `enforce` 或 `strict`（非 `monitor`）
- [ ] `failMode` 设为 `fail-closed`
- [ ] 审计日志目录权限限制为 600
- [ ] 定期检查审计哈希链完整性
- [ ] npm 账户启用 2FA

---

## 5. 已知限制

| 限制 | 影响 | 缓解 |
|------|------|------|
| Shield 与 Gateway 同进程 | 被攻破的 Gateway 可绕过 Shield | 计划支持 sidecar/独立进程模式 |
| 本地正则无法覆盖所有 PII 变体 | 编码/语言变体可能逃逸 | 远程 API 语义分析作为第二层 |
| Dashboard 使用 inline JS/CSS | CSP 需 `unsafe-inline` | 计划迁移到独立静态资源 + nonce |
| 审计哈希链仅本地可验证 | 整盘替换则链无效 | 远程 API 同步提供独立校验副本 |

---

## 6. 漏洞报告

发现安全问题请发送至: **security@logionos.com**

请勿在公开 issue 中报告安全漏洞。我们承诺在 48 小时内响应。

---

## 7. 版本

| 版本 | 日期 | 变更 |
|------|------|------|
| 1.0 | 2026-03-06 | 初始安全模型文档 |
