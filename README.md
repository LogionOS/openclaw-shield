# LogionOS Shield for OpenClaw

> Enterprise compliance layer for OpenClaw — PII protection, audit trails, and regulatory compliance for AI agents.

OpenClaw is the fastest-growing open-source AI agent platform, but it ships with **zero built-in compliance controls**. LogionOS Shield adds enterprise-grade security without changing the user experience.

## What It Does

| Capability | Description |
|---|---|
| **Inbound Guard** | Scans user messages for PII, credentials, and prompt injection before they reach the AI |
| **Outbound Guard** | Filters AI responses for data leaks, adds regulatory disclaimers |
| **Prompt Guard** | Detects ClawJacked attacks and context injection in system prompts |
| **Tool Guard** | Controls which tools the agent can use, scans tool arguments and results |
| **Audit Trail** | Tamper-evident hash chain of every compliance decision |
| **Policy Engine** | Sync enterprise policies from LogionOS API |
| **Kill Switch** | Emergency shutdown of all AI interactions |

## Quick Start

### 1. Install

```bash
openclaw plugins install @logionos/openclaw-shield
```

### 2. Configure

Add to your `~/.openclaw/openclaw.json`:

```json5
{
  plugins: {
    entries: {
      "@logionos/openclaw-shield": {
        enabled: true,
        config: {
          apiEndpoint: "http://localhost:8000",  // Your LogionOS API
          apiKey: "los_your_api_key_here",
          mode: "monitor",  // Start with monitor, upgrade to enforce/strict
        },
      },
    },
  },
}
```

### 3. Restart Gateway

```bash
openclaw restart
```

### 4. Verify

```bash
# In any connected channel, type:
/shield status
```

## Enforcement Modes

| Mode | PASS | WARN | FLAG | BLOCK |
|---|---|---|---|---|
| **Monitor** | Allow | Allow + log | Allow + log + incident | Block + alert |
| **Enforce** | Allow | Allow + log | Block + incident | Block + alert |
| **Strict** | Allow | Allow + alert | Block + incident + alert | Block + alert + notify admin |

Start with `monitor` to understand your traffic patterns, then graduate to `enforce` when ready.

## Agent Commands

| Command | Description |
|---|---|
| `/shield` | Show Shield status |
| `/shield stats` | Compliance statistics |
| `/shield mode <mode>` | Change enforcement mode |
| `/shield sessions` | Active session summaries |

## HTTP API Endpoints

Shield exposes endpoints on the OpenClaw Gateway:

| Endpoint | Method | Description |
|---|---|---|
| `/logionos/status` | GET | Shield status + configuration |
| `/logionos/stats` | GET | Compliance statistics |
| `/logionos/sessions` | GET | Active session data |

## Configuration Reference

```json5
{
  // LogionOS API connection
  apiEndpoint: "http://localhost:8000",
  apiKey: "los_xxxxxxxxxxxx",

  // Enforcement mode: monitor | enforce | strict
  mode: "monitor",

  // Toggle individual guards
  guards: {
    inbound: true,   // Scan incoming messages
    outbound: true,  // Scan outgoing responses
    prompt: true,    // Detect prompt injection
    tool: true,      // Control tool access
  },

  // Tool access control
  toolPolicy: {
    allowlist: [],                    // Empty = allow all
    denylist: ["shell_exec"],         // Always block these tools
    requireApproval: ["send_email"],  // Flag for review
  },

  // Audit trail settings
  audit: {
    enabled: true,
    localBufferPath: "~/.openclaw/logionos-audit/",
    syncInterval: 30,      // Seconds between API syncs
    retentionDays: 90,
  },

  // Alert configuration
  alerts: {
    webhookUrl: "",           // Webhook for real-time alerts
    notifyOnBlock: true,
    notifyOnFlag: true,
    dailyDigest: false,
  },

  // Performance tuning
  performance: {
    localCacheTtl: 300,       // Policy cache TTL (seconds)
    deepCheckTimeout: 5000,   // API timeout (ms)
    failMode: "fail-open",    // fail-open | fail-closed
  },
}
```

## Architecture

```
OpenClaw Gateway
  ├─ [request.pre]  → Inbound Guard  → PII + blocklist scan
  ├─ [prompt.pre]   → Prompt Guard   → ClawJacked detection
  ├─ [tool.pre]     → Tool Guard     → Access control + arg scan
  ├─ [tool.post]    → Tool Guard     → Result PII scan
  ├─ [message.pre]  → Outbound Guard → Response filtering
  │
  └─► LogionOS API (self-hosted or cloud)
       ├─ L1: PII + Blocklist (hot rules)
       ├─ L2: Regulation Matching (semantic)
       ├─ L3: AI Judge (intent analysis)
       └─ Audit DB (hash chain)
```

**Dual-layer design:** Fast local checks (<2ms) handle 90%+ of traffic. Only complex cases call the LogionOS API for deep analysis.

## Requirements

- OpenClaw 2026.2+ (Lifecycle Interception API)
- LogionOS API v0.4+ (self-hosted or cloud)
- Node.js 20+

## License

Apache 2.0 — Free and open source. See [LICENSE](LICENSE) for details.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Enterprise

Need regulation matching, AI-powered intent analysis, or on-premise deployment? [Contact us](mailto:chris@logionos.com) about LogionOS Cloud and Enterprise plans.
