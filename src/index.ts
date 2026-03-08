import type { ShieldConfig } from "./config.js";
import { DEFAULT_CONFIG, CONFIG_SCHEMA } from "./config.js";
import { LogionOSClient } from "./client.js";
import { InboundGuard } from "./guards/inbound-guard.js";
import { OutboundGuard } from "./guards/outbound-guard.js";
import { PromptGuard } from "./guards/prompt-guard.js";
import { ToolGuard } from "./guards/tool-guard.js";
import { AuditLogger } from "./audit/audit-logger.js";
import { SessionTracker } from "./audit/session-tracker.js";
import { PolicySync } from "./policy/policy-sync.js";
import { LocalCache } from "./policy/local-cache.js";
import { registerDashboardRoutes } from "./dashboard/serve.js";
import { heartbeat, isWatchdogHealthy, computeModuleHash, validateApiEndpoint } from "./hardening.js";

interface PluginAPI {
  logger: { info: (...args: unknown[]) => void; warn: (...args: unknown[]) => void; error: (...args: unknown[]) => void };
  config: Record<string, unknown>;
  lifecycle: {
    on: (
      phase: string,
      handler: (ctx: Record<string, unknown>) => Promise<Record<string, unknown> | void>,
      opts?: { priority?: number; timeout?: number; mode?: "fail-open" | "fail-closed" },
    ) => void;
  };
  on: (
    hookName: string,
    handler: (ctx: Record<string, unknown>) => Promise<Record<string, unknown> | void>,
    opts?: { priority?: number; timeout?: number; mode?: "fail-open" | "fail-closed" },
  ) => void;
  registerHttpRoute: (route: {
    path: string;
    auth: "gateway" | "plugin";
    match?: "exact" | "prefix";
    handler: (req: unknown, res: { statusCode: number; end: (body: string) => void; setHeader: (k: string, v: string) => void }) => Promise<boolean>;
  }) => void;
  registerCommand: (cmd: {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requireAuth?: boolean;
    handler: (ctx: { args?: string; senderId?: string }) => Promise<{ text: string }>;
  }) => void;
  registerService: (svc: { id: string; start: () => Promise<void> | void; stop: () => Promise<void> | void }) => void;
}

let shield: ShieldInstance | null = null;

class ShieldInstance {
  client: LogionOSClient;
  audit: AuditLogger;
  sessions: SessionTracker;
  cache: LocalCache;
  policySync: PolicySync;
  inbound: InboundGuard;
  outbound: OutboundGuard;
  prompt: PromptGuard;
  tool: ToolGuard;

  constructor(public config: ShieldConfig) {
    this.client = new LogionOSClient(config);
    this.audit = new AuditLogger(config, this.client);
    this.sessions = new SessionTracker();
    this.cache = new LocalCache(config, this.client);
    this.policySync = new PolicySync(config, this.client, this.cache);
    this.inbound = new InboundGuard(config, this.client, this.audit);
    this.outbound = new OutboundGuard(config, this.client, this.audit);
    this.prompt = new PromptGuard(config, this.audit);
    this.tool = new ToolGuard(config, this.client, this.audit);
  }

  private watchdogInterval: ReturnType<typeof setInterval> | null = null;
  moduleHash = "";

  async start(): Promise<void> {
    await this.audit.start();
    await this.policySync.start();

    heartbeat();
    this.watchdogInterval = setInterval(() => heartbeat(), 10_000);
  }

  async stop(): Promise<void> {
    if (this.watchdogInterval) clearInterval(this.watchdogInterval);
    await this.audit.stop();
    await this.policySync.stop();
  }
}

export default function register(api: PluginAPI) {
  const pluginConfig = resolveConfig(api.config);
  shield = new ShieldInstance(pluginConfig);

  const endpointCheck = validateApiEndpoint(pluginConfig.apiEndpoint);
  if (!endpointCheck.valid) {
    api.logger.error(`[LogionOS Shield] FATAL: ${endpointCheck.reason}`);
    return;
  }

  api.logger.info("[LogionOS Shield] Initializing...");
  api.logger.info(`[LogionOS Shield] Mode: ${pluginConfig.mode}`);
  api.logger.info(`[LogionOS Shield] API: ${pluginConfig.apiEndpoint}`);
  api.logger.info(`[LogionOS Shield] Guards: inbound=${pluginConfig.guards.inbound} outbound=${pluginConfig.guards.outbound} prompt=${pluginConfig.guards.prompt} tool=${pluginConfig.guards.tool}`);

  // ── Background service ──────────────────────────────────────
  api.registerService({
    id: "logionos-shield",
    start: async () => {
      await shield!.start();
      shield!.moduleHash = computeModuleHash(
        JSON.stringify(pluginConfig.guards),
        pluginConfig.mode,
        pluginConfig.apiEndpoint,
      );
      const healthy = await shield!.client.isHealthy();
      api.logger.info(`[LogionOS Shield] Started. API health: ${healthy ? "OK" : "UNREACHABLE"}`);
      api.logger.info(`[LogionOS Shield] Module integrity: ${shield!.moduleHash}`);
    },
    stop: async () => {
      api.logger.info("[LogionOS Shield] Shutting down...");
      await shield!.stop();
    },
  });

  // ── Lifecycle: request.pre (Inbound Guard) ──────────────────
  if (pluginConfig.guards.inbound) {
    api.lifecycle.on("request.pre", async (ctx) => {
      if (!isWatchdogHealthy()) {
        api.logger.error("[LogionOS Shield] Watchdog timeout — fail-closed, blocking request");
        return {
          ...ctx,
          blocked: true,
          reply: "🔒 LogionOS Shield: Security subsystem unresponsive. Request blocked (fail-closed).",
        };
      }

      if (shield!.cache.isKillSwitchActive()) {
        return {
          ...ctx,
          blocked: true,
          reply: "🔒 LogionOS Shield: System is in lockdown mode. All requests are blocked.",
        };
      }

      const message = String(ctx.message ?? ctx.text ?? "");
      if (!message) return ctx;

      const result = await shield!.inbound.evaluate({
        message,
        senderId: String(ctx.senderId ?? "unknown"),
        channel: String(ctx.channel ?? "unknown"),
        sessionId: String(ctx.sessionId ?? "unknown"),
      });

      shield!.sessions.recordCheck(
        String(ctx.sessionId ?? "unknown"),
        String(ctx.channel ?? "unknown"),
        result.decision.action,
        result.decision.piiDetected.length,
        result.decision.matchedRules.length,
      );

      if (!result.allowed) {
        return {
          ...ctx,
          blocked: true,
          reply: result.replacementMessage,
        };
      }

      return ctx;
    }, { priority: 10, timeout: 10_000, mode: pluginConfig.performance.failMode });
  }

  // ── Lifecycle: prompt.pre (Prompt Guard) ────────────────────
  if (pluginConfig.guards.prompt) {
    api.lifecycle.on("prompt.pre", async (ctx) => {
      const result = await shield!.prompt.evaluate({
        systemPrompt: String(ctx.systemPrompt ?? ""),
        contextFiles: Array.isArray(ctx.contextFiles)
          ? ctx.contextFiles.map(String)
          : undefined,
        memories: Array.isArray(ctx.memories) ? ctx.memories.map(String) : undefined,
        sessionId: String(ctx.sessionId ?? "unknown"),
        channel: String(ctx.channel ?? "unknown"),
      });

      if (!result.allowed) {
        return {
          ...ctx,
          blocked: true,
          reply: "🛡️ LogionOS Shield: Prompt injection attempt detected and blocked.",
        };
      }

      if (result.sanitizedContext) {
        return { ...ctx, contextFiles: result.sanitizedContext };
      }

      return ctx;
    }, { priority: 5, timeout: 5_000, mode: pluginConfig.performance.failMode });
  }

  // ── Lifecycle: tool.pre (Tool Guard) ────────────────────────
  if (pluginConfig.guards.tool) {
    api.lifecycle.on("tool.pre", async (ctx) => {
      const result = await shield!.tool.evaluatePre({
        toolName: String(ctx.toolName ?? ""),
        toolArgs: (ctx.toolArgs as Record<string, unknown>) ?? {},
        agentRole: ctx.agentRole ? String(ctx.agentRole) : undefined,
        sessionId: String(ctx.sessionId ?? "unknown"),
        channel: String(ctx.channel ?? "unknown"),
      });

      shield!.sessions.recordToolCall(
        String(ctx.sessionId ?? "unknown"),
        String(ctx.toolName ?? ""),
        result.allowed,
      );

      if (!result.allowed) {
        return {
          ...ctx,
          blocked: true,
          error: result.blockReason,
        };
      }

      return ctx;
    }, { priority: 10, timeout: 10_000, mode: pluginConfig.performance.failMode });

    // ── Lifecycle: tool.post (Tool Result Scan) ───────────────
    api.lifecycle.on("tool.post", async (ctx) => {
      const result = await shield!.tool.evaluatePost({
        toolName: String(ctx.toolName ?? ""),
        toolResult: String(ctx.toolResult ?? ""),
        sessionId: String(ctx.sessionId ?? "unknown"),
        channel: String(ctx.channel ?? "unknown"),
      });

      if (result.sanitizedResult) {
        return { ...ctx, toolResult: result.sanitizedResult };
      }

      return ctx;
    }, { priority: 10, timeout: 5_000, mode: "fail-open" });
  }

  // ── Lifecycle: message.pre (Outbound Guard) ─────────────────
  if (pluginConfig.guards.outbound) {
    api.lifecycle.on("message.pre", async (ctx) => {
      const response = String(ctx.text ?? ctx.message ?? "");
      if (!response) return ctx;

      const result = await shield!.outbound.evaluate({
        response,
        channel: String(ctx.channel ?? "unknown"),
        sessionId: String(ctx.sessionId ?? "unknown"),
      });

      if (!result.allowed) {
        return {
          ...ctx,
          text: result.modifiedResponse,
          message: result.modifiedResponse,
        };
      }

      if (result.modifiedResponse && result.modifiedResponse !== response) {
        return {
          ...ctx,
          text: result.modifiedResponse,
          message: result.modifiedResponse,
        };
      }

      return ctx;
    }, { priority: 10, timeout: 10_000, mode: pluginConfig.performance.failMode });
  }

  // ── Agent commands ──────────────────────────────────────────
  api.registerCommand({
    name: "shield",
    description: "LogionOS Shield compliance status and controls",
    acceptsArgs: true,
    requireAuth: true,
    handler: async (ctx) => {
      const args = ctx.args?.trim() ?? "";
      if (args === "status" || args === "") {
        return handleStatusCommand();
      }
      if (args === "stats") {
        return handleStatsCommand();
      }
      if (args.startsWith("mode ")) {
        return handleModeCommand(args.slice(5).trim());
      }
      if (args === "sessions") {
        return handleSessionsCommand();
      }
      return {
        text: [
          "🛡️ **LogionOS Shield Commands**",
          "",
          "`/shield` or `/shield status` — Shield status",
          "`/shield stats` — Compliance statistics",
          "`/shield mode <monitor|enforce|strict>` — Change enforcement mode",
          "`/shield sessions` — Active session summaries",
        ].join("\n"),
      };
    },
  });

  // ── Dashboard + HTTP API routes ─────────────────────────────
  registerDashboardRoutes(
    api.registerHttpRoute.bind(api),
    () => shield as unknown as Parameters<typeof registerDashboardRoutes>[1] extends () => infer R ? R : never,
  );

  api.logger.info("[LogionOS Shield] Registration complete. All lifecycle hooks active.");
}

// ── Command handlers ────────────────────────────────────────

function handleStatusCommand(): { text: string } {
  const s = shield!;
  const stats = s.audit.getStats();
  const sync = s.policySync.getStatus();
  const modeEmoji = s.config.mode === "strict" ? "🔴" : s.config.mode === "enforce" ? "🟡" : "🟢";

  return {
    text: [
      "🛡️ **LogionOS Shield Status**",
      "",
      `${modeEmoji} Mode: **${s.config.mode}**`,
      `📡 API: ${sync.healthy ? "✅ Connected" : "❌ Disconnected"}`,
      `🔐 Kill Switch: ${sync.killSwitchMode === "block_all" ? "🔒 ACTIVE" : "✅ Normal"}`,
      "",
      "**Guards:**",
      `  Inbound: ${s.config.guards.inbound ? "✅" : "⬜"}`,
      `  Outbound: ${s.config.guards.outbound ? "✅" : "⬜"}`,
      `  Prompt: ${s.config.guards.prompt ? "✅" : "⬜"}`,
      `  Tool: ${s.config.guards.tool ? "✅" : "⬜"}`,
      "",
      `**Checks:** ${stats.total} total | ${stats.blocked} blocked | ${stats.flagged} flagged`,
    ].join("\n"),
  };
}

function handleStatsCommand(): { text: string } {
  const stats = shield!.audit.getStats();
  const blockRate = stats.total > 0 ? ((stats.blocked / stats.total) * 100).toFixed(1) : "0.0";
  const complianceRate = stats.total > 0 ? (((stats.passed + stats.warned) / stats.total) * 100).toFixed(1) : "100.0";

  return {
    text: [
      "📊 **Compliance Statistics**",
      "",
      `Total checks: **${stats.total}**`,
      `├ ✅ Passed: ${stats.passed}`,
      `├ ⚠️ Warned: ${stats.warned}`,
      `├ 🚩 Flagged: ${stats.flagged}`,
      `└ ⛔ Blocked: ${stats.blocked}`,
      "",
      `Block rate: ${blockRate}%`,
      `Compliance rate: ${complianceRate}%`,
    ].join("\n"),
  };
}

function handleModeCommand(newMode: string): { text: string } {
  const valid = ["monitor", "enforce", "strict"];
  if (!valid.includes(newMode)) {
    return { text: `❌ Invalid mode. Choose: ${valid.join(", ")}` };
  }
  const old = shield!.config.mode;
  shield!.config.mode = newMode as ShieldConfig["mode"];
  return { text: `🛡️ Mode changed: **${old}** → **${newMode}**` };
}

function handleSessionsCommand(): { text: string } {
  const sessions = shield!.sessions.getActiveSessions();
  if (sessions.length === 0) {
    return { text: "No active sessions." };
  }

  const lines = sessions.slice(0, 10).map((s) => {
    const risk = s.riskProfile === "critical" ? "🔴" : s.riskProfile === "high" ? "🟠" : s.riskProfile === "medium" ? "🟡" : "🟢";
    return `${risk} \`${s.sessionId.slice(0, 8)}\` | ${s.checkCount} checks | ${s.actions.block} blocked | ${s.toolCallCount} tools`;
  });

  return {
    text: [`🗂️ **Active Sessions** (${sessions.length})`, "", ...lines].join("\n"),
  };
}

// ── Config resolution ───────────────────────────────────────

function resolveConfig(raw: Record<string, unknown>): ShieldConfig {
  const pluginCfg = (raw as Record<string, Record<string, unknown>>)?.["@logionos/openclaw-shield"]?.config ?? raw;

  return {
    apiEndpoint: String(pluginCfg.apiEndpoint ?? DEFAULT_CONFIG.apiEndpoint),
    apiKey: String(pluginCfg.apiKey ?? DEFAULT_CONFIG.apiKey),
    mode: (pluginCfg.mode as ShieldConfig["mode"]) ?? DEFAULT_CONFIG.mode,
    guards: { ...DEFAULT_CONFIG.guards, ...(pluginCfg.guards as Partial<ShieldConfig["guards"]>) },
    toolPolicy: { ...DEFAULT_CONFIG.toolPolicy, ...(pluginCfg.toolPolicy as Partial<ShieldConfig["toolPolicy"]>) },
    audit: { ...DEFAULT_CONFIG.audit, ...(pluginCfg.audit as Partial<ShieldConfig["audit"]>) },
    alerts: { ...DEFAULT_CONFIG.alerts, ...(pluginCfg.alerts as Partial<ShieldConfig["alerts"]>) },
    performance: { ...DEFAULT_CONFIG.performance, ...(pluginCfg.performance as Partial<ShieldConfig["performance"]>) },
  };
}

export { ShieldInstance, ShieldConfig, CONFIG_SCHEMA };
