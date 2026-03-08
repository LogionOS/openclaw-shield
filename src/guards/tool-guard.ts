import type { ShieldConfig, ComplianceDecision, ComplianceAction } from "../config.js";
import type { LogionOSClient } from "../client.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import { scanPII } from "../utils/pii-scanner.js";
import { generateId } from "../utils/hash.js";

export interface ToolPreEvent {
  toolName: string;
  toolArgs: Record<string, unknown>;
  agentRole?: string;
  sessionId: string;
  channel: string;
}

export interface ToolPostEvent {
  toolName: string;
  toolResult: string;
  sessionId: string;
  channel: string;
}

export interface ToolPreResult {
  allowed: boolean;
  decision: ComplianceDecision;
  blockReason?: string;
}

export interface ToolPostResult {
  decision: ComplianceDecision;
  sanitizedResult?: string;
}

const HIGH_RISK_TOOLS = new Set([
  "shell_exec", "bash", "terminal",
  "file_delete", "file_write", "rm",
  "database_query", "sql_exec",
  "send_email", "send_message",
  "http_request", "fetch", "curl",
  "code_exec", "eval", "python_exec",
]);

const DANGEROUS_ARG_PATTERNS = [
  { pattern: /rm\s+-rf?\s+\//i, reason: "destructive_filesystem_operation" },
  { pattern: /DROP\s+(?:TABLE|DATABASE|SCHEMA)/i, reason: "destructive_sql_operation" },
  { pattern: /;\s*(?:DROP|DELETE|TRUNCATE|ALTER)/i, reason: "sql_injection_attempt" },
  { pattern: /(?:\/etc\/passwd|\/etc\/shadow|\.ssh\/|\.env)/i, reason: "sensitive_file_access" },
  { pattern: /(?:169\.254\.169\.254|metadata\.google)/i, reason: "cloud_metadata_access" },
  { pattern: /(?:curl|wget|fetch).*(?:\||>)/i, reason: "pipe_download_execution" },
];

export class ToolGuard {
  constructor(
    private config: ShieldConfig,
    private client: LogionOSClient,
    private audit: AuditLogger,
  ) {}

  async evaluatePre(event: ToolPreEvent): Promise<ToolPreResult> {
    const start = performance.now();
    const requestId = generateId();

    let action: ComplianceAction = "PASS";
    const reasons: string[] = [];

    const { denylist, allowlist, requireApproval } = this.config.toolPolicy;

    if (denylist.length > 0 && denylist.includes(event.toolName)) {
      action = "BLOCK";
      reasons.push(`tool_denied:${event.toolName}`);
    }

    if (allowlist.length > 0 && !allowlist.includes(event.toolName)) {
      action = "BLOCK";
      reasons.push(`tool_not_in_allowlist:${event.toolName}`);
    }

    if (requireApproval.includes(event.toolName)) {
      action = escalate(action, "FLAG");
      reasons.push(`tool_requires_approval:${event.toolName}`);
    }

    if (HIGH_RISK_TOOLS.has(event.toolName)) {
      action = escalate(action, "WARN");
      reasons.push(`high_risk_tool:${event.toolName}`);
    }

    const argsStr = JSON.stringify(event.toolArgs);
    for (const { pattern, reason } of DANGEROUS_ARG_PATTERNS) {
      if (pattern.test(argsStr)) {
        action = escalate(action, "BLOCK");
        reasons.push(`dangerous_arg:${reason}`);
      }
    }

    const piiInArgs = scanPII(argsStr);
    if (piiInArgs.some((p) => ["SSN", "CREDIT_CARD", "PRIVATE_KEY", "AWS_KEY"].includes(p.type))) {
      action = escalate(action, "FLAG");
      reasons.push(`pii_in_tool_args:${piiInArgs.map((p) => p.type).join(",")}`);
    } else if (piiInArgs.length > 0) {
      action = escalate(action, "WARN");
      reasons.push(`pii_in_tool_args:${piiInArgs.map((p) => p.type).join(",")}`);
    }

    if (action !== "BLOCK" && event.agentRole) {
      const remoteCheck = await this.client.checkWithRetry({
        query: `Tool call: ${event.toolName}`,
        resource_tags: [event.toolName],
        agent_role: event.agentRole,
        metadata: { tool_args: event.toolArgs, guard: "tool_pre" },
      });

      if (remoteCheck?.action === "BLOCK") {
        action = "BLOCK";
        reasons.push("resource_access_denied");
      }
    }

    const localMs = performance.now() - start;

    const decision: ComplianceDecision = {
      action,
      riskLevel: action === "BLOCK" ? "critical" : action === "FLAG" ? "high" : action === "WARN" ? "medium" : "low",
      reasons,
      piiDetected: piiInArgs,
      matchedRules: [],
      timing: { localMs },
      requestId,
    };

    const allowed = this.isAllowed(action);

    await this.audit.record({
      guard: "tool",
      sessionId: event.sessionId,
      channel: event.channel,
      decision,
      extra: { toolName: event.toolName, phase: "pre" },
    });

    return {
      allowed,
      decision,
      blockReason: allowed ? undefined : `Tool '${event.toolName}' blocked: ${reasons.join(", ")}`,
    };
  }

  async evaluatePost(event: ToolPostEvent): Promise<ToolPostResult> {
    const start = performance.now();
    const requestId = generateId();

    let action: ComplianceAction = "PASS";
    const reasons: string[] = [];

    const piiInResult = scanPII(event.toolResult);
    if (piiInResult.some((p) => ["SSN", "CREDIT_CARD", "MY_NUMBER", "PRIVATE_KEY", "AWS_KEY"].includes(p.type))) {
      action = "FLAG";
      reasons.push(`pii_in_tool_result:${piiInResult.map((p) => p.type).join(",")}`);
    } else if (piiInResult.length > 0) {
      action = "WARN";
      reasons.push(`pii_in_tool_result:${piiInResult.map((p) => p.type).join(",")}`);
    }

    const localMs = performance.now() - start;

    const decision: ComplianceDecision = {
      action,
      riskLevel: action === "FLAG" ? "high" : action === "WARN" ? "medium" : "low",
      reasons,
      piiDetected: piiInResult,
      matchedRules: [],
      timing: { localMs },
      requestId,
    };

    let sanitizedResult: string | undefined;
    if (piiInResult.length > 0) {
      sanitizedResult = event.toolResult;
      const sorted = [...piiInResult].sort((a, b) => b.value.length - a.value.length);
      for (const item of sorted) {
        sanitizedResult = sanitizedResult.replaceAll(item.value, item.masked);
      }
    }

    await this.audit.record({
      guard: "tool",
      sessionId: event.sessionId,
      channel: event.channel,
      decision,
      extra: { toolName: event.toolName, phase: "post" },
    });

    return { decision, sanitizedResult };
  }

  private isAllowed(action: ComplianceAction): boolean {
    switch (this.config.mode) {
      case "monitor": return action !== "BLOCK";
      case "enforce": return action === "PASS" || action === "WARN";
      case "strict": return action === "PASS";
    }
  }
}

function escalate(current: ComplianceAction, incoming: ComplianceAction): ComplianceAction {
  const order: ComplianceAction[] = ["PASS", "WARN", "FLAG", "BLOCK"];
  return order.indexOf(incoming) > order.indexOf(current) ? incoming : current;
}
