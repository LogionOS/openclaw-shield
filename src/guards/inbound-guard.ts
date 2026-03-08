import type { ShieldConfig, ComplianceDecision, ComplianceAction } from "../config.js";
import type { LogionOSClient } from "../client.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import { scanPII, scanBlocklist } from "../utils/pii-scanner.js";
import { generateId } from "../utils/hash.js";

export interface InboundEvent {
  message: string;
  senderId: string;
  channel: string;
  sessionId: string;
}

export interface InboundResult {
  allowed: boolean;
  decision: ComplianceDecision;
  replacementMessage?: string;
}

export class InboundGuard {
  constructor(
    private config: ShieldConfig,
    private client: LogionOSClient,
    private audit: AuditLogger,
  ) {}

  async evaluate(event: InboundEvent): Promise<InboundResult> {
    const start = performance.now();
    const requestId = generateId();

    const piiItems = scanPII(event.message);
    const blocklistHits = scanBlocklist(event.message);

    const localMs = performance.now() - start;

    let action: ComplianceAction = "PASS";
    const reasons: string[] = [];

    if (blocklistHits.length > 0) {
      action = "BLOCK";
      reasons.push(...blocklistHits.map((h) => `blocklist:${h.category}`));
    }

    if (piiItems.some((p) => ["SSN", "CREDIT_CARD", "MY_NUMBER", "PRIVATE_KEY"].includes(p.type))) {
      action = escalate(action, "FLAG");
      reasons.push(`high_severity_pii:${piiItems.filter((p) => ["SSN", "CREDIT_CARD", "MY_NUMBER", "PRIVATE_KEY"].includes(p.type)).map((p) => p.type).join(",")}`);
    } else if (piiItems.length > 0) {
      action = escalate(action, "WARN");
      reasons.push(`pii_detected:${piiItems.map((p) => p.type).join(",")}`);
    }

    let remoteMs: number | undefined;
    if (action !== "BLOCK" && this.shouldDeepCheck(piiItems.length, blocklistHits.length)) {
      const deepStart = performance.now();
      const remote = await this.client.checkWithRetry({
        query: event.message,
        user_id: event.senderId,
        metadata: { channel: event.channel, session: event.sessionId, guard: "inbound" },
      });

      remoteMs = performance.now() - deepStart;

      if (remote) {
        action = escalate(action, remote.action);
        if (remote.matched_rules?.length) {
          reasons.push(...remote.matched_rules.map((r) => `rule:${r.ruleId}`));
        }
        if (remote.ai_judge) {
          reasons.push(`intent:${remote.ai_judge.intent}`);
        }
      } else if (this.config.performance.failMode === "fail-closed") {
        action = escalate(action, "FLAG");
        reasons.push("api_unreachable:fail_closed");
      }
    }

    const decision: ComplianceDecision = {
      action,
      riskLevel: actionToRisk(action),
      reasons,
      piiDetected: piiItems,
      matchedRules: [],
      timing: { localMs, remoteMs },
      requestId,
    };

    const allowed = this.isAllowed(action);

    await this.audit.record({
      guard: "inbound",
      sessionId: event.sessionId,
      channel: event.channel,
      decision,
    });

    return {
      allowed,
      decision,
      replacementMessage: allowed ? undefined : this.buildBlockMessage(action, reasons),
    };
  }

  private shouldDeepCheck(piiCount: number, blockHits: number): boolean {
    if (blockHits > 0) return false;
    if (piiCount > 0) return true;
    return Math.random() < 0.1;
  }

  private isAllowed(action: ComplianceAction): boolean {
    switch (this.config.mode) {
      case "monitor":
        return action !== "BLOCK";
      case "enforce":
        return action === "PASS" || action === "WARN";
      case "strict":
        return action === "PASS";
    }
  }

  private buildBlockMessage(action: ComplianceAction, reasons: string[]): string {
    if (reasons.some((r) => r.startsWith("blocklist:prompt_injection"))) {
      return "⚠️ Security alert: This message was blocked by LogionOS Shield. Potential prompt injection detected.";
    }
    if (reasons.some((r) => r.includes("high_severity_pii"))) {
      return "⚠️ Compliance alert: This message contains sensitive personal information (PII) and has been blocked. Please remove personal identifiers and try again.";
    }
    if (action === "BLOCK") {
      return "⚠️ This message was blocked by compliance policy. Contact your administrator for assistance.";
    }
    return "⚠️ This message was flagged for compliance review and cannot be processed in the current enforcement mode.";
  }
}

function escalate(current: ComplianceAction, incoming: ComplianceAction): ComplianceAction {
  const order: ComplianceAction[] = ["PASS", "WARN", "FLAG", "BLOCK"];
  const ci = order.indexOf(current);
  const ii = order.indexOf(incoming);
  return ii > ci ? incoming : current;
}

function actionToRisk(action: ComplianceAction): "low" | "medium" | "high" | "critical" {
  switch (action) {
    case "PASS": return "low";
    case "WARN": return "medium";
    case "FLAG": return "high";
    case "BLOCK": return "critical";
  }
}
