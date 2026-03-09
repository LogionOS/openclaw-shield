import type { ShieldConfig, ComplianceDecision, ComplianceAction } from "../config.js";
import type { LogionOSClient } from "../client.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import { scanPII } from "../utils/pii-scanner.js";
import { generateId } from "../utils/hash.js";
import { checkCanaryLeak, checkPromptLeakage } from "../utils/canary.js";

export interface OutboundEvent {
  response: string;
  channel: string;
  sessionId: string;
}

export interface OutboundResult {
  allowed: boolean;
  decision: ComplianceDecision;
  modifiedResponse?: string;
}

const DISCLAIMER_TOPICS = [
  { pattern: /(?:medical|health|diagnosis|treatment|symptom)/i, disclaimer: "\n\n⚕️ This is AI-generated content for informational purposes only. It does not constitute medical advice. Please consult a healthcare professional." },
  { pattern: /(?:legal|law|regulation|statute|litigation|attorney)/i, disclaimer: "\n\n⚖️ This is AI-generated content for informational purposes only. It does not constitute legal advice. Please consult a qualified attorney." },
  { pattern: /(?:invest|stock|portfolio|financial|trading|crypto)/i, disclaimer: "\n\n💰 This is AI-generated content for informational purposes only. It does not constitute financial advice. Please consult a licensed financial advisor." },
];

export class OutboundGuard {
  constructor(
    private config: ShieldConfig,
    private client: LogionOSClient,
    private audit: AuditLogger,
  ) {}

  async evaluate(event: OutboundEvent): Promise<OutboundResult> {
    const start = performance.now();
    const requestId = generateId();

    const piiItems = scanPII(event.response);
    const localMs = performance.now() - start;

    let action: ComplianceAction = "PASS";
    const reasons: string[] = [];

    if (piiItems.some((p) => ["SSN", "CREDIT_CARD", "MY_NUMBER", "AWS_KEY", "PRIVATE_KEY", "SEED_PHRASE", "WIF_KEY", "XPRV_KEY", "HEX_SECRET_64"].includes(p.type))) {
      action = "BLOCK";
      reasons.push(`output_pii_leak:${piiItems.map((p) => p.type).join(",")}`);
    } else if (piiItems.length > 0) {
      action = "WARN";
      reasons.push(`output_pii:${piiItems.map((p) => p.type).join(",")}`);
    }

    if (checkCanaryLeak(event.response)) {
      action = "BLOCK";
      reasons.push("canary_token_leaked");
    }

    const leakCheck = checkPromptLeakage(event.response);
    if (leakCheck.leaked) {
      action = escalate(action, "BLOCK");
      reasons.push(`system_prompt_leak:${leakCheck.reason}`);
    }

    let remoteMs: number | undefined;
    if (action === "PASS" || action === "WARN") {
      const deepStart = performance.now();
      const remote = await this.client.checkWithRetry({
        query: "",
        response_text: event.response,
        metadata: { channel: event.channel, session: event.sessionId, guard: "outbound" },
      });
      remoteMs = performance.now() - deepStart;

      if (remote) {
        if (remote.action === "BLOCK" || remote.action === "FLAG") {
          action = remote.action;
          reasons.push(...(remote.matched_rules?.map((r) => `rule:${r.ruleId}`) ?? []));
        }
      }
    }

    const decision: ComplianceDecision = {
      action,
      riskLevel: action === "BLOCK" ? "critical" : action === "FLAG" ? "high" : action === "WARN" ? "medium" : "low",
      reasons,
      piiDetected: piiItems,
      matchedRules: [],
      timing: { localMs, remoteMs },
      requestId,
    };

    const allowed = this.isAllowed(action);

    let modifiedResponse: string | undefined;
    if (!allowed) {
      modifiedResponse = "⚠️ The AI response was blocked by compliance policy due to sensitive content. Please rephrase your request.";
    } else if (action === "WARN" && piiItems.length > 0) {
      modifiedResponse = this.redactPII(event.response, piiItems);
    } else {
      modifiedResponse = this.appendDisclaimers(event.response);
    }

    await this.audit.record({
      guard: "outbound",
      sessionId: event.sessionId,
      channel: event.channel,
      decision,
    });

    return { allowed, decision, modifiedResponse };
  }

  private isAllowed(action: ComplianceAction): boolean {
    switch (this.config.mode) {
      case "monitor": return action !== "BLOCK";
      case "enforce": return action === "PASS" || action === "WARN";
      case "strict": return action === "PASS";
    }
  }

  private redactPII(text: string, piiItems: { type: string; value: string; masked: string }[]): string {
    let result = text;
    const sorted = [...piiItems].sort((a, b) => b.value.length - a.value.length);
    for (const item of sorted) {
      result = result.replaceAll(item.value, item.masked);
    }
    return result;
  }

  private appendDisclaimers(text: string): string {
    let result = text;
    for (const { pattern, disclaimer } of DISCLAIMER_TOPICS) {
      if (pattern.test(text)) {
        result += disclaimer;
        break;
      }
    }
    return result;
  }
}

function escalate(current: ComplianceAction, incoming: ComplianceAction): ComplianceAction {
  const order: ComplianceAction[] = ["PASS", "WARN", "FLAG", "BLOCK"];
  return order.indexOf(incoming) > order.indexOf(current) ? incoming : current;
}
