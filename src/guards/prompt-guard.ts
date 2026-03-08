import type { ShieldConfig, ComplianceDecision, ComplianceAction } from "../config.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import { scanPII, scanBlocklist } from "../utils/pii-scanner.js";
import { generateId } from "../utils/hash.js";

export interface PromptEvent {
  systemPrompt: string;
  contextFiles?: string[];
  memories?: string[];
  sessionId: string;
  channel: string;
}

export interface PromptResult {
  allowed: boolean;
  decision: ComplianceDecision;
  sanitizedPrompt?: string;
  sanitizedContext?: string[];
}

const CLAWJACKED_SIGNATURES = [
  /\[SYSTEM\]\s*(?:OVERRIDE|RESET|NEW INSTRUCTION)/i,
  /<\|im_start\|>system/i,
  /<<SYS>>.*?<<\/SYS>>/s,
  /Human:\s*(?:ignore|disregard|override)/i,
  /Assistant:\s*(?:I understand|Of course|Sure).*(?:ignore|disregard|override)/i,
  /\x00|\x1b\[|\x08/,
  /<!--.*?(?:ignore|override|system).*?-->/si,
  /\{\{(?:system|admin|root)\}\}/i,
];

const CONTEXT_INJECTION_PATTERNS = [
  /(?:password|secret|token|key)\s*[:=]\s*\S+/gi,
  /(?:BEGIN|END)\s+(?:RSA |EC |DSA )?(?:PRIVATE|PUBLIC)\s+KEY/i,
  /(?:mysql|postgres|mongodb|redis):\/\/[^\s]+/i,
  /(?:AWS_SECRET|AWS_ACCESS|AZURE_|GCP_|OPENAI_API)[\w]*\s*[:=]\s*\S+/gi,
];

export class PromptGuard {
  constructor(
    private config: ShieldConfig,
    private audit: AuditLogger,
  ) {}

  async evaluate(event: PromptEvent): Promise<PromptResult> {
    const start = performance.now();
    const requestId = generateId();

    let action: ComplianceAction = "PASS";
    const reasons: string[] = [];
    const allPII: ComplianceDecision["piiDetected"] = [];

    const clawjackedHits = this.detectClawJacked(event.systemPrompt);
    if (clawjackedHits.length > 0) {
      action = "BLOCK";
      reasons.push(`clawjacked:${clawjackedHits.join(",")}`);
    }

    if (event.contextFiles) {
      for (let i = 0; i < event.contextFiles.length; i++) {
        const file = event.contextFiles[i];
        const injections = this.detectContextInjection(file);
        if (injections.length > 0) {
          action = escalate(action, "FLAG");
          reasons.push(`context_injection:file_${i}:${injections.join(",")}`);
        }

        const pii = scanPII(file);
        if (pii.length > 0) {
          action = escalate(action, "WARN");
          reasons.push(`context_pii:file_${i}:${pii.map((p) => p.type).join(",")}`);
          allPII.push(...pii);
        }
      }
    }

    if (event.memories) {
      for (let i = 0; i < event.memories.length; i++) {
        const mem = event.memories[i];
        const blockHits = scanBlocklist(mem);
        if (blockHits.length > 0) {
          action = escalate(action, "FLAG");
          reasons.push(`memory_contamination:${i}:${blockHits.map((h) => h.category).join(",")}`);
        }
      }
    }

    const localMs = performance.now() - start;

    const decision: ComplianceDecision = {
      action,
      riskLevel: action === "BLOCK" ? "critical" : action === "FLAG" ? "high" : action === "WARN" ? "medium" : "low",
      reasons,
      piiDetected: allPII,
      matchedRules: [],
      timing: { localMs },
      requestId,
    };

    const allowed = this.isAllowed(action);

    let sanitizedPrompt: string | undefined;
    let sanitizedContext: string[] | undefined;

    if (!allowed) {
      sanitizedPrompt = event.systemPrompt;
    } else {
      if (allPII.length > 0 && event.contextFiles) {
        sanitizedContext = event.contextFiles.map((f) => this.redactSensitiveContent(f));
      }
    }

    await this.audit.record({
      guard: "prompt",
      sessionId: event.sessionId,
      channel: event.channel,
      decision,
    });

    return { allowed, decision, sanitizedPrompt, sanitizedContext };
  }

  private detectClawJacked(prompt: string): string[] {
    const hits: string[] = [];
    for (let i = 0; i < CLAWJACKED_SIGNATURES.length; i++) {
      if (CLAWJACKED_SIGNATURES[i].test(prompt)) {
        hits.push(`sig_${i}`);
      }
    }
    return hits;
  }

  private detectContextInjection(content: string): string[] {
    const hits: string[] = [];
    for (const pattern of CONTEXT_INJECTION_PATTERNS) {
      if (pattern.test(content)) {
        hits.push(pattern.source.slice(0, 30));
      }
    }
    return hits;
  }

  private redactSensitiveContent(content: string): string {
    let result = content;
    for (const pattern of CONTEXT_INJECTION_PATTERNS) {
      result = result.replace(new RegExp(pattern.source, pattern.flags), "[REDACTED]");
    }
    return result;
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
