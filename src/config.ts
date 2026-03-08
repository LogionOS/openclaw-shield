export type EnforcementMode = "monitor" | "enforce" | "strict";
export type FailMode = "fail-open" | "fail-closed";
export type ComplianceAction = "PASS" | "WARN" | "FLAG" | "BLOCK";
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface GuardConfig {
  inbound: boolean;
  outbound: boolean;
  prompt: boolean;
  tool: boolean;
}

export interface ToolPolicyConfig {
  allowlist: string[];
  denylist: string[];
  requireApproval: string[];
}

export interface AuditConfig {
  enabled: boolean;
  localBufferPath: string;
  syncInterval: number;
  retentionDays: number;
}

export interface AlertConfig {
  webhookUrl: string;
  notifyOnBlock: boolean;
  notifyOnFlag: boolean;
  dailyDigest: boolean;
}

export interface PerformanceConfig {
  localCacheTtl: number;
  deepCheckTimeout: number;
  failMode: FailMode;
}

export interface ShieldConfig {
  apiEndpoint: string;
  apiKey: string;
  mode: EnforcementMode;
  guards: GuardConfig;
  toolPolicy: ToolPolicyConfig;
  audit: AuditConfig;
  alerts: AlertConfig;
  performance: PerformanceConfig;
}

export const DEFAULT_CONFIG: ShieldConfig = {
  apiEndpoint: "http://localhost:8000",
  apiKey: "",
  mode: "monitor",
  guards: {
    inbound: true,
    outbound: true,
    prompt: true,
    tool: true,
  },
  toolPolicy: {
    allowlist: [],
    denylist: [],
    requireApproval: [],
  },
  audit: {
    enabled: true,
    localBufferPath: "~/.openclaw/logionos-audit/",
    syncInterval: 30,
    retentionDays: 90,
  },
  alerts: {
    webhookUrl: "",
    notifyOnBlock: true,
    notifyOnFlag: true,
    dailyDigest: false,
  },
  performance: {
    localCacheTtl: 300,
    deepCheckTimeout: 5000,
    failMode: "fail-open",
  },
};

export const CONFIG_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    apiEndpoint: { type: "string", description: "LogionOS API endpoint URL" },
    apiKey: { type: "string", description: "LogionOS API key (Bearer token)" },
    mode: { type: "string", enum: ["monitor", "enforce", "strict"], default: "monitor" },
    guards: {
      type: "object",
      properties: {
        inbound: { type: "boolean", default: true },
        outbound: { type: "boolean", default: true },
        prompt: { type: "boolean", default: true },
        tool: { type: "boolean", default: true },
      },
    },
    toolPolicy: {
      type: "object",
      properties: {
        allowlist: { type: "array", items: { type: "string" }, default: [] },
        denylist: { type: "array", items: { type: "string" }, default: [] },
        requireApproval: { type: "array", items: { type: "string" }, default: [] },
      },
    },
    audit: {
      type: "object",
      properties: {
        enabled: { type: "boolean", default: true },
        localBufferPath: { type: "string", default: "~/.openclaw/logionos-audit/" },
        syncInterval: { type: "number", default: 30 },
        retentionDays: { type: "number", default: 90 },
      },
    },
    alerts: {
      type: "object",
      properties: {
        webhookUrl: { type: "string", default: "" },
        notifyOnBlock: { type: "boolean", default: true },
        notifyOnFlag: { type: "boolean", default: true },
        dailyDigest: { type: "boolean", default: false },
      },
    },
    performance: {
      type: "object",
      properties: {
        localCacheTtl: { type: "number", default: 300 },
        deepCheckTimeout: { type: "number", default: 5000 },
        failMode: { type: "string", enum: ["fail-open", "fail-closed"], default: "fail-open" },
      },
    },
  },
  required: ["apiEndpoint", "apiKey"],
} as const;

export interface ComplianceDecision {
  action: ComplianceAction;
  riskLevel: RiskLevel;
  reasons: string[];
  piiDetected: PIIItem[];
  matchedRules: MatchedRule[];
  timing: { localMs: number; remoteMs?: number };
  requestId: string;
}

export interface PIIItem {
  type: string;
  value: string;
  location: { start: number; end: number };
  masked: string;
}

export interface MatchedRule {
  ruleId: string;
  title: string;
  severity: number;
  jurisdiction: string;
  source: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  sessionId: string;
  channel: string;
  guard: "inbound" | "outbound" | "prompt" | "tool";
  action: ComplianceAction;
  riskLevel: RiskLevel;
  reasons: string[];
  piiCount: number;
  ruleCount: number;
  timing: { localMs: number; remoteMs?: number };
  hash: string;
  prevHash: string;
}
