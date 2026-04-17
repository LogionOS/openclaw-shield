import type { ShieldConfig, ComplianceAction, RiskLevel, MatchedRule, PIIItem } from "./config.js";
import { validateApiEndpoint, requireTls } from "./hardening.js";

export interface CheckRequest {
  query: string;
  response_text?: string;
  resource_tags?: string[];
  agent_role?: string;
  user_id?: string;
  department?: string;
  metadata?: Record<string, unknown>;
}

export interface CheckResponse {
  request_id: string;
  action: ComplianceAction;
  risk_level: RiskLevel;
  matched_rules: MatchedRule[];
  pii_detected: PIIItem[];
  ai_judge?: {
    intent: string;
    confidence: number;
    reasoning: string;
  };
  timing: {
    total_ms: number;
    layer1_ms: number;
    layer2_ms: number;
    layer3_ms: number;
  };
  compliance_report?: string;
  recommendations?: string[];
}

export interface HealthResponse {
  status: string;
  version: string;
  engine: Record<string, unknown> | null;
}

export class LogionOSClient {
  private endpoint: string;
  private apiKey: string;
  private timeout: number;
  private healthy = false;
  private lastHealthCheck = 0;

  constructor(config: ShieldConfig) {
    this.endpoint = config.apiEndpoint.replace(/\/+$/, "");
    this.apiKey = config.apiKey;
    this.timeout = config.performance.deepCheckTimeout;

    const validation = validateApiEndpoint(this.endpoint);
    if (!validation.valid) {
      throw new Error(`Shield: invalid API endpoint — ${validation.reason}`);
    }

    if (requireTls(this.endpoint, config.mode)) {
      throw new Error(
        "Shield: TLS required for non-localhost API endpoints in enforce/strict mode. " +
        "Use https:// or set mode to 'monitor' for development.",
      );
    }
  }

  private async fetch<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.endpoint}${path}`;

    // Prevent open-redirect / path traversal in API path
    const parsed = new URL(url);
    if (!parsed.pathname.startsWith("/v1/")) {
      throw new APIError(0, "Blocked: API path must start with /v1/", path);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const res = await fetch(url, {
        ...options,
        signal: controller.signal,
        redirect: "error",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
          "X-Client": "logionos-shield/0.1.0",
          ...options.headers,
        },
      });

      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new APIError(res.status, body, path);
      }

      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  async check(req: CheckRequest): Promise<CheckResponse> {
    return this.fetch<CheckResponse>("/v1/check", {
      method: "POST",
      body: JSON.stringify(req),
    });
  }

  async health(): Promise<HealthResponse> {
    return this.fetch<HealthResponse>("/v1/health");
  }

  async submitAudit(entries: Record<string, unknown>[]): Promise<void> {
    await this.fetch("/v1/audit/batch", {
      method: "POST",
      body: JSON.stringify({ entries }),
    });
  }

  async getKillSwitch(): Promise<{ mode: string }> {
    return this.fetch("/v1/admin/kill-switch");
  }

  async getPolicies(): Promise<{ policies: Record<string, unknown>[] }> {
    return this.fetch("/v1/policies");
  }

  async isHealthy(): Promise<boolean> {
    const now = Date.now();
    if (now - this.lastHealthCheck < 30_000) return this.healthy;

    try {
      const h = await this.health();
      this.healthy = h.status === "ok" || h.status === "starting";
      this.lastHealthCheck = now;
    } catch {
      this.healthy = false;
      this.lastHealthCheck = now;
    }
    return this.healthy;
  }

  async checkWithRetry(req: CheckRequest, retries = 2): Promise<CheckResponse | null> {
    for (let i = 0; i <= retries; i++) {
      try {
        return await this.check(req);
      } catch {
        if (i === retries) return null;
        const delay = Math.min(100 * 2 ** i, 2000);
        await new Promise((r) => setTimeout(r, delay));
      }
    }
    return null;
  }
}

export class APIError extends Error {
  constructor(
    public status: number,
    public body: string,
    public path: string,
  ) {
    super(`LogionOS API ${path} returned ${status}: ${body}`);
    this.name = "LogionOSAPIError";
  }
}
