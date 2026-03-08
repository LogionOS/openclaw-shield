import { writeFile, appendFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import type { ShieldConfig, ComplianceDecision, AuditEntry } from "../config.js";
import type { LogionOSClient } from "../client.js";
import { computeAuditHash, generateId } from "../utils/hash.js";

export interface AuditRecordInput {
  guard: "inbound" | "outbound" | "prompt" | "tool";
  sessionId: string;
  channel: string;
  decision: ComplianceDecision;
  extra?: Record<string, unknown>;
}

export class AuditLogger {
  private buffer: AuditEntry[] = [];
  private prevHash = "genesis";
  private syncTimer: ReturnType<typeof setInterval> | null = null;
  private bufferPath: string;
  private stats = { total: 0, blocked: 0, flagged: 0, warned: 0, passed: 0 };

  constructor(
    private config: ShieldConfig,
    private client: LogionOSClient,
  ) {
    const raw = config.audit.localBufferPath;
    this.bufferPath = raw.startsWith("~") ? join(homedir(), raw.slice(1)) : raw;
  }

  async start(): Promise<void> {
    if (!this.config.audit.enabled) return;

    await mkdir(this.bufferPath, { recursive: true });

    this.syncTimer = setInterval(
      () => this.flush().catch(() => {}),
      this.config.audit.syncInterval * 1000,
    );
  }

  async stop(): Promise<void> {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
    await this.flush();
  }

  async record(input: AuditRecordInput): Promise<AuditEntry> {
    const entry: AuditEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      sessionId: input.sessionId,
      channel: input.channel,
      guard: input.guard,
      action: input.decision.action,
      riskLevel: input.decision.riskLevel,
      reasons: input.decision.reasons,
      piiCount: input.decision.piiDetected.length,
      ruleCount: input.decision.matchedRules.length,
      timing: input.decision.timing,
      hash: "",
      prevHash: this.prevHash,
    };

    const entryData = JSON.stringify({ ...entry, hash: undefined });
    entry.hash = computeAuditHash(this.prevHash, entryData);
    this.prevHash = entry.hash;

    this.buffer.push(entry);
    this.updateStats(entry.action);

    await this.writeLocal(entry);

    if (this.buffer.length >= 50) {
      this.flush().catch(() => {});
    }

    return entry;
  }

  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const batch = [...this.buffer];
    this.buffer = [];

    try {
      await this.client.submitAudit(batch as unknown as Record<string, unknown>[]);
    } catch {
      this.buffer.unshift(...batch);
    }
  }

  getStats() {
    return { ...this.stats };
  }

  private async writeLocal(entry: AuditEntry): Promise<void> {
    try {
      const date = entry.timestamp.slice(0, 10);
      const filePath = join(this.bufferPath, `shield_audit_${date}.jsonl`);
      await appendFile(filePath, JSON.stringify(entry) + "\n");
    } catch {
      // Best-effort local write
    }
  }

  private updateStats(action: string): void {
    this.stats.total++;
    switch (action) {
      case "BLOCK": this.stats.blocked++; break;
      case "FLAG": this.stats.flagged++; break;
      case "WARN": this.stats.warned++; break;
      case "PASS": this.stats.passed++; break;
    }
  }
}
