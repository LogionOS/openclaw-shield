import type { ComplianceAction, RiskLevel } from "../config.js";

interface SessionState {
  sessionId: string;
  channel: string;
  startedAt: string;
  lastActivityAt: string;
  checkCount: number;
  blockCount: number;
  flagCount: number;
  warnCount: number;
  passCount: number;
  piiDetections: number;
  ruleMatches: number;
  cumulativeRiskScore: number;
  highestAction: ComplianceAction;
  toolCalls: { name: string; allowed: boolean }[];
}

export interface SessionSummary {
  sessionId: string;
  channel: string;
  duration: number;
  checkCount: number;
  riskProfile: RiskLevel;
  actions: { block: number; flag: number; warn: number; pass: number };
  piiDetections: number;
  ruleMatches: number;
  toolCallCount: number;
  blockedToolCount: number;
}

const RISK_WEIGHTS: Record<ComplianceAction, number> = {
  PASS: 0,
  WARN: 1,
  FLAG: 5,
  BLOCK: 10,
};

export class SessionTracker {
  private sessions = new Map<string, SessionState>();
  private maxSessions = 1000;

  recordCheck(
    sessionId: string,
    channel: string,
    action: ComplianceAction,
    piiCount: number,
    ruleCount: number,
  ): void {
    let state = this.sessions.get(sessionId);
    if (!state) {
      if (this.sessions.size >= this.maxSessions) {
        this.evictOldest();
      }
      state = {
        sessionId,
        channel,
        startedAt: new Date().toISOString(),
        lastActivityAt: new Date().toISOString(),
        checkCount: 0,
        blockCount: 0,
        flagCount: 0,
        warnCount: 0,
        passCount: 0,
        piiDetections: 0,
        ruleMatches: 0,
        cumulativeRiskScore: 0,
        highestAction: "PASS",
        toolCalls: [],
      };
      this.sessions.set(sessionId, state);
    }

    state.lastActivityAt = new Date().toISOString();
    state.checkCount++;
    state.piiDetections += piiCount;
    state.ruleMatches += ruleCount;
    state.cumulativeRiskScore += RISK_WEIGHTS[action];

    switch (action) {
      case "BLOCK": state.blockCount++; break;
      case "FLAG": state.flagCount++; break;
      case "WARN": state.warnCount++; break;
      case "PASS": state.passCount++; break;
    }

    const actionOrder: ComplianceAction[] = ["PASS", "WARN", "FLAG", "BLOCK"];
    if (actionOrder.indexOf(action) > actionOrder.indexOf(state.highestAction)) {
      state.highestAction = action;
    }
  }

  recordToolCall(sessionId: string, toolName: string, allowed: boolean): void {
    const state = this.sessions.get(sessionId);
    if (state) {
      state.toolCalls.push({ name: toolName, allowed });
    }
  }

  getSummary(sessionId: string): SessionSummary | null {
    const state = this.sessions.get(sessionId);
    if (!state) return null;

    const duration = new Date(state.lastActivityAt).getTime() - new Date(state.startedAt).getTime();
    const avgRisk = state.checkCount > 0 ? state.cumulativeRiskScore / state.checkCount : 0;

    return {
      sessionId: state.sessionId,
      channel: state.channel,
      duration,
      checkCount: state.checkCount,
      riskProfile: avgRisk >= 8 ? "critical" : avgRisk >= 4 ? "high" : avgRisk >= 1 ? "medium" : "low",
      actions: {
        block: state.blockCount,
        flag: state.flagCount,
        warn: state.warnCount,
        pass: state.passCount,
      },
      piiDetections: state.piiDetections,
      ruleMatches: state.ruleMatches,
      toolCallCount: state.toolCalls.length,
      blockedToolCount: state.toolCalls.filter((t) => !t.allowed).length,
    };
  }

  getActiveSessions(): SessionSummary[] {
    return Array.from(this.sessions.keys())
      .map((id) => this.getSummary(id))
      .filter((s): s is SessionSummary => s !== null);
  }

  endSession(sessionId: string): SessionSummary | null {
    const summary = this.getSummary(sessionId);
    this.sessions.delete(sessionId);
    return summary;
  }

  private evictOldest(): void {
    let oldest: string | null = null;
    let oldestTime = Infinity;

    for (const [id, state] of this.sessions) {
      const t = new Date(state.lastActivityAt).getTime();
      if (t < oldestTime) {
        oldestTime = t;
        oldest = id;
      }
    }

    if (oldest) this.sessions.delete(oldest);
  }
}
