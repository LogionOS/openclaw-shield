import type { HookHandler } from "../../src/types.js";

const handler: HookHandler = async (event) => {
  if (event.type !== "command") return;

  const shield = (globalThis as Record<string, unknown>).__logionos_shield as
    | {
        sessions: {
          endSession: (id: string) => { riskProfile: string; checkCount: number; actions: { block: number } } | null;
        };
        audit: { flush: () => Promise<void> };
      }
    | undefined;

  if (!shield) return;

  const sessionId = String(event.sessionId ?? "unknown");

  if (event.action === "stop" || event.action === "reset") {
    const summary = shield.sessions.endSession(sessionId);

    if (summary) {
      const risk =
        summary.riskProfile === "critical" ? "🔴" :
        summary.riskProfile === "high" ? "🟠" :
        summary.riskProfile === "medium" ? "🟡" : "🟢";

      event.messages.push(
        `${risk} **Session Compliance Summary**: ${summary.checkCount} checks, ${summary.actions.block} blocked, risk: ${summary.riskProfile}`,
      );
    }

    await shield.audit.flush();
  }
};

export default handler;
