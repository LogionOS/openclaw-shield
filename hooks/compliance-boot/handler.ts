import type { HookHandler } from "../../src/types.js";

const handler: HookHandler = async (event) => {
  if (event.type !== "command") return;
  if (event.action !== "new" && event.action !== "reset") return;

  const shield = (globalThis as Record<string, unknown>).__logionos_shield as
    | { cache: { isKillSwitchActive: () => boolean; isHealthy: () => boolean }; config: { mode: string } }
    | undefined;

  if (!shield) return;

  if (shield.cache.isKillSwitchActive()) {
    event.messages.push(
      "🔒 **LogionOS Shield**: System is in lockdown mode. All AI interactions are blocked until an administrator lifts the restriction.",
    );
    return;
  }

  if (!shield.cache.isHealthy()) {
    event.messages.push(
      "⚠️ **LogionOS Shield**: Compliance API is unreachable. Operating in degraded mode with local-only checks.",
    );
  }

  if (shield.config.mode === "strict") {
    event.messages.push(
      "🛡️ **LogionOS Shield**: Strict compliance mode is active. All messages and tool calls are subject to compliance screening.",
    );
  }
};

export default handler;
