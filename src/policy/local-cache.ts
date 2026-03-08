import type { ShieldConfig } from "../config.js";
import type { LogionOSClient } from "../client.js";

interface CachedPolicy {
  id: string;
  name: string;
  category: string;
  scope: string[];
  enabled: boolean;
  rules: Record<string, unknown>;
  deniedResourceTags?: string[];
  allowedAgentRoles?: string[];
}

interface CacheState {
  policies: CachedPolicy[];
  killSwitchMode: string;
  lastSync: number;
  healthy: boolean;
}

export class LocalCache {
  private state: CacheState = {
    policies: [],
    killSwitchMode: "normal",
    lastSync: 0,
    healthy: false,
  };
  private refreshTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private config: ShieldConfig,
    private client: LogionOSClient,
  ) {}

  async start(): Promise<void> {
    await this.refresh();

    this.refreshTimer = setInterval(
      () => this.refresh().catch(() => {}),
      this.config.performance.localCacheTtl * 1000,
    );
  }

  async stop(): Promise<void> {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  isKillSwitchActive(): boolean {
    return this.state.killSwitchMode === "block_all";
  }

  getKillSwitchMode(): string {
    return this.state.killSwitchMode;
  }

  getResourcePolicies(): CachedPolicy[] {
    return this.state.policies.filter(
      (p) => p.category === "resource_access" && p.enabled,
    );
  }

  checkResourceAccess(resourceTags: string[], agentRole?: string): { allowed: boolean; violations: string[] } {
    const violations: string[] = [];

    for (const policy of this.getResourcePolicies()) {
      if (agentRole && policy.allowedAgentRoles?.includes(agentRole)) continue;

      const denied = policy.deniedResourceTags ?? [];
      const overlap = resourceTags.filter((t) => denied.includes(t));
      if (overlap.length > 0) {
        violations.push(`${policy.id}:${overlap.join(",")}`);
      }
    }

    return { allowed: violations.length === 0, violations };
  }

  isHealthy(): boolean {
    return this.state.healthy;
  }

  getLastSyncTime(): number {
    return this.state.lastSync;
  }

  private async refresh(): Promise<void> {
    try {
      const [policiesRes, killRes] = await Promise.allSettled([
        this.client.getPolicies(),
        this.client.getKillSwitch(),
      ]);

      if (policiesRes.status === "fulfilled") {
        this.state.policies = policiesRes.value.policies as unknown as CachedPolicy[];
      }

      if (killRes.status === "fulfilled") {
        this.state.killSwitchMode = killRes.value.mode;
      }

      this.state.lastSync = Date.now();
      this.state.healthy = true;
    } catch {
      this.state.healthy = false;
    }
  }
}
