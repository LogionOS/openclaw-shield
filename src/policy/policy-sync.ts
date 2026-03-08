import type { ShieldConfig } from "../config.js";
import type { LogionOSClient } from "../client.js";
import type { LocalCache } from "./local-cache.js";

export interface SyncStatus {
  lastSync: string | null;
  policyCount: number;
  killSwitchMode: string;
  healthy: boolean;
  nextSync: string;
}

export class PolicySync {
  private syncInterval: ReturnType<typeof setInterval> | null = null;
  private lastSyncTime: Date | null = null;

  constructor(
    private config: ShieldConfig,
    private client: LogionOSClient,
    private cache: LocalCache,
  ) {}

  async start(): Promise<void> {
    await this.cache.start();
    this.lastSyncTime = new Date();

    this.syncInterval = setInterval(
      () => this.checkForUpdates().catch(() => {}),
      this.config.performance.localCacheTtl * 1000,
    );
  }

  async stop(): Promise<void> {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
    await this.cache.stop();
  }

  getStatus(): SyncStatus {
    const nextSyncMs = this.cache.getLastSyncTime() + this.config.performance.localCacheTtl * 1000;
    return {
      lastSync: this.lastSyncTime?.toISOString() ?? null,
      policyCount: this.cache.getResourcePolicies().length,
      killSwitchMode: this.cache.getKillSwitchMode(),
      healthy: this.cache.isHealthy(),
      nextSync: new Date(nextSyncMs).toISOString(),
    };
  }

  async forceSync(): Promise<void> {
    await this.cache.stop();
    await this.cache.start();
    this.lastSyncTime = new Date();
  }

  private async checkForUpdates(): Promise<void> {
    try {
      const healthy = await this.client.isHealthy();
      if (healthy) {
        this.lastSyncTime = new Date();
      }
    } catch {
      // Silent fail — cache continues with stale data
    }
  }
}
