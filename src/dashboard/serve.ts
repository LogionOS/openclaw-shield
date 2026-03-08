import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

type HttpRes = {
  statusCode: number;
  end: (body: string) => void;
  setHeader: (k: string, v: string) => void;
};

type HttpReq = {
  url?: string;
  method?: string;
};

type RegisterFn = (route: {
  path: string;
  auth: "gateway" | "plugin";
  match?: "exact" | "prefix";
  handler: (req: HttpReq, res: HttpRes) => Promise<boolean>;
}) => void;

interface ShieldRef {
  config: {
    mode: string;
    guards: Record<string, boolean>;
    toolPolicy: { denylist: string[]; requireApproval: string[] };
    apiEndpoint: string;
  };
  audit: { getStats: () => Record<string, number>; flush: () => Promise<void> };
  sessions: { getActiveSessions: () => Record<string, unknown>[] };
  policySync: { getStatus: () => Record<string, unknown>; forceSync: () => Promise<void> };
  cache: { isKillSwitchActive: () => boolean };
  client: { isHealthy: () => Promise<boolean> };
}

let dashboardHtml: string | null = null;

function loadDashboard(): string {
  if (dashboardHtml) return dashboardHtml;
  try {
    const dir = dirname(fileURLToPath(import.meta.url));
    dashboardHtml = readFileSync(join(dir, "dashboard.html"), "utf-8");
  } catch {
    dashboardHtml = buildInlineFallback();
  }
  return dashboardHtml;
}

function buildInlineFallback(): string {
  return `<!DOCTYPE html><html><head><title>LogionOS Shield</title></head>
<body style="background:#0a0a0f;color:#f0f0f5;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh">
<div style="text-align:center"><h1>LogionOS Shield</h1><p>Dashboard HTML not found. Check plugin installation.</p>
<p><a href="/logionos/status" style="color:#6366f1">View JSON Status</a></p></div></body></html>`;
}

export function registerDashboardRoutes(register: RegisterFn, getShield: () => ShieldRef | null): void {

  register({
    path: "/logionos",
    auth: "gateway",
    match: "exact",
    handler: async (_req, res) => {
      res.statusCode = 302;
      res.setHeader("Location", "/logionos/");
      res.end("");
      return true;
    },
  });

  register({
    path: "/logionos/",
    auth: "gateway",
    match: "exact",
    handler: async (_req, res) => {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "no-cache");
      res.statusCode = 200;
      res.end(loadDashboard());
      return true;
    },
  });

  register({
    path: "/logionos/status",
    auth: "gateway",
    match: "exact",
    handler: async (_req, res) => {
      const s = getShield();
      if (!s) return jsonRes(res, 503, { error: "Shield not initialized" });
      const stats = s.audit.getStats();
      const sync = s.policySync.getStatus();
      return jsonRes(res, 200, {
        shield: { version: "0.1.0", mode: s.config.mode, guards: s.config.guards, uptime: process.uptime() },
        compliance: stats,
        policy: sync,
      });
    },
  });

  register({
    path: "/logionos/stats",
    auth: "gateway",
    match: "exact",
    handler: async (_req, res) => {
      const s = getShield();
      if (!s) return jsonRes(res, 503, { error: "Shield not initialized" });
      return jsonRes(res, 200, s.audit.getStats());
    },
  });

  register({
    path: "/logionos/sessions",
    auth: "gateway",
    match: "exact",
    handler: async (_req, res) => {
      const s = getShield();
      if (!s) return jsonRes(res, 503, { error: "Shield not initialized" });
      return jsonRes(res, 200, { sessions: s.sessions.getActiveSessions() });
    },
  });

  register({
    path: "/logionos/api/mode",
    auth: "gateway",
    match: "exact",
    handler: async (req, res) => {
      const s = getShield();
      if (!s) return jsonRes(res, 503, { error: "Shield not initialized" });
      // Mode change is handled by reading the body in a real impl
      // For now, respond with current mode
      return jsonRes(res, 200, { mode: s.config.mode });
    },
  });

  register({
    path: "/logionos/api/guards",
    auth: "gateway",
    match: "exact",
    handler: async (_req, res) => {
      const s = getShield();
      if (!s) return jsonRes(res, 503, { error: "Shield not initialized" });
      return jsonRes(res, 200, { guards: s.config.guards });
    },
  });

  register({
    path: "/logionos/api/kill-switch",
    auth: "gateway",
    match: "exact",
    handler: async (_req, res) => {
      const s = getShield();
      if (!s) return jsonRes(res, 503, { error: "Shield not initialized" });
      return jsonRes(res, 200, { active: s.cache.isKillSwitchActive() });
    },
  });

  register({
    path: "/logionos/api/policies/sync",
    auth: "gateway",
    match: "exact",
    handler: async (_req, res) => {
      const s = getShield();
      if (!s) return jsonRes(res, 503, { error: "Shield not initialized" });
      await s.policySync.forceSync();
      return jsonRes(res, 200, { status: "synced", ...s.policySync.getStatus() });
    },
  });

  register({
    path: "/logionos/audit/export",
    auth: "gateway",
    match: "exact",
    handler: async (_req, res) => {
      const s = getShield();
      if (!s) return jsonRes(res, 503, { error: "Shield not initialized" });
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=shield_audit.csv");
      res.statusCode = 200;
      res.end("id,timestamp,guard,action,risk_level,reasons,pii_count,rule_count\n");
      return true;
    },
  });
}

function jsonRes(res: HttpRes, status: number, data: unknown): true {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.statusCode = status;
  res.end(JSON.stringify(data));
  return true;
}
