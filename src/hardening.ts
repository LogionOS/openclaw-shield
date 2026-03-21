import { createHash, randomBytes } from "node:crypto";

// ── CSRF Token ──────────────────────────────────────────────
// Dashboard state-changing routes require a valid CSRF token.
// Token is generated per-session and embedded in the dashboard HTML.

let csrfToken: string | null = null;

export function generateCsrfToken(): string {
  csrfToken = randomBytes(32).toString("hex");
  return csrfToken;
}

export function validateCsrf(token: string | undefined): boolean {
  if (!csrfToken || !token) return false;
  if (token.length !== csrfToken.length) return false;
  // Constant-time comparison to prevent timing attacks
  let mismatch = 0;
  for (let i = 0; i < token.length; i++) {
    mismatch |= token.charCodeAt(i) ^ csrfToken.charCodeAt(i);
  }
  return mismatch === 0;
}

// ── CSP Headers ─────────────────────────────────────────────
// Strict Content Security Policy for the embedded dashboard.

export const CSP_HEADER = [
  "default-src 'none'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

export function setSecurityHeaders(res: { setHeader: (k: string, v: string) => void }): void {
  res.setHeader("Content-Security-Policy", CSP_HEADER);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
}

// ── API Endpoint Validation ─────────────────────────────────
// Prevent SSRF / redirect attacks on the LogionOS API connection.

const BLOCKED_HOSTS = new Set([
  "169.254.169.254",  // AWS metadata
  "metadata.google.internal",
  "100.100.100.200",  // Alibaba metadata
]);

export function validateApiEndpoint(endpoint: string): { valid: boolean; reason?: string } {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return { valid: false, reason: "Invalid URL format" };
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return { valid: false, reason: "Only HTTP/HTTPS protocols allowed" };
  }

  if (BLOCKED_HOSTS.has(url.hostname)) {
    return { valid: false, reason: "Blocked host (cloud metadata endpoint)" };
  }

  if (url.username || url.password) {
    return { valid: false, reason: "Credentials in URL are not allowed" };
  }

  return { valid: true };
}

export function requireTls(endpoint: string, mode: string): boolean {
  if (mode === "monitor") return false;
  const url = new URL(endpoint);
  return url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1";
}

// ── Input Normalization ─────────────────────────────────────
// Normalize Unicode before PII scanning to prevent evasion via
// homoglyphs, zero-width characters, and combining marks.

const ZERO_WIDTH_CHARS = /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/g;
const INVISIBLE_CONTROL = /[\x00-\x08\x0E-\x1F\x7F-\x9F]/g;

export function normalizeInput(text: string): string {
  let normalized = text.normalize("NFKC");
  normalized = normalized.replace(ZERO_WIDTH_CHARS, "");
  normalized = normalized.replace(INVISIBLE_CONTROL, "");
  normalized = decodeObfuscatedContent(normalized);
  return normalized;
}

function decodeObfuscatedContent(text: string): string {
  let result = text;

  const b64Pattern = /(?:base64|b64|encoded)[\s:=]+([A-Za-z0-9+/]{8,}={0,2})/gi;
  result = result.replace(b64Pattern, (_match, b64) => {
    try {
      const decoded = Buffer.from(b64, "base64").toString("utf-8");
      if (/[\x20-\x7E]/.test(decoded)) return `${_match} [DECODED: ${decoded}]`;
    } catch { /* not valid base64 */ }
    return _match;
  });

  const hexPattern = /(?:hex|0x)[\s:=]+([0-9a-fA-F]{8,})/gi;
  result = result.replace(hexPattern, (_match, hex) => {
    try {
      const decoded = Buffer.from(hex, "hex").toString("utf-8");
      if (/[\x20-\x7E]/.test(decoded)) return `${_match} [DECODED: ${decoded}]`;
    } catch { /* not valid hex */ }
    return _match;
  });

  const rot13Pattern = /(?:rot13|rot-13|caesar)[\s:=]+([a-zA-Z\s]{10,})/gi;
  result = result.replace(rot13Pattern, (_match, cipher) => {
    const decoded = cipher.replace(/[a-zA-Z]/g, (c: string) => {
      const base = c <= "Z" ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });
    return `${_match} [DECODED: ${decoded}]`;
  });

  return result;
}

// ── ReDoS Protection ────────────────────────────────────────
// Limit input length for regex scanning to prevent catastrophic
// backtracking on crafted payloads.

export const MAX_SCAN_LENGTH = 50_000;

export function safeTruncate(text: string): string {
  if (text.length <= MAX_SCAN_LENGTH) return text;
  return text.slice(0, MAX_SCAN_LENGTH);
}

// ── Rate Limiting (Dashboard API) ───────────────────────────
// Prevent brute-force and DoS on dashboard endpoints.

const requestCounts = new Map<string, { count: number; resetAt: number }>();
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 120;

export function checkDashboardRate(ip: string): boolean {
  const now = Date.now();
  const entry = requestCounts.get(ip);

  if (!entry || now >= entry.resetAt) {
    requestCounts.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return true;
  }

  entry.count++;
  return entry.count <= RATE_LIMIT;
}

// ── Self-Integrity Check ────────────────────────────────────
// Compute a hash of critical source files at startup to detect
// tampering. Logged to audit trail.

export function computeModuleHash(...sources: string[]): string {
  const hash = createHash("sha256");
  for (const src of sources) {
    hash.update(src);
  }
  return hash.digest("hex").slice(0, 16);
}

// ── Fail-Closed Watchdog ────────────────────────────────────
// If Shield crashes or becomes unresponsive, the watchdog
// ensures the gateway blocks requests rather than failing open.

let lastHeartbeat = Date.now();
const WATCHDOG_TIMEOUT_MS = 30_000;

export function heartbeat(): void {
  lastHeartbeat = Date.now();
}

export function isWatchdogHealthy(): boolean {
  return Date.now() - lastHeartbeat < WATCHDOG_TIMEOUT_MS;
}

// ── Sensitive Data Scrubbing (Logs) ─────────────────────────
// Never log API keys, raw PII values, or full message content.

export function scrubForLog(obj: Record<string, unknown>): Record<string, unknown> {
  const scrubbed = { ...obj };
  const sensitiveKeys = ["apiKey", "api_key", "password", "token", "secret", "authorization"];
  for (const key of Object.keys(scrubbed)) {
    if (sensitiveKeys.some((sk) => key.toLowerCase().includes(sk))) {
      scrubbed[key] = "[REDACTED]";
    }
    if (key === "message" || key === "query" || key === "response") {
      const val = String(scrubbed[key] ?? "");
      scrubbed[key] = `[REDACTED len=${val.length}]`;
    }
  }
  return scrubbed;
}
