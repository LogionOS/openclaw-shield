import { createHash } from "node:crypto";

export function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function computeAuditHash(prevHash: string, entryData: string): string {
  return sha256(`${prevHash}:${entryData}`);
}

export function generateId(): string {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  return `${ts}-${rand}`;
}
