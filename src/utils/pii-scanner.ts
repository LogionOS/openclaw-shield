import type { PIIItem } from "../config.js";

interface PIIPattern {
  type: string;
  pattern: RegExp;
  severity: "high" | "medium" | "low";
}

const PII_PATTERNS: PIIPattern[] = [
  { type: "EMAIL", pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, severity: "medium" },
  { type: "PHONE_US", pattern: /(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, severity: "medium" },
  { type: "PHONE_JP", pattern: /(?:\+81[\s.-]?|0)\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{3,4}/g, severity: "medium" },
  { type: "SSN", pattern: /\b\d{3}[\s.-]\d{2}[\s.-]\d{4}\b/g, severity: "high" },
  { type: "CREDIT_CARD", pattern: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, severity: "high" },
  { type: "MY_NUMBER", pattern: /\b\d{4}\s?\d{4}\s?\d{4}\b/g, severity: "high" },
  { type: "API_KEY", pattern: /(?:sk|pk|api|key|token|bearer)[_\-]?[a-zA-Z0-9]{20,}/gi, severity: "high" },
  { type: "JWT", pattern: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, severity: "high" },
  { type: "AWS_KEY", pattern: /(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}/g, severity: "high" },
  { type: "PRIVATE_KEY", pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: "high" },
  { type: "PASSWORD", pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/gi, severity: "high" },
  { type: "IP_ADDRESS", pattern: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, severity: "low" },
];

const BLOCKLIST_PATTERNS = [
  { category: "prompt_injection", patterns: [
    /ignore (?:all |any )?(?:previous |prior |above )?instructions/i,
    /disregard (?:all |any )?(?:previous |prior |above )?(?:instructions|rules|guidelines)/i,
    /you are now (?:a |an )?(?:different|new) (?:ai|assistant|bot)/i,
    /override (?:your |the )?(?:system|safety|security) (?:prompt|instructions|rules)/i,
    /pretend (?:you are|to be|you're) (?:a |an )?(?:different|evil|unrestricted)/i,
    /jailbreak/i,
    /DAN mode/i,
    /bypass (?:your |the )?(?:safety|security|content) (?:filter|policy|rules)/i,
    /\[SYSTEM\]|\[INST\]|\<\|im_start\|/i,
  ]},
  { category: "harmful_content", patterns: [
    /how to (?:make|create|build|synthesize) (?:a )?(?:bomb|explosive|weapon)/i,
    /how to (?:hack|breach|exploit|attack) (?:a |an )?(?:system|server|network|database)/i,
  ]},
];

export function scanPII(text: string): PIIItem[] {
  const results: PIIItem[] = [];

  for (const { type, pattern, severity: _severity } of PII_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      results.push({
        type,
        value,
        location: { start: match.index, end: match.index + value.length },
        masked: maskValue(type, value),
      });
    }
  }

  return deduplicateByLocation(results);
}

export function scanBlocklist(text: string): { category: string; matched: string }[] {
  const hits: { category: string; matched: string }[] = [];

  for (const { category, patterns } of BLOCKLIST_PATTERNS) {
    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match) {
        hits.push({ category, matched: match[0] });
        break;
      }
    }
  }

  return hits;
}

export function maskValue(type: string, value: string): string {
  if (type === "EMAIL") {
    const [local, domain] = value.split("@");
    return `${local[0]}${"*".repeat(local.length - 1)}@${domain}`;
  }
  if (type === "CREDIT_CARD") {
    return `****-****-****-${value.slice(-4)}`;
  }
  if (type === "SSN") {
    return `***-**-${value.slice(-4)}`;
  }
  if (type === "PHONE_US" || type === "PHONE_JP") {
    return `${"*".repeat(value.length - 4)}${value.slice(-4)}`;
  }
  if (value.length > 8) {
    return `${value.slice(0, 4)}${"*".repeat(value.length - 8)}${value.slice(-4)}`;
  }
  return "*".repeat(value.length);
}

function deduplicateByLocation(items: PIIItem[]): PIIItem[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.location.start}:${item.location.end}:${item.type}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
