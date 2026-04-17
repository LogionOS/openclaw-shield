import type { PIIItem } from "../config.js";
import { normalizeInput, safeTruncate } from "../hardening.js";

interface PIIPattern {
  type: string;
  pattern: RegExp;
  severity: "high" | "medium" | "low";
}

const PII_PATTERNS: PIIPattern[] = [
  { type: "EMAIL", pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: "medium" },
  { type: "PHONE_US", pattern: /(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, severity: "medium" },
  { type: "PHONE_JP", pattern: /(?:\+81[\s.-]?|0)\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{3,4}/g, severity: "medium" },
  { type: "SSN", pattern: /\b\d{3}[\s.-]\d{2}[\s.-]\d{4}\b/g, severity: "high" },
  { type: "CREDIT_CARD", pattern: /\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, severity: "high" },
  { type: "CREDIT_CARD", pattern: /\b3[47]\d{2}[- ]?\d{6}[- ]?\d{5}\b/g, severity: "high" },
  { type: "CREDIT_CARD", pattern: /\b3[47]\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{3}\b/g, severity: "high" },
  { type: "MY_NUMBER", pattern: /\b\d{4}\s?\d{4}\s?\d{4}\b/g, severity: "high" },
  { type: "API_KEY", pattern: /(?:sk|pk|api|key|token|bearer)[_-][a-zA-Z0-9_-]{20,}/gi, severity: "high" },
  { type: "JWT", pattern: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, severity: "high" },
  { type: "AWS_KEY", pattern: /(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}/g, severity: "high" },
  { type: "PRIVATE_KEY", pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: "high" },
  { type: "PASSWORD", pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/gi, severity: "high" },
  { type: "IP_ADDRESS", pattern: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, severity: "low" },
  { type: "US_ADDRESS", pattern: /\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Rd|Road|Ln|Lane|Way|Ct|Court|Pl(?:ace)?|Terr?(?:ace)?|Cir(?:cle)?|Pkwy|Hwy)\b/g, severity: "medium" },
  { type: "SALARY", pattern: /(?:salary|compensation|income|wage|pay|earning)[s]?\s*(?:is|of|:)?\s*\$[\d,]+(?:\.\d{2})?/gi, severity: "medium" },
  { type: "MONETARY_PII", pattern: /\$\d{2,3},\d{3}(?:,\d{3})*(?:\.\d{2})?\b/g, severity: "low" },
  // Crypto wallet and key patterns
  { type: "ETH_ADDRESS", pattern: /\b0x[a-fA-F0-9]{40}\b/g, severity: "high" },
  { type: "BTC_ADDRESS", pattern: /\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b/g, severity: "high" },
  { type: "SOL_ADDRESS", pattern: /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g, severity: "high" },
  { type: "HEX_SECRET_64", pattern: /\b[0-9a-fA-F]{64}\b/g, severity: "high" },
  { type: "SEED_PHRASE", pattern: /(?:seed|mnemonic|recovery|backup)\s*(?:phrase|words?)?\s*[:=]?\s*(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}/gi, severity: "high" },
  { type: "WIF_KEY", pattern: /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g, severity: "high" },
  { type: "XPRV_KEY", pattern: /\bxprv[a-zA-Z0-9]{107,108}\b/g, severity: "high" },
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
    /\[SYSTEM\]|\[INST\]|<\|im_start\|/i,
  ]},
  { category: "prompt_extraction", patterns: [
    /(?:show|display|print|output|reveal|repeat|echo|dump)\s+(?:me\s+)?(?:your |the |my )?(?:(?:full|complete|entire|exact)\s+)?(?:system|original|initial)?\s*(?:prompt|instructions|rules|guidelines|configuration|directives)/i,
    /what (?:are|were|is) your (?:system |original |initial )?(?:prompt|instructions|rules|guidelines|directives)/i,
    /(?:copy(?:\s+and\s+paste)?|paste|reproduce|recite|verbatim|word.for.word)\s+(?:your |the |my )?(?:(?:full|complete|entire|exact|original)\s+)?(?:instructions|prompt|rules|system message)/i,
    /(?:tell|give|send)\s+me\s+(?:your |the )?(?:(?:exact|full|complete|entire|original)\s+){1,2}(?:prompt|instructions|system)/i,
    /(?:begin|start)\s+(?:your |the )?(?:response|output|reply)\s+with\s+(?:your |the )?(?:system|original)\s+(?:prompt|instructions)/i,
    /(?:translate|encode|convert)\s+(?:your |the )?(?:(?:system|original)\s+)?(?:prompt|instructions)\s+(?:to|into|in)\s+/i,
    /(?:summarize|paraphrase|rephrase)\s+(?:your |the )?(?:(?:system|original)\s+)?(?:prompt|instructions|rules)/i,
    /(?:ignore|forget).*(?:then|and|now)\s+(?:show|print|output|tell|give)\s+(?:me\s+)?(?:your |the )?(?:prompt|instructions|rules)/i,
    /(?:first|before)\s+(?:\d+ )?(?:words?|lines?|sentences?|characters?)\s+of\s+(?:your |the )?(?:prompt|instructions|system)/i,
  ]},
  { category: "harmful_content", patterns: [
    /how to (?:make|create|build|synthesize) (?:a )?(?:bomb|explosive|weapon)/i,
    /how to (?:hack|breach|exploit|attack) (?:a |an )?(?:system|server|network|database)/i,
  ]},
  { category: "crypto_exfiltration", patterns: [
    /(?:send|transfer|withdraw|move)\s+(?:all|my|the)\s+(?:funds|tokens|coins|balance|crypto|eth|btc|sol|usdt|usdc)/i,
    /(?:export|dump|show|print|read|get)\s+(?:my |the )?(?:seed|mnemonic|private.?key|keystore|wallet)/i,
    /(?:wallet\.dat|keystore\.json|\.keys|device\.json|soul\.md)/i,
    /(?:sign|approve)\s+(?:transaction|transfer|swap)\s+(?:to|for)\s+(?:0x|bc1)/i,
  ]},
];

export function scanPII(rawText: string): PIIItem[] {
  const text = safeTruncate(normalizeInput(rawText));
  const results: PIIItem[] = [];

  for (const { type, pattern, severity: _severity } of PII_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    let iterations = 0;
    while ((match = regex.exec(text)) !== null) {
      if (++iterations > 500) break;
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

export function scanBlocklist(rawText: string): { category: string; matched: string }[] {
  const text = safeTruncate(normalizeInput(rawText));
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
  if (type === "US_ADDRESS") {
    return "[REDACTED ADDRESS]";
  }
  if (type === "SALARY" || type === "MONETARY_PII") {
    return "$***,***";
  }
  if (type === "ETH_ADDRESS" || type === "BTC_ADDRESS" || type === "SOL_ADDRESS") {
    return `${value.slice(0, 6)}..${value.slice(-4)}`;
  }
  if (type === "SEED_PHRASE") {
    return "[REDACTED SEED PHRASE]";
  }
  if (type === "WIF_KEY" || type === "XPRV_KEY" || type === "HEX_SECRET_64") {
    return `${value.slice(0, 4)}${"*".repeat(8)}`;
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
