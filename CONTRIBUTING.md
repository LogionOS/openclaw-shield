# Contributing to LogionOS Shield

Thanks for your interest in making AI agents safer. Here's how to contribute.

## Quick Start

```bash
git clone https://github.com/LogionOS/openclaw-shield.git
cd openclaw-shield
npm install
npm run typecheck
```

## Development

Shield is a TypeScript OpenClaw plugin. It runs inside the OpenClaw gateway process.

### Project Structure

- `src/guards/` — The four compliance guards (inbound, outbound, prompt, tool)
- `src/audit/` — Audit logging and session tracking
- `src/policy/` — Policy sync and local cache
- `src/dashboard/` — Embedded web dashboard
- `src/utils/` — PII scanner, hash chain utilities
- `hooks/` — OpenClaw lifecycle hooks
- `skills/` — Agent compliance instructions

### Adding a PII Pattern

Edit `src/utils/pii-scanner.ts` and add your pattern to the `PII_PATTERNS` array:

```typescript
{ type: "YOUR_TYPE", pattern: /your-regex/g, severity: "high" | "medium" | "low" }
```

### Adding a Blocklist Pattern

Edit `src/utils/pii-scanner.ts` and add to `BLOCKLIST_PATTERNS`.

### Adding a ClawJacked Signature

Edit `src/guards/prompt-guard.ts` and add to `CLAWJACKED_SIGNATURES`.

## Pull Requests

1. Fork the repo and create a feature branch
2. Make your changes with clear commit messages
3. Run `npm run typecheck` to verify no type errors
4. Submit a PR with a description of what and why

## Reporting Security Issues

If you find a security vulnerability in Shield, please email security@logionos.com instead of opening a public issue.

## Code of Conduct

Be respectful. We're building safety tools — let's be safe with each other too.
