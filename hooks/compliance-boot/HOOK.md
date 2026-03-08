# LogionOS Shield — Boot Compliance Check

Runs a compliance health check when a new OpenClaw session starts.
Verifies API connectivity, policy sync status, and kill switch state.

## Events

- `/new` — New session created
- `/reset` — Session reset

## Behavior

On session start:
1. Verify LogionOS API is reachable
2. Check kill switch status
3. Log session start to audit trail
4. Inject compliance notice if in Strict mode
