# LogionOS Shield — Session Audit

Records session lifecycle events to the compliance audit trail.
Generates a compliance summary when a session ends.

## Events

- `/new` — Session created → log start
- `/stop` — Session ended → log end + generate summary
- `/reset` — Session reset → log reset + archive session data

## Behavior

On session end:
1. Retrieve session compliance summary from SessionTracker
2. Calculate risk profile and key metrics
3. Write final audit entry
4. Flush buffered audit data to LogionOS API
