---
name: incognito-privacy
description: "Use when managing ephemeral, private, or incognito sessions and verifying zero-trace deletion."
---

# Incognito Privacy

Operational procedures for ephemeral sessions, outbound PII redaction, tool mutation guards, and zero-trace forensic verification.

## Modes

- `standard`:
  - Ephemeral session hidden from session history listings and dashboard sidebars.
  - Blocks persistent memory writes (`memory` tool) and skill modifications (`skill_manage` tool).
  - Outbound queries retain existing user profile and notes for contextual assistance.
  - Automatically deleted upon session close or TTL expiration.
- `strict` (Clean-Room):
  - All guarantees of `standard`.
  - Blocks cross-session inspection tools (`session_search`, `cronjob_manage`).
  - Completely strips user profile and personal notes sections from outbound LLM prompts in RAM before sending.
  - Reversible RAM-only PII redaction (masks emails, phone numbers, cards, synthetic secrets).
  - Enforces strict confirmation on outbound message dispatches (`send_message`).

## Tools & Commands

### Tool: `incognito_control`
Control ephemeral state on the current or target session.
- Engage standard mode:
  `incognito_control(action="enable", mode="standard", ttl_minutes=60)`
- Engage strict clean-room mode with PII masking:
  `incognito_control(action="enable", mode="strict", ttl_minutes=30, redact_pii=true)`
- Arm next new session:
  `incognito_control(action="arm", mode="strict", ttl_minutes=45)`
- Disarm pending session:
  `incognito_control(action="disarm")`
- Purge and burn immediately:
  `incognito_control(action="burn")`
- Disable incognito while retaining chat transcript:
  `incognito_control(action="disable", keep=true)`

### Tool: `incognito_verify`
Run forensic verification on a session ID to confirm zero lingering trace on disk and in memory:
- `incognito_verify(session_id="<session_id>")`
- Verifies:
  - SQLite `state.db` session and message rows are 0.
  - Session transcript JSONL files are deleted.
  - Hook output spill directories are wiped.
  - RAM PII vault entries are purged.
  - Returns cryptographic receipt ID proving zero residue.

### Slash Commands
- `/incognito`: Show status summary and active mode.
- `/incognito on [standard|strict]`: Engage incognito for current chat.
- `/incognito arm [standard|strict]`: Arm the next created chat.
- `/incognito burn`: Immediately overwrite, unlink, and delete current chat.
- `/incognito sweep`: Purge all expired incognito sessions.
- `/incognito verify <id>`: Run forensic zero-trace audit.

### CLI Commands
- `hermes incognito status`
- `hermes incognito arm --mode strict --ttl 30`
- `hermes incognito sweep`
- `hermes incognito verify <session_id>`

## Privacy Boundaries

- **Local Machine Scoping:** SQLite records, JSONL transcripts, compaction continuations, and temporary hook files are zero-filled and unlinked upon session burn or expiry.
- **Provider-Side Retention:** Ephemeral status protects the local host. While provider Zero Data Retention (ZDR) request hints are sent to compatible backends, upstream LLM provider API retention policies remain governed by the provider terms of service.
- **RAM-Only Vault:** PII redaction mappings exist solely in volatile memory and are cleared instantly when the session is burned.
