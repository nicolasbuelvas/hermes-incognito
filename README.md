# Hermes Incognito

Zero-trace ephemeral sessions, outbound PII redaction, tool mutation guards, and cryptographic forensic verification for Hermes Agent CLI, TUI, Gateway, and Desktop.

## Architecture

Hermes Incognito operates as an in-process security and privacy layer intercepting lifecycle events, tool calls, and model communication:

```
┌─────────────────────────────────────────────────────────────┐
│                      Hermes Agent                           │
├───────────────┬─────────────────────────────┬───────────────┤
│ CLI / TUI     │ Desktop (React / SDK)       │ Gateway / RPC │
└───────┬───────┴──────────────┬──────────────┴───────┬───────┘
        │                      │                      │
        ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   Incognito Engine                          │
├──────────────────────────────┬──────────────────────────────┤
│ Lifecycle Hooks              │ Security Interceptors        │
│ • on_session_start           │ • pre_tool_call (Tool Guard) │
│ • on_session_end             │ • pre_llm_call (Middleware)  │
│ • post_compaction            │ • RAM-Only PII Vault         │
├──────────────────────────────┴──────────────────────────────┤
│ Secure Deletion & Forensic Verifier                         │
│ • SQLite row removal (`state.db`)                           │
│ • File zero-filling & unlinking (`sessions/*.jsonl`)        │
│ • Cryptographic receipt generation                          │
└─────────────────────────────────────────────────────────────┘
```

1. **State Isolation:** Ephemeral sessions are tagged in an isolated, volatile registry and filtered out of standard conversation lists and sidebars.
2. **Tool Mutation Guard:** Active incognito chats intercept `pre_tool_call`. Attempts to mutate persistent storage (`memory`, `skill_manage`) or inspect historical chats (`session_search`, `cronjob_manage` in strict mode) are blocked with structured explanations returned to the agent.
3. **RAM-Only Middleware:** In strict mode, user profiles and personal notes are stripped from outbound prompts in RAM before reaching model providers. When PII redaction is enabled, sensitive tokens (emails, phone numbers, identifiers) are replaced with synthetic placeholders and restored transparently upon response streaming.
4. **Lifecycle & Compaction Tracking:** When context compaction occurs, incognito status, TTL leases, and active RAM vault tables transfer seamlessly to continuation sessions while unlinking compressed history.
5. **Secure Scrubbing:** Upon chat completion or TTL idle expiration, sessions are burned: associated SQLite database rows are deleted, transcript files are overwritten with zeros and unlinked, hook output caches are removed, and volatile RAM vaults are wiped.

---

## Feature Matrix: Standard vs Strict Mode

| Security Feature | Off (Standard Hermes) | Standard Incognito | Strict Clean-Room |
| :--- | :---: | :---: | :---: |
| **Session Persistence** | Retained permanently | Ephemeral (Auto-purged) | Ephemeral (Auto-purged) |
| **Visible in Sidebars/Lists** | Yes | Hidden | Hidden |
| **Memory Writes (`memory`)** | Allowed | **Blocked** | **Blocked** |
| **Skill Mutations (`skill_manage`)** | Allowed | **Blocked** | **Blocked** |
| **Cross-Session Search (`session_search`)** | Allowed | Allowed | **Blocked** |
| **Scheduled Tasks (`cronjob_manage`)** | Allowed | Allowed | **Blocked** |
| **Outbound Profile / Notes Stripping** | No | No | **Enforced in RAM** |
| **Reversible In-RAM PII Masking** | Disabled | Optional | Optional / Enabled |
| **Provider Non-Retention Hints (ZDR)** | No | Attached | Attached |
| **Zero-Fill Prior to Unlink** | No | Yes | Yes |
| **Cryptographic Zero-Trace Audit** | N/A | Supported | Supported |

---

## Installation

Install using Hermes Plugin Manager:

```bash
hermes plugins install nicolasbuelvas/hermes-incognito
```

Or install locally for development:

```bash
hermes plugins install ./hermes-incognito
```

To enable the plugin:

```bash
hermes plugins enable incognito
```

---

## Usage

### 1. Command-Line Interface (CLI)

```bash
# Check global and session status
hermes incognito status

# Arm next interactive chat in strict mode with 30m TTL
hermes incognito arm --mode strict --ttl 30

# Disarm pending session
hermes incognito disarm

# Run orphan sweeper across all expired sessions
hermes incognito sweep

# Perform forensic zero-trace audit on a session
hermes incognito verify <session_id>
```

### 2. Slash Commands

Within any active Hermes conversation:

- `/incognito`: View privacy status, active mode, and metric counters.
- `/incognito on [standard|strict]`: Transition the current chat into incognito mode.
- `/incognito off`: Disable incognito mode and retain future conversation history.
- `/incognito arm [standard|strict]`: Arm the next new draft chat.
- `/incognito burn`: Immediately scrub, zero-fill, and unlink the active session.
- `/incognito sweep`: Purge idle or orphaned incognito sessions.
- `/incognito verify [session_id]`: Audit local files and database state for residual traces.

### 3. Agent Tool Calling

The plugin registers two tools for autonomous or user-guided privacy operations:

- **`incognito_control`**: Enables, arms, toggles, disables, or burns sessions.
  ```json
  {
    "action": "enable",
    "mode": "strict",
    "ttl_minutes": 45,
    "redact_pii": true
  }
  ```
- **`incognito_verify`**: Audits database tables, disk transcripts, and memory vaults.
  ```json
  {
    "session_id": "sess-current-id"
  }
  ```

### 4. Desktop Integration

When used with Hermes Desktop, Incognito provides native integration:

- **High-Contrast Privacy Banner (`COMPOSER_AREAS.top`):** Appears above the composer when an incognito session or armed draft is active. Displays real-time counters for blocked writes, RAM redactions, and remaining TTL, alongside instant `Switch Strict/Standard`, `Keep & Exit`, and `Burn Now` buttons.
- **Status Bar Indicator (`STATUSBAR_AREAS.right`):** One-click indicator showing `INCOGNITO: ON (STRICT)`, `INCOGNITO: ON (STANDARD)`, `INCOGNITO: ARMED`, or `INCOGNITO: OFF`.
- **Keyboard Shortcut (`KEYBINDS_AREA`):** Press `Ctrl+Shift+I` (or `Cmd+Shift+I` on macOS) to instantly toggle incognito mode on the focused chat.
- **Command Palette (`PALETTE_AREA`):** Five registered commands for quick navigation, arming, burning, and mode switching.
- **Privacy Control Center (`ROUTES_AREA` & `SIDEBAR_NAV_AREA`):** Dedicated `/incognito` dashboard featuring real-time telemetry, session arming toggles, and an interactive Forensic Zero-Trace Verifier.

---

## Forensic Zero-Trace Verification Walkthrough

When an incognito session is burned or expires via idle TTL, the scrubbing engine guarantees complete elimination of local residue:

1. **Database Scrubbing:** Removes incognito session and compression-chain rows (including FTS5 index entries) via `SessionDB.delete_session(..., include_compression_chain=True)`, retaining a pending-burn tombstone for deferred retry if an active turn guard is still settling.
2. **File Overwrite & Unlink:** Locates exact session files in `$HERMES_HOME/sessions/` and confined per-session spill directories/files in `$HERMES_HOME/hook_outputs/`. Overwrites every byte with zero blocks before calling file unlink.
3. **Vault Depletion:** Discards in-memory encryption keys and reversible PII mapping tables.
4. **Audit Receipt:** Emits a content-free cryptographic receipt containing timestamp, verification checksum, and counts of cleared artifacts.

To verify zero trace at any time:

```bash
hermes incognito verify <session_id>
```

Sample audit report:

```json
{
  "session_id": "sess-92a18f4d",
  "zero_trace": true,
  "db_rows_found": 0,
  "session_files_found": 0,
  "hook_files_found": 0,
  "ram_vault_entries": 0,
  "active_lease": false,
  "receipt_id": "rcpt-55e2a10b42c98d7f"
}
```

---

## Privacy Boundaries & Catalog Rule 13 Security Disclosure

Hermes Incognito is designed to provide high-assurance defense against **local inspection, persistence leakage, and unintentional profile pollution**. To maintain rigorous engineering honesty, the following boundaries must be understood:

1. **Local Host Scope:** Incognito guarantees that session history, tool mutations, and temporary spill files are scrubbed from the local host system. It cannot prevent host-level memory dump inspection while a process is actively executing with administrative privileges.
2. **Upstream Provider Retention:** Outbound prompts travel to configured model provider APIs over encrypted TLS. While this plugin attaches Zero Data Retention (ZDR) request hints where supported, the upstream provider's logging, training, and data retention policies remain governed by your provider account agreement.
3. **Hardware Storage Media (SSDs):** When `zero_fill_files` is enabled, the plugin overwrites files prior to unlinking. However, on modern Solid-State Drives (SSDs) utilizing wear-leveling algorithms or Copy-on-Write (CoW) filesystems (such as Btrfs, APFS, or ZFS), physical flash blocks may retain historical data until garbage collection cycles occur. For absolute hardware guarantees, run Hermes within encrypted disk volumes (LUKS, BitLocker, FileVault).
4. **Reversible PII Masking:** Outbound PII masking operates using pattern recognition for standard email formats, phone numbers, and common token structures. Obfuscated or non-standard identifiers not matched by regex filters may not be caught by outbound redaction.

---

## Configuration Reference

Configure via `config.yaml` or through the Hermes settings UI:

| Setting | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `default_mode` | string | `"off"` | Starting mode for new chats (`"off"`, `"standard"`, `"strict"`). |
| `auto_purge_on_exit` | boolean | `true` | Automatically scrub SQLite rows and files when a chat ends. |
| `default_ttl_minutes` | integer | `60` | Maximum idle minutes before orphan sweeper purges chat (0 disables). |
| `redact_outbound_pii` | boolean | `false` | Mask emails, phone numbers, and secrets in RAM before sending. |
| `provider_zdr_hints` | boolean | `true` | Transmit non-retention headers to compatible model providers. |
| `zero_fill_files` | boolean | `true` | Overwrite transcript files with zero bytes prior to unlinking. |

---

## License

MIT License. Copyright (c) 2026 Nicolas Buelvas.
