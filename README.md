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
4. **Lifecycle & Compaction Tracking:** When context compaction occurs, incognito status, TTL leases, and active RAM vault tables transfer to the continuation session. The compacted sessions become ancestors: they have no TTL of their own, are never swept or finalized on their own, and are deleted together with the live continuation when it is burned.
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
| **Reversible In-RAM PII Masking** | Disabled | Optional (`redact_pii`) | Optional (`redact_pii`); on by default when Desktop starts a Strict chat |
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

- `/incognito` or `/incognito status`: View privacy status, active mode, and metric counters. It never changes the mode.
- `/incognito on [standard|strict]`: Transition the current chat into incognito mode.
- `/incognito off`: Disable incognito mode and retain future conversation history.
- `/incognito toggle`: Switch incognito mode on or off for the current chat.
- `/incognito arm [standard|strict]`: Arm the next new draft chat.
- `/incognito burn`: Immediately scrub, zero-fill, and unlink the active session.
- `/incognito sweep`: Purge idle or orphaned incognito sessions.
- `/incognito verify [session_id]`: Audit local files and database state for residual traces.

### 3. Agent Tool Calling

The plugin registers two tools for autonomous or user-guided privacy operations:

- **`incognito_control`**: Manages privacy for the active session and arms the next session. Its `status` reports only the active session. Use `/incognito burn`, the CLI, or the Desktop burn control to delete a session.
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

The Desktop UI uses the Hermes UI kit (`Badge`, `SegmentedControl`, `ToggleRow`, `Tip`, `ConfirmDialog`) and theme variables, so it follows the active Hermes theme. Newer kit pieces are feature-detected, with plain fallbacks on older Desktop builds.

- **First-run hint (`COMPOSER_AREAS.top`):** A dismissible note above the composer explains the two levels and offers **Try Standard** and **Compare levels**. It stays dismissed after you close it, try a level, or open the Incognito page.
- **Chat banner (`COMPOSER_AREAS.top`):** While a chat is in Incognito, shows the level (with a tooltip that explains it), the auto-delete deadline and time left (for example, `Deleted after 60 min idle · 42 min left`), and whether personal details are masked. Buttons: **Switch to Strict/Standard**, **Exit Incognito, keep chat**, and **Delete now…**.
- **Status bar (`STATUSBAR_AREAS.right`):** `Incognito off`, `Incognito · Standard`, `Incognito · Strict`, or `Next chat: Incognito · …`, with a tooltip. Clicking it turns Incognito on (Standard) or off (keeps the chat).
- **Keyboard shortcut (`KEYBINDS_AREA`):** `Ctrl+Shift+I` (`Cmd+Shift+I` on macOS) turns Incognito on or off for the focused chat. The toast states the resulting state.
- **Command palette (`PALETTE_AREA`):** Turn on or off, use Standard, use Strict, start the next new chat in Incognito, delete this chat, and open the privacy levels page.
- **Incognito page (`ROUTES_AREA` and `SIDEBAR_NAV_AREA`):** A level picker (Normal, Standard, Strict) for the focused chat, with what each level protects, a **Mask personal details** switch, a **Next new chat** picker, a **When to use each level** guide, and a collapsed **Advanced** section with content-free totals and the leftover check (zero-trace verifier).
- **Delete confirmation:** Every delete entry point asks first: "Delete this chat permanently?".

---

## Forensic Zero-Trace Verification Walkthrough

A manual burn or idle TTL cleanup clears local artifacts associated with the incognito session:

1. **Database Scrubbing:** Uses Hermes `SessionDB.delete_session()` for authorized incognito rows. If Hermes defers deletion during an active write or an artifact cannot be removed, the lease and privacy protections remain active while cleanup retries.
2. **File Overwrite & Unlink:** Locates JSONL transcripts in `$HERMES_HOME/sessions/` and temporary artifacts in `$HERMES_HOME/hook_outputs/`. Overwrites regular, unshared files with zeros before unlinking when zero fill is enabled. Skips symlinks.
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
