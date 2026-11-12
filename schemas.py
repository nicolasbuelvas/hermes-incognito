"""Schemas, contracts, and constants for the Incognito privacy plugin.

Provides configuration defaults, action enumerations, and validation schemas
for the incognito control and verification tools.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict

# Valid incognito operating modes
VALID_MODES: tuple[str, ...] = ("off", "standard", "strict")

# Default settings matching plugin.yaml config_schema
DEFAULT_SETTINGS: dict[str, Any] = {
    "default_mode": "off",
    "auto_purge_on_exit": True,
    "default_ttl_minutes": 60,
    "redact_outbound_pii": False,
    "provider_zdr_hints": True,
    "zero_fill_files": True,
}


class IncognitoLease(TypedDict, total=False):
    """Metadata schema for an active incognito session lease."""

    session_id: str
    mode: str
    ttl_minutes: int
    owner_pid: int
    started_at: float
    last_activity: float
    expires_at: Optional[float]
    redact_pii: bool
    blocked_writes: int
    redactions: int
    lineage_ids: list[str]


class BurnReceipt(TypedDict, total=False):
    """Content-free receipt created when a session is burned."""

    receipt_id: str
    session_hash: str
    timestamp: float
    reason: str
    db_deleted: bool
    files_scrubbed: int
    vault_keys_cleared: int


class AuditData(TypedDict, total=False):
    """Content-free operational metrics ledger."""

    sessions_protected: int
    sessions_burned: int
    orphans_swept: int
    writes_blocked: int
    pii_redactions: int
    files_scrubbed: int
    receipts: list[BurnReceipt]


# Tool schema for incognito_control
INCOGNITO_CONTROL_SCHEMA: dict[str, Any] = {
    "name": "incognito_control",
    "description": (
        "Control ephemeral and incognito session privacy: view status, enable standard or strict "
        "clean-room mode, arm the next session, update inactivity TTL, sweep expired orphans, "
        "or immediately burn and scrub session records."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "status",
                    "enable",
                    "disable",
                    "toggle",
                    "burn",
                    "arm",
                    "disarm",
                    "sweep",
                    "ttl",
                ],
                "description": (
                    "Action to execute: 'status' to view state, 'enable' to enter incognito, "
                    "'disable' to leave incognito, 'toggle' to switch, 'burn' to purge immediately, "
                    "'arm' to prepare next session, 'disarm' to cancel armed token, 'sweep' to clean expired, "
                    "or 'ttl' to update inactivity timeout."
                ),
                "default": "status",
            },
            "mode": {
                "type": "string",
                "enum": ["standard", "strict"],
                "description": (
                    "Incognito level: 'standard' blocks memory/skill updates; "
                    "'strict' also strips profile memory and blocks search/cron tools."
                ),
                "default": "standard",
            },
            "ttl_minutes": {
                "type": "integer",
                "description": "Idle inactivity timeout in minutes before orphan sweeps purge the session (0 disables).",
                "minimum": 0,
            },
            "redact_pii": {
                "type": "boolean",
                "description": "Whether to mask outbound emails, phone numbers, cards, and tokens in RAM.",
            },
            "disable_action": {
                "type": "string",
                "enum": ["keep", "burn"],
                "description": "When disabling incognito: 'keep' unhides into history, 'burn' purges traces immediately.",
                "default": "keep",
            },
        },
        "required": [],
    },
}

# Tool schema for incognito_verify
INCOGNITO_VERIFY_SCHEMA: dict[str, Any] = {
    "name": "incognito_verify",
    "description": (
        "Perform a forensic zero-trace verification on a session ID across SQLite state.db rows, "
        "JSONL session transcripts, hook spill directories, and in-RAM redaction vaults."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "session_id": {
                "type": "string",
                "description": "Session ID to verify for zero residual trace in SQLite, disk files, and RAM.",
            },
        },
        "required": ["session_id"],
    },
}
