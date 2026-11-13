"""Per-pattern tests for the masker (pii.py): many positives and negatives per category.

tests/fixtures/pii_cases.json is shared with the Desktop masker (tests/js/pii.test.mjs), so both
sides are held to the same cases.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hermes_sim import load_plugin

load_plugin()
from hermes_plugin_incognito_test import pii

CASES = json.loads((Path(__file__).parent / "fixtures" / "pii_cases.json").read_text(encoding="utf-8"))
POSITIVES = CASES["positives"]
NEGATIVES = CASES["negatives"]

EXTRA_POSITIVES = [
    # (kind, value, text)
    ("EMAIL", "maria_lopez@empresa.com.co", "escríbeme a maria_lopez@empresa.com.co hoy"),
    ("EMAIL", "UPPER.CASE@EXAMPLE.COM", "Mail: UPPER.CASE@EXAMPLE.COM"),
    ("PHONE", "+57 300 123 4567", "Mi cel es +57 300 123 4567."),
    ("PHONE", "+573001234567", "WhatsApp +573001234567"),
    ("PHONE", "(415) 555-0132", "call (415) 555-0132 tomorrow"),
    ("PHONE", "+44 20 7946 0958", "London office +44 20 7946 0958"),
    ("CARD", "5500 0000 0000 0004", "Mastercard 5500 0000 0000 0004"),
    ("CARD", "378282246310005", "amex 378282246310005"),
    ("CARD", "4012-8888-8888-1881", "visa 4012-8888-8888-1881 exp 12/29"),
    ("IBAN", "GB82WEST12345698765432", "IBAN GB82WEST12345698765432"),
    ("SSN", "123-45-6789", "SSN 123-45-6789"),
    ("IP", "192.168.10.24", "router at 192.168.10.24"),
    ("IP", "2001:db8::8a2e:370:7334", "v6 2001:db8::8a2e:370:7334"),
    ("SECRET", "ghp_" + "A" * 36, "token ghp_" + "A" * 36),
    ("SECRET", "AKIAIOSFODNN7EXAMPLE", "aws AKIAIOSFODNN7EXAMPLE"),
    ("SECRET", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123", "key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"),
]

EXTRA_NEGATIVES = [
    "Call me in 5 minutes.",
    "The total was $1,234.56 for 3 items.",
    "Room 101, floor 3.",
    "ISO date 2026-11-12T10:00:00Z",
    "Use version 3.11.4 of Python.",
    "Build #4521 passed in 12.3s",
    "The ratio is 16:9 and the score 3-2.",
    "Email me later, I'll be at the office.",
    "My password manager is great.",
    "ticket ABC-1234 closed",
    "port 8080 and 127.0.0.1 loopback",
    "1234 5678 9012 3456 is not grouped like a card here? it is",  # grouped 4x4: masked on purpose
]


def _kinds(text: str) -> list[str]:
    return [f.kind for f in pii.find_pii(text)]


@pytest.mark.parametrize("case", POSITIVES, ids=[f"{c['kind']}:{c['value'][:24]}" for c in POSITIVES])
def test_fixture_positive_is_masked(case):
    vault = pii.Vault()
    masked, kinds = pii.mask_text(case["text"], vault)
    assert case["value"] not in masked
    assert case["kind"] in kinds
    # The vault keeps the original only in RAM, so it can be shown locally and cleared on burn.
    assert any(case["value"] in v or v in case["value"] for v in vault.values())


@pytest.mark.parametrize("text", NEGATIVES)
def test_fixture_negative_is_left_alone(text):
    masked, kinds = pii.mask_text(text, pii.Vault())
    assert kinds == []
    assert masked == text


@pytest.mark.parametrize("kind,value,text", EXTRA_POSITIVES, ids=[f"{k}:{v[:20]}" for k, v, _ in EXTRA_POSITIVES])
def test_extra_positive_is_masked(kind, value, text):
    masked, kinds = pii.mask_text(text, pii.Vault())
    assert value not in masked
    assert kind in kinds


@pytest.mark.parametrize("text", EXTRA_NEGATIVES[:-1])
def test_extra_negative_is_left_alone(text):
    assert pii.mask_text(text, pii.Vault()) == (text, [])


def test_corpus_size_is_meaningful():
    kinds = {c["kind"] for c in POSITIVES}
    assert kinds >= {"EMAIL", "PHONE", "CARD", "IBAN", "SSN", "ID", "NIT", "IP", "SECRET", "PASSWORD", "ADDRESS"}
    assert len(POSITIVES) >= 80 and len(NEGATIVES) >= 30


# --- validators -----------------------------------------------------------------------------------

@pytest.mark.parametrize("number,ok", [
    ("4111111111111111", True), ("4111111111111112", False), ("378282246310005", True),
    ("6011111111111117", True), ("1234567812345678", False), ("0000000000000000", False),
])
def test_luhn(number, ok):
    assert pii.luhn_ok(number) is ok


@pytest.mark.parametrize("iban,ok", [
    ("DE89370400440532013000", True), ("DE89370400440532013001", False), ("GB82WEST12345698765432", True),
    ("ES9121000418450200051332", True), ("FR1420041010050500013M02606", True), ("DE8937040044053201300", False),
])
def test_iban(iban, ok):
    assert pii.iban_ok(iban) is ok


def test_ungrouped_digits_need_luhn_to_be_a_card():
    assert "CARD" in _kinds("pay 4111111111111111 now")
    assert "CARD" not in _kinds("order 4111111111111112 shipped")


def test_cedula_needs_context_but_dotted_form_is_masked():
    assert "ID" in _kinds("mi cédula es 1020304050")
    assert "ID" in _kinds("CC 1.020.304.050")
    assert _kinds("invoice 1020304050 paid") in ([], ["PHONE"])  # never labelled ID without context


def test_nit_with_check_digit():
    assert "NIT" in _kinds("NIT 900.123.456-8")
    assert "NIT" in _kinds("nit: 900123456-8")


def test_obfuscated_emails():
    for text in ("juan [at] gmail [dot] com", "juan(at)gmail(dot)com", "juan at gmail dot com",
                 "juan.perez arroba hotmail punto com"):
        masked, kinds = pii.mask_text(text, pii.Vault())
        assert "EMAIL" in kinds, text
        assert "gmail" not in masked and "hotmail" not in masked


def test_password_patterns():
    for text, secret in (("password: hunter2!", "hunter2!"), ("pwd=Sup3r$ecret", "Sup3r$ecret"),
                         ("contraseña: Gato.2024", "Gato.2024"), ("my password is Tr0ub4dor&3", "Tr0ub4dor&3"),
                         ("la clave es Mango#77", "Mango#77")):
        masked, _ = pii.mask_text(text, pii.Vault())
        assert secret not in masked, text


def test_jwt_and_pem():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
    for text, value in ((f"Authorization: Bearer {jwt}", jwt), (f"key:\n{pem}\n", pem)):
        masked, _ = pii.mask_text(text, pii.Vault())
        assert value not in masked
        assert "MIIEvQ" not in masked and "eyJzdWIi" not in masked


# --- placeholders ---------------------------------------------------------------------------------

def test_placeholders_are_stable_and_numbered_per_kind():
    vault = pii.Vault()
    a, _ = pii.mask_text("a@x.io and b@y.io and a@x.io", vault)
    assert a == "[EMAIL_1] and [EMAIL_2] and [EMAIL_1]"
    b, _ = pii.mask_text("again b@y.io, phone +57 311 555 0199", vault)
    assert b == "again [EMAIL_2], phone [PHONE_1]"
    assert vault.counts() == {"EMAIL": 2, "PHONE": 1}


def test_masking_is_idempotent_and_placeholders_never_remasked():
    vault = pii.Vault()
    once, _ = pii.mask_text(" ".join(c["text"] for c in POSITIVES), vault)
    twice, kinds = pii.mask_text(once, vault)
    assert twice == once and kinds == []
    assert pii.find_pii("[EMAIL_1] [PHONE_12] [CARD_3] [SECRET_9]") == []


def test_user_typed_placeholder_does_not_collide():
    vault = pii.Vault()
    masked, _ = pii.mask_text("literal [EMAIL_1] and real a@x.io", vault)
    assert masked == "literal [EMAIL_1] and real [EMAIL_2]"


def test_value_seen_once_in_context_stays_masked_without_context():
    vault = pii.Vault()
    pii.mask_text("password: Kq9#zzTop", vault)
    masked, kinds = pii.mask_text("I reused Kq9#zzTop on the router", vault)
    assert "Kq9#zzTop" not in masked and kinds == ["PASSWORD"]


# --- payloads -------------------------------------------------------------------------------------

def test_mask_payload_covers_every_text_leaf_and_withholds_binary():
    payload = {
        "model": "m", "api_key": "sk-proj-THISisAPIkeyNOTcontent123456",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "mail a@x.io"},
                                         {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]},
            {"role": "assistant", "tool_calls": [{"id": "c1", "type": "function",
                                                  "function": {"name": "send", "arguments": "{\"to\": \"b@y.io\"}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "sent to b@y.io"},
        ],
        "input": [{"type": "function_call_output", "call_id": "c1", "output": "ip 203.0.113.9"}],
    }
    vault, report = pii.Vault(), pii.MaskReport()
    out = pii.mask_payload(payload, vault, report)
    blob = json.dumps(out)
    for raw in ("a@x.io", "b@y.io", "203.0.113.9", "data:image"):
        assert raw not in blob
    assert pii.WITHHELD_TEXT in blob
    assert out["api_key"] == payload["api_key"]  # auth headers are not content and must stay usable
    assert payload["messages"][0]["content"][0]["text"] == "mail a@x.io"  # caller's dict untouched
    assert pii.verify_payload(out, vault) == []


def test_verify_payload_reports_kinds_never_values():
    vault = pii.Vault()
    problems = pii.verify_payload({"messages": [{"role": "user", "content": "x a@x.io +57 311 555 0199"}]}, vault)
    assert problems and all("a@x.io" not in p and "311" not in p for p in problems)
    assert any("email" in p.lower() for p in problems)


def test_vault_clear_forgets_everything():
    vault = pii.Vault()
    pii.mask_text("a@x.io", vault)
    vault.clear()
    assert len(vault) == 0 and vault.values() == [] and vault.counts() == {}
