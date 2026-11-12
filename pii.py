"""Personal-detail detection and masking for Incognito's "Mask personal details" option.

Everything here is pure and deterministic so the same rules can be tested exhaustively and
mirrored by the Desktop composer (``desktop/plugin.js``). The vault that maps a placeholder such as
``[EMAIL_1]`` back to the original value lives in RAM only, per session, and is never written to
disk, logs, audit receipts, or API responses.

Masking is fail-closed by design: :func:`mask_payload` withholds any content it cannot inspect
(images, audio, files, opaque data URLs), and :func:`verify_payload` re-scans the final payload so a
caller can refuse to send anything that still looks personal.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

# Kinds, in the order they are applied. Earlier kinds win when two patterns overlap
# (a card number is masked as CARD before the phone pattern can see a part of it).
KINDS = (
    "SECRET",
    "PASSWORD",
    "EMAIL",
    "IBAN",
    "CARD",
    "NIT",
    "ID",
    "SSN",
    "IP",
    "PHONE",
    "ADDRESS",
)

PLACEHOLDER_RE = re.compile(r"\[(SECRET|PASSWORD|EMAIL|IBAN|CARD|NIT|ID|SSN|IP|PHONE|ADDRESS)_(\d+)\]")
_NOT_PLACEHOLDER = r"(?!\[(?:SECRET|PASSWORD|EMAIL|IBAN|CARD|NIT|ID|SSN|IP|PHONE|ADDRESS)_\d+\])"

WITHHELD_TEXT = "[content withheld: Incognito masking is on and can't check images, audio, or files]"

# Keys whose values are structural or opaque. They are neither masked nor scanned: masking them
# would break the provider request (ids, model names, signed reasoning blobs, auth headers).
# Structural keys: their plain values (role names, ids, model names) are left as they are. A list or
# object under one of these keys is still walked, so content can't hide behind a structural name.
SKIP_KEYS = frozenset({
    "role", "type", "id", "call_id", "tool_call_id", "model", "name", "object", "status",
    "finish_reason", "index", "cache_control", "tool_choice",
    "media_type", "mime_type", "detail", "format", "service_tier", "reasoning_effort",
    "timeout", "stream", "store", "parallel_tool_calls",
})
# Opaque keys: provider-signed blobs and connection settings, never sent as message content.
OPAQUE_KEYS = frozenset({
    "encrypted_content", "signature", "base_url", "api_key", "headers", "extra_headers",
    "extra_query", "http_client",
})


def skip_key(key: Any, value: Any) -> bool:
    """True when ``value`` under ``key`` is structure or transport, not content to mask."""
    if key in OPAQUE_KEYS:
        return True
    return key in SKIP_KEYS and not isinstance(value, (dict, list, tuple))

# Content parts that carry bytes the masker cannot read.
BINARY_PART_TYPES = frozenset({
    "image", "image_url", "input_image", "input_audio", "audio", "file", "input_file",
    "document", "video", "image_file",
})


# -----------------------------------------------------------------------------
# Validators
# -----------------------------------------------------------------------------

def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def luhn_ok(number: str) -> bool:
    digits = _digits(number)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
    "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "ES": 24, "FI": 18,
    "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18,
    "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SE": 24,
    "SI": 19, "SK": 24, "SM": 27, "TN": 24, "TR": 26, "UA": 29, "VG": 24, "XK": 20,
}


def iban_ok(value: str) -> bool:
    iban = re.sub(r"\s", "", value).upper()
    expected = _IBAN_LENGTHS.get(iban[:2])
    if expected is None or len(iban) != expected or not iban[2:4].isdigit():
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


_NIT_WEIGHTS = (3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67, 71)


def nit_ok(value: str) -> bool:
    """DIAN check digit for a Colombian NIT written as ``900.123.456-7``."""
    digits = _digits(value)
    if len(digits) < 2:
        return False
    body, check = digits[:-1], int(digits[-1])
    total = sum(int(d) * w for d, w in zip(reversed(body), _NIT_WEIGHTS))
    rest = total % 11
    expected = rest if rest in (0, 1) else 11 - rest
    return expected == check


def ipv4_ok(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


def ipv6_ok(value: str) -> bool:
    if value.count(":") < 2:
        return False
    try:
        ip = ipaddress.IPv6Address(value.split("%", 1)[0])
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


def phone_ok(value: str) -> bool:
    digits = _digits(value)
    return 7 <= len(digits) <= 15 and len(set(digits)) > 2


# -----------------------------------------------------------------------------
# Detectors: (kind, compiled regex, group to mask, validator)
# -----------------------------------------------------------------------------

_TLDS = (
    "com|org|net|edu|gov|mil|int|info|biz|io|co|ai|app|dev|me|us|uk|ca|au|de|fr|es|it|nl|be|ch|at|se|no|"
    "dk|fi|pl|pt|br|mx|ar|cl|pe|ec|ve|uy|py|bo|cr|pa|gt|do|cu|jp|cn|in|ru|xyz|online|site|tech|email|mail"
)
_MAIL_PROVIDERS = (
    "gmail|googlemail|hotmail|outlook|live|msn|yahoo|ymail|icloud|me|mac|aol|proton|protonmail|pm|gmx|"
    "yandex|zoho|mail|fastmail|tutanota|une|etb|unal|udea|javeriana|uniandes"
)


@dataclass(frozen=True)
class Detector:
    kind: str
    pattern: re.Pattern[str]
    group: int = 0
    validator: Callable[[str], bool] | None = None


_SEP = r"[ .\-]?"

DETECTORS: tuple[Detector, ...] = (
    # --- Secrets with well-known shapes ---------------------------------------------------------
    Detector("SECRET", re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    Detector("SECRET", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")),
    Detector("SECRET", re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-|ant-(?:api\d{2}-)?|live-|test-|or-v1-)?[A-Za-z0-9_\-]{20,}")),
    Detector("SECRET", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    Detector("SECRET", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    Detector("SECRET", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{12,}\b")),
    Detector("SECRET", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b")),
    Detector("SECRET", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}")),
    Detector("SECRET", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    Detector("SECRET", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    Detector("SECRET", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")),
    Detector("SECRET", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
    Detector("SECRET", re.compile(r"\bya29\.[A-Za-z0-9_\-]{20,}")),
    Detector("SECRET", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}")),
    Detector("SECRET", re.compile(r"(?i)\bbearer\s+" + _NOT_PLACEHOLDER + r"([A-Za-z0-9_\-.~+/=]{16,})"), group=1),
    Detector("SECRET", re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@\[\]]+:(" + _NOT_PLACEHOLDER + r"[^\s@/\[\]]+)@"), group=1),
    Detector("SECRET", re.compile(
        r"(?i)\b(?:api[_\-\s]?key|apikey|access[_\-\s]?token|auth[_\-\s]?token|refresh[_\-\s]?token|"
        r"secret(?:[_\-\s]?key)?|client[_\-\s]?secret|private[_\-\s]?key|token)\b\s*[:=]\s*[\"']?"
        + _NOT_PLACEHOLDER + r"([^\s\"',;]{6,})"), group=1),
    # --- Passwords and PINs given in context --------------------------------------------------------
    Detector("PASSWORD", re.compile(
        r"(?i)\b(?:password|passwd|pwd|passcode|pass|contrase[ñn]a|clave|pin)\b\s*[:=]\s*[\"']?"
        + _NOT_PLACEHOLDER + r"([^\s\"',;]{3,})"), group=1),
    Detector("PASSWORD", re.compile(
        r"(?i)\b(?:password|passcode|contrase[ñn]a|clave|pin)\s+(?:is|es|era|was)\s*[:=]?\s*[\"']?"
        + _NOT_PLACEHOLDER + r"([^\s\"',;]{3,})"), group=1),
    # --- Email, plain and obfuscated -----------------------------------------------------------------
    Detector("EMAIL", re.compile(
        r"(?<![\w.+\-])[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,24}(?![\w\-])")),
    Detector("EMAIL", re.compile(
        r"(?i)(?<![\w.+\-])[a-z0-9][a-z0-9._%+\-]*\s*(?:\[\s*(?:at|arroba)\s*\]|\(\s*(?:at|arroba)\s*\)|\{\s*(?:at|arroba)\s*\}|<\s*(?:at|arroba)\s*>)\s*"
        r"[a-z0-9\-]+(?:\s*(?:\[\s*(?:dot|punto)\s*\]|\(\s*(?:dot|punto)\s*\)|\{\s*(?:dot|punto)\s*\}|<\s*(?:dot|punto)\s*>|\s+(?:dot|punto)\s+|\.)\s*[a-z0-9\-]+)+")),
    Detector("EMAIL", re.compile(
        r"(?i)(?<![\w.+\-])[a-z0-9][a-z0-9._%+\-]*\s+(?:at|arroba)\s+(?:" + _MAIL_PROVIDERS + r")"
        r"(?:\s*(?:\s(?:dot|punto)\s|\.)\s*[a-z]{2,6}){1,2}\b")),
    Detector("EMAIL", re.compile(
        r"(?i)(?<![\w.+\-])[a-z0-9]*[._+\d][a-z0-9._%+\-]*\s+(?:at|arroba)\s+[a-z0-9\-]+"
        r"(?:\s*(?:\s(?:dot|punto)\s|\.)\s*[a-z0-9\-]+)*\s*(?:\s(?:dot|punto)\s|\.)\s*(?:" + _TLDS + r")\b")),
    # --- Financial -------------------------------------------------------------------------------
    Detector("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"), validator=iban_ok),
    # Grouped 4-4-4-4 is a card even with a typo in it; other digit runs must pass Luhn.
    Detector("CARD", re.compile(r"(?<![\d\-])\d{4}([ \-])\d{4}\1\d{4}\1\d{4}(?:\1\d{1,3})?(?![\d\-]|[ \-]\d)")),
    Detector("CARD", re.compile(r"(?<![\d\-])\d(?:[ \-]?\d){12,18}(?![\d\-]|[ \-]\d)"), validator=luhn_ok),
    # --- Colombian and US identifiers -------------------------------------------------------------
    Detector("NIT", re.compile(
        r"(?i)\bNIT\.?\s*(?:(?:es|is)\s+)?(?:n[°ºo]\.?|no\.?|:|#)?\s*(\d{3}\.?\d{3}\.?\d{3}\d?(?:\s?-\s?\d)?)(?!\d)")
        , group=1),
    Detector("NIT", re.compile(r"(?<![\d.])\d{3}\.\d{3}\.\d{3}-\d(?!\d)"), validator=nit_ok),
    Detector("ID", re.compile(
        r"(?i)(?<!\w)(?:c\.\s?c\.?|cc|c[ée]dula(?:\s+de\s+(?:ciudadan[íi]a|extranjer[íi]a))?|"
        r"documento(?:\s+de\s+identidad)?|n[úu]mero\s+de\s+identificaci[óo]n|identificaci[óo]n|"
        r"tarjeta\s+de\s+identidad|t\.\s?i\.?|dni|pasaporte|passport(?:\s+(?:no|number))?)\.?\s*"
        r"(?:(?:es|is|was|era)\s+)?(?:n[°ºo]\.?|no\.?|num\.?|n[úu]mero|#|:)?\s*(\d{1,3}(?:[.\s]\d{3}){1,3}|\d{5,12}|[A-Z]{1,2}\d{6,9})(?![\d.]\d)"),
        group=1),
    Detector("SSN", re.compile(r"(?<![\d\-])(?!000|666|9\d\d)\d{3}([\- ])(?!00)\d{2}\1(?!0000)\d{4}(?![\d\-])")),
    Detector("SSN", re.compile(r"(?i)\b(?:ssn|social\s+security(?:\s+(?:no|number|#))?)\s*[:#]?\s*(\d{9})\b"), group=1),
    # --- Network -------------------------------------------------------------------------------------
    Detector("IP", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d]|\.\d)"), validator=ipv4_ok),
    Detector("IP", re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?(?:%\w+)?(?![\w:])"),
             validator=ipv6_ok),
    # --- Phones --------------------------------------------------------------------------------------
    Detector("PHONE", re.compile(r"(?<![\w+])\+\s?\d{1,3}(?:[ .\-]?\(?\d{1,4}\)?){2,5}(?![\w])"), validator=phone_ok),
    Detector("PHONE", re.compile(r"(?<![\w+])00\d{1,3}(?:[ .\-]?\(?\d{1,4}\)?){2,5}(?![\w])"), validator=phone_ok),
    Detector("PHONE", re.compile(r"(?<![\w.\-])3[0-5]\d" + _SEP + r"\d{3}" + _SEP + r"\d{4}(?![\w]|[.\-]\d)")),
    Detector("PHONE", re.compile(r"(?<![\w.\-])\(?60[1-8]\)?" + _SEP + r"\d{3}" + _SEP + r"\d{4}(?![\w]|[.\-]\d)")),
    Detector("PHONE", re.compile(
        r"(?<![\w.\-])(?:\(\d{3}\)\s?|\d{3}[ .\-])\d{3}[ .\-]\d{4}(?![\w]|[.\-]\d)"), validator=phone_ok),
    # --- Street addresses ----------------------------------------------------------------------------
    Detector("ADDRESS", re.compile(
        r"(?i)\b(?:calle|cl|cll|carrera|cra|kra|kr|cr|avenida(?:\s+calle|\s+carrera)?|av|ak|ac|diagonal|dg|"
        r"transversal|tv|tr|circular|autopista)\.?\s*\d{1,3}\s?[a-z]?(?:\s?bis)?(?:\s?[a-z])?(?:\s(?:sur|norte|este|oeste))?"
        r"\s*(?:#|no\.?|n[°º]|n[úu]mero)\s*\d{1,3}\s?[a-z]?\s*-\s*\d{1,3}(?:\s?(?:sur|norte|este|oeste)\b)?")),
    Detector("ADDRESS", re.compile(
        r"\b\d{1,6}\s+(?:[NSEW]\.?\s+)?(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|"
        r"Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Parkway|Pkwy|Highway|Hwy)\b\.?(?:,?\s*(?:Apt|Suite|Unit|#)\.?\s*\w+)?")),
)


# -----------------------------------------------------------------------------
# Findings and the per-session vault
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    value: str


def _normalize(kind: str, value: str) -> str:
    if kind in ("EMAIL",):
        return re.sub(r"\s+", "", value).lower()
    if kind in ("CARD", "PHONE", "NIT", "ID", "SSN"):
        return _digits(value) or value
    if kind == "IBAN":
        return re.sub(r"\s", "", value).upper()
    return value


def find_pii(text: str) -> list[Finding]:
    """All non-overlapping findings, earlier detectors first."""
    if not text:
        return []
    taken: list[tuple[int, int]] = []
    found: list[Finding] = []
    for det in DETECTORS:
        for match in det.pattern.finditer(text):
            start, end = match.span(det.group)
            if start < 0 or end <= start:
                continue
            value = match.group(det.group)
            if det.validator is not None and not det.validator(value):
                continue
            if PLACEHOLDER_RE.fullmatch(value):
                continue
            if any(start < t_end and t_start < end for t_start, t_end in taken):
                continue
            taken.append((start, end))
            found.append(Finding(det.kind, start, end, value))
    found.sort(key=lambda f: f.start)
    return found


@dataclass
class Vault:
    """RAM-only map between originals and stable placeholders for one session."""

    forward: dict[tuple[str, str], str] = field(default_factory=dict)
    originals: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    def reserve(self, text: str) -> None:
        """Never reuse a number that a placeholder in the conversation already carries."""
        for match in PLACEHOLDER_RE.finditer(text or ""):
            kind, num = match.group(1), int(match.group(2))
            if num > self.counters.get(kind, 0):
                self.counters[kind] = num

    def placeholder(self, kind: str, value: str) -> str:
        key = (kind, _normalize(kind, value))
        existing = self.forward.get(key)
        if existing:
            return existing
        self.counters[kind] = self.counters.get(kind, 0) + 1
        ph = f"[{kind}_{self.counters[kind]}]"
        self.forward[key] = ph
        self.originals[ph] = value
        return ph

    def set(self, placeholder: str, original: str) -> None:
        match = PLACEHOLDER_RE.fullmatch(placeholder)
        kind = match.group(1) if match else "SECRET"
        self.forward[(kind, _normalize(kind, original))] = placeholder
        self.originals[placeholder] = original
        self.reserve(placeholder)

    def get(self, placeholder: str) -> str | None:
        return self.originals.get(placeholder)

    def values(self) -> list[str]:
        return list(self.originals.values())

    def counts(self) -> dict[str, int]:
        return dict(self.counters)

    def copy(self) -> Vault:
        return Vault(dict(self.forward), dict(self.originals), dict(self.counters))

    def clear(self) -> int:
        n = len(self.originals)
        self.forward.clear()
        self.originals.clear()
        self.counters.clear()
        return n

    def __len__(self) -> int:
        return len(self.originals)


def mask_text(text: str, vault: Vault) -> tuple[str, list[str]]:
    """Replace every finding with its placeholder. Returns the text and the kinds masked."""
    if not isinstance(text, str) or not text:
        return text, []
    vault.reserve(text)
    # Values masked before (in any message) are replaced first, so a value that only matched
    # in context ("password: x") stays masked wherever it shows up again.
    kinds: list[str] = []
    for ph, original in sorted(vault.originals.items(), key=lambda kv: -len(kv[1])):
        if len(original) >= 4 and original in text:
            hits = text.count(original)
            text = text.replace(original, ph)
            match = PLACEHOLDER_RE.fullmatch(ph)
            kinds.extend([match.group(1) if match else "SECRET"] * hits)
    findings = find_pii(text)
    if not findings:
        return text, kinds
    out: list[str] = []
    cursor = 0
    for f in findings:
        out.append(text[cursor:f.start])
        out.append(vault.placeholder(f.kind, f.value))
        kinds.append(f.kind)
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out), kinds


# -----------------------------------------------------------------------------
# Provider payloads
# -----------------------------------------------------------------------------

def _withheld_part(part: dict[str, Any]) -> dict[str, Any]:
    kind = str(part.get("type") or "")
    text_type = "input_text" if kind.startswith("input_") else "text"
    return {"type": text_type, "text": WITHHELD_TEXT}


def _is_binary_part(node: Any) -> bool:
    return isinstance(node, dict) and str(node.get("type") or "") in BINARY_PART_TYPES


def _is_data_url(value: str) -> bool:
    return value.startswith("data:") and ";base64," in value[:200]


@dataclass
class MaskReport:
    masked: int = 0
    kinds: list[str] = field(default_factory=list)
    withheld: int = 0


def mask_payload(payload: Any, vault: Vault, report: MaskReport | None = None) -> Any:
    """Return a deep copy of a provider request with personal details masked everywhere.

    Every string value is masked except under :data:`SKIP_KEYS`. Image, audio, and file parts and
    base64 data URLs are replaced with a text note, because their contents can't be checked.
    """
    report = report if report is not None else MaskReport()
    payload = copy.deepcopy(payload)
    for text in iter_strings(payload):
        vault.reserve(text)

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            if _is_data_url(node):
                report.withheld += 1
                return WITHHELD_TEXT
            masked, kinds = mask_text(node, vault)
            report.masked += len(kinds)
            report.kinds.extend(kinds)
            return masked
        if isinstance(node, list):
            return [walk(item) for item in node]
        if isinstance(node, tuple):
            return [walk(item) for item in node]
        if isinstance(node, dict):
            if _is_binary_part(node):
                report.withheld += 1
                return _withheld_part(node)
            return {k: (v if skip_key(k, v) else walk(v)) for k, v in node.items()}
        return node

    return walk(payload)


def iter_strings(node: Any) -> Iterable[str]:
    """Every string value in a payload that masking covers (skips :data:`SKIP_KEYS`)."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from iter_strings(item)
    elif isinstance(node, dict):
        for key, value in node.items():
            if not skip_key(key, value):
                yield from iter_strings(value)


def verify_payload(payload: Any, vault: Vault) -> list[str]:
    """Problems that must stop a send. Messages name kinds only, never values."""
    problems: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if _is_binary_part(node):
                problems.append("unreadable attachment")
                return
            for key, value in node.items():
                if not skip_key(key, value):
                    walk(value)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item)
        elif isinstance(node, str):
            if _is_data_url(node):
                problems.append("unreadable attachment")
            for f in find_pii(node):
                problems.append(f"unmasked {f.kind.lower()}")
        elif node is not None and not isinstance(node, (int, float, bool)):
            # An object Hermes did not serialize yet: inspect its text form.
            try:
                text = json.dumps(node, default=str)
            except Exception:
                text = str(node)
            for f in find_pii(text):
                problems.append(f"unmasked {f.kind.lower()}")

    walk(payload)
    originals = [v for v in vault.values() if len(v) >= 4]
    if originals:
        for text in iter_strings(payload):
            lowered = text.lower()
            if any(o in text or o.lower() in lowered for o in originals):
                problems.append("a masked value reappeared")
                break
    return sorted(set(problems))


def summarize_kinds(kinds: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for k in kinds:
        out[k] = out.get(k, 0) + 1
    return out
