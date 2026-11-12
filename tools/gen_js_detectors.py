"""Generate the Desktop masker's detector table from pii.py, so both sides use the same patterns.

Usage: python tools/gen_js_detectors.py [--write]
Without --write, prints the block. With --write, replaces the generated block in desktop/plugin.js.
tests/test_desktop_js.py fails when the block in plugin.js is out of date.

Python's \\w and \\b are Unicode-aware; the translation spells them out with Unicode property
classes so JavaScript matches the same text.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pii

BEGIN = "// <generated:pii-detectors> (tools/gen_js_detectors.py; do not edit by hand)"
END = "// </generated:pii-detectors>"
WORD = r"\p{L}\p{N}_"
VALIDATORS = {
    pii.luhn_ok: "luhnOk", pii.iban_ok: "ibanOk", pii.nit_ok: "nitOk",
    pii.ipv4_ok: "ipv4Ok", pii.ipv6_ok: "ipv6Ok", pii.phone_ok: "phoneOk",
}


def translate(source: str) -> str:
    out: list[str] = []
    in_class = False
    i = 0
    while i < len(source):
        ch = source[i]
        if ch == "\\" and i + 1 < len(source):
            nxt = source[i + 1]
            if nxt == "w":
                out.append(WORD if in_class else f"[{WORD}]")
            elif nxt == "W":
                if in_class:
                    raise ValueError("\\W inside a class is not supported")
                out.append(f"[^{WORD}]")
            elif nxt == "b" and not in_class:
                out.append(f"(?:(?<![{WORD}])(?=[{WORD}])|(?<=[{WORD}])(?![{WORD}]))")
            elif nxt in "#% '\"":
                out.append(nxt)  # needless escapes are errors in JS unicode mode
            else:
                out.append(ch + nxt)
            i += 2
            continue
        if ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        out.append(ch)
        i += 1
    return "".join(out)


def render() -> str:
    lines = [BEGIN, "const DETECTOR_SPECS = ["]
    for det in pii.DETECTORS:
        source = det.pattern.pattern
        flags = "gud"
        if source.startswith("(?i)"):
            source = source[4:]
            flags += "i"
        if det.pattern.flags & re.IGNORECASE:
            flags += "" if "i" in flags else "i"
        validator = VALIDATORS.get(det.validator, "null") if det.validator else "null"
        lines.append(
            f"  [{json.dumps(det.kind)}, {json.dumps(translate(source))}, {json.dumps(flags)}, {det.group}, {validator}],"
        )
    lines.append("]")
    lines.append(END)
    return "\n".join(lines)


def main() -> int:
    block = render()
    if "--write" not in sys.argv:
        print(block)
        return 0
    path = ROOT / "desktop" / "plugin.js"
    text = path.read_text(encoding="utf-8")
    start, end = text.index(BEGIN), text.index(END) + len(END)
    path.write_text(text[:start] + block + text[end:], encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
