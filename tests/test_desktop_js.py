"""Runs the Desktop plugin logic tests (tests/js) with Node's built-in test runner."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _node_supports_register(node: str) -> bool:
    out = subprocess.run([node, "-p", "typeof require('node:module').register"], capture_output=True, text=True, check=False)
    return out.returncode == 0 and out.stdout.strip() == "function"


def test_desktop_plugin_logic_with_node():
    node = shutil.which("node")
    if not node or not _node_supports_register(node):
        pytest.skip("Node.js 20.6+ is required for the Desktop plugin JS tests")
    result = subprocess.run(
        [node, "--import", "./tests/js/register.mjs", "--test", "tests/js/plugin_logic.test.mjs",
         "tests/js/masking_and_save.test.mjs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _node_or_skip() -> str:
    node = shutil.which("node")
    if not node or not _node_supports_register(node):
        pytest.skip("Node.js 20.6+ is required for the Desktop plugin JS tests")
    return node


def _parity_texts() -> list[str]:
    import json
    import random
    import sys

    sys.path.insert(0, str(ROOT / "tests"))
    from test_pii_patterns import EXTRA_NEGATIVES, EXTRA_POSITIVES
    from test_pii_properties import FILLER, VALUE_MAKERS

    cases = json.loads((ROOT / "tests" / "fixtures" / "pii_cases.json").read_text(encoding="utf-8"))
    texts = [c["text"] for c in cases["positives"]] + list(cases["negatives"])
    texts += [t for _, _, t in EXTRA_POSITIVES] + list(EXTRA_NEGATIVES)
    rng = random.Random(1337)
    for _ in range(300):
        words = []
        for _ in range(rng.randint(1, 5)):
            words += rng.choices(FILLER, k=rng.randint(1, 3))
            words.append(VALUE_MAKERS[rng.choice(sorted(VALUE_MAKERS))](rng))
        texts.append(" ".join(words))
    alphabet = "abc xyz@.:-+#()[]0123456789 éñ_/"
    for _ in range(300):
        texts.append("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60))))
    return texts


def test_desktop_masker_matches_backend_masker(tmp_path):
    """Desktop masks in the composer; the backend re-checks. Both must agree on every case."""
    import json

    from hermes_sim import load_plugin

    load_plugin()
    from hermes_plugin_incognito_test import pii

    node = _node_or_skip()
    texts = _parity_texts()
    src = tmp_path / "texts.json"
    src.write_text(json.dumps(texts), encoding="utf-8")
    result = subprocess.run(
        [node, "--import", "./tests/js/register.mjs", "tests/js/pii_parity.mjs", str(src)],
        cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stderr
    js = json.loads(result.stdout)
    shared = pii.Vault()
    mismatches = []
    for text, got in zip(texts, js):
        py_text, py_kinds = pii.mask_text(text, pii.Vault())
        py_shared, _ = pii.mask_text(text, shared)
        if (got["text"], got["kinds"], got["shared"]) != (py_text, py_kinds, py_shared):
            mismatches.append((text, py_text, got["text"]))
    assert len(texts) > 700
    assert mismatches == []


def test_generated_desktop_detectors_are_up_to_date():
    import sys

    sys.path.insert(0, str(ROOT / "tools"))
    import gen_js_detectors

    assert gen_js_detectors.render() in (ROOT / "desktop" / "plugin.js").read_text(encoding="utf-8"), (
        "desktop/plugin.js detectors differ from pii.py; run: python tools/gen_js_detectors.py --write"
    )
