"""Property and fuzz tests for the masker.

Hypothesis (a dev dependency) drives most of them; a seeded fallback runs the same checks when it
isn't installed, so CI without extras still exercises them.
"""

from __future__ import annotations

import json
import random
import string

import pytest
from hermes_sim import load_plugin

load_plugin()
from hermes_plugin_incognito_test import pii

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover - exercised when hypothesis is missing
    given = None


def _luhn_complete(prefix: str) -> str:
    for d in "0123456789":
        if pii.luhn_ok(prefix + d):
            return prefix + d
    raise AssertionError("unreachable")


VALUE_MAKERS = {
    "EMAIL": lambda r: f"{''.join(r.choices(string.ascii_lowercase, k=r.randint(1, 10)))}"
                       f"{r.choice(['', '.', '_', '+'])}{r.randint(0, 999)}@"
                       f"{''.join(r.choices(string.ascii_lowercase, k=r.randint(2, 9)))}.{r.choice(['com', 'co', 'org', 'io', 'com.co'])}",
    "PHONE": lambda r: r.choice([
        f"+57 3{r.randint(0, 5)}{r.randint(0, 9)} {r.randint(100, 999)} {r.randint(1000, 9999)}",
        f"+573{r.randint(0, 5)}{r.randint(10000000, 99999999)}",
        f"3{r.randint(0, 5)}{r.randint(0, 9)}-{r.randint(100, 999)}-{r.randint(1000, 9999)}",
        f"+1 ({r.randint(201, 989)}) {r.randint(200, 999)}-{r.randint(1000, 9999)}",
    ]),
    "CARD": lambda r: (lambda n: " ".join(n[i:i + 4] for i in range(0, 16, 4)))(
        _luhn_complete("4" + "".join(r.choices(string.digits, k=14)))),
    "IP": lambda r: f"{r.choice([n for n in range(11, 224) if n != 127])}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}",
    "SECRET": lambda r: r.choice(["sk-", "ghp_", "AKIA"]) + "".join(
        r.choices(string.ascii_uppercase + string.digits, k=r.randint(20, 36))),
    "SSN": lambda r: f"{r.randint(100, 665)}-{r.randint(10, 99)}-{r.randint(1000, 9999)}",
}

FILLER = ["hola", "please", "ver", "the", "y", "and", "mañana", "llámame", "en", "at", "por favor", "ok", "—", ",", "."]


def _check_sentence(rng: random.Random) -> None:
    vault = pii.Vault()
    values: list[str] = []
    words: list[str] = []
    for _ in range(rng.randint(1, 6)):
        words.extend(rng.choices(FILLER, k=rng.randint(1, 4)))
        kind = rng.choice(sorted(VALUE_MAKERS))
        value = VALUE_MAKERS[kind](rng)
        values.append(value)
        words.append(value)
    words.extend(rng.choices(FILLER, k=rng.randint(0, 3)))
    text = " ".join(words)
    masked, _ = pii.mask_text(text, vault)
    for value in values:
        assert value not in masked, (value, masked)
    again, kinds = pii.mask_text(masked, vault)
    assert again == masked and kinds == []
    payload = {"messages": [{"role": "user", "content": text}]}
    assert pii.verify_payload(pii.mask_payload(payload, pii.Vault(), pii.MaskReport()), pii.Vault()) == []


def _content_only(node):
    if isinstance(node, dict):
        return {k: _content_only(v) for k, v in node.items() if not pii.skip_key(k, v)}
    if isinstance(node, (list, tuple)):
        return [_content_only(v) for v in node]
    return node


@pytest.mark.parametrize("seed", range(200))
def test_seeded_sentences_never_leak(seed):
    _check_sentence(random.Random(seed))


if given is not None:
    @settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(st.randoms(use_true_random=False))
    def test_hypothesis_sentences_never_leak(rng):
        _check_sentence(rng)

    @settings(max_examples=300, deadline=None)
    @given(st.text(max_size=400))
    def test_hypothesis_arbitrary_text_is_stable(text):
        vault = pii.Vault()
        masked, _ = pii.mask_text(text, vault)
        assert pii.mask_text(masked, vault)[0] == masked
        assert pii.find_pii(masked) == []
        for original in vault.values():
            assert original not in masked or len(original) < 4

    @settings(max_examples=200, deadline=None)
    @given(st.recursive(
        st.one_of(st.text(max_size=60), st.integers(), st.booleans(), st.none(),
                  st.sampled_from(["a@x.io", "+57 311 555 0199", "4111 1111 1111 1111", "sk-proj-ABCDEFGHIJKLMNOPQRST"])),
        lambda children: st.one_of(st.lists(children, max_size=4),
                                   st.dictionaries(st.sampled_from(["content", "text", "arguments", "output", "x", "role"]),
                                                   children, max_size=4)),
        max_leaves=20))
    def test_hypothesis_payloads_verify_clean_after_masking(payload):
        vault = pii.Vault()
        out = pii.mask_payload({"messages": [payload]}, vault, pii.MaskReport())
        assert pii.verify_payload(out, vault) == []
        json.dumps(out)
        # Plain values under structural keys ("role", "id", ...) are not content; everything else,
        # including lists or objects placed under a structural key, must come out masked.
        blob = json.dumps(_content_only(out))
        for raw in ("a@x.io", "+57 311 555 0199", "4111 1111 1111 1111", "sk-proj-ABCDEFGHIJKLMNOPQRST"):
            assert raw not in blob
