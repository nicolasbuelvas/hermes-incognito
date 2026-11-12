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
        [node, "--import", "./tests/js/register.mjs", "--test", "tests/js/plugin_logic.test.mjs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
