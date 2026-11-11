import os
import sys
import json
import re
from pathlib import Path
import pytest
import yaml

PROJECT_ROOT = Path("C:/Users/nicol/Downloads/Proyectos personales/hermes-incognito").resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def test_manifest_structure_and_contracts():
    """Verify plugin.yaml contains all required fields and valid schema configuration."""
    manifest_path = PROJECT_ROOT / "plugin.yaml"
    assert manifest_path.exists(), f"plugin.yaml must exist at {manifest_path}"

    with open(manifest_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert data.get("name") == "incognito"
    assert "version" in data
    assert "description" in data
    assert "requires_hermes" in data
    assert "provides_tools" in data
    assert "provides_hooks" in data
    assert "provides_middleware" in data
    assert "config_schema" in data

    # Verify declared tools
    assert "incognito_control" in data["provides_tools"]
    assert "incognito_verify" in data["provides_tools"]

    # Verify declared hooks
    hooks = data["provides_hooks"]
    assert "on_session_start" in hooks
    assert "pre_llm_call" in hooks
    assert "pre_tool_call" in hooks
    assert "post_compaction" in hooks
    assert "on_session_end" in hooks

    # Verify declared middleware
    middleware = data["provides_middleware"]
    assert "llm_request" in middleware or "llm_execution" in middleware

    # Verify config schema properties
    cfg = data["config_schema"]
    assert "default_mode" in cfg
    assert "auto_purge_on_exit" in cfg
    assert "default_ttl_minutes" in cfg
    assert "redact_outbound_pii" in cfg
    assert "provider_zdr_hints" in cfg
    assert "zero_fill_files" in cfg


def test_plugin_init_registration():
    """
    When __init__.py exists, calling register(mock_ctx) registers tools, hooks,
    middleware, /incognito slash command, and incognito CLI command,
    and tool handlers return valid JSON string accepting **kwargs.
    """
    init_path = PROJECT_ROOT / "__init__.py"
    if not init_path.exists():
        pytest.skip("__init__.py not yet created by sibling agent")

    import importlib
    mod = importlib.import_module("__init__")
    assert hasattr(mod, "register"), "__init__.py must define register(ctx)"

    class MockContext:
        def __init__(self):
            self.tools = {}
            self.hooks = {}
            self.middleware = {}
            self.commands = {}
            self.cli_commands = {}

        def register_tool(self, name, handler, **kwargs):
            self.tools[name] = handler

        def register_hook(self, name, handler, **kwargs):
            self.hooks[name] = handler

        def register_middleware(self, name, handler, **kwargs):
            self.middleware[name] = handler

        def register_command(self, name, handler, **kwargs):
            self.commands[name] = handler

        def register_cli(self, name, handler, **kwargs):
            self.cli_commands[name] = handler

    ctx = MockContext()
    mod.register(ctx)

    # Check tools registered
    assert "incognito_control" in ctx.tools
    assert "incognito_verify" in ctx.tools

    # Test tools return valid JSON string even on invalid or empty args, and accept **kwargs
    for tool_name, handler in ctx.tools.items():
        res = handler(unknown_param="random", session_id="test-sess")
        assert isinstance(res, str), f"Tool {tool_name} must return string"
        parsed = json.loads(res)
        assert isinstance(parsed, (dict, list, bool, int, float, str))

    # Check command registrations
    assert any("incognito" in cmd for cmd in ctx.commands.keys()) or any("incognito" in cmd for cmd in ctx.cli_commands.keys())


def test_desktop_plugin_js_contracts():
    """
    When desktop/plugin.js exists, verifies it contains NO forbidden patterns
    and imports only allowed modules (@hermes/plugin-sdk, react, react/jsx-runtime).
    """
    desktop_js = PROJECT_ROOT / "desktop" / "plugin.js"
    if not desktop_js.exists():
        pytest.skip("desktop/plugin.js not yet created by sibling agent")

    content = desktop_js.read_text(encoding="utf-8")

    # Forbidden patterns
    forbidden = [
        "window.hermesDesktop",
        "eval(",
        "new Function(",
        "<script",
        "[data-slot",
        "[data-testid",
        "[data-sidebar"
    ]
    for pattern in forbidden:
        assert pattern not in content, f"Forbidden pattern '{pattern}' found in desktop/plugin.js"

    # Check imports
    import_lines = re.findall(r'(?:import\s+.*?from\s+[\'"](.*?)[\'"]|require\([\'"](.*?)[\'"]\))', content)
    allowed_modules = {"@hermes/plugin-sdk", "react", "react/jsx-runtime", "./", "../"}
    for match in import_lines:
        mod_name = match[0] or match[1]
        is_allowed = any(mod_name == allowed or mod_name.startswith(allowed) for allowed in allowed_modules)
        assert is_allowed, f"Disallowed import '{mod_name}' in desktop/plugin.js"
