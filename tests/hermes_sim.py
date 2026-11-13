"""A small stand-in for the Hermes host paths this plugin hooks into.

It mirrors the upstream contracts the masking relies on (NousResearch/hermes-agent):

- ``pre_llm_call`` runs before turn-start compaction, titling, and memory prefetch and gets
  ``conversation_history=list(messages)`` (same message dicts) -- agent/turn_context.py.
  ``{"action": "block", "message": ...}`` vetoes the turn with no model call.
- ``llm_request`` middleware: each callback gets a copy; a raising callback is skipped and the request
  continues unmodified -- hermes_cli/plugins_dispatch.py ``invoke_middleware``.
- ``llm_execution`` middleware: the chain in hermes_cli/middleware.py ``_run_execution_chain``, copied
  below, including its skip-on-error behaviour and ``_DownstreamExecutionError``.
- ``transform_tool_result`` runs before a tool result is appended to the conversation.
- Titling and compaction call an auxiliary model with conversation text and no middleware
  (agent/title_generator.py, agent/context_compressor.py).
- Every request attempt (retries included) is rebuilt and goes through both middleware kinds.

Every byte "sent" to a model is recorded so tests can assert on it.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class _DownstreamExecutionError(Exception):
    def __init__(self, original: BaseException) -> None:
        super().__init__(str(original))
        self.original = original


def load_plugin():
    pkg_name = "hermes_plugin_incognito_test"
    if pkg_name in sys.modules:
        return sys.modules[pkg_name]
    spec = importlib.util.spec_from_file_location(
        pkg_name, str(PROJECT_ROOT / "__init__.py"), submodule_search_locations=[str(PROJECT_ROOT)]
    )
    mod = importlib.util.module_from_spec(spec)
    mod.__path__ = [str(PROJECT_ROOT)]
    sys.modules[pkg_name] = mod
    spec.loader.exec_module(mod)
    return mod


class SimCtx:
    def __init__(self) -> None:
        self.hooks: dict[str, list[Callable]] = {}
        self.middleware: dict[str, list[Callable]] = {}
        self.rpcs: dict[str, Callable] = {}
        self.commands: dict[str, Callable] = {}
        self.events: list[Any] = []

    def register_tool(self, *a, **k): pass
    def register_skill(self, *a, **k): pass
    def register_cli_command(self, *a, **k): pass

    def register_hook(self, name, fn, **kwargs):
        self.hooks.setdefault(name, []).append(fn)

    def register_middleware(self, kind, fn):
        self.middleware.setdefault(kind, []).append(fn)

    def register_command(self, name, handler, **kwargs):
        self.commands[name] = handler

    def register_rpc(self, name, fn):
        self.rpcs[name] = fn

    def emit_to_session(self, session_id, event, payload=None):
        self.events.append((session_id, event, payload))


class TransientProviderError(Exception):
    pass


def _flatten(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return "" if content is None else str(content)


class FakeModel:
    """Asks for one tool call per scripted tool output, then echoes what it saw."""

    def __init__(self) -> None:
        self.pending_tools = 0
        self.fail_next = 0

    def respond(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.fail_next:
            self.fail_next -= 1
            raise TransientProviderError("503 from provider")
        if self.pending_tools:
            self.pending_tools -= 1
            return {"choices": [{"message": {
                "role": "assistant", "content": None,
                "tool_calls": [{"id": f"call_{self.pending_tools}", "type": "function",
                                "function": {"name": "read_file", "arguments": json.dumps({"path": "notes.txt"})}}],
            }}]}
        seen = json.dumps(payload, ensure_ascii=False)
        last_user = ""
        for msg in payload.get("messages") or payload.get("input") or []:
            if isinstance(msg, dict) and msg.get("role") == "user":
                last_user = _flatten(msg.get("content"))
        return {"choices": [{"message": {"role": "assistant",
                                         "content": f"You said: {last_user} (payload {len(seen)} bytes)"}}]}


class SimHermes:
    def __init__(self, plugin, home: Path, *, api_mode: str = "chat_completions",
                 system_prompt: str = "You are Hermes.") -> None:
        self.ctx = SimCtx()
        plugin.register(self.ctx)
        self.home = home
        self.api_mode = api_mode
        self.system_prompt = system_prompt
        self.model = FakeModel()
        self.sent: list[str] = []          # main provider payloads, serialized
        self.aux_sent: list[str] = []      # auxiliary model payloads (titles, compaction)
        self.observer_payloads: list[str] = []
        self.tool_args_seen: list[str] = []
        self.history: dict[str, list[dict[str, Any]]] = {}

    # --- host plumbing ------------------------------------------------------------------------
    def hook(self, name: str, **kwargs: Any) -> list[Any]:
        out = []
        for cb in self.ctx.hooks.get(name, []):
            try:
                result = cb(**kwargs)
            except Exception:
                continue  # hooks are fail-open in Hermes
            if result is not None:
                out.append(result)
        return out

    def request_chain(self, request: dict[str, Any], **context: Any) -> dict[str, Any]:
        original = copy.deepcopy(request)
        current = copy.deepcopy(request)
        for cb in self.ctx.middleware.get("llm_request", []):
            try:
                ret = cb(request=copy.deepcopy(current), original_request=copy.deepcopy(original), **context)
            except Exception:
                continue
            if isinstance(ret, dict) and isinstance(ret.get("request"), dict):
                current = copy.deepcopy(ret["request"])
        return current

    def execution_chain(self, request: dict[str, Any], terminal: Callable[[Any], Any], **context: Any) -> Any:
        callbacks = list(self.ctx.middleware.get("llm_execution", []))

        def call_at(index: int, payload: Any) -> Any:
            if index >= len(callbacks):
                return terminal(payload)
            callback = callbacks[index]
            state = {"called": False, "ok": False, "result": None}

            def next_call(next_payload: Any = None) -> Any:
                if state["called"]:
                    raise RuntimeError("next_call() more than once")
                state["called"] = True
                try:
                    state["result"] = call_at(index + 1, payload if next_payload is None else next_payload)
                    state["ok"] = True
                    return state["result"]
                except Exception as exc:
                    raise _DownstreamExecutionError(exc) from exc

            try:
                return callback(request=payload, next_call=next_call, **context)
            except _DownstreamExecutionError as exc:
                raise exc.original
            except Exception:
                if state["ok"]:
                    return state["result"]
                if state["called"]:
                    raise
                return call_at(index + 1, payload)

        return call_at(0, request)

    def provider(self, payload: Any) -> Any:
        self.sent.append(json.dumps(payload, ensure_ascii=False, default=str))
        return self.model.respond(payload)

    def aux(self, task: str, payload: dict[str, Any]) -> None:
        self.aux_sent.append(json.dumps({"task": task, **payload}, ensure_ascii=False, default=str))

    # --- request shapes per API mode ---------------------------------------------------------------
    def build_request(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        msgs = copy.deepcopy(messages)
        if self.api_mode == "chat_completions":
            return {"model": "sim", "messages": [{"role": "system", "content": self.system_prompt}] + msgs,
                    "tools": [{"type": "function", "function": {"name": "read_file", "description": "Read a file"}}]}
        if self.api_mode == "codex_responses":
            items: list[dict[str, Any]] = []
            for m in msgs:
                if m.get("role") == "tool":
                    items.append({"type": "function_call_output", "call_id": m.get("tool_call_id"), "output": m["content"]})
                elif m.get("tool_calls"):
                    for tc in m["tool_calls"]:
                        items.append({"type": "function_call", "call_id": tc["id"], "name": tc["function"]["name"],
                                      "arguments": tc["function"]["arguments"]})
                else:
                    content = m.get("content")
                    if isinstance(content, str):
                        content = [{"type": "input_text" if m["role"] == "user" else "output_text", "text": content}]
                    items.append({"role": m["role"], "content": content})
            return {"model": "sim", "instructions": self.system_prompt, "input": items}
        if self.api_mode == "anthropic_messages":
            out: list[dict[str, Any]] = []
            for m in msgs:
                if m.get("role") == "tool":
                    out.append({"role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": m.get("tool_call_id"), "content": m["content"]}]})
                elif m.get("tool_calls"):
                    out.append({"role": "assistant", "content": [
                        {"type": "tool_use", "id": tc["id"], "name": tc["function"]["name"],
                         "input": json.loads(tc["function"]["arguments"])} for tc in m["tool_calls"]]})
                else:
                    content = m.get("content")
                    if isinstance(content, str):
                        content = [{"type": "text", "text": content}]
                    out.append({"role": m["role"], "content": content})
            return {"model": "sim", "system": [{"type": "text", "text": self.system_prompt}], "messages": out}
        raise ValueError(self.api_mode)

    # --- one user turn ----------------------------------------------------------------------------
    def turn(self, sid: str, text: str, *, parts: list[dict[str, Any]] | None = None,
             tool_outputs: list[str] | None = None, transient_failures: int = 0) -> dict[str, Any]:
        msgs = self.history.setdefault(sid, [])
        first = not msgs
        user = {"role": "user", "content": parts if parts is not None else text}
        msgs.append(user)

        results = self.hook("pre_llm_call", session_id=sid, user_message=text,
                            conversation_history=list(msgs), is_first_turn=first)
        blocks = [r["message"] for r in results if isinstance(r, dict) and r.get("action") == "block"]
        if blocks:
            user["content"] = "[prompt withheld]"
            self.persist(sid)
            return {"blocked": blocks[0]}

        # Titling (aux, no middleware) reads the user's ask from the message list.
        self.aux("title_generation", {"messages": [{"role": "user", "content": _flatten(user["content"])}]})

        outputs = list(tool_outputs or [])
        self.model.pending_tools = len(outputs)
        self.model.fail_next = transient_failures
        reply: dict[str, Any] = {}
        for _round in range(len(outputs) + 1):
            for _attempt in range(3):
                request = self.request_chain(self.build_request(msgs), session_id=sid)
                try:
                    response = self.execution_chain(request, self.provider, session_id=sid)
                except TransientProviderError:
                    continue
                except Exception as exc:
                    self.persist(sid)
                    return {"error": str(exc)}
                break
            else:
                return {"error": "retries exhausted"}
            if not isinstance(response, dict):
                return {"blocked": response.choices[0].message.content}
            message = dict(response["choices"][0]["message"])
            msgs.append(message)
            reply = message
            if not message.get("tool_calls"):
                break
            for tc in message["tool_calls"]:
                self.tool_args_seen.append(tc["function"]["arguments"])
                output = outputs.pop(0)
                transformed = self.hook("transform_tool_result", tool_name="read_file",
                                        args=json.loads(tc["function"]["arguments"]), result=output, session_id=sid)
                result = transformed[-1] if transformed else output
                msgs.append({"role": "tool", "tool_call_id": tc["id"], "content": result})
        self.persist(sid)
        self.hook("on_session_end", session_id=sid)
        return reply

    def compact(self, sid: str, new_sid: str) -> None:
        msgs = self.history[sid]
        self.aux("compression", {"messages": [{"role": "user", "content": "Summarize:\n" + json.dumps(msgs, ensure_ascii=False)}]})
        self.hook("post_compaction", old_session_id=sid, session_id=new_sid)
        self.history[new_sid] = [{"role": "user", "content": "[summary] " + _flatten(msgs[0].get("content"))}]

    def spawn_subagent(self, parent: str, child: str, goal: str, tool_outputs: list[str]) -> dict[str, Any]:
        self.hook("subagent_start", parent_session_id=parent, child_session_id=child, child_goal=goal)
        return self.turn(child, goal, tool_outputs=tool_outputs)

    def persist(self, sid: str) -> None:
        path = self.home / "sessions" / f"{sid}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for m in self.history.get(sid, []):
                fh.write(json.dumps(m, ensure_ascii=False, default=str) + "\n")


def scan_files(root: Path, needles: list[str]) -> list[tuple[str, str]]:
    hits = []
    for path in root.rglob("*"):
        if path.is_file():
            try:
                data = path.read_bytes().decode("utf-8", "ignore")
            except OSError:
                continue
            for n in needles:
                if n in data or n.lower() in data.lower():
                    hits.append((str(path.relative_to(root)), n))
    return hits
