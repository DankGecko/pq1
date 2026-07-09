#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp[cli]>=1.2", "openai>=1.40"]
# ///
"""Leanstral MCP server — expose an OpenAI-compatible Leanstral endpoint to Claude Code.

Leanstral 1.5 (mistralai/Leanstral-1.5-119B-A6B) is Mistral's Apache-2.0 Lean 4
proof-engineering model. Native Claude Code subagents can only run Anthropic models,
so we expose Leanstral as an MCP *tool* that a Claude subagent (see
.claude/agents/lean-prover.md) calls inside a draft -> verify(lean-lsp) -> refine loop.

The endpoint is fully swappable via env — the same code targets:
  * local Ollama            LEANSTRAL_BASE_URL=http://localhost:11434/v1  LEANSTRAL_MODEL=leanstral
  * local llama.cpp server  LEANSTRAL_BASE_URL=http://localhost:8080/v1   LEANSTRAL_MODEL=leanstral-1.5
  * free Mistral Labs API   LEANSTRAL_BASE_URL=https://api.mistral.ai/v1  LEANSTRAL_MODEL=labs-leanstral-1-5
                            LEANSTRAL_API_KEY=<key from console.mistral.ai>

Run standalone (for the smoke test) with e.g.:
  LEANSTRAL_MODEL=goedel-prover-v2-8b uv run tools/leanstral_mcp.py
"""
from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from openai import OpenAI

BASE_URL = os.environ.get("LEANSTRAL_BASE_URL", "http://localhost:11434/v1")
MODEL = os.environ.get("LEANSTRAL_MODEL", "leanstral")
API_KEY = os.environ.get("LEANSTRAL_API_KEY", "ollama")  # any non-empty string for local servers
TEMPERATURE = float(os.environ.get("LEANSTRAL_TEMPERATURE", "1.0"))  # Mistral's stated default
MAX_TOKENS = int(os.environ.get("LEANSTRAL_MAX_TOKENS", "8192"))
# Claude Code sets CLAUDE_PROJECT_DIR in the server env; fall back to cwd.
PROJECT = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())

SYSTEM = (
    "You are Leanstral, an expert Lean 4 / Mathlib proof engineer. "
    "Given a goal, produce a Lean 4 proof term or tactic block that closes it. "
    "Output ONLY compiling Lean 4 code — no prose, no explanation, no markdown fences. "
    "Prefer library lemmas over `sorry`; never emit `sorry` or `admit`."
)

client = OpenAI(base_url=BASE_URL, api_key=API_KEY)
mcp = FastMCP("leanstral")


def _complete(user: str, reasoning_effort: str) -> str:
    """One chat completion. `reasoning_effort` is Leanstral/vLLM-specific; local GGUF
    servers may reject unknown body fields, so retry once without it on failure."""
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
    kwargs = dict(model=MODEL, messages=msgs, temperature=TEMPERATURE, max_tokens=MAX_TOKENS)
    try:
        r = client.chat.completions.create(**kwargs, extra_body={"reasoning_effort": reasoning_effort})
    except Exception:
        r = client.chat.completions.create(**kwargs)  # endpoint ignored reasoning_effort
    return (r.choices[0].message.content or "").strip()


@mcp.tool()
def leanstral_prove(
    target: str,
    file_path: str = "",
    goal_state: str = "",
    reasoning_effort: str = "high",
) -> str:
    """Draft a candidate Lean 4 proof with Leanstral. Returns proof code to VERIFY with
    lean-lsp (this tool does NOT compile or edit anything).

    Args:
        target: the theorem name to prove, or an informal statement of the goal.
        file_path: OPTIONAL repo-relative path to the Lean file for context. Pass the
            PATH, never the file contents — the server reads it so large files stay out
            of the orchestrator's context window.
        goal_state: OPTIONAL current goal state (from `lean_goal`) and/or the compiler
            error from the previous attempt — pass this back on a refinement loop.
        reasoning_effort: "high" (default, for hard proofs) or "none". Honored by the
            Mistral endpoint; silently ignored by local GGUF servers.
    """
    context = ""
    if file_path:
        path = os.path.normpath(os.path.join(PROJECT, file_path))
        if not path.startswith(os.path.normpath(PROJECT)):
            return f"ERROR: file_path {file_path!r} escapes the project directory."
        try:
            with open(path, encoding="utf-8") as fh:
                context = f"# File `{file_path}`:\n```lean\n{fh.read()}\n```\n\n"
        except OSError as exc:
            return f"ERROR reading {file_path!r}: {exc}"

    parts = [context, f"Goal to close: {target}"]
    if goal_state:
        parts.append(f"\nCurrent goal state / last error:\n```\n{goal_state}\n```")
    try:
        return _complete("".join(parts), reasoning_effort) or "ERROR: empty completion."
    except Exception as exc:  # noqa: BLE001 — surface transport/model errors to Claude, don't crash
        return f"ERROR calling Leanstral endpoint ({BASE_URL}, model={MODEL}): {exc}"


if __name__ == "__main__":
    mcp.run()  # stdio transport (default) — not subject to the MCP HTTP idle timeout
