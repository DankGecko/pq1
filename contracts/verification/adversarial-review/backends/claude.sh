#!/usr/bin/env bash
# Claude Code backend for the FV adversarial review.
# Reads an assembled prompt file ($1, or stdin) and emits the model's JSON answer
# on stdout. Claude Code runs as an AGENT with file-read tools, so the prompt
# lists target PATHS and Claude reads them itself (no --inline-files needed).
#
# Use directly:   bash backends/claude.sh /path/to/prompt.md
# Or via runner:  run_review.py --backend generic --cmd 'bash backends/claude.sh {prompt_file}'
# (The default `--backend claude` template in protocol.json pipes via `claude -p`.)
set -euo pipefail
PROMPT_FILE="${1:-/dev/stdin}"
# -p = print mode (non-interactive). Allow file reads; deny edits (review-only).
claude -p \
  --output-format text \
  --allowedTools Read Grep Glob \
  < "${PROMPT_FILE}"
