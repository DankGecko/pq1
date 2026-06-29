#!/usr/bin/env bash
# Codex CLI backend for the FV adversarial review.
# Reads an assembled prompt file ($1, or stdin) and emits the model's JSON answer
# on stdout. Codex `exec` runs non-interactively as an agent with file tools, so
# the prompt lists target PATHS and Codex reads them itself.
#
# Use directly:   bash backends/codex.sh /path/to/prompt.md
# Or via runner:  run_review.py --backend codex
#                 run_review.py --backend generic --cmd 'bash backends/codex.sh {prompt_file}'
#
# Notes:
#  * `codex exec -` reads the prompt from stdin and runs to completion.
#  * --skip-git-repo-check lets it run from any cwd.
#  * Adjust --model / --sandbox to your Codex config; read-only is ideal for review.
set -euo pipefail
PROMPT_FILE="${1:-/dev/stdin}"
codex exec \
  --skip-git-repo-check \
  --sandbox read-only \
  - < "${PROMPT_FILE}"
