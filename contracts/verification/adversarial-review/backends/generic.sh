#!/usr/bin/env bash
# Generic / raw-LLM backend TEMPLATE for the FV adversarial review.
# Copy this and wire it to whatever model endpoint you use. The contract:
#   IN : an assembled prompt on stdin (or $1)
#   OUT: a single JSON object {findings:[...], honest_residual:"..."} on stdout
#
# A raw API endpoint has NO file tools, so run the runner with --inline-files
# (file contents are embedded in the prompt). Example with a hypothetical CLI:
#
#   run_review.py --backend generic --inline-files \
#     --cmd 'bash backends/generic.sh {prompt_file}'
#
# Below is a sketch using a generic OpenAI-compatible /chat/completions endpoint.
# Edit MODEL / API_BASE / API_KEY for your provider, or replace the curl wholesale.
set -euo pipefail
PROMPT_FILE="${1:-/dev/stdin}"
: "${API_BASE:=https://api.example.com/v1}"
: "${MODEL:=your-model-here}"
: "${API_KEY:?set API_KEY}"

PROMPT="$(cat "${PROMPT_FILE}")"
# jq builds a safe JSON request body from the prompt text.
jq -n --arg m "$MODEL" --arg p "$PROMPT" \
  '{model:$m, messages:[{role:"user",content:$p}], temperature:0.2}' \
| curl -sS "${API_BASE}/chat/completions" \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d @- \
| jq -r '.choices[0].message.content'
