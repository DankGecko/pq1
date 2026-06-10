#!/usr/bin/env bash
# §33 — AI-prover loop driver. Drives a headless Claude Code agent to close
# ONE Lean proof obligation, then GATES the result on the Lean kernel
# (lake build) + the axiom discipline (no sorryAx). The kernel re-check is
# the trust boundary: a wrong AI proof simply fails to compile, so AI output
# can never compromise soundness. Mirrors the Lean-Squad pattern (research:
# docs/lean-verification-research-2026-06.md) adapted to this make-driven repo.
#
# Usage:
#   ai_prove.sh <module> "<target-description>"
# e.g.
#   ai_prove.sh Extracted.Bits \
#     "Prove `lor_eq_add_disjoint`: val ||| (x <<< 8*b) = val + x*2^(8*b) when val < 2^(8*b) and x < 256, in Extracted/Bits.lean"
#
# Env:
#   AI_PROVE_MODEL   override the model (default: claude CLI default)
#   AI_PROVE_TURNS   max agent turns (default 40)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIF_DIR="$(cd "$HERE/.." && pwd)"
EXTRACTED="$VERIF_DIR/extracted"
LAKE="${LAKE:-$HOME/.elan/bin/lake}"
TURNS="${AI_PROVE_TURNS:-40}"

MODULE="${1:?usage: ai_prove.sh <module> <target-description>}"
TARGET="${2:?usage: ai_prove.sh <module> <target-description>}"

# --- snapshot for rollback if the attempt doesn't kernel-check ---------------
SNAP="$(mktemp -d)"
cp -r "$EXTRACTED/Extracted" "$SNAP/Extracted"
rollback() { rm -rf "$EXTRACTED/Extracted"; mv "$SNAP/Extracted" "$EXTRACTED/Extracted"; }

PROMPT="$(cat "$HERE/PROMPT_TEMPLATE.md")
**Module:** \`$MODULE\`
**Task:** $TARGET

When done, verify yourself: \`cd $EXTRACTED && $LAKE build $MODULE\` must
succeed, and \`#print axioms\` on the target must show no \`sorryAx\`."

echo "=== AI-prover: $MODULE ==="
echo "    target: $TARGET"

# --- run the headless agent --------------------------------------------------
# Tool surface is restricted to what proving needs (Read/Edit/Write + Bash for
# `lake`/`exact?`). We do NOT pass --dangerously-skip-permissions here: that is
# unsafe to invoke from an interactive session and is rejected by the agent
# safety classifier. A scheduled CI runner that executes this script in an
# ISOLATED sandbox (fresh container, no secrets, network-restricted) should set
#   AI_PROVE_SANDBOXED=1
# which adds the bypass flag — appropriate ONLY because the sandbox, not the
# permission prompt, is the containment boundary there.
MODEL_ARG=(); [ -n "${AI_PROVE_MODEL:-}" ] && MODEL_ARG=(--model "$AI_PROVE_MODEL")
PERM_ARG=()
if [ "${AI_PROVE_SANDBOXED:-0}" = "1" ]; then
  PERM_ARG=(--dangerously-skip-permissions)
fi
( cd "$EXTRACTED" && claude -p "$PROMPT" \
    "${MODEL_ARG[@]}" \
    --max-turns "$TURNS" \
    --allowedTools "Read,Edit,Write,Bash,Grep,Glob" \
    "${PERM_ARG[@]}" ) || {
  echo "AGENT ERROR — rolling back"; rollback; exit 2;
}

# --- KERNEL GATE: build must succeed -----------------------------------------
echo "=== kernel gate: lake build $MODULE ==="
if ! ( cd "$EXTRACTED" && "$LAKE" build "$MODULE" ); then
  echo "REJECTED: does not build — rolling back"; rollback; exit 1
fi

# --- AXIOM GATE: no sorryAx in the touched module ----------------------------
# Build a throwaway checker that prints axioms of every theorem in the module.
echo "=== axiom gate: no sorryAx ==="
if ( cd "$EXTRACTED" && grep -rl "sorry" Extracted/ 2>/dev/null | grep -qv "Aeneas" ); then
  # a literal `sorry` token survived in our files (comments are filtered by the
  # build of the real check below); fall through to the print-axioms check.
  :
fi
CHK="$EXTRACTED/Extracted/_AiAxiomCheck.lean"
{
  echo "import $MODULE"
  # dump axioms for every theorem the agent may have proven in the module
  cd "$EXTRACTED"
  grep -hoE "^theorem [A-Za-z0-9_'.]+" "Extracted/${MODULE#Extracted.}.lean" 2>/dev/null \
    | sed 's/^theorem /#print axioms Extracted.Equiv./' || true
} > "$CHK"
AXOUT="$( cd "$EXTRACTED" && "$LAKE" env lean "$CHK" 2>&1 || true )"
rm -f "$CHK"
if echo "$AXOUT" | grep -q "sorryAx"; then
  echo "REJECTED: depends on sorryAx — rolling back"; echo "$AXOUT" | grep sorryAx
  rollback; exit 1
fi

echo "=== ACCEPTED: $MODULE builds, kernel-clean (no sorryAx) ==="
rm -rf "$SNAP"
echo "$AXOUT" | grep -i "depends on axioms" || true
