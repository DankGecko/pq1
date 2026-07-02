#!/usr/bin/env bash
# Turnkey Kontrol (KEVM) proof runner for the PQSmartWallet model-to-bytecode
# bridge (axioms A3.2 / A3.3 / A3.4) — KEVM symbolic-execution proofs DIRECTLY
# against the deployed runtime bytecode, an engine independent of Halmos with no
# hand-written LeanModel.sol mirror in the loop. REQUIRES a working K Framework
# backend (`kompile`, `kore-rpc-booster`); install via `kup install kontrol`
# (Nix) or the runtimeverification/kontrol Docker image. See
# ../docs/KONTROL_SCOPING.md.
#
# Stages EVERY harness under kontrol/test/ into the smart-wallet Foundry project
# (so its remappings + lib submodules resolve), then runs `kontrol build` +
# `kontrol prove` over all Kontrol* test contracts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SW="$HERE/../../smart-wallet"            # the Foundry project (has lib/ + remappings)
SRC_DIR="$HERE/test"                     # all Kontrol harnesses live here
DEST_DIR="$SW/test/kontrol"

# NOTE: `kompile` / `kore-rpc-booster` are NOT expected on the outer PATH when
# Kontrol is installed via `kup install kontrol` (Nix) — the `kontrol` wrapper
# prepends its OWN bundled K backend (k-<ver>/bin) internally. So we require
# only the `kontrol` CLI; it self-contains the symbolic-execution engine.
command -v kontrol >/dev/null 2>&1 || {
  echo "ERROR: 'kontrol' CLI not found. Install with:"
  echo "         bash <(curl https://kframework.org/install)   # installs kup (Nix)"
  echo "         kup install kontrol"
  echo "       or use the runtimeverification/kontrol Docker image."
  echo "       See ../docs/KONTROL_SCOPING.md."
  exit 2
}

# kontrol-cheatcodes (symbolic helpers) is a TRANSIENT kontrol artifact and must
# NOT linger in the smart-wallet lib/: Foundry auto-generates a remapping for
# every lib/ dir and folds the remapping list into solc metadata, so its mere
# presence shifts EVERY pinned contract codehash and turns the codehash freeze
# tests (`forge test`) red — a phantom failure for anyone who has run Kontrol.
# So we (a) install it only when a staged harness actually imports it (deferred
# until after staging; current harnesses use only forge-std cheatcodes), and
# (b) remove it on exit so a later `forge test` / CI sees the canonical
# foundry.lock lib set. See work-todo §34 + docs/KONTROL_SCOPING.md.
KCC_DIR="$SW/lib/kontrol-cheatcodes"
cleanup() {
  if [ -d "$KCC_DIR" ]; then
    rm -rf "$KCC_DIR"
    echo "Removed transient kontrol-cheatcodes from lib/ (keeps codehash pins canonical)."
  fi
}
trap cleanup EXIT

mkdir -p "$DEST_DIR"
# Stage every Kontrol harness, rewriting the repo-relative imports to the
# in-project location.
for h in "$SRC_DIR"/*.t.sol; do
  base="$(basename "$h")"
  sed 's#\.\./\.\./\.\./smart-wallet/src/#../../src/#g; s#\.\./\.\./\.\./smart-wallet/test/mocks/#../mocks/#g' \
    "$h" > "$DEST_DIR/$base"
  echo "Staged harness -> $DEST_DIR/$base"
done

# Install kontrol-cheatcodes ONLY if a staged harness imports it. The EXIT trap
# above removes it again afterward, so the common forge-std-only case never
# leaves lib/ polluted for the next `forge test` / CI codehash freeze check.
if grep -rqlE "kontrol-cheatcodes|KontrolCheats|KEVMCheats" "$DEST_DIR"/*.t.sol 2>/dev/null; then
  if [ ! -d "$KCC_DIR" ]; then
    echo "A staged harness imports kontrol-cheatcodes; installing transiently ..."
    ( cd "$SW" && forge install runtimeverification/kontrol-cheatcodes ) || true
  fi
fi

cd "$SW"
# Force the staged harnesses to recompile under kontrol's own
# `forge build --extra-output storageLayout ...`. A prior plain `forge build`
# can leave a harness artifact WITHOUT storageLayout, which `kontrol build`'s
# incremental forge step won't refresh, and kontrol then SILENTLY SKIPS the
# contract as "non-compatible JSON" (→ "Test identifiers not found" at prove).
for h in "$DEST_DIR"/*.t.sol; do rm -rf "out/$(basename "$h")"; done

# NOTE (2026-07-02, finding kontrol-gate-not-codehash-anchored): unlike run_halmos.sh
# — which runs PinnedCodehashes / PinnedBytecodeImmutableLemma / DeployedBytecodeReproCheck
# BEFORE its symbolic pass — this gate proves against whatever `kontrol build` emits from
# the current tree, with NO in-flow codehash certification. "Directly on the deployed
# bytecode" (THE_CLAIM / KONTROL_SCOPING) is anchored EXTERNALLY: the `contracts` CI job's
# codehash-freeze (test/PinnedCodehashes.t.sol) fails on any drift from the pinned/on-chain
# codehash, so on an undrifted tree the built bytecode matches the pins. A source drift would
# be proven against the drifted bytecode here without THIS gate flagging it — the freeze test
# is the tripwire, not run_kontrol.sh.
echo "=== kontrol build ==="
kontrol build --verbose

# Prove every `prove_*` test in the Kontrol* harnesses. `--match-test` is a
# regex over the full `Contract.func(sig)` name (override with MATCH=..., or the
# worker count with KONTROL_WORKERS=...).
echo "=== kontrol prove (all Kontrol*.prove_* tests) ==="
kontrol prove \
  --match-test "${MATCH:-Kontrol.*\.prove_}" \
  --use-booster --workers "${KONTROL_WORKERS:-4}" --verbose

echo "=== kontrol list (proof status) ==="
kontrol list
