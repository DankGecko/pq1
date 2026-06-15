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

# kontrol-cheatcodes (symbolic helpers) — only needed if a harness uses
# kevm.* / KontrolCheats. This harness uses ONLY forge-std cheatcodes, but
# install it anyway so future harnesses work out of the box.
if [ ! -d "$SW/lib/kontrol-cheatcodes" ]; then
  echo "Installing kontrol-cheatcodes ..."
  ( cd "$SW" && forge install runtimeverification/kontrol-cheatcodes ) || true
fi

mkdir -p "$DEST_DIR"
# Stage every Kontrol harness, rewriting the repo-relative imports to the
# in-project location.
for h in "$SRC_DIR"/*.t.sol; do
  base="$(basename "$h")"
  sed 's#\.\./\.\./\.\./smart-wallet/src/#../../src/#g; s#\.\./\.\./\.\./smart-wallet/test/mocks/#../mocks/#g' \
    "$h" > "$DEST_DIR/$base"
  echo "Staged harness -> $DEST_DIR/$base"
done

cd "$SW"
# Force the staged harnesses to recompile under kontrol's own
# `forge build --extra-output storageLayout ...`. A prior plain `forge build`
# can leave a harness artifact WITHOUT storageLayout, which `kontrol build`'s
# incremental forge step won't refresh, and kontrol then SILENTLY SKIPS the
# contract as "non-compatible JSON" (→ "Test identifiers not found" at prove).
for h in "$DEST_DIR"/*.t.sol; do rm -rf "out/$(basename "$h")"; done

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
