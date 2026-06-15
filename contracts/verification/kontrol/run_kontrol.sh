#!/usr/bin/env bash
# Turnkey Kontrol (KEVM) proof runner for the PQSmartWallet bootstrap-
# unremovable property. REQUIRES a working K Framework backend (`kompile`,
# `kore-rpc-booster`) — see ../docs/KONTROL_SCOPING.md for why that is the
# install blocker on this host and how to get one (`kup install kontrol`
# or the runtimeverification/kontrol Docker image).
#
# This script copies the harness into the smart-wallet Foundry project (so
# the existing remappings + lib submodules resolve), then runs
# `kontrol build` + `kontrol prove`. It is a no-op against the verifier's
# SHA-256 (the chosen property reverts before any hashing).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SW="$HERE/../../smart-wallet"            # the Foundry project (has lib/ + remappings)
HARNESS="$HERE/test/KontrolBootstrapUnremovable.t.sol"
DEST_DIR="$SW/test/kontrol"
DEST="$DEST_DIR/KontrolBootstrapUnremovable.t.sol"

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
# Rewrite the worktree-relative imports to the in-project location.
sed 's#\.\./\.\./\.\./smart-wallet/src/#../../src/#g; s#\.\./\.\./\.\./smart-wallet/test/mocks/#../mocks/#g' \
  "$HARNESS" > "$DEST"
echo "Staged harness -> $DEST"

cd "$SW"
echo "=== kontrol build ==="
kontrol build --verbose

echo "=== kontrol prove (bootstrap-unremovable, all rules) ==="
kontrol prove \
  --match-test 'KontrolBootstrapUnremovable.prove_bootstrap_unremovable_from_entrypoint' \
  --match-test 'KontrolBootstrapUnremovable.prove_bootstrap_unremovable_exact_bytes' \
  --match-test 'KontrolBootstrapUnremovable.prove_bootstrap_remove_rejected_non_entrypoint' \
  --use-booster --workers 3 --verbose

echo "=== kontrol list (proof status) ==="
kontrol list
