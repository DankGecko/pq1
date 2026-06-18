#!/usr/bin/env bash
# Run a command with NO network access (SOTA 2026-06 §7 egress discipline).
#
# On a key-holding repo, the binary/fuzz/SCA tools — cargo-fuzz, rainbow,
# lascar, scared, the tools/sca harnesses — have no business reaching the
# network. A compromised dependency or a malicious test input must not be able
# to exfiltrate anything. This wrapper drops the network namespace (via
# unprivileged bubblewrap) while keeping the full filesystem + the repo +
# the cargo/rustup caches available read-write, so builds and runs work
# normally — just with no route off-box.
#
#   tools/sca/run-isolated.sh make -C tools/sca c10-sign
#   tools/sca/run-isolated.sh make fuzz-all
#   tools/sca/run-isolated.sh cargo build -p <fuzz-target>
#
# Prefer bubblewrap (works unprivileged here). Falls back to `unshare -n` only
# when run as root. If neither is available it REFUSES (fails closed) rather
# than silently running with a live network.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]   # runs <command> with no network" >&2
  exit 2
fi

if command -v bwrap >/dev/null 2>&1; then
  exec bwrap \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --bind "$PWD" "$PWD" \
    --bind-try "$HOME/.cargo" "$HOME/.cargo" \
    --bind-try "$HOME/.rustup" "$HOME/.rustup" \
    --bind-try "$PWD/target" "$PWD/target" \
    --unshare-net \
    --die-with-parent \
    --chdir "$PWD" \
    "$@"
elif [ "$(id -u)" = "0" ]; then
  exec unshare -n "$@"
else
  echo "run-isolated: need bwrap (bubblewrap) or root to drop the network; \
refusing to run '$1' WITH a live network (fail-closed)." >&2
  exit 1
fi
