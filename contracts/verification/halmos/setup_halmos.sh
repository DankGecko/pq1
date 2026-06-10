#!/usr/bin/env bash
#
# setup_halmos.sh — install the patched Halmos used for the PQSmartWallet
# bytecode-level discharge (A3.1 gates / A3.2 / A3.3).
#
# Why patched: stock halmos 0.3.3 declares the uninterpreted SHA-256
# precompile function with a domain sort keyed on the CALL's *byte* size
# (`f_sha256_32 : BitVec 32`) while applying it to the argument's *bit*
# width (`BitVec 256`), so z3 aborts with a sort mismatch on any path that
# reaches a SHA-256 precompile call (which every `validateUserOp` success
# path does, via `sphincsDigest`). The one-line fix
# (`0001-sha256-precompile-sort.patch`) keys the function on the argument's
# bit-width, matching how KECCAK is handled elsewhere in the same file. It
# only corrects the declared sort; the function stays UNINTERPRETED, so the
# abstraction is unchanged (the proof still bottoms out at A1 — SHA-256 is
# some function — exactly as intended).
#
# Idempotent. Requires: git, python3, pipx (or pip).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="${HERE}/0001-sha256-precompile-sort.patch"
SRC="${HALMOS_SRC_DIR:-${HOME}/.cache/pq1-halmos-src}"
VERSION="${HALMOS_VERSION:-v0.3.3}"

echo "==> Cloning halmos ${VERSION} into ${SRC}"
if [ ! -d "${SRC}/.git" ]; then
  git clone --quiet https://github.com/a16z/halmos.git "${SRC}"
fi
git -C "${SRC}" fetch --quiet --tags
git -C "${SRC}" checkout --quiet "${VERSION}"
git -C "${SRC}" reset --hard --quiet "${VERSION}"

echo "==> Applying SHA-256 precompile sort patch"
git -C "${SRC}" apply --check "${PATCH}" 2>/dev/null && git -C "${SRC}" apply "${PATCH}" \
  || echo "    (patch already applied or rebased; verifying below)"

grep -q 'f_sha256_{arg_bits}' "${SRC}/src/halmos/sevm.py" \
  || { echo "ERROR: patch did not land (f_sha256_{arg_bits} not found)"; exit 1; }
grep -q 'f_sha256_empty' "${SRC}/src/halmos/sevm.py" \
  || { echo "ERROR: patch part 2 did not land (f_sha256_empty not found)"; exit 1; }

echo "==> Installing patched halmos"
if command -v pipx >/dev/null 2>&1; then
  pipx install "${SRC}" --force
else
  python3 -m pip install --user --force-reinstall "${SRC}"
fi

echo "==> Done. halmos: $(cd /tmp && halmos --version 2>/dev/null | head -1)"
