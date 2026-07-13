#!/bin/bash -eu
# Build PQSigner's libFuzzer harnesses for ClusterFuzzLite / OSS-Fuzz.
#
# fuzz/ is a standalone cargo workspace (workspace.exclude in the root
# Cargo.toml) that requires nightly + cargo-fuzz; both are preinstalled in
# base-builder-rust. cargo-fuzz is driven from the repo root (it looks for
# ./fuzz/Cargo.toml). The OSS-Fuzz harness exports $RUSTFLAGS with the
# sanitizer/coverage instrumentation; `cargo fuzz build` honours it.

cd "$SRC/pqsigner"

# Generated renderer seeds are intentionally not checked in because they drift
# with every authenticated catalogue root. Fresh ClusterFuzzLite workers must
# rebuild them before packaging corpora; otherwise this target starts from
# random bytes and almost never crosses Erc7730Ir::parse. Do not inherit the
# fuzzer sanitizer RUSTFLAGS for this ordinary host-side generator test.
env -u RUSTFLAGS cargo +nightly test --locked --manifest-path fuzz/Cargo.toml \
  --test gen_render_seeds -- --ignored --nocapture

cargo +nightly fuzz build -O

BIN_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"
if ! targets=$(cargo +nightly fuzz list); then
  echo "cargo-fuzz could not enumerate targets" >&2
  exit 1
fi
if [ -z "$(printf '%s' "$targets" | tr -d '[:space:]')" ]; then
  echo "cargo-fuzz enumerated zero targets" >&2
  exit 1
fi

built_targets=0
while IFS= read -r target; do
  [ -n "$target" ] || continue
  built_targets=$((built_targets + 1))
  cp "$BIN_DIR/$target" "$OUT/"
  # Package only non-hidden regular corpus entries. Once that precondition is
  # true, a zip failure is a build failure rather than a silently seedless job.
  corpus_files=()
  if [ -d "fuzz/corpus/$target" ]; then
    for candidate in "fuzz/corpus/$target"/*; do
      [ -f "$candidate" ] && corpus_files+=("$candidate")
    done
  fi
  if [ "${#corpus_files[@]}" -gt 0 ]; then
    zip -j "$OUT/${target}_seed_corpus.zip" "${corpus_files[@]}" >/dev/null
  fi
done <<< "$targets"

if [ "$built_targets" -eq 0 ]; then
  echo "cargo-fuzz target enumeration produced no packageable targets" >&2
  exit 1
fi
