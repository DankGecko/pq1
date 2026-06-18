#!/bin/bash -eu
# Build PQSigner's libFuzzer harnesses for ClusterFuzzLite / OSS-Fuzz.
#
# fuzz/ is a standalone cargo workspace (workspace.exclude in the root
# Cargo.toml) that requires nightly + cargo-fuzz; both are preinstalled in
# base-builder-rust. cargo-fuzz is driven from the repo root (it looks for
# ./fuzz/Cargo.toml). The OSS-Fuzz harness exports $RUSTFLAGS with the
# sanitizer/coverage instrumentation; `cargo fuzz build` honours it.

cd "$SRC/pqsigner"

cargo +nightly fuzz build -O

BIN_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"
for target in $(cargo +nightly fuzz list); do
  cp "$BIN_DIR/$target" "$OUT/"
  # Seed each fuzzer with its committed corpus, when present.
  if [ -d "fuzz/corpus/$target" ] && [ -n "$(ls -A "fuzz/corpus/$target" 2>/dev/null)" ]; then
    zip -j "$OUT/${target}_seed_corpus.zip" "fuzz/corpus/$target"/* >/dev/null 2>&1 || true
  fi
done
