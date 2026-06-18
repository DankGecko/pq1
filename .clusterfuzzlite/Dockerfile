# ClusterFuzzLite build container for PQSigner (SOTA 2026-06 §6).
# base-builder-rust ships nightly + cargo-fuzz + the libFuzzer/ASan wrappers.
FROM gcr.io/oss-fuzz-base/base-builder-rust

# fuzz/ is a STANDALONE cargo workspace (excluded from the main workspace —
# it needs nightly + sanitizers), so the whole repo is copied and the build
# script drives cargo-fuzz from the repo root (which contains fuzz/).
COPY . $SRC/pqsigner
WORKDIR $SRC/pqsigner
COPY .clusterfuzzlite/build.sh $SRC/build.sh
