# ClusterFuzzLite build container for PQSigner (SOTA 2026-06 §6).
# base-builder-rust ships nightly + cargo-fuzz + the libFuzzer/ASan wrappers.
# PINNED by digest (2026-06-18 ToB supply-chain audit — was an unpinned :latest,
# re-pulled every build). This is the digest that the first green build
# (cflite-batch run 27770338025) used. OSS-Fuzz publishes no semver tags for
# base-builder-rust, so a digest is the only immutable pin; bump deliberately
# (gcr.io/v2/oss-fuzz-base/base-builder-rust/manifests/latest Docker-Content-Digest).
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:a96c8dfb5e0b4c418a3a63c6b1acd04a13d70335fbcaa370d4e1840780a58ce6

# fuzz/ is a STANDALONE cargo workspace (excluded from the main workspace —
# it needs nightly + sanitizers), so the whole repo is copied and the build
# script drives cargo-fuzz from the repo root (which contains fuzz/).
COPY . $SRC/pqsigner
WORKDIR $SRC/pqsigner
COPY .clusterfuzzlite/build.sh $SRC/build.sh
