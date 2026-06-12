# PQSmartWallet formal-verification project (Lean 4).
#
# Targets:
#   make verify              — build the Lean project and run the executable.
#   make verify-build        — just type-check the Lean project.
#   make verify-audit        — print the sorry count + every axiom each headline
#                              theorem transitively depends on.
#   make verify-three-claims — run the full end-to-end three-claim pipeline
#                              (Lean + Foundry + Halmos-if-installed +
#                               Certora-if-licensed).
#   make verify-exec-gate    — focused build + axiom dump for Claim 4
#                              (execution-gate non-bypass): TxFlow.lean +
#                              every_call_gated_by_verifier + corollary.
#   make verify-clean        — remove build artefacts.

LEAN_DIR := lean
LAKE     ?= $(shell command -v lake 2>/dev/null || echo $$HOME/.elan/bin/lake)

.PHONY: verify verify-build verify-audit verify-three-claims verify-exec-gate verify-clean verify-bytecode verify-bytecode-setup

verify: verify-build
	@cd $(LEAN_DIR) && $(LAKE) exe verify-test-vectors

verify-build:
	@cd $(LEAN_DIR) && $(LAKE) build

verify-audit:
	@echo "=== Pending sorry tactics ==="
	@cd $(LEAN_DIR) && $(LAKE) env lean --run scripts/check_no_sorry.lean
	@echo ""
	@echo "=== Axiom dependency of headline theorems ==="
	@cd $(LEAN_DIR) && $(LAKE) env lean scripts/dump_axioms.lean || true

verify-three-claims:
	@bash scripts/verify-three-claims.sh

verify-exec-gate:
	@echo "=== Building TxFlow + Spec.Theorems (Claim 4 dep closure) ==="
	@cd $(LEAN_DIR) && $(LAKE) build SphincsCVerify.Wallet.TxFlow SphincsCVerify.Spec.Theorems
	@echo ""
	@echo "=== Axiom closure for Claim 4 theorems ==="
	@echo "Expected closure: { propext, Classical.choice, Quot.sound } (kernel-only)"
	@echo ""
	@cd $(LEAN_DIR) && $(LAKE) env lean scripts/dump_axioms_claim4.lean

verify-bytecode-setup:
	@bash halmos/setup_halmos.sh

# Bytecode-level discharge of the A3.* bridge axioms: certifies the
# compiled runtime codehashes match PINNED_CODEHASHES.md (BOTH the default
# runs=200 and deploy runs=999999 profiles) + the immutable-window lemma,
# then symbolically executes the deployed PQSmartWallet / factory / verifier
# bytecode with the patched Halmos — including the full pointwise-equivalence
# session for A3.2. Run `make verify-bytecode-setup` once first.
# Set PQ1_HALMOS_BOTH_PROFILES=1 to also re-run the symbolic suite under the
# deploy profile.
verify-bytecode:
	@bash halmos/run_halmos.sh

verify-clean:
	@cd $(LEAN_DIR) && rm -rf .lake build

# ---------------------------------------------------------------------------
# §33 — Aeneas-extracted firmware code (contracts/verification/extracted/)
#
#   make verify-extracted        — type-check the extracted-code project
#                                  (generated Lean + equivalence theorems +
#                                   axiom check). Needs elan; first run pulls
#                                  mathlib from the cloud cache.
#   make extract-sphincs-adrs    — REGENERATE the scoped address.rs extraction
#                                  and fail if it drifts from the committed
#                                  Extracted/Adrs.lean (proof-rot guard).
#                                  Needs the §33 toolchain in
#                                  ~/.local/share/pqsigner-lean (charon
#                                  nightly-2026.06.08 + aeneas
#                                  nightly-2026.06.10 + rustup
#                                  nightly-2026-06-01).
# ---------------------------------------------------------------------------

EXTRACTED_DIR := extracted
PQLEAN        := $(HOME)/.local/share/pqsigner-lean
REPO_ROOT     := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)

.PHONY: verify-extracted extract-sphincs-adrs extract-aa-userop extract-fors-index

verify-extracted:
	@cd $(EXTRACTED_DIR) && $(LAKE) build
	@echo "=== Axiom closure of the §33 theorems (expect exactly propext, Classical.choice, Quot.sound) ==="
	@cd $(EXTRACTED_DIR) && $(LAKE) env lean Extracted/AxiomCheck.lean

extract-sphincs-adrs:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --start-from 'sphincs_c10::address' --dest-file /tmp/pqsigner-extract/adrs.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/out && mkdir -p /tmp/pqsigner-extract/out
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/out /tmp/pqsigner-extract/adrs.llbc
	@diff -u $(EXTRACTED_DIR)/Extracted/Adrs.lean /tmp/pqsigner-extract/out/Adrs.lean \
	  && echo "OK: committed extraction matches the current Rust" \
	  || { echo "DRIFT: address.rs changed — re-extract, re-prove, re-commit"; exit 1; }

extract-aa-userop:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/aa && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --opaque 'pqsigner_tx_core::hash' \
	  --start-from 'pqsigner_aa::userop::compute_user_op_hash' \
	  --dest-file /tmp/pqsigner-extract/userop.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/uout && mkdir -p /tmp/pqsigner-extract/uout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/uout -split-files /tmp/pqsigner-extract/userop.llbc
	@sed 's/import Userop\./import Extracted.UserOp./' /tmp/pqsigner-extract/uout/Funs.lean > /tmp/pqsigner-extract/uout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/UserOp/Funs.lean /tmp/pqsigner-extract/uout/Funs.fixed.lean \
	  && echo "OK: committed userop extraction matches the current Rust" \
	  || { echo "DRIFT: aa/userop.rs changed — re-extract, re-prove, re-commit"; exit 1; }

extract-fors-index:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --start-from 'sphincs_c10::fors::extract_ht_index' \
	  --start-from 'sphincs_c10::fors::extract_fors_indices' \
	  --dest-file /tmp/pqsigner-extract/fors.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/fout && mkdir -p /tmp/pqsigner-extract/fout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/fout -split-files /tmp/pqsigner-extract/fors.llbc
	@sed 's/import Fors\./import Extracted.Fors./' /tmp/pqsigner-extract/fout/Funs.lean > /tmp/pqsigner-extract/fout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Fors/Funs.lean /tmp/pqsigner-extract/fout/Funs.fixed.lean \
	  && echo "OK: committed FORS extraction matches the current Rust" \
	  || { echo "DRIFT: fors.rs index path changed — re-extract, re-prove, re-commit"; exit 1; }

# §33 P1 — guard that Extracted/SpecVendored.lean stays a faithful copy of
# the SphincsCVerify source it vendors (the version bridge's trust rests on
# the verbatim transcription). Compares the named ByteVec/Adrs definitions.
.PHONY: verify-spec-vendored-fidelity
verify-spec-vendored-fidelity:
	@python3 scripts/check_vendored_spec.py

# §33 — AI-prover loop: drive a headless Claude agent to close ONE proof
# obligation, gated on the Lean kernel + axiom discipline. See
# ai-prover/ai_prove.sh. Usage:
#   make ai-prove MODULE=Extracted.Bits TARGET="Prove lor_eq_add_disjoint ..."
.PHONY: ai-prove
ai-prove:
	@ai-prover/ai_prove.sh "$(MODULE)" "$(TARGET)"

# §33 rank 3 — eip1271 byte-layout extraction (domain_separator + replay_safe_hash).
# keccak is opaque (the single keccak256_pure axiom); reuses UserOp/FunsExternal.
.PHONY: extract-aa-eip1271
extract-aa-eip1271:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/aa && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --opaque 'pqsigner_tx_core::hash' \
	  --start-from 'pqsigner_aa::eip1271::replay_safe_hash' \
	  --dest-file /tmp/pqsigner-extract/eip1271.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/eout && mkdir -p /tmp/pqsigner-extract/eout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/eout -split-files /tmp/pqsigner-extract/eip1271.llbc
	@sed 's/import Eip1271\./import Extracted.Eip1271./' /tmp/pqsigner-extract/eout/Funs.lean > /tmp/pqsigner-extract/eout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Eip1271/Funs.lean /tmp/pqsigner-extract/eout/Funs.fixed.lean \
	  && echo "OK: committed eip1271 extraction matches the current Rust" \
	  || { echo "DRIFT: aa/eip1271.rs changed — re-extract, re-prove, re-commit"; exit 1; }

# §33 rank 4 — wots::extract_digits (independent bit-extractor; proven = same
# closed-form window as read_bits_le). opaque sha2/zeroize like fors.
.PHONY: extract-wots-digits
extract-wots-digits:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --start-from 'sphincs_c10::wots::extract_digits' \
	  --dest-file /tmp/pqsigner-extract/wots.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/wout && mkdir -p /tmp/pqsigner-extract/wout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/wout -split-files /tmp/pqsigner-extract/wots.llbc
	@sed 's/import Wots\./import Extracted.Wots./' /tmp/pqsigner-extract/wout/Funs.lean > /tmp/pqsigner-extract/wout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Wots/Funs.lean /tmp/pqsigner-extract/wout/Funs.fixed.lean \
	  && echo "OK: committed wots extraction matches the current Rust" \
	  || { echo "DRIFT: sphincs-c10/src/wots.rs changed — re-extract, re-prove, re-commit"; exit 1; }

# §33 rank 7 — tx-core RLP bytes_to_u64 + bytes_to_u256 (canonical BE-int decode).
# into_iter is given a DEF (not axiom) in Extracted/Rlp/FunsExternal.lean.
.PHONY: extract-txcore-rlp
extract-txcore-rlp:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/tx-core && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --start-from 'pqsigner_tx_core::rlp::bytes_to_u64' \
	  --start-from 'pqsigner_tx_core::rlp::bytes_to_u256' \
	  --dest-file /tmp/pqsigner-extract/rlp.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/rout && mkdir -p /tmp/pqsigner-extract/rout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/rout -split-files /tmp/pqsigner-extract/rlp.llbc
	@sed 's/import Rlp\./import Extracted.Rlp./' /tmp/pqsigner-extract/rout/Funs.lean > /tmp/pqsigner-extract/rout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Rlp/Funs.lean /tmp/pqsigner-extract/rout/Funs.fixed.lean \
	  && echo "OK: committed RLP extraction matches the current Rust" \
	  || { echo "DRIFT: tx-core/src/rlp.rs changed — re-extract, re-prove, re-commit"; exit 1; }

# §33 rank 12 — fw-manifest signed_preimage (75-byte frozen FW-signing layout).
.PHONY: extract-fwmanifest-preimage
extract-fwmanifest-preimage:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/fw-manifest && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sphincs_c10 --opaque subtle \
	  --start-from 'fw_manifest::signed_preimage' \
	  --dest-file /tmp/pqsigner-extract/fwman.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/fmout && mkdir -p /tmp/pqsigner-extract/fmout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/fmout -split-files /tmp/pqsigner-extract/fwman.llbc
	@sed 's/import Fwman\./import Extracted.FwManifest./' /tmp/pqsigner-extract/fmout/Funs.lean > /tmp/pqsigner-extract/fmout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/FwManifest/Funs.lean /tmp/pqsigner-extract/fmout/Funs.fixed.lean \
	  && echo "OK: committed fw-manifest extraction matches the current Rust" \
	  || { echo "DRIFT: fw-manifest/src/lib.rs changed — re-extract, re-prove, re-commit"; exit 1; }

# §33 rank 10 — U256::saturating_mul_u64 (via the u256_saturating_mul_u64 wrapper;
# --start-from cannot target inherent-impl methods).
.PHONY: extract-u256-mul
extract-u256-mul:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/tx-core && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --start-from 'pqsigner_tx_core::eip1559::u256_saturating_mul_u64' \
	  --dest-file /tmp/pqsigner-extract/u256mul.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/mout && mkdir -p /tmp/pqsigner-extract/mout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/mout -split-files /tmp/pqsigner-extract/u256mul.llbc
	@sed 's/import U256mul\./import Extracted.U256Mul./' /tmp/pqsigner-extract/mout/Funs.lean > /tmp/pqsigner-extract/mout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/U256Mul/Funs.lean /tmp/pqsigner-extract/mout/Funs.fixed.lean \
	  && echo "OK: committed u256-mul extraction matches the current Rust" \
	  || { echo "DRIFT: tx-core/src/eip1559.rs changed — re-extract, re-prove, re-commit"; exit 1; }

# §33 rank 6 — merkle::verify_auth_path (XMSS auth-path walk; th_pair opaque →
# th_pair_pure axiom in Merkle/FunsExternal.lean). The dedup filter drops the
# re-extracted make_adrs / params.H duplicates and imports their canonical homes.
.PHONY: extract-merkle-verify
extract-merkle-verify:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --opaque 'sphincs_c10::hash::th_pair' \
	  --start-from 'sphincs_c10::merkle::verify_auth_path' \
	  --dest-file /tmp/pqsigner-extract/merkle.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/mkout && mkdir -p /tmp/pqsigner-extract/mkout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/mkout -split-files /tmp/pqsigner-extract/merkle.llbc
	@python3 scripts/dedup_extraction.py /tmp/pqsigner-extract/mkout/Funs.lean /tmp/pqsigner-extract/mkout/Funs.fixed.lean \
	  --sed-import 'Merkle.=Extracted.Merkle.' \
	  --kill 'sphincs_c10::address::make_adrs' --kill 'sphincs_c10::params::H' \
	  --add-import Extracted.Adrs --add-import Extracted.Fors.Funs
	@diff -u $(EXTRACTED_DIR)/Extracted/Merkle/Funs.lean /tmp/pqsigner-extract/mkout/Funs.fixed.lean \
	  && echo "OK: committed merkle extraction matches the current Rust" \
	  || { echo "DRIFT: sphincs-c10/src/merkle.rs changed — re-extract, re-prove, re-commit"; exit 1; }

# §33 rank 5 — wots::pk_from_sig (verifier-side WOTS+C; wots_digest/chain_hash/
# th_multi opaque → _pure axioms in PkFromSig/FunsExternal.lean; dedup drops
# the re-extracted make_adrs/set_chain_index/extract_digits/params/pad16).
.PHONY: extract-wots-pkfromsig
extract-wots-pkfromsig:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --opaque 'sphincs_c10::hash::chain_hash' --opaque 'sphincs_c10::hash::th_multi' \
	  --opaque 'sphincs_c10::hash::wots_digest' \
	  --start-from 'sphincs_c10::wots::pk_from_sig' \
	  --dest-file /tmp/pqsigner-extract/pkfs.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/pout && mkdir -p /tmp/pqsigner-extract/pout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/pout -split-files /tmp/pqsigner-extract/pkfs.llbc
	@python3 scripts/dedup_extraction.py /tmp/pqsigner-extract/pout/Funs.lean /tmp/pqsigner-extract/pout/Funs.fixed.lean \
	  --sed-import 'Pkfs.=Extracted.PkFromSig.' \
	  --kill 'sphincs_c10::address::make_adrs' --kill 'sphincs_c10::address::set_chain_index' \
	  --kill 'sphincs_c10::wots::extract_digits' \
	  --kill 'sphincs_c10::params::W' --kill 'sphincs_c10::params::LOG_W' \
	  --kill 'sphincs_c10::params::L' --kill 'sphincs_c10::params::W_MASK' \
	  --kill 'sphincs_c10::hash::pad16' --kill 'sphincs_c10::params::N' \
	  --add-import Extracted.Adrs --add-import Extracted.Wots.Funs --add-import Extracted.Merkle.Funs
	@diff -u $(EXTRACTED_DIR)/Extracted/PkFromSig/Funs.lean /tmp/pqsigner-extract/pout/Funs.fixed.lean \
	  && echo "OK: committed pk_from_sig extraction matches the current Rust" \
	  || { echo "DRIFT: sphincs-c10/src/wots.rs changed — re-extract, re-prove, re-commit"; exit 1; }

# §33 rank 11 — tx::erc20::merkle::verify_proof (trust-bundle merkle walk;
# leaf_hash/node_hash opaque → _pure axioms in TxMerkle/FunsExternal.lean).
.PHONY: extract-tx-merkle
extract-tx-merkle:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/tx && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 \
	  --opaque 'pqsigner_tx::erc20::merkle::leaf_hash' \
	  --opaque 'pqsigner_tx::erc20::merkle::node_hash' \
	  --start-from 'pqsigner_tx::erc20::merkle::verify_proof' \
	  --dest-file /tmp/pqsigner-extract/txmk.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/tout && mkdir -p /tmp/pqsigner-extract/tout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/tout -split-files /tmp/pqsigner-extract/txmk.llbc
	@sed 's/import Txmk\./import Extracted.TxMerkle./' /tmp/pqsigner-extract/tout/Funs.lean > /tmp/pqsigner-extract/tout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/TxMerkle/Funs.lean /tmp/pqsigner-extract/tout/Funs.fixed.lean \
	  && echo "OK: committed tx-merkle extraction matches the current Rust" \
	  || { echo "DRIFT: tx/src/erc20/merkle.rs changed — re-extract, re-prove, re-commit"; exit 1; }

# §33 rank 9 — bip39 11-bit pack/unpack round-trip (via the roundtrip_11 pub
# wrapper; private write_11_bits/read_11_bits can't be --start-from'd).
.PHONY: extract-bip39-roundtrip
extract-bip39-roundtrip:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/bip39 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize --opaque subtle \
	  --start-from 'sphincs_tz_bip39::full::roundtrip_11' \
	  --dest-file /tmp/pqsigner-extract/bip39.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/bout && mkdir -p /tmp/pqsigner-extract/bout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/bout -split-files /tmp/pqsigner-extract/bip39.llbc
	@sed 's/import Bip39\./import Extracted.Bip39./' /tmp/pqsigner-extract/bout/Funs.lean > /tmp/pqsigner-extract/bout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Bip39/Funs.lean /tmp/pqsigner-extract/bout/Funs.fixed.lean \
	  && echo "OK: committed bip39 extraction matches the current Rust" \
	  || { echo "DRIFT: bip39/src changed — re-extract, re-prove, re-commit"; exit 1; }

# §33 rank 8 — rlp::decode_item (canonical-RLP grammar). Types/FunsExternal are
# hand-deduped against Rlp.* (shared RlpError + into_iter) — re-do that dedup if
# re-extracting; only Funs is drift-guarded here.
.PHONY: extract-decode-item
extract-decode-item:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/tx-core && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --start-from 'pqsigner_tx_core::rlp::decode_item' \
	  --dest-file /tmp/pqsigner-extract/decode.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/dout && mkdir -p /tmp/pqsigner-extract/dout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/dout -split-files /tmp/pqsigner-extract/decode.llbc
	@sed 's/import Decode\./import Extracted.Decode./' /tmp/pqsigner-extract/dout/Funs.lean > /tmp/pqsigner-extract/dout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/Decode/Funs.lean /tmp/pqsigner-extract/dout/Funs.fixed.lean \
	  && echo "OK: committed decode_item extraction matches the current Rust" \
	  || { echo "DRIFT: tx-core/src/rlp.rs changed — re-extract, re-prove, re-commit"; exit 1; }
