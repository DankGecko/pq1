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
