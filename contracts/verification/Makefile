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
# compiled runtime codehashes match PINNED_CODEHASHES.md, then symbolically
# executes the deployed PQSmartWallet / factory / verifier bytecode with the
# patched Halmos. Run `make verify-bytecode-setup` once first.
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

.PHONY: verify-extracted extract-sphincs-adrs

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
