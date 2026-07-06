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

# Fail pipelines on the first failing stage, not just the last (finding P4).
# The `extract-*` gates run `charon ... 2>&1 | tail -1`; without pipefail the
# pipeline's exit status is `tail`'s (always 0), so a Charon failure was masked
# and the recipe proceeded to run Aeneas on the STALE .llbc — regenerating the
# previously-committed Lean, matching the diff, and printing "OK" while the Rust
# had actually drifted. With pipefail the failing Charon exit propagates and
# make aborts the recipe before the stale .llbc is consumed. (Also un-masks the
# `lake env lean ... | tee` axiom-check gates below.) bash is required because
# POSIX sh does not guarantee `pipefail`.
SHELL        := bash
.SHELLFLAGS  := -o pipefail -c

LEAN_DIR := lean
LAKE     ?= $(shell command -v lake 2>/dev/null || echo $$HOME/.elan/bin/lake)

# `make` / `make help` lists every runnable target that carries a `## ` blurb
# (the self-documenting convention — it can't drift from reality the way a
# hand-maintained list does). Add `## one-liner` to a target's rule line to
# surface it here.
.DEFAULT_GOAL := help
.PHONY: help
help: ## Show the runnable FV targets (those with a description)
	@grep -hE '^[a-zA-Z0-9_.-]+:.*## ' $(MAKEFILE_LIST) | sort | awk -F':.*## ' '!seen[$$1]++ {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: verify verify-build verify-audit verify-three-claims verify-exec-gate verify-clean verify-bytecode verify-bytecode-setup verify-cavp verify-bulk verify-interp verify-transcription verify-parse-transcription verify-independent-signer verify-primitive-kat verify-storage-mutators verify-lean-proto-domain verify-fv-lints verify-lean4checker verify-kontrol verify-halmos verify-ledger-consistency verify-proof-mutation

# NOTE: verify-build (the `lake build` this bundle depends on) now also
# kernel-checks the A3.1 in-kernel parse theorem + elision bridge (the root
# module imports Interpreter/{YulParse,C10Source,C10Parse}); the byte-pin
# below keeps the embedded c10Source literal honest against the .sol.
verify: verify-build ## Default FV bundle: build + transcription + KAT + mutant-corpus
	@python3 scripts/check_c10_transcription.py
	@python3 scripts/check_c10_transcription_ast.py
	@python3 scripts/test_c10_transcription_ast_negative.py
	@python3 scripts/check_c10_source_pin.py
	@python3 scripts/check_lean_proto_domain.py
	@cd $(LEAN_DIR) && $(LAKE) exe verify-test-vectors
	@cd $(LEAN_DIR) && $(LAKE) exe verify-mutant-corpus

# I-3 closed-world gate: `no_reset_path` (Wallet/Invariants.lean) proves the
# KNOWN Storage counter-mutators are non-decreasing, but "these are the ONLY
# mutators" is an out-of-Lean assertion. This lint extracts every
# Storage-returning / `{ s with }`-updating def in Wallet/Storage.lean and
# FAILS if the set drifts from the pinned allow-list — so adding a new mutator
# forces a conscious allow-list update + a matching no-decrease lemma. Pure
# source lint (no lake build); positive=current tree PASS, negative=fake
# resetter FAIL. See scripts/check_storage_mutators.sh.
verify-storage-mutators: ## I-3 closed-world Storage-mutator allowlist gate
	@bash scripts/check_storage_mutators.sh

# P7 source lint (no lake build): the Lean factory add-slot domain tag must be
# byte-identical to proto::FACTORY_ADD_SLOT_DOMAIN, so the squat-defence proof
# (invariant #6) stays bound to the digest the device actually signs. Closes
# the "Lean-only domain drift undetected by the bytecode harnesses" residual.
verify-lean-proto-domain: ## Lean factory domain tag == proto (P7)
	@python3 scripts/check_lean_proto_domain.py

# FV-invariant escape-hatch gate: fails CI on the audit anti-patterns over the
# lean/ + extracted/ Lean SOURCE (comment-stripped). Four sub-lints:
#   (a) no proof-path escape hatches (native_decide / decide +native / @[csimp]
#       / @[implemented_by] / @[extern] / unsafe / partial / reduceBool);
#   (b) BreaksHash firewall (no `¬ BreaksHash` / `BreaksHash → False`);
#   (c) Gap-3 + theft_free axiom-closure tripwire (dump_axioms.lean must show
#       keccak_sha256_cross_separation in the offchain closure + the expected
#       A1/A2/A3.1/A4/A5 + kernel premises in theft_free's closure);
#   (d) opaque-guard (`trivial` must NOT inhabit Bridge.evmDeliversCall default
#       — catches an opaque→def A4 regression that #print-axioms misses).
# Sub-lints (c)/(d) read the built oleans, so this depends on verify-build.
# See scripts/lint_fv_invariants.sh (positive=clean tree PASS; negative trips
# documented in the script header).
verify-fv-lints: verify-build ## FV anti-vacuity sub-lints (escape-hatch/closures/opaque-guard)
	@bash scripts/lint_fv_invariants.sh

# LEDGER-CONSISTENCY gate (anti-vacuity class V5: "advertised != actual"). Makes
# the human-facing assurance ledger (docs/AXIOM_STATUS.json) FALSIFIABLE against
# the live Lean truth: cross-checks the advertised `closures` (exact-set, per
# theorem), the headline `signature_pins` (statement-shape — catches a
# re-introduced raw hypothesis like the EF P1/hInv finding, invisible to closure
# checks), the per-status summary COUNTS, the no-undocumented / no-phantom axiom
# invariants, status hygiene, and C9 ENFORCED non-vacuity-witness coverage (the
# `witness_coverage` block: every headline hypothesis has a kernel-only witness
# lemma present in the dump — closes the playbook §B gap #3) — against
# `dump_axioms.lean` + the Lean source +
# the lint_fv THEFT_EXPECTED pin (single authoritative source). Reads the built
# oleans (runs the dump), so depends on verify-build. Ships its own WIRED-IN
# NEGATIVE CONTROL: `python3 scripts/check_ledger_consistency.py --self-test`
# corrupts each check's input and asserts it fires (proves the gate is not vacuous).
# CAVEAT: the live source is `#print axioms`, which under-reports in lean v4.22.0;
# verify-lean4checker is the completeness backstop. See the script header and
# docs/fv-adversarial-review-playbook.md §B.
verify-ledger-consistency: verify-build ## AXIOM_STATUS.json falsifiable vs live dump (closures/pins/witnesses)
	@python3 scripts/check_ledger_consistency.py --self-test
	@python3 scripts/check_ledger_consistency.py

# PROOF-MUTATION gate (anti-vacuity class V4: "dead conjunct / vacuous lemma").
# The proof-side analogue of cargo-mutants: for each entry in
# lean/scripts/proof_mutations.json it DELETES (by rename) a load-bearing axiom
# or WEAKENS a lemma and asserts the rebuild REACTS as the ledger claims — a
# load-bearing axiom's removal must break the build; a non-consumed marker's
# removal must leave it green AND drop EXACTLY the advertised axiom from the
# closure; a zero-consumer axiom (A3.4) must stay green. A green-when-it-should-
# be-red is a vacuity, caught. Each mutation asserts it MATERIALLY changed the
# file (no-op = HARD FAIL, never a skip), fully rebuilds (no stale-cache false
# pass), and ALWAYS reverts; a permanent CANARY must trip or the harness is void.
# SLOW (each mutation = a full `lake build SphincsCVerify`). Tiers:
#   MUTATIONS=quick   make verify-proof-mutation   # canary + A3.1 (smoke)
#   (default)         make verify-proof-mutation   # curated 8
#   MUTATIONS=full    make verify-proof-mutation   # + corollary bridge axioms (13)
# Does NOT catch V7 (latent-FALSE axiom — still type-checks) or V11 (wrong spec).
# See scripts/check_proof_mutations.py + docs/fv-adversarial-review-playbook.md §B.
verify-proof-mutation: verify-build ## Proof-side cargo-mutants: delete axiom/weaken lemma, expect break (SLOW)
	@python3 scripts/check_proof_mutations.py

# EXTERNAL kernel re-check gate (deep-research rec #1). lean/ is Lean v4.22.0,
# inside the pre-#8842 collectAxioms under-report window, so `#print axioms`
# (verify-audit) can under-report the trust base. lean4checker independently
# replays the whole SphincsCVerify environment back through the Lean kernel and
# computes the TRUE closure — non-zero exit on any rejected declaration. Needs a
# version-matched lean4checker at ~/lean4checker (see scripts/run_lean4checker.sh
# header for the one-time build: git clone + checkout v4.22.0 + lake build);
# override the location with LEAN4CHECKER_DIR=...
verify-lean4checker: ## External kernel re-check (true axiom closure; SLOW)
	@bash scripts/run_lean4checker.sh

# Model-to-bytecode (D): Kontrol/KEVM symbolic-execution proofs DIRECTLY against
# the deployed contract bytecode — an engine independent of Halmos, with no
# hand-written LeanModel.sol mirror in the loop. Currently proves the
# bootstrap-unremovable owner-table slice (A3.4 / invariant #6). Requires a K
# backend (`kup install kontrol` via Nix, or the RV Docker image); ~5 min
# build+prove. See kontrol/run_kontrol.sh + docs/KONTROL_SCOPING.md.
verify-kontrol: ## Kontrol/KEVM symbolic proofs on deployed bytecode (heavy)
	@bash kontrol/run_kontrol.sh

# Halmos bytecode-level discharge of the A3.* bridge axioms: certifies the
# compiled runtime codehashes match the pins, then symbolically executes the
# deployed wallet/factory/verifier bytecode over the full check_* rule suite
# (both compiler profiles). Source of truth: halmos/run_halmos.sh.
verify-halmos: ## Halmos symbolic discharge of A3.* bridge axioms (heavy)
	@bash halmos/run_halmos.sh

# Bulk executable-spec differential (A3.1 follow-up): regenerate the random
# corpus from the Rust signer (slow; gated behind GEN=1), embed it, and run
# Spec.Signature.verify over every vector, asserting it matches the Rust
# oracle's verdict. Non-zero exit on any mismatch. The committed
# bulk_vectors.json + BulkVectors.lean make the default run reproducible
# without re-signing.
verify-bulk: ## Bulk executable-spec differential (Lean vs Rust oracle)
ifeq ($(GEN),1)
	@cd $(REPO_ROOT) && cargo test -p sphincs-c10 --test gen_bulk_vectors --release -- --nocapture
	@cd $(LEAN_DIR) && python3 scripts/gen_bulk_lean.py
endif
	@cd $(LEAN_DIR) && $(LAKE) exe verify-bulk

# A3.1 full-(a) empirical interpreter↔bytecode bridge: replays the KAT + bulk
# corpus THROUGH the transcribed Yul interpreter (Interpreter/C10Program.lean,
# under the real Spec.Sha256Impl oracle) and asserts execC10Asm ==
# Spec.Signature.verify AND == the KAT/bulk ground-truth verdict on every vector.
# The load-bearing precondition for the interpreter-refinement proof (see
# docs/A3_1_CLOSURE_PATH.md §8). HARD CHECK (non-zero exit on any mismatch).
verify-interp: ## A3.1 interpreter<->bytecode KAT+bulk replay
	@cd $(LEAN_DIR) && $(LAKE) exe verify-interp

# A3.1 transcription-fidelity lint (POSITIONAL). Cross-checks the hand transcription
# c10Program (lean/SphincsCVerify/Interpreter/C10Program.lean) against the deployed
# verifier SOURCE (../smart-wallet/src/verifiers/SPHINCsC10Asm.sol) — the single
# residual the kernel proof `execC10Asm_eq` cannot see (it relates c10Program<->spec,
# never c10Program<->.sol). Three checks: (A) POSITIONAL constant cross-check per the
# `-- L<n>` anchors (catches a constant in the WRONG fragment — a cross-fragment swap —
# which a flat/global check misses); (B) global constant-set equality; (C) statement-kind
# histogram. Pure source lint, no lake build. A REGRESSION GATE, not a proof.
# Negative-controls (a mutated constant; a cross-fragment swap) verified to FAIL it.
#
# The STATISTICAL lint's documented hole — an intra-fragment edit that preserves the
# constant-set + kind-histogram + gate-vars (a same-kind statement REORDER, a non-gate
# var swap, a non-commutative operand-order swap) — is now closed by the STRUCTURAL check
# `check_c10_transcription_ast.py`: it PARSES both sides into the `Interpreter.Yul` AST and
# asserts TREE EQUALITY, so a reorder/var-swap/operand-swap flips the tree and fails. The
# negative-control harness `test_c10_transcription_ast_negative.py` proves 3 such mutants are
# invisible to the statistical lint yet caught by the structural check. HONEST SCOPE: this
# upgrades the source<->AST leg from statistical to STRUCTURAL; it does NOT close R1 — the
# solc source->deployed-bytecode leg is untouched, and the parser + its 2 normalization rules
# (error-string mstore elision; return-var init) are themselves the TCB. See
# docs/A3_1_ADVERSARIAL_REVIEW_2026-06-18.md + docs/A3_1_CLOSURE_PATH.md §8.
verify-transcription: ## A3.1 c10Program <-> .sol transcription checks (positional + structural + source byte-pin)
	@python3 scripts/check_c10_transcription.py
	@python3 scripts/check_c10_transcription_ast.py
	@python3 scripts/test_c10_transcription_ast_negative.py
	@python3 scripts/check_c10_source_pin.py

# A3.1 R1a IN-KERNEL parser leg (2026-07-04). Lake-builds the Lean Yul-subset
# parser (Interpreter/YulParse.lean), the pinned byte-exact source + faithful
# parse target (Interpreter/C10Source.lean), and the kernel theorems
# (Interpreter/C10Parse.lean):
#   parse_c10                  : parseYul c10Source = some c10ProgramFull  (rfl, NO axioms)
#   execFrom_c10ProgramFull_eq : the N1/N2 elision bridge (verdict-equal to c10Program
#                                for every oracle/sig/env/mem)
#   execC10Asm_eq_parsed_source: ANY successful parse of the pinned source runs as
#                                execC10Asm — chaining into execC10Asm_eq = Spec.verify
# The ~9K-char kernel reduction needs --tstack=32768, wired via the lakefile's
# moreLeanArgs (so a plain `lake build` — and hence `verify-build` and the
# `verify` bundle, whose verify-build dependency compiles these modules via the
# root import — gets it automatically). The byte-pin (check_c10_source_pin.py,
# pure Python) asserting the embedded c10Source literal == .sol L37-230 runs in
# CI via verify-transcription / a31-transcription.yml; the LAKE proof itself is
# a LOCAL gate (CI has no Lean toolchain).
verify-parse-transcription: ## A3.1 in-kernel Yul parse: parseYul c10Source = some c10ProgramFull (kernel rfl) + elision bridge
	@python3 scripts/check_c10_source_pin.py
	@cd $(LEAN_DIR) && $(LAKE) build SphincsCVerify.Interpreter.YulParse SphincsCVerify.Interpreter.C10Source SphincsCVerify.Interpreter.C10Parse
	@echo "PASS: parse_c10 + elision bridge + execC10Asm_eq_parsed_source kernel-checked"
	@echo "      (SphincsCVerify/Interpreter/C10Parse.lean; axiom closure: parse_c10 NONE,"
	@echo "       bridge/corollary [propext, Classical.choice, Quot.sound] — see verify-audit)"

# A3.1 INDEPENDENT-SOURCE KAT leg (work-todo #7). A clean-room SHA-256 C10 signer
# (scripts/independent_c10_signer.py) written from the deployed SPHINCsC10Asm.sol +
# the documented PRF preimages — NOT transliterated from the Rust `sphincs-c10`
# signer — giving implementation diversity for the differential oracle (today's
# 3-way Lean/Yul/Rust vectors all originate from the ONE Rust signer). Two checks:
#  (1) byte-equivalence — the independent signer reproduces the Rust pk_root + all 4
#      valid KAT vectors BYTE-FOR-BYTE + round-trips fresh messages (pure Python, ~5s);
#  (2) cross-verifier — the EXISTING Rust verifier accepts FRESH independent-signer
#      output (the genuine independence guard vs a shared Python sign+verify bug).
# Honest scope: diversity over the shared C10 spec, not a second spec. Needs python3.
verify-independent-signer: ## Clean-room C10 signer cross-check
	@python3 scripts/independent_c10_signer.py
	@cd $(REPO_ROOT) && cargo test -p sphincs-c10 --test independent_signer_xcheck --release -- --nocapture

# Per-primitive component KAT (ETHFALCON-port R1). Golden intermediate-value
# vectors for each C10 tweakable-hash primitive (th/th_pair/th_multi/h_msg/
# chain_hash/wots_digest + the wots_secret/fors_secret PRFs), cross-checked across
# THREE independent implementations: Rust `sphincs-c10` (recompute regression pin),
# the clean-room Python signer (independence guard), and the on-chain Yul verifier's
# SHA-256 preimage layout via the precompile (Foundry, the 6 verify-side primitives).
# Localizes an A3.1-class per-primitive divergence to the exact boundary. Golden is
# self-generated + N-way cross-checked; NOT externally conformant — C10 shares only
# raw SHA-256 with any standard (that layer is anchored to NIST CAVP). Regenerate
# with `C10_KAT_REGEN=1 cargo test -p sphincs-c10 --features sim-internals \
# --test primitive_kat --release`. Needs python3 + forge on PATH.
# See docs/verification/external-kat-provenance-and-ethfalcon-port-2026-07.md.
verify-primitive-kat: ## Per-primitive tweakable-hash KAT (Rust<->Python<->Yul)
	@cd $(REPO_ROOT) && cargo test -p sphincs-c10 --features sim-internals --test primitive_kat --release
	@python3 scripts/independent_c10_signer.py --check-primitives $(REPO_ROOT)/contracts/smart-wallet/test/c10_primitive_kat_vectors.json
	@cd $(REPO_ROOT)/contracts/smart-wallet && forge test --match-contract C10PrimitiveKat

# NIST CAVP SHA-256 conformance: regenerate the embedded vector module from
# the official byte-oriented .rsp suite (cavp/ — idempotent) and replay ALL
# ShortMsg + LongMsg vectors plus the full SHAVS Monte Carlo procedure
# through the executable FIPS 180-4 spec (Spec/Sha256Impl.lean). Compiled
# IO-level comparison; non-zero exit on any mismatch so CI can gate.
verify-cavp: ## NIST CAVP SHA-256 conformance over the FIPS spec
	@python3 scripts/gen_cavp_vectors.py
	@cd $(LEAN_DIR) && $(LAKE) exe verify-cavp

verify-build: ## lake build SphincsCVerify (the kernel gate)
	@cd $(LEAN_DIR) && $(LAKE) build

verify-audit: ## no-sorryAx + #print-axioms closure dump
	@echo "=== Build + capture compiler 'declaration uses sorry' warnings (P8: authoritative sorry gate) ==="
	@cd $(LEAN_DIR) && $(LAKE) build 2>&1 | tee /tmp/pq_audit_build.out
	@if grep -E "declaration uses 'sorry'" /tmp/pq_audit_build.out; then \
	  echo "FAIL: a SphincsCVerify declaration uses 'sorry' (incomplete proof — the compiler caught it regardless of source position)"; exit 1; fi
	@echo ""
	@echo "=== Pending sorry tactics (textual belt-and-braces) ==="
	@cd $(LEAN_DIR) && $(LAKE) env lean --run scripts/check_no_sorry.lean
	@echo ""
	@echo "=== Axiom dependency of headline theorems (P8: fail on sorryAx / elaboration error) ==="
	@cd $(LEAN_DIR) && $(LAKE) env lean scripts/dump_axioms.lean > /tmp/pq_audit_axioms.out 2>&1; \
	  status=$$?; cat /tmp/pq_audit_axioms.out; \
	  if [ $$status -ne 0 ]; then echo "FAIL: dump_axioms.lean elaboration error (a pinned theorem may be renamed/missing — the dump no longer covers the headline closure)"; exit 1; fi
	@if grep -q sorryAx /tmp/pq_audit_axioms.out; then \
	  echo "FAIL: sorryAx in a headline/corollary axiom closure — a proof is incomplete"; exit 1; fi
	@echo "OK: build emitted no 'uses sorry' warning and no headline/corollary closure contains sorryAx."

verify-three-claims: ## The three security-claim summary
	@bash scripts/verify-three-claims.sh

verify-exec-gate: ## Claim-4 trace gate closure (kernel-only)
	@echo "=== Building TxFlow + Spec.Theorems (Claim 4 dep closure) ==="
	@cd $(LEAN_DIR) && $(LAKE) build SphincsCVerify.Wallet.TxFlow SphincsCVerify.Spec.Theorems
	@echo ""
	@echo "=== Axiom closure for Claim 4 theorems ==="
	@echo "Expected closure: { propext, Classical.choice, Quot.sound } (kernel-only)"
	@echo ""
	@cd $(LEAN_DIR) && $(LAKE) env lean scripts/dump_axioms_claim4.lean > /tmp/pq_claim4_axioms.out 2>&1; \
	  status=$$?; cat /tmp/pq_claim4_axioms.out; \
	  if [ $$status -ne 0 ]; then echo "FAIL: Claim-4 axiom dump elaboration error"; exit 1; fi
	@# P8: actually ENFORCE kernel-only (was print-only). Fail on sorryAx or any
	@# non-kernel axiom (bridge/crypto) entering a Claim-4 closure — e.g. if the
	@# trace gate were ever pinned to the deployed verifier (which would pull in
	@# A1/A3.1/A4 and is the P13 over-claim this gate now catches). The python
	@# helper flattens `#print axioms`'s wrapped output before parsing.
	@python3 scripts/check_axiom_closure.py /tmp/pq_claim4_axioms.out

verify-bytecode-setup: ## One-time Halmos setup
	@bash halmos/setup_halmos.sh

# Bytecode-level discharge of the A3.* bridge axioms: certifies the
# compiled runtime codehashes match PINNED_CODEHASHES.md (BOTH the default
# runs=200 and deploy runs=999999 profiles) + the immutable-window lemma,
# then symbolically executes the deployed PQSmartWallet / factory / verifier
# bytecode with the patched Halmos — including the full pointwise-equivalence
# session for A3.2. Run `make verify-bytecode-setup` once first.
# Set PQ1_HALMOS_BOTH_PROFILES=1 to also re-run the symbolic suite under the
# deploy profile.
verify-bytecode: ## Halmos bytecode-level A3.* discharge (heavy)
	@bash halmos/run_halmos.sh

verify-clean: ## rm -rf .lake build
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

.PHONY: verify-extracted verify-extract-differential extract-sphincs-adrs extract-aa-userop extract-fors-index extract-format-decimal

# roadmap T1.3 (ii) — extracted-Lean vs shipped-Rust DIFFERENTIAL gate.
# The `extract-*` regen-diff targets catch a Rust change that was not re-extracted;
# they do NOT catch a CONSISTENTLY-WRONG Charon/Aeneas translation. This gate
# EXECUTES the extracted Lean functions on vectors whose EXPECTED outputs were
# produced by running the SHIPPED Rust (`fw-manifest/tests/gen_extract_vectors.rs`)
# and fails on any divergence. Includes a permanent negative control. CORPUS
# evidence (tier C) — shrinks the Charon faithfulness TCB on tested inputs, not a ∀.
#   make verify-extract-differential          replay committed (Rust-generated) vectors
#   make verify-extract-differential GEN=1    re-execute the Rust to regenerate them
verify-extract-differential: ## Extracted-Lean vs shipped-Rust differential
ifeq ($(GEN),1)
	@echo "=== regenerating EXPECTED outputs from the SHIPPED Rust (ground truth) ==="
	@cd $(REPO_ROOT) && cargo test -p fw-manifest --test gen_extract_vectors --release -- --nocapture 2>&1 \
	  | grep -E 'gen_extract_vectors:|test result'
endif
	@cd $(EXTRACTED_DIR) && $(LAKE) build Extracted.ExtractDiffVectors 2>&1 | tail -1
	@cd $(EXTRACTED_DIR) && $(LAKE) env lean Extracted/ExtractDiffCheck.lean

verify-extracted: ## S33 Aeneas-extracted build + axiom-discipline
	@cd $(EXTRACTED_DIR) && $(LAKE) build 2>&1 | tee /tmp/pq_extracted_build.out
	@if grep -E "Extracted/[^ ]*\.lean:.*declaration uses" /tmp/pq_extracted_build.out; then \
	  echo "FAIL: an Extracted/ declaration uses 'sorry' (incomplete proof)"; exit 1; fi
	@echo "=== Axiom closure of the §33 theorems (expect propext, Classical.choice, Quot.sound + the three disclosed hash-boundary postulates: keccak256_pure, sha256_pure_bytes, hmac_sha512_pure_bytes — NB sha256_pure is a kernel THEOREM, not an axiom) ==="
	@cd $(EXTRACTED_DIR) && $(LAKE) env lean Extracted/AxiomCheck.lean 2>&1 | tee /tmp/pq_axiomcheck.out
	@if grep -q sorryAx /tmp/pq_axiomcheck.out; then \
	  echo "FAIL: a §33 theorem axiom closure contains sorryAx — a proof is incomplete"; exit 1; \
	else echo "OK: extracted/ axiom-discipline gate passed — no sorryAx in any §33 theorem closure"; fi

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

# §33 P1 — guard that the vendored copies in extracted/Extracted/ stay
# faithful to the SphincsCVerify sources they vendor (the version bridge's
# trust rests on the verbatim transcription). Compares the named ByteVec/Adrs
# definitions (SpecVendored.lean) and the FIPS 180-4 SHA-256 definitions
# (Sha256Vendored.lean, source Spec/Sha256Impl.lean).
.PHONY: verify-spec-vendored-fidelity
verify-spec-vendored-fidelity: ## Vendored-spec fidelity check
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

# §33 — U256::format_decimal (via the u256_format_decimal wrapper; the four
# fmt_* phase helpers exist BECAUSE the fused body hits an aeneas
# `Unimplemented` — see the note inside format_decimal). The Types.lean dedup:
# this extraction re-defines eip1559.U256, whose canonical home is
# Extracted/U256Mul/Types.lean, so only Funs.lean is committed and its Types
# import is rewritten to the canonical module (a duplicate def fails the lake
# build LOUDLY — 'environment already contains ...' — so the dedup cannot
# silently drift).
.PHONY: extract-format-decimal
extract-format-decimal:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/tx-core && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque sha3 \
	  --start-from 'pqsigner_tx_core::eip1559::u256_format_decimal' \
	  --dest-file /tmp/pqsigner-extract/fmtdec.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/fdout && mkdir -p /tmp/pqsigner-extract/fdout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/fdout -split-files /tmp/pqsigner-extract/fmtdec.llbc
	@sed -e 's/^import Fmtdec.Types$$/import Extracted.U256Mul.Types -- canonical eip1559.U256 home (dedup: both extractions define it)/' \
	     -e 's/import Fmtdec\./import Extracted.FormatDecimal./' \
	     /tmp/pqsigner-extract/fdout/Funs.lean > /tmp/pqsigner-extract/fdout/Funs.fixed.lean
	@diff -u $(EXTRACTED_DIR)/Extracted/FormatDecimal/Funs.lean /tmp/pqsigner-extract/fdout/Funs.fixed.lean \
	  && echo "OK: committed format-decimal extraction matches the current Rust" \
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
	  --kill 'sphincs_c10::hash::pad16' --kill 'sphincs_c10::params::N' \
	  --add-import Extracted.Adrs --add-import Extracted.Fors.Funs \
	  --add-import Extracted.Hash.Funs
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

# §33 axiom-collapse — the five sphincs-c10 tweakable-hash primitives with
# sha256_bytes as the SINGLE opaque boundary (FunsExternal wires it to the
# vendored FIPS 180-4 sha256_pure). chain_hash extracts its real loop (calls
# th); th/th_pair/th_multi/wots_digest expose their exact preimage assembly.
.PHONY: extract-hash-fns
extract-hash-fns:
	@mkdir -p /tmp/pqsigner-extract
	@cd $(REPO_ROOT)/sphincs-c10 && RUSTFLAGS="--cfg lean_extract" \
	  $(PQLEAN)/charon cargo --preset=aeneas --opaque sha2 --opaque zeroize \
	  --opaque 'sphincs_c10::hash::sha256_bytes' \
	  --start-from 'sphincs_c10::hash::th' \
	  --start-from 'sphincs_c10::hash::th_pair' \
	  --start-from 'sphincs_c10::hash::th_multi' \
	  --start-from 'sphincs_c10::hash::chain_hash' \
	  --start-from 'sphincs_c10::hash::wots_digest' \
	  --dest-file /tmp/pqsigner-extract/hashfns.llbc 2>&1 | tail -1
	@rm -rf /tmp/pqsigner-extract/hout && mkdir -p /tmp/pqsigner-extract/hout
	@$(PQLEAN)/aeneas -backend lean -dest /tmp/pqsigner-extract/hout -split-files /tmp/pqsigner-extract/hashfns.llbc
	@python3 scripts/dedup_extraction.py /tmp/pqsigner-extract/hout/Funs.lean /tmp/pqsigner-extract/hout/Funs.fixed.lean \
	  --sed-import 'Hashfns.=Extracted.Hash.'
	@diff -u $(EXTRACTED_DIR)/Extracted/Hash/Funs.lean /tmp/pqsigner-extract/hout/Funs.fixed.lean \
	  && echo "OK: committed hash-fns extraction matches the current Rust" \
	  || { echo "DRIFT: sphincs-c10/src/hash.rs changed — re-extract, re-prove, re-commit"; exit 1; }
