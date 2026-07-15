# Build, release, provenance, signing-key custody, and distribution adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for attacking the
off-device chain that turns reviewed source into firmware bytes and makes those
bytes available to users: source snapshot identity, generated inputs,
toolchains/dependencies/CI, reproducibility, ELF flattening/measurement,
artifact pairing, firmware signing, vendor-key custody/lifecycle, SBOM and
provenance binding, packaging, publication, transparency, revocation, and
incident response.

> **Target claim.** Every released byte is reproducibly derived from one frozen
> reviewed source/configuration snapshot; the artifact actually signed is the
> artifact actually measured, attested, and published; authorization requires
> the approved production HSM/quorum and policy; no development key or stale
> artifact can substitute; and users can verify artifact/source identity and
> learn about revocation without trusting the same actor that signs releases.

> **Current NO-AUTHORITY posture (2026-07-14).** `make release`, `_release`,
> and `fsbl-release` are refusal-only while the rollback backend is quarantined.
> `config/production-firmware-vendor-key.sha256` is intentionally
> `UNPROVISIONED`. `docs/STATUS.md` tracks the HSM/release-pipeline and
> SLSA/cosign/Rekor gaps; a planned M-of-N shape is sketched in
> `docs/security/threat-model.md` and `docs/security/production-security.md`,
> but its threshold, roles, custody, recovery, audit workflow, and application
> to the firmware-signing key remain open.
> `fwsign sign` emits legacy unsigned-slot `PQFW_V1`, requires an
> explicit bench acknowledgement, and has **no production authority**. A green
> review may prove that these refusals fail closed; it may not conclude
> “release-ready.”

**Sibling boundaries.** The [production-configuration playbook](./production-configuration-prodtest-adversarial-review.md)
owns which program/features the artifact contains; the
[firmware-update playbook](./firmware-update-secure-boot-adversarial-review.md)
owns what the device accepts and boots; the [silicon-lockdown playbook](./silicon-lockdown-adversarial-review.md)
owns the immutable on-device key/option-byte state; and the
[lifecycle playbook](./lifecycle-persistent-state-adversarial-review.md) owns
factory/first-boot device transitions. The
[clear-signing playbook](./clear-signing-adversarial-review.md) owns descriptor
semantics, while this playbook owns the identity and authority of the
ERC-7730 registry snapshot and generated catalogue. **This playbook owns source/config
receipt import, build causality, release authorization, signing custody,
package/publication identity, and distribution recovery.**

---

## Part A — The build/release/provenance failure catalog (BR1–BR12)

| # | Failure mode | What to try to prove | Status / anchor in this tree | Detection | Auto? |
|---|---|---|---|---|---|
| BR1 | **Frozen source identity differs from built/signed bytes** | Dirty/untracked files, submodules, ignored/generated inputs, stale target output, wrong commit/worktree, or TOCTOU changes are included/excluded from the artifact without the receipt showing it | **ACTIVE CLAIM CONFLICT.** `docs/firmware/reproducible-builds.md` says the flake sees only committed state, while `flake.nix` says `builtins.path` uses the actual on-disk tree with a narrow output/noise filter. Until executable negatives settle the real evaluator semantics, neither claim is release evidence. No active end-to-end receipt freezes every included input and signs its identity. | Initial/final snapshot; tracked-dirty, untracked, ignored, generated, and TOCTOU negatives; clean-room rebuild and input manifest | ✅ process/tool |
| BR2 | **Wrong configuration/artifact enters the release chain** | A valid but dev/mock/factory/bench profile, mismatched S/NS/FSBL trio, or artifact from another target directory is signed | **QUARANTINED/PARTIAL.** Production feature gates and config checks exist; no active production packaging path consumes a bound config receipt. | Import config receipt; digest/symbol/profile checks immediately before signing/package | ✅ artifact |
| BR3 | **Toolchain, dependency, action, build script, proc macro, or CI runner substitution** | A compromised/unpinned executable or fetched input changes bytes or steals signing material while locks appear green | **PARTIAL.** Toolchain/flake/lock/action pins, cargo-deny, cargo-vet, and source policy exist. Exemptions, install scripts, imported audits, runners, and build-time code remain trust inputs. | Pin/integrity inventory, dependency diff, sandbox/network log, runner/action permissions review | ✅ audit |
| BR4 | **Reproducibility false-green** | Two builds share a compromised source/tool/veneer/cache/host and match, or the gate exercises a dev profile rather than the release profile | **CONCRETE EVIDENCE TENSION.** `verify-repro` uses the supplied/default `FEATURES` (default dev/QEMU shape), and Nix `#measure` invokes non-shipping `make measure`. Same-host equality proves determinism for that shape, not independent production causality. | Independent environment/builders with exact release receipt; deliberate nondeterminism negative | ✅ build |
| BR5 | **Generated code/database/catalog provenance drift** | ERC-7730 database, Solidity constants, manifests, keys, fonts/assets, or other generated output is stale, built from an unauthenticated corpus, or differs from reviewed source | **MIXED.** `check-codegen`, descriptor/root gates, and Solidity checks exist; production ERC-7730 provenance deliberately refuses, and not every generated input has equal authority. | Regenerate in clean env; compare input/output digests and upstream attestations | ✅ codegen |
| BR6 | **Flattening, measurement, embedded key, slot, manifest, or package mismatch** | Signer hashes different bytes/ranges than FSBL; FSBL and secure embed different keys; post-sign mutation, wrong slot/version, truncation, duplicate archive members, or stale sidecar changes what users/device see | **STRONG LEGACY/BENCH MECHANICS; PRODUCTION A/B OPEN.** `fwmeasure` is shared and strict, final-ELF key checks exist, and fwsign tests cover legacy bundles. Draft 0.9's V4 format is historical; Draft 1.1 proposes V6 but remains a research candidate and is not implementation-approved. There is no approved production A/B artifact. | Adversarial ELF/tar fixtures, independent re-hash/verify, post-sign mutation | ✅ host |
| BR7 | **Signing-key extraction or unauthorized signing** | Laptop/malware/operator/CI compromise obtains or invokes the legitimate key; no quorum/policy distinguishes an authorized release | **PRODUCTION GAP.** Legacy `fwsign` uses a passphrase-encrypted software blob with Argon2id/AEAD and zeroizes decrypted signing-key material, but the passphrase remains an ordinary `String` lifetime residual and the design explicitly excludes malware during signing. Production HSM/M-of-N custody is absent. | HSM policy/quorum negative tests, software-keystore memory-lifetime audit, witnessed ceremony, audit log and role separation | ❌ operational |
| BR8 | **Key loss, reuse, rotation, compromise, or revocation failure** | Lost key strands immutable FSBLs; compromised key authorizes malicious firmware; backup/restore clones authority; rotation cannot reach the fleet | **OPEN ARCHITECTURE/OPERATIONS.** An on-device valid signature cannot distinguish legitimate release from abuse of the real key. No completed fleet key-loss/compromise recovery is identified. | Tabletop + HSM backup/restore/rotation/revocation drills; device acceptance model | ❌ operational/model |
| BR9 | **Signer authorizes wrong release or signing-budget/version policy fails** | Correct key signs wrong commit/profile/slot/version/epoch, replayed approval, or excessive C10 operations; record-only ledger is mistaken for enforcement | **LEGACY BENCH ONLY.** `fwsign`'s ledger is explicitly record-only, V1 slot metadata is unsigned, and production authorization/counter policy is absent. | Two-person approval challenge, manifest/preimage display, duplicate/stale/wrong-profile negatives | ✅ host + ❌ ceremony |
| BR10 | **SBOM/provenance/attestation names a different artifact** | Sidecar is generated after the fact, hashes a stale ELF, omits build inputs, or is swapped independently of package | **PARTIAL MECHANICS, OPEN CAUSAL PROVENANCE.** SBOM hash stamping binds a sidecar to an ELF digest but does not prove that its dependency graph produced that ELF. SLSA/in-toto/cosign/Rekor are open. | Swap/mismatch negatives; in-toto-style causal step chain verified from final package | ✅ host/CI |
| BR11 | **CI/quarantine/expected-failure false-green or artifact poisoning** | Gate is non-blocking/path-incomplete, fails for the wrong reason, untrusted PR writes cache/artifact, or workflow permissions/secrets permit substitution | **PARTIAL, WITH CADENCE CLAIM DRIFT.** Exact-reason quarantines and gate-enforcement tests exist. `docs/firmware/reproducible-builds.md` says `verify-repro` runs per PR, while the live invocation is in scheduled/manual `nightly.yml`; reconcile the promised cadence. Review arguments, triggers, permissions, environments, artifact attestations, and fork/PR trust boundaries. | Mutate error reason/path/argument; hostile PR/cache/artifact simulation in isolated CI | ✅ meta-test |
| BR12 | **Packaging/publication/mirror/transparency/incident failure** | Partial/mixed package publishes, CDN/mirror/feed substitutes/rolls back, release is deleted/replaced, users cannot discover compromise, or fleet scope is unknown | **SAFELY ABSENT, THEREFORE OPEN BEFORE SHIP.** Release targets publish nothing. Atomic publisher, signed index, transparency, mirror policy, fleet inventory, and emergency distribution remain to be designed/tested. | Interrupted publish model, stale/mirror substitution, transparency split-view, incident exercise | ❌ operations + ✅ model |

**Catalog rule.** Reproducibility, authenticity, authorization, and provenance
are different claims. Identical outputs from two compromised builds are
reproducible; they are not trustworthy. A valid firmware signature proves
possession/use of the vendor key; it does not prove quorum approval. An SBOM
containing an artifact hash is bound to that hash; it does not prove the SBOM's
dependency set caused the artifact.

---

## Part B — The existing defenses (Layer 1)

1. **Key-policy and final-artifact checks.** `release-pubkey-check` rejects
   missing, zero, development, malformed, or non-policy keys;
   `release-key-snapshot` creates a read-only hash-checked input; final ELF
   verification can prove FSBL and secure use the same key. The production
   policy is deliberately unprovisioned today.
2. **Configuration and quarantine.** `prod-feature-check`,
   `prod-check-ship`, FSBL rollback fences, ERC-7730 provenance refusal, and
   exact-reason negative tests prevent an accidental current “release.”
3. **Reproducibility/measurement mechanics.** Pinned toolchains/flake/lock,
   remapped paths, isolated `verify-repro` builds, shared `fwmeasure` flattening,
   measurement/FSBL byte-identity tests, and capacity checks are strong local
   components. Apply them to the exact candidate in independent environments.
4. **Dependency/CI controls.** `tools/verify_pins.sh`, cargo-deny,
   cargo-vet/import locks, SHA-pinned actions, workflow permissions, and gate
   enrollment constrain supply-chain drift. Audit exemptions and installers.
5. **Generated-input gates.** `check-codegen`, ERC-7730 descriptor/root checks,
   Solidity constant checks, and `xtask --check`-style generators provide
   reproducible input/output comparisons.
6. **Legacy signer tests.** `fwsign`/`fwmeasure` parser, flattening, bundle,
   key, verification, and negative fixtures are useful attack seeds. They do
   not upgrade V1 or the software keystore into production authority.
7. **SBOM mechanics.** Workspace CycloneDX generation and firmware hash
   stamping support inventory. They are sidecars, not SLSA provenance.
8. **Hard refusal.** `release`, `_release`, and `fsbl-release` publish nothing.
   Under the current architecture, this is the strongest release defense.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS build/release provenance, signing
custody, packaging, and distribution. Break source->config receipt->build->measure->sign->
attest->publish identity and release authorization. Do not access a real production key,
HSM, release service, external package/update/publication registry, Rekor log,
distribution channel, or hardware without separate explicit authority. Read-only
inspection of the named local ERC-7730 sibling checkout is permitted. Use synthetic
keys/artifacts and isolated scratch outputs.

TARGET (read first, in this order):
  - docs/security/adversarial-review/build-release-provenance-adversarial-review.md
    §A — BR1–BR12 and current NO-AUTHORITY posture.
  - Makefile release-pubkey-check / release-key-snapshot / verify-repro /
    prod-check-ship / prod-erc7730-provenance-check / fsbl-release / _release /
    release / check-codegen / vet / sbom*.
  - rust-toolchain.toml, Cargo.lock/manifests, flake.{nix,lock}, build.rs files,
    .cargo/, deny.toml, supply-chain/, scripts/ and .github/workflows/.
  - fwmeasure/ and fwsign/ (especially keystore, artifact_key, sign, bundle,
    verify-release); fw-manifest/, fsbl/build.rs, and secure/build.rs key embedding.
  - dbgen/ and the official sibling clear-signing registry checkout (currently
    /home/nicola/repos/clear-signing-erc7730-registry): pin/revision, authority
    inputs, generated catalogue, and root identity. Descriptor meaning stays with
    the clear-signing playbook.
  - docs/firmware/reproducible-builds.md, docs/STATUS.md,
    docs/security/{threat-model,production-security}.md, docs/production-todo.md,
    and the protected external-release-ledger sections of
    docs/security/a-b-firmware-rollback-architecture.md.
  - production-configuration playbook output for the exact candidate profile.
SCOPE THIS RUN: {{build inputs, reproducibility, signer/custody, package, CI, or publish}}.

REQUIRED LOCAL COMMAND/EVIDENCE MATRIX (run in an isolated scratch copy or with
external target/out-link directories; keep canonical source/index immutable):
  Baseline policy, supply-chain, codegen, and gate enrollment:
    tools/verify_pins.sh
    make invariant-gates
    make vet
    make check-codegen
    make verify-gate-enforcement
    python3 scripts/check_gate_enforcement.py --self-test

  Host mechanics and policy models:
    cargo test --locked --tests -p fwsign -p fwmeasure -p dbgen -p pqsigner-xtask
    make prod-feature-check RELEASE_FEATURES='stm32u585,se050,optiga-trust-m,dual-se,ui-lcd,usb,iwdg,saes-dhuk,se050-derived-scp03,mode-production,optiga-lock-operational,optiga-hw-counter,consumption-mask,tamp,tamp-wipe,tzic-wipe'
    cargo test --locked -p pqsigner-fsbl-tests --test rollback_ship_fences
    cargo test --locked -p pqsigner-fsbl-tests --test erc7730_provenance_fences

  Expected refusals — each MUST fail for its own exact documented reason and
  leave candidate/publication outputs unchanged:
    make prod-check-ship
    make prod-erc7730-provenance-check
    make fsbl-release
    make _release
    make release

  Current non-shipping reproducibility evidence only; record the exact cfg and
  do not present either command as release-candidate evidence:
    make verify-repro
    nix build --no-link .#measure

ATTACK PROTOCOL — walk EVERY BR1–BR12 mode:
  BR1 snapshot drift · BR2 wrong artifact/config · BR3 build supply chain ·
  BR4 reproducibility false-green · BR5 generated inputs · BR6 measure/package mismatch ·
  BR7 unauthorized signing · BR8 key lifecycle/compromise · BR9 wrong authorization/budget ·
  BR10 detached SBOM/provenance · BR11 CI/quarantine poisoning · BR12 publication/incident.

IDENTITY LEDGER FIRST: capture initial commit + dirty/untracked/submodule state; toolchain,
dependency, flake/action/generator inputs; imported configuration receipt; environment and
network policy; every intermediate/final digest; signing authorization; sidecar/package/
publication identifiers; and final snapshot drift. A build_id alone is not this ledger.

SAFE NEGATIVE CONTROLS (scratch/synthetic only):
  - dirty/untracked/generated/stale inputs and a source mutation during build;
  - exact candidate vs default-dev reproducibility and an injected nondeterministic input;
  - altered tool/action/dependency pins or build-script/proc-macro output;
  - swapped FSBL/secure key, wrong S/NS pair, wrong slot/version/commit/config receipt;
  - malformed/overlapping ELF ranges, post-sign byte mutation, duplicate/truncated tar,
    interrupted atomic package, stale output, swapped SBOM/provenance;
  - expected production refusal changed, skipped, non-blocking, or failing for wrong reason;
  - synthetic signer approvals, duplicate/stale authorization, key backup/rotation tabletop;
  - mirror/feed/rollback/transparency/incident simulations without external publication.

For each candidate finding produce a FALSIFIABLE PoC: two different inputs sharing a
receipt, wrong artifact accepted for signing, exact-profile reproducibility failure, a
shared-compromise false-green, key/quorum policy bypass, package/sidecar mismatch that
verifies, wrong-reason quarantine, publication interruption/substitution, or an executable
incident/key-loss contradiction. No PoC => “suspicion, unverified.”

RULES:
  - Every command under EXPECTED REFUSALS MUST fail for its own exact documented reason
    and publish/modify nothing. Unexpected success or stale output mutation is adverse.
  - Never use a real vendor secret in logs/tests/reports. Synthetic fingerprints only.
  - Keep architecture, implementation, merge, and production-shipment verdicts separate.
    A code-ready component is not an authorized release pipeline.
  - Reproducibility evidence must name profile/config, isolation, builders, caches, shared
    inputs, and network. Same-host equality is a narrower claim.
  - Cross-link device acceptance, config content, and silicon/lifecycle findings to siblings.
    This report owns build causality, authorization, package, and distribution.
  - Cite paths + unique target/policy/symbol strings; line numbers alone rot.

FIRST-PASS OUTPUT — use the raw-report schema in
docs/planning-and-review-workflow.md §8; do not use the post-cross canonical
docs/security/adversarial-review/findings/TEMPLATE.md:
  Return build-release-provenance-<YYYY-MM-DD>-<partner-or-run>.md in external/isolated scratch output; do
  not edit the frozen repository or findings index. After both first passes and
  both cross-reviews freeze, an authorized maintainer may archive byte-for-byte
  copies in a separate reporting commit; only the frozen cross matrix feeds the
  canonical findings catalogue. Each candidate needs BR-mode, frozen
  inputs/identities, synthetic PoC, severity, proposed minimal correction, and separate
  architecture/implementation/merge/production-shipment impact. First-pass discovery
  must not assign canonical disposition or finding Status; the required exact partner
  pair does that only through symmetric cross-adjudication.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. What I tried to break and COULDN'T — strongest snapshot/build/sign/package mutation.
  2. What I did NOT inspect — runners, dependencies, HSM operations, mirrors, fleet/incident.
  3. PROVENANCE — commands actually RUN, environments/builders, artifact digests, synthetic
     vs operational evidence, and whether any conclusion is only source review.
  Never claim custody/provenance from an SBOM, signature validity, or reproducible equality.
```

**Running it as a swarm.** Use separate adversaries for build inputs and
reproducibility, dependency/CI supply chain, signing-key custody/authorization,
and package/publication/incident recovery; have one lane trace a synthetic
artifact end-to-end and substitute it at every handoff. These are supplemental
lanes: apply the exact dual-partner, mutually withheld first-pass, and symmetric
cross-adjudication procedure in
[`docs/planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
swarm quorum never replaces either required partner or resolves its blocker.

---

## Part D — Cadence + honest boundary

- **Per-PR touching build/release/generator/dependency/workflow code:** run
  scoped input/provenance negatives and exact-reason quarantine checks.
- **Per-milestone:** rebuild the intended profile in independent clean
  environments, exercise signer/package fixtures with synthetic keys, and run
  CI/gate-enrollment mutations.
- **Before enabling any release path:** complete production key policy and HSM
  ceremony review, exact-profile causal provenance, atomic publishing,
  transparency, rollback/revocation, and incident drills.
- **Per-release after authority exists:** freeze inputs/approval, reproduce
  independently, sign only digest-bound reviewed artifacts, publish atomically,
  verify mirrors/transparency, and archive the witnessed receipt.
- **The one-line gut check:** *can I prove that these exact published bytes came
  from the reviewed snapshot/config and were authorized by the approved quorum,
  rather than merely showing they are reproducible and validly signed?*

**The boundary, stated on purpose.** A green local pass can establish agreement
among reviewed source, profile, toolchain, and synthetic artifacts under the
executed checks. It cannot establish production key custody or causal
provenance. Two compromised builds may be identically reproducible; an SBOM
stamped after a build is not proof it produced it; and a valid device signature
cannot distinguish an authorized release from abuse of the legitimate key.
While quarantine remains active, the strongest valid conclusion is “the
refusal failed closed,” never “release-ready.”
