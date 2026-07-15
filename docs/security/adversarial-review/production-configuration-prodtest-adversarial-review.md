# Production configuration, prodtest, and assurance-fidelity adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for attacking
PQSigner's resolved program configuration: Cargo features and unification,
target/profile/cfg/environment axes, paired secure/non-secure/FSBL builds,
compile fences and CI enrollment, factory prodtest commands/fixture semantics,
and the correspondence between a reviewed feature list and the exact ELF that
would be presented to a release pipeline. This surface asks whether the tested
program is the program the project believes it is testing.

> **Target claim.** A candidate production artifact is built from one
> machine-readable, reviewed configuration; includes every required hardening
> control; excludes every development, mock, diagnostic, factory, and
> irreversible-test path; uses compatible S/NS/FSBL interfaces; and carries a
> receipt proving its resolved features, target, profile, environment inputs,
> and relevant symbols. Factory prodtest runs only in an evidenced fresh-device
> lifecycle and reports PASS only for checks that actually executed.

> **Current posture (2026-07-14).** Production image/release paths are
> intentionally quarantined independently by the unimplemented rollback
> architecture and by the `prod-erc7730-provenance-check` refusal for the
> current `dev-unattested` catalogue. The
> current canonical feature list is therefore a policy target, not shipping
> evidence. `bhk` and `rdp2-self-lock` are now present in
> `PROD_SHIP_FEATURES`, and the device-side first-boot candidate is implemented,
> but this grants no execution or shipment authority: authenticated per-unit
> handoff, recovery/KVN semantics, E140 ordering, and silicon evidence remain
> open. Do not exercise the irreversible path on unprepared hardware.

**Sibling boundaries.** The [build/release playbook](./build-release-provenance-adversarial-review.md)
owns source-to-artifact provenance, signing custody, and publication; the
[silicon-lockdown playbook](./silicon-lockdown-adversarial-review.md) owns
physical option-byte/LcsO state; the
[lifecycle playbook](./lifecycle-persistent-state-adversarial-review.md) owns
fresh-device/prodtest/provisioning transitions; and the [FV playbook](../../verification/fv-adversarial-review-playbook.md)
owns generic proof/gate vacuity. **This playbook owns the selected program,
paired configuration, prodtest truthfulness, and evidence-to-artifact parity.**

---

## Part A — The production-configuration failure catalog (PC1–PC12)

| # | Failure mode | What to try to prove | Status / anchor in this tree | Detection | Auto? |
|---|---|---|---|---|---|
| PC1 | **Canonical profile omits required hardening** | Removing a required control still passes all production gates or compiles the protected path out | **PARTIAL.** `PROD_REQUIRED` and compile fences cover major controls, but the set is manually maintained and the eventual BHK/first-boot profile is unresolved. | Remove each claimed requirement; require exact gate failure and negative ELF evidence | ✅ matrix |
| PC2 | **Forbidden/dev/factory feature resolves active** | Direct flag, alias, dependency, or Cargo feature unification activates a mock, test key, debug, recovery, prodtest, or irreversible path | **REMEDIATED IN SOFTWARE POLICY; KEEP AS REGRESSION LENS.** `PROD_FORBIDDEN` is command-line-override-resistant and includes the direct persistent/destructive harness activators; `secure/src/nsc/mod.rs` independently rejects them with `mode-production`. Mutation tests exercise both policy layers. This does not authorize any factory or hardware action. | Add every forbidden leaf/activator and attempt empty/forged Make overrides; inspect normalized resolved features | ✅ matrix |
| PC3 | **Zero/multiple choices on an exact-one axis** | No or conflicting platform, top-level SE selector, UI, or mode choice compiles into an unintended hybrid | **PARTIAL.** The Cargo manifest declares exact-one platform, secure-element, UI, and mode axes; accelerators explicitly compose. The SE axis must allow one top-level `secure-element-dual`/`dual-se` selector to resolve both component leaves. Root and transport are composable/policy-controlled rather than declared exact-one axes; future production can legitimately compose DHUK+BHK. | Zero/pairwise matrix for declared axes; explicit policy tests for roots/transports; resolved-feature and implementation evidence | ✅ matrix |
| PC4 | **Secure/non-secure/FSBL configuration or ABI mismatch** | Worlds disagree on veneers, watchdog, prodtest, transport, slot/manifest contract, UI, or shared constants yet link/boot | **PARTIAL.** Separate recipes mirror some features manually; no single paired-config/ABI receipt was identified. | Cross-product builds + imports/exports/shared-constant comparison | ✅ link/audit |
| PC5 | **Target/profile/cfg/env/RUSTFLAGS/build-script escape** | Same nominal feature list has different security behavior under accepted target, profile, `cfg(test)`, debug assertions, environment, linker, or custom flags | **PARTIAL.** Many recipes use `--locked`, `--no-default-features`, release, and build-script checks, but not uniformly; target/test arms materially differ. | Configuration-differential build and symbol/behavior comparison | ✅ build matrix |
| PC6 | **PIN-less factory/prodtest surface in production** | `nsc_prodtest_*` veneers or prodtest APDU routes compile/link with `mode-production` or a candidate shipping profile | **COMPILE- AND POLICY-FENCED.** Prodtest is deliberately PIN-less. `secure/src/nsc/mod.rs` rejects `prodtest` with `mode-production`, persistent roots/actions, factory ceremony, RDP shipping, or an unqualified root; `PROD_FORBIDDEN` independently includes prodtest/factory/destructive activators and cannot be emptied from the Make command line. | Require S production+prodtest to fail for the dedicated fence, verify NS/S pairing cannot hide the route, and mutate both fence and resolved-feature policy | ✅ compile/link |
| PC7 | **Diagnostic oracle, identifier leak, destructive range, or lifecycle misuse** | UID, TRNG samples, DHUK/BHK fingerprints, SE handshakes, flash test, or fixture state is reachable after user secrets exist or outside a controlled station | **BY DESIGN, CONFINEMENT-CRITICAL.** Outputs are intentional factory diagnostics, not automatically secret leaks. The fresh-device/lifecycle and data-retention claims require evidence. | Model lifecycle reachability first; hardware only on an explicitly authorized sacrificial unit using dummy lifecycle state—never a user/provisioned production unit; validate fixed ranges and retention policy | ⚠ process/HW |
| PC8 | **Stub/compiled-out case reported as assurance** | Fixture or CI reports all-pass while required command is `InternalError`, skipped invisibly, or absent from the built image | **REMEDIATED; KEEP AS REGRESSION LENS.** The exact reversible profile includes `saes-dhuk`. BHK and FLASH remain deliberately unsupported negative-capability probes and must appear as visible `SKIP_UNSUPPORTED` with `passed=false`; any unexpected success or other response fails the profile. The receipt's feature list is host-required policy, not device-attested identity. | Exact safe-profile build plus transport-mocked full run; mutate every unsupported response and receipt field | ✅ host |
| PC9 | **Fixture/protocol/docs drift makes a check impossible or different** | Required vector cannot be encoded, response cap differs, or skip/fail policy and hardware/UI names disagree | **REMEDIATED; KEEP AS REGRESSION LENS.** Payload limits, LCD terminology, explicit unsupported outcomes, and the runner/firmware protocol agree. Firmware version 3 binds the dedicated prodtest-only plaintext OPTIGA liveness probe; GET_ID/version failure stops the sequence before any later command. | Boundary tests + full-run/report-write assertions + version-mismatch fail-fast + docs/runner/firmware differential | ✅ host |
| PC10 | **Mock/QEMU/host result substituted for target behavior** | A mock SE/UI/mailbox or `cfg(test)` pass is cited for CMSE, real peripherals, production randomness, linker, or target-only code | **OPEN/PARTIAL.** Host/QEMU coverage is useful; nightly ARM checks compile a hardened bench shape and do not execute real target behavior. | Executed-vs-claimed matrix with exact cfg parity; target differential | ✅ audit + ⚠ HW |
| PC11 | **Gate unenrolled, non-blocking, path-incomplete, or wrong-graph** | A config-relevant change avoids its gate, expected failure is accepted for the wrong reason, or CI green does not block the relevant decision | **PARTIAL.** `verify-gate-enforcement` and negative CI exist; every Cargo/build.rs/Make/prodtest/runner/workflow path class still needs mutation-based enrollment review. | Mutate each path/argument/expected error; require relevant blocking failure | ✅ meta-test |
| PC12 | **Exact artifact does not match reviewed resolved config** | ELF contains prodtest/dev/test-key/debug behavior, lacks required hardening, or S/NS/FSBL hashes and receipts describe different builds/stale outputs | **OPEN until an exact candidate is linkable.** A feature-policy pass is not binary-content evidence, and current release quarantine intentionally emits no production artifact. Named symbols/strings may be stripped or inlined, so their absence is not proof of exclusion and their presence is not proof of enforcement. | Bind resolved cfg plus a retained machine-readable config marker/link map and disassembly/reachability evidence to artifact digests; use nm/strings only as supporting evidence | ✅ artifact audit |

**Catalog rule.** Treat `RELEASE_FEATURES`, `PROD_SHIP_FEATURES`, Cargo's
resolved graph, and final ELF content as four distinct layers. A matching CLI
string does not prove the resolved graph; a matching graph does not prove the
packaged artifact. Likewise, a factory test that returns “unsupported” is
neither PASS nor a hardware failure—it must be an explicit, policy-approved
SKIP tied to the artifact's feature receipt.

---

## Part B — The existing defenses (Layer 1)

1. **Feature fence wall.** Secure crates use few/no implicit defaults and many
   `compile_error!` combinations for production, SE, UI, root, recovery, and
   test features. Review predicates and aliases, not just message strings.
2. **Resolved production policy.** `PROD_SHIP_FEATURES`, `PROD_REQUIRED`,
   `PROD_FORBIDDEN`, and `prod-feature-check` inspect Cargo's resolved secure
   feature set. Negative mutation must establish list completeness.
3. **Production quarantine.** `prod-check-ship`, release targets, FSBL build
   guards, rollback fence tests, and the independent
   `prod-erc7730-provenance-check` refusal must each fail for its exact
   documented reason. Current successful production output is an adverse
   result, not progress.
4. **Gate enforcement.** `scripts/gate_enforcement.json`, its checker/self-test,
   CI negative builds, and nightly ARM checks defend against some path and
   argument drift. Confirm enrollment for new configuration inputs.
5. **Prodtest separation mechanics.** Stable command/INS IDs, S and NS feature
   gates, pointer validation, and `InternalError` for missing local support
   avoid false local success. They do not close PC6, PC8, or PC9.
6. **Locks and build-script checks.** Cargo locks, vendor-key snapshots,
   environment checks, isolated target dirs, and explicit feature recipes are
   useful inputs to an exact configuration receipt.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS production configuration,
prodtest, and assurance fidelity. Break the mapping from intended policy -> resolved Cargo
graph -> paired S/NS/FSBL binaries -> executed test evidence. Do not flash, probe, run a
factory fixture, or execute irreversible commands without separate explicit authorization.

TARGET (read first, in this order):
  - docs/security/adversarial-review/production-configuration-prodtest-adversarial-review.md
    §A — PC1–PC12.
  - Makefile strings RELEASE_FEATURES / PROD_SHIP_FEATURES / PROD_REQUIRED /
    PROD_FORBIDDEN / prod-feature-check / prod-check-ship /
    prod-erc7730-provenance-check / build-hw-prodtest.
  - secure/Cargo.toml, nonsecure/Cargo.toml, fsbl/Cargo.toml, workspace Cargo files/lock,
    all build.rs files, linker scripts, and target/config files.
  - secure/src/nsc/{mod,prodtest}.rs, nonsecure/src/usb/commands.rs,
    tools/factory-prodtest-runner.py, docs/provisioning/factory-prodtest.md.
  - secure/src/main.rs, nonsecure/src/{main,nsc_api}.rs, and proto/src/lib.rs —
    early-boot/prodtest routing, watchdog lifecycle, veneers, and canonical wire IDs.
  - .github/workflows/, scripts/gate_enforcement.json, and its checker/self-test.
SCOPE THIS RUN: {{feature axis, paired build, prodtest command/fixture, gate, or artifact}}.

ATTACK PROTOCOL — walk EVERY PC1–PC12 mode:
  PC1 missing required · PC2 forbidden/transitive · PC3 exact-one axes · PC4 S/NS/FSBL
  mismatch · PC5 target/profile/env escape · PC6 PIN-less prodtest shipping · PC7 diagnostic
  confinement · PC8 stub false-pass · PC9 fixture/docs drift · PC10 mock substitution ·
  PC11 gate enrollment/vacuity · PC12 artifact/config mismatch.

CAPTURE FIRST: commit + dirty state, Cargo.lock digest, rustc/cargo, target/profile,
RUSTFLAGS/linker/build env, exact feature lists for S/NS/FSBL, normalized resolved graphs,
and artifact digests. Never infer resolved features from a Make variable alone.

REQUIRED MUTATION MATRIX:
  - remove every required feature and demand failure;
  - add every forbidden feature AND transitive alias, explicitly including prodtest,
    factory-provisioning, factory-provisioning-rehearsal, and irreversible factory flags;
  - try zero and multiple choices for the declared platform/top-level-SE/UI/mode axes;
    test root and transport composition against their explicit owner policy instead of
    inventing an exact-one rule;
  - mismatch S/NS/FSBL watchdog, prodtest, transport, veneer, and manifest expectations;
  - vary test/release profile, target, relevant environment/build flags;
  - mutate each config-relevant path class and require the enrolled blocking gate.
Use isolated target directories so stale artifacts cannot satisfy the test.

PRODTEST HOST CHECKS:
  Transport-mock every command and `run_all_tests`: supported pass, explicit skip,
  failure, malformed/short/oversized response, timeout, and lengths 254/255/256.
  Compare build-hw-prodtest's resolved features to each command's requirements. Require a
  machine-readable receipt of artifact hash, features, executed cases, approved skips, and
  result. A stub/unsupported response cannot count as pass.

ARTIFACT CHECKS (when exact linked ELFs exist):
  Scan secure AND nonsecure plus FSBL imports/exports/maps with nm/objdump/readelf/strings.
  Negative examples: nsc_prodtest_*, INS_V2_PRODTEST_*, test PIN routes, mock/test keys,
  debug/semihosting/recovery symbols. Positive examples: every claimed hardening control.
  Bind resolved cfg, a retained machine-readable config marker/link map, and disassembly or
  reachability evidence to digests. Raw symbol/string scans are supporting evidence only:
  absence may mean stripping/inlining, and presence does not prove enforcement. A
  cargo-check-only result is not linked-artifact evidence.

For each finding produce a FALSIFIABLE PoC: an accepted forbidden graph, accepted missing
requirement, exact-one hybrid, mismatched pair, production ELF with a PIN-less route, runner
false-pass/impossible vector, path mutation evading a blocking gate, or artifact/receipt
mismatch. No PoC => “suspicion, unverified.”

RULES:
  - Current production/release targets SHOULD refuse. Require `prod-check-ship` and
    `prod-erc7730-provenance-check` to fail for their own exact documented reasons; do not
    collapse independent blockers or call expected refusal release readiness. Vendor-key
    policy and `release-pubkey-check` enrollment belong to the build/release playbook.
  - Keep prodtest diagnostic exposure separate from secret leakage. Show lifecycle/policy
    violation and data impact.
  - Cross-link build provenance/custody, physical lockdown, and lifecycle findings to their
    owner playbooks; this report owns configuration and assurance parity.
  - Cite unique feature/gate/symbol strings and paths, not line numbers alone.

FIRST-PASS OUTPUT — use the raw-report schema in
docs/planning-and-review-workflow.md §8; do not use the post-cross canonical
docs/security/adversarial-review/findings/TEMPLATE.md:
  Return production-configuration-prodtest-<YYYY-MM-DD>-<partner-or-run>.md in external/isolated scratch output;
  do not edit the frozen repository or findings index. After both first passes and
  both cross-reviews freeze, an authorized maintainer may archive byte-for-byte
  copies in a separate reporting commit; only the frozen cross matrix feeds the
  canonical findings catalogue. Each candidate needs PC-mode, exact
  config/graph/artifact, falsifiable PoC, severity, proposed minimal correction, and
  evidence-level label. First-pass discovery must not assign canonical disposition or
  finding Status; the required exact partner pair does that only through symmetric
  cross-adjudication.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. What I tried to break and COULDN'T — strongest feature/pair/runner/gate mutation.
  2. What I did NOT inspect — axes, env inputs, paths, linked artifacts, fixture, hardware.
  3. PROVENANCE — source/host/mock/QEMU/ARM-check/ARM-link/authorized-silicon table with
     exact feature/profile parity and explicit skips.
  Never label a mock execution, target check, or expected refusal as production execution.
```

**Running it as a swarm.** Use independent reviewers for Cargo feature
unification/axes, S/NS/FSBL ABI and artifact content, prodtest fixture semantics,
and CI/gate enrollment; reproduce each finding in a clean target directory from
the captured configuration. These are supplemental lanes: apply the exact
dual-partner, mutually withheld first-pass, and symmetric cross-adjudication
procedure in
[`docs/planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
swarm quorum never replaces either required partner or resolves its blocker.

---

## Part D — Cadence + honest boundary

- **Per-PR touching Cargo/build.rs/Make/config/workflow/prodtest:** run the
  relevant mutation slice and update the config-to-artifact receipt schema.
- **Per-milestone:** exercise the full required/forbidden/exact-one matrix,
  paired-build checks, runner mock suite, and gate-enrollment self-tests.
- **Before any release candidate:** link exact S/NS/FSBL artifacts, bind
  normalized graphs and positive/negative symbol evidence to their digests,
  and obtain independent review.
- **Before factory execution:** reconcile prodtest docs/build/runner, authorize
  a fresh sacrificial unit and controlled station, and define output retention.
- **The one-line gut check:** *which exact cfg graph produced this exact binary,
  what proves forbidden routes are absent and required controls present, and
  did every claimed factory check actually execute rather than stub/skip?*

**The boundary, stated on purpose.** This playbook can prove resolved
configuration and exact-binary contents. It cannot prove which bytes were
signed/flashed, release-key custody, physical option-byte state, or hardware
behavior. Prodtest safety also depends on lifecycle evidence that the device is
fresh and that diagnostic state/output is contained. Those are sibling owners,
not assumptions to hide in a green configuration report.
