# Trezor-parity sweep 2026-07-20 — findings index

Adversarial comparison of PQSigner OS (`master`) against trezor-firmware
(`3db63dfecb`), four parallel lanes: testing infrastructure, user-facing/clear-signing
features, low-level security engineering, and a prior-art dedup digest over the
existing comparison docs (`docs/architecture/trezor-comparison.md`,
`trezor-comparison-critical-port-2026-06.md`, research bundles) and the tracker.
Every PQ1-side "absent" claim was verified against source, not docs.

**Headline:** PQ1 is at parity or ahead on most classic Trezor hardening (FI
stack, masked SHA-2, dual-SE PIN custody, curated ERC-7730 clear signing,
reproducible builds + SBOM + cargo-vet — Trezor has no SBOM/vet at all). The
real gaps are **test orchestration** (host-driven e2e, HW CI, coverage) plus a
handful of trusted-UI items. Strongest single finding: **#472** — the device
never shows the receive address, and the companion doc falsely claims it does.

## New issues (18)

High:
- #472 — TZP-1: `GET_WALLET_ADDRESS` never renders the address on-device; companion doc promises it does. Fix doc now, add optional display flag.
- #476 — TZP-5: no host-driven device-test harness (Trezor debuglink analog); e2e is one auto-confirmed QEMU boot. First consumer: #421.
- #477 — TZP-6: no hardware-in-the-loop nightly CI; all `*-hw` targets are manual bench. Slices already banked: #402, #390, #375.

Medium:
- #473 — TZP-2: UserOp signing pages omit signer identity (Acct/Slot); off-chain pages already have the pattern.
- #478 — TZP-7: no line-coverage measurement anywhere (`cargo llvm-cov` + ratcheting CI threshold).
- #479 — TZP-8: no host-side behavioral OPTIGA/SE050 model (Trezor `tropic_model` analog); SCP03/T=1' integration never runs off-bench. Serves #419, #394.
- #480 — TZP-9: no old→new firmware upgrade e2e with archived prior-release images (pre-ship, so medium).
- #481 — TZP-10: prodtest build + factory-runner tests run in no CI job (factory image can bit-rot). Under the #456 umbrella.
- #484 — TZP-13: no user-visible fatal-security-state screen (Trezor RSOD); panic/FI halt is a silent WFI.
- #485 — TZP-14: no never-reset OPTIGA lifetime operation counter on the main auth path; provision E122 inside the #443 ceremony work.

Low:
- #474 — TZP-3: frame `approve(spender, 0)` as "Revoke".
- #475 — TZP-4: configurable idle-wipe delay (only if a settings surface lands).
- #482 — TZP-11: secure-slot image-capacity gate (fwmeasure) not in CI.
- #483 — TZP-12: publish the runnable QEMU artifact for companion developers.
- #486 — TZP-15: vendor signing-key compromise recovery undocumented (decline Trezor's m-of-n; write the design note).
- #487 — TZP-16: no hw-model byte in the signed preimage (add only when a second board exists).
- #488 — TZP-17: page-position counter on multi-page confirms (`td-3`, prior-pass residual never banked).
- #489 — TZP-18: scrub R0–R12 before the FSBL→firmware jump (April-2026 §8.3 residual never banked).

## Already covered — deliberately not re-filed

- Device attestation (host challenge-response, cert chains, factory manifest): #249, #245, #244, #210.
- Factory SE-genuineness gate: #272.
- `personal_sign` non-injective rendering (`?`-substitution): #154.
- On-device backup re-verification ("Check backup"): #250 (with §32-safe constraints).
- June-2026 critical-port backlog (SAU/RCC/OPTR, IWDG, golden tests, reseed, BHK marker, SEC counter, addr chunking): #366, #278.
- ClusterFuzzLite CI, ui-capture golden gates, security-review Action: #309. Three-tier key hierarchy: #202.
- Consent-proof lane (#421), FW-path host e2e (#167), scenario-fn extraction (#82), blob-format versioning (#243).

## Declined with reason (do not resurface)

Passphrase hidden wallets (breaks CREATE2 same-address invariant #6; duress decoy covers coercion) · SLIP-39 · wipe code · FIDO2/U2F (invariant #5, no PQ WebAuthn) · safety-checks strict/prompt knob (PQ1's fail-closed filter *is* the policy) · SLIP-24 payment requests (trusted display obviates) · bespoke staking renderers (subsumed by the ERC-7730 programme) · wycheproof classical vectors (no classical crypto) · ASAN/valgrind C matrix (Miri + fuzz-ASAN instead) · i18n test matrix (no i18n) · THP/Noise host channel · secmon port · Trezor m-of-n vendor committee → design note instead (#486) · Merkle chunked image verification (stage-then-verify is sound for internal-flash A/B) · OTP monoctr (illegal QW reprogram; Draft 1.1 owns rollback) · Trezor build ceremony (PQ1's repro + SBOM + vet is strictly stronger).

## Not filed (too micro / record-only)

`ctr+1==ctr_ck` pre-commit micro-assert (optional P3) · diversifier doc comments (15-min) · C-1 MPU-lite intra-S privilege split: prior pass already decided "deferred-with-rationale, record it" — the June doc is the record.

Method honesty: findings came from source-verified sub-agent lanes; no hardware,
QEMU, or CI job was run for this sweep. Issue bodies carry the file:line evidence.

## Corrections (2026-07-20, discovered while planning fixes)

- **#473 withdrawn** — signer identity was already implemented and FI-enforced
  on every sign path (`build_signer_identity_page`, value_page.rs:139-157;
  wired in cmd_sign_userop{,_batch}.rs). The lane checked only the leaf
  renderers, not the dispatcher splicing. Closed with evidence.
- **#474 rescoped** — the known-token path already paints `Revoke approval`
  (primitives.rs:953-956); only the unknown-token path lacked it. Fixed in
  the S1 batch.
- First fix batch (S1–S4) tracks: #472, #474, #488 (firmware UI), #484, #489
  (resilience), #478, #481, #482, #483 + qemu-e2e timeout (CI), #486 (design
  note, `docs/security/vendor-signing-key-compromise.md`). Deferred by design:
  #475, #485, #487, and the infrastructure projects #476, #477, #479, #480.
