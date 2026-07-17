Adjudication complete. Final drift receipt clean; both frozen reports unmodified. Writing the cross report.

BEGIN PARTNER A CROSS V1

# PARTNER A — SYMMETRIC CROSS-ADJUDICATION (V1)
## PQ1 ERC-7730 Phase-B architecture · architecture stage only

Not a new first pass, implementation authorization, owner decision, or production recommendation. I did not seek or infer Partner B's cross result. Target and both frozen reports unmodified.

## 1. Runtime and frozen-input receipt

| Property | Value |
|---|---|
| Model / context / effort (self-report) | `claude-opus-4-8[1m]`, ultracode → xhigh — **self-report is not attestation**; I cannot observe launcher args or control-plane routing |
| Permissions | plan/read-only; target recursively non-writable (`test -w .` fails) |
| Partner A V5 | `4b34ae5f1459d2d6dbfe21a1a9019235b74344cb0440aac76551efe6823a884c` — **recomputed, MATCH** |
| Partner B V4 | `bcb8a52e7dba0ecf49e651467615a9c47da2a2a0756563d4362252dde5f1110f` — **recomputed, MATCH** |
| A postlaunch V5 | `b070c733…1a6440c2` — MATCH |
| B postlaunch V4 | `dbcdf3ed…c637cf4d3` — MATCH |
| Executed evidence this leg | One Python recomputation of B's Bloom collision, run in my scratchpad against a **read-only copy of the shipped filter** — disclosed below. No build, no ELF, no hardware. |

**Initial target identity:** HEAD `9647b79374d5e2e10445254492308101b8be708b`; status = the two expected docs only; untracked 0; ignored **files** 0; diff `b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25` (plain and `--binary` identical). MATCH.

## 2. Complete disposition table (24/24 IDs; no ID omitted)

| ID | Origin claim / sev / stage | Disposition | Evidence (reproduced or refuted) | Correction / residual | Stage impact | Owner decision |
|---|---|---|---|---|---|---|
| **PA5-1** | Detected fault inside eligible class / CRIT / arch | **CONFIRMED** | Re-verified `cmd_sign_userop.rs:570-577`; `bind_gate_a/b != OK_SENTINEL → None`. 4 causes → identical `None`. B's AR-001 corroborates the shape; mine names the FI/CFI collapse concretely | Mint eligibility as affirmative sentinel-encoded proof; FI/CFI failures structurally disjoint | **Arch: BLOCKS** | — |
| **PA5-2** | Eligible set contradicts §4 + in-source doctrine / HIGH / arch | **CONFIRMED** | `dispatch.rs:216-221` verbatim; all 3 `RenderErr` arms `return Err(())`; §5 fatal list names "mandatory-page overflow" ≠ `RenderErr::PageBudget`. Exploit stays **unverified** (`MAX_ARRAY_RENDER=8` closes the lever) | Narrow to descriptor-absent/unrooted; or amend the doctrine by recorded decision | **Arch: BLOCKS** | **YES — eligible set** |
| **PA5-3** | Control-flow → data-flow inversion / HIGH / arch | **CONFIRMED** | 5 `return Err(())` sites above `:425` ordinary blind + selector-name. B's AR-005 independently extends with short-`execTransaction` | Direct return at gate site; forced renderer type-level unable to take `SelectorMeta` | **Arch: BLOCKS** | — |
| **PA5-4** | Habituation is a missing device-local control / MED | **NARROWED** | `crypto.rs:84` `pre_sign()` inside signing (confirmed); ordering `:1249`→`:1346`→`:1388` (confirmed). **B's PB-UX-012 counter is good**: a prompt budget itself creates host-driven DoS + new state | The control *exists* but mandating it is an **owner trade-off**, not an obvious fix. I withdraw "fixable → plan's framing incomplete" as overstated | Arch: no block | **YES — budget vs DoS** |
| **PA5-5** | `entry_point` signed, never rendered/pinned / MED | **CONFIRMED** | `snap[32..52]`; `userop.rs:702` `chain_update`; zero hits under `tx/display/`; `ENTRY_POINT_V06` at `userop.rs:619` used **only** under `#[cfg(test)]`(`:941`)/`aa/tests/` | Add to §4 invariant + transcript; pin or record why not | Arch: blocks the transcript claim | — |
| **PA5-6** | "Both consents mandatory" undischargeable / MED | **CONFIRMED** | `confirm.rs:59-65` e2e auto-confirm returns `(Confirmed, OK_SENTINEL)`. Sharper than B's UI3 ("no end-to-end evidence") | Scripted-input consent harness = unnamed prerequisite | Impl/merge gate | — |
| **PA5-7** | Gas idempotence → SIMPLIFY / MED | **CONFIRMED** | Converges exactly with B's AR-006. Both partners independently corrected the *same* discovery-lane provenance error | One owner = handler; delete renderer append | Arch: no block | — |
| **PA5-8** | Drift guard too narrow / MED | **CONFIRMED + STRENGTHENED** | `erc7730-integration.md:35,37,55`. **B's DOC-011 supplies a semantic-drift instance I missed** (NftName opcode), proving the "too narrow" claim | Guard opcode/formatter/semantic policy, not just root/count/size | Arch: no block | — |
| **PA5-9** | Stale-r0 exploit refuted; sentinel redline survives / LOW-MED | **NARROWED** | My refutation stands (intervening calls; B concedes "optimized-ELF exploitability remains unexecuted"). **B adds request-digest binding — a requirement I missed** | Domain-separated + **request-bound** receipts; optimized-ELF | **Severity disagreement preserved** (B: blocks; A: redline) | — |
| **PA5-10** | Unbounded prompts re-open HIGH-13 via button-press timer refresh / MED | **CONFIRMED (uncorroborated)** | `confirm.rs:81-88` vs `:118` `reset_activity()`. **B is silent on this** | Prompt budget must bound timer refresh, or interstitial must not count as activity | Arch: no block | — |
| **PA5-11** | Forced renderer = second decoder (CS9) / LOW | **NARROWED** | Reconciled with B: B KEEPs "separate forced-blind renderer"; B's CS9 row agrees it must be "incapable of generic formatter fallback" | **Both**: separate renderer, **shared primitives**, differential test | Arch: no block | — |
| **PB-AR-001** | Eligibility from ambiguous negative evidence / HIGH / arch | **CONFIRMED (eligible-set element NARROWED)** | Reproduced: `Option` collapse is real. **My PA5-1 is strictly sharper** — B lists "potentially a skipped check" as a *prerequisite*; I verified FI/CFI failure **is** in the class | Closed `Clear/BlindEligible/Fatal` taxonomy — **adopt**. But B's proposed eligible member `NoMatchingFormat` **conflicts with `dispatch.rs:216-221`, which B never cites** | **Arch: BLOCKS** | **YES — is `NoFormat` eligible?** |
| **PB-AR-002** | "Known call" is Bloom filter-positive, not membership / MED / arch | **CONFIRMED — independently reproduced** | I recomputed from `pqsigner-erc7730/src/known_calls.rs`: `BLOOM_HASHES=7`, 131,072 bits. **All 7 positions match B exactly** `[99335,23186,78109,1960,56883,111806,35657]`, **all bits set** in the shipped filter; occupancy 28,235/131,072 = 21.54%, corroborating the `:37` doc receipt | Rename to **filter-positive** + positive FI-protected `filter_positive` receipt; "never infer from `prove_unknown != OK`" ties directly to PA5-1 | **Arch: BLOCKS until terminology fixed** | **YES — filter-positive vs exact** |
| **PB-AR-003** | Two dialogs ≠ independent receipts / HIGH / arch | **NARROWED** | Spec gap **confirmed** (one global `OK_SENTINEL`; no domain separation, no request binding, no independent fail-init slots). Stale-register **exploit refuted** (PA5-9). B's positive result on `hw/buttons.rs` (release required) reproduces as a real defence | Distinct receipt types/constants, separate CFI steps, request-digest binding, single consumption, sequence check | **Disagreement: B blocks; A = FIX-NOW redline.** Moot for verdict (PA5-1/2/3 already block) | — |
| **PB-AR-004** | Transcript not injective / HIGH / arch | **CONFIRMED** | Reproduced at source: `tx-core/src/eip1559.rs` `format_decimal` → **`fmt_round_half_up(...)`**. At `decimals=18, frac=6`, `1 ETH+1 wei` and `+2 wei` both → `1.000000`. Fee fields + `maxFeePerGas`/`maxPriorityFeePerGas` absent from the plan's schema; ERC-8213 hashes **inner calldata only** | Freeze an exact static forced schema — **adopt B's list, plus `entry_point` (PA5-5)** | **Arch: BLOCKS** | **YES — paymaster representation** |
| **PB-AR-005** | Fatal exclusions not closed / HIGH / arch | **CONFIRMED** | Reproduced: `cmd_sign_userop.rs:1107-1111` — refusal requires `safe_exec_selector && safe_exec_enough_len && …`. `EXEC_TRANSACTION_MIN_CALLDATA_LEN = 4+10*32+2*32 = 388` (`proto/src/lib.rs:1460`). **The comment immediately above states the opposite intent**: "the firmware refuses rather than falling through to a generic blind-sign view". A short `execTransaction` falls through **today** | Exhaustive pre-dispatch exclusion classifier; batch maps every `BlindEligible` → fatal incl. one-element batches; permit private/non-`Copy`/request-bound/consume-once | **Arch: BLOCKS** | — |
| **PB-AR-006** | Exactly-one gas ownership underdefined / MED / arch | **CONFIRMED** | Converges with PA5-7. B's "proof establishes prior+1, not global uniqueness" reproduces against `userop_gas_page_proof` | One owner = handler | Arch: blocks (exactly-one is normative) | — |
| **PB-AR-007** | Lexical `drop` is not a stack argument / MED / arch | **NARROWED** | **Arithmetic exact and target-correct**: `Pages{buf:[Page;31], len:usize}`, Page=4×16=64 → 31×64 + 4 (ARM32 `usize`) = **1,988**. B correctly reasoned about target ABI, not host. Overflow itself **unverified** — B labels it "unresolved feasibility suspicion", correct | One cleared reusable buffer or non-inlined child phases; post-LTO stack/MSPLIM/high-water evidence | Arch: freeze construction; **evidence legitimately an impl/production gate** | — |
| **PB-AR-008** | Conflicts with owner contracts / HIGH / arch | **CONFIRMED** | Converges with my CS2 finding from the opposite direction. B's owner list is **more complete than mine** (adds root-rotation rule 3, guide §§1/9/10, ERC-8176 status owner) | Amend all listed owners; "Forced blind is not clear signing" | **Arch: BLOCKS** | **YES — all amendments** |
| **PB-AS-009** | Differential glue omits gas insertion / MED | **UNRESOLVED** | **Not reproduced.** Path mis-cited (`secure/tests/…`; actual `secure/src/display_under_test/wysiwys_dispatch_differential_tests.rs`). Header does claim "dispatcher-level value/gas splice gates" — which is **not** the handler's F10 insertion, so B's claim is plausible. I did not read `drive_glue` closely enough to rule | Model the complete handler transformation; assert exact page sequence/count at the confirmation boundary | Impl/merge gate; cheap to settle | — |
| **PB-BR-010** | ERC-8176 readiness false green / HIGH prod | **NARROWED** | Mechanism **confirmed**: `trusted & atsts` is a **set intersection** (≥1), and `:135-136` `elif n_trusted_attested == n_desc: … "Safe to flip."`. **But B's premise "policy requires at least two qualifying attesters per descriptor" is unsourced** — I found no such policy in the script or `erc8176-attestation-status.md` | Stronger correct framing: the threshold is **undefined and unbound to authenticated policy**, yet drives a production-flip recommendation. B's own correction ("bind the trust list and threshold to authenticated policy") already covers it | **Arch: no block. Production: YES** | **YES — threshold** |
| **PB-DOC-011** | Drift guards too narrow / LOW | **CONFIRMED** | Reproduced exactly: guide `:1051` "`NftName` formatter (0x09)" vs `ir.rs:224` `NftName = 0x04`, `:229` `Unit = 0x09`. **Strengthens my PA5-8** | Semantic manifest/corpus guards; drop `td-2` | Arch: no block; assurance gate | — |
| **PB-UX-012** | Warning fatigue bounded residual / MED | **CONFIRMED** | Reproduces; and **B's adjudication improves mine** — the session toggle saves `N-1` warnings (not one), and a device attempt budget creates host DoS + new state. This narrows my PA5-4 | Keep per-request; treat habituation as usability evidence | Arch: no block if explicitly accepted | **YES — accept residual** |
| **PB-PROC-013** | Two-backend coverage not attestably complete / gate | **NARROWED** | **Cured as to the pairing**: the coordinator's separate receipts show A = Opus 4.8/1M/ultracode/xhigh with three adjudicated Opus lanes, B = `gpt-5.6-sol`/ultra with three Codex lanes — two independent backends. B's in-report `ENOTFOUND` (session `d3700b4a…`, zero inference tokens) was correctly disclosed and does **not** taint B's technical evidence. **Not cured**: B's own boundary — *"Model/effort actually exposed to reviewer: NOT_EXPOSED"* — **applies identically to me**. Neither partner can attest its own model identity | Coordinator must bind both legs from launcher/control-plane logs. **Self-report ≠ attestation for either leg** | Blocks convergence **only** on the attestation boundary, not on technical evidence | **YES — accept coordinator attestation** |

## 3. Agreements and explicit disagreements

**Independent convergence (strong).** Both legs reached **NO-GO** on disjoint reasoning. Both independently: (a) demanded a closed `Clear/BlindEligible/Fatal` taxonomy with fatal default; (b) rejected eligibility-by-negation; (c) chose **one gas owner = the handler, delete the renderer append**; (d) **corrected the same discovery-lane "provenance tagging" error identically** — provenance is unnecessary when the expected page is recomputed from signed inputs; (e) required owner amendment of CS2/`CLAUDE.md` and the phrase *forced blind is not clear signing*; (f) kept refusal as default/rollback; (g) DROPped `td-2`. Convergence from two backends on (c)/(d) is the most load-bearing agreement in this pair.

**Preserved disagreements — not averaged, not voted:**

1. **Is `NoFormat` eligible?** B's AR-001 admits "verified-and-bound descriptor with a specifically enumerated unsupported capability, such as `NoMatchingFormat`." My PA5-2 narrows to **descriptor-absent/unrooted only**, because all three `RenderErr` arms arise *after* verify+bind and `dispatch.rs:216-221` declares a post-binding renderer failure an **integrity failure, not permission to downgrade**. **B never cites that doctrine.** Both positions are defensible — `NoFormat` is arguably "the catalogue does not describe this call" rather than an integrity failure — but the doctrine is the **current owner** and cannot be overridden by an implementer. **Owner decision required.**
2. **Does PB-AR-003 independently block?** B: yes. A: FIX-NOW redline, since the single-fault exploit is refuted. Moot for the verdict — PA5-1/2/3 and PB-AR-004/005/008 already block — but I do not adopt B's blocking framing, and B should not adopt my downgrade.
3. **Prompt budget.** My PA5-4 called it an available device-local fix; B declines to mandate it (DoS + new state). **B is right that it is a trade-off; I narrow accordingly.** Neither of us should present it as settled.

## 4. Inherited framing / unsupported assumptions in Partner B

- **Unsourced threshold (→ XB-2).** PB-BR-010 rests on "policy requires at least two qualifying attesters per descriptor" with **no citation**; I could not find it. The finding survives only in the narrowed "threshold unbound" form.
- **Eligible-set carve-out proposed without engaging the governing doctrine.** B proposes admitting `NoMatchingFormat` without citing or refuting `dispatch.rs:216-221`.
- **`Pages` "approximately 1,988 bytes"** — I verified it is **exactly** 1,988 on the ARM32 target. B under-claimed; the number is exact.
- **Where B did *not* inherit the plan's framing — credit:** B attacked "known call" head-on (AR-002) rather than accepting the plan's word, and produced the only executed counterexample in either leg. B's owner-amendment list is more complete than mine.
- **My own error, recorded:** I attempted to sharpen AR-002 by arguing a Bloom false positive converts today's *refusal* into a signable path. **That attack fails.** An FP tuple is semantically **unknown**; absent the FP it would reach ordinary blind-sign with one confirm. Forced-blind is **stricter** than that baseline, so the FP gains no authority it would not otherwise have had. **B's reasoning holds; mine did not.** The finding is the semantic contradiction, exactly as B framed it.
- **Joint blind spot (both legs).** Neither partner read `state.rs`. B's LC rows are written as *requirements* ("LC7: Reset/disconnect **must** destroy local authorization"), not verifications. So the plan's central claim — **the permission "dies on every return"** — is **unverified by either partner**. The LC lens is undischarged across the whole pair.

## 5. Required reconciliations

- **Gas page.** Converged: **one owner = the handler**, synthesizing from signed words; delete the renderer's `append_userop_gas_page` (`display/render/mod.rs:805`). Provenance tagging **not** required (both partners refuted the lane). **Independent FI proof still needed**: skip-decision and completion-proof must be **FI-independent A/B evaluations** (a single predicate serving as both is the break); prove **exactly one** canonical page globally **immediately before every confirmation** — an existence predicate cannot discharge "exactly one"; retain fail-closed on full buffer and near-shaped conflict. If idempotence is nevertheless kept, adopt B's rule set verbatim (recompute; scan all visible; insert only on count 0; leave count 1; reject >1 / near-match).
- **Bloom.** Adopt **filter-positive** semantics with a **positive FI-protected `filter_positive` receipt**, never inferred from `prove_unknown != OK`. Exact membership remains a legitimate owner alternative (minority lane view, retained). Reproduced FP rate is bounded by the generator's own `<1/10000` cap.
- **Bad / root-misbound proof.** **Both partners recommend preserving hard refusal.** Root-rotation policy currently mandates it; the plan contemplates folding it into "unavailable". **Owner must choose explicitly**; default = preserve refusal.
- **Paymaster.** Neither partner resolved representation. `paymaster_and_data_hash` is already reserved a page in the handler's budget. **Owner decision; must appear in the frozen schema or be explicitly excluded.**
- **Two-stage receipts.** Domain-separated constants + distinct types + separate CFI steps + **request-digest binding** (B's addition) + independent fail-initialized caller-owned slots + single consumption + sequence check. The stale-register exploit is **refuted**; the specification gap is **real**.
- **Resource construction.** One cleared reusable `Pages`, or a thin parent owning no `Pages` calling non-inlined warning/transcript children. Lexical `drop` is not an argument. Evidence (post-LTO stack, MSPLIM, exception headroom, high-water) is legitimately an **implementation/production gate**, not an architecture blocker.
- **Fatal routing.** Exhaustive pre-dispatch classifier; close the short/malformed `execTransaction` hole (`< 388` bytes) **today**; batch maps every `BlindEligible` → fatal including one-element batches.

## 6. Minimum revised architecture

**Closed outcome taxonomy** (no wildcard, no permissive `From`, no `Default`, no `Option`-collapse; unknown future reason = fatal):
```
Outcome = Clear(Pages) | BlindEligible(BlindReason) | Fatal(FatalReason)
BlindReason ∈ { MetadataAbsent_FilterPositive_SingleDirect }   // + NoMatchingFormat ONLY on owner decision
FatalReason ⊇ { Malformed, MisBound, RootMismatch, BadProof, Reject(*), NoFormat*, PageBudget,
                CfiOrFiGateFailure, WrongChainOrTarget, Batch, OffChain, Safe*, CoW*,
                Delegatecall, MultiSend, ApproveHash, SetPreSignature, MandatoryPageOverflow,
                ShortOrMalformedExecTransaction, UnknownFutureReason }
```
`BlindEligible` is **minted affirmatively** by a sentinel-encoded proof at the site where the honest cause is still known — **never** by negation of a failed refuse-gate. FI/CFI failures are structurally disjoint from `BlindReason`.

**Receipt sequence:** `filter_positive` (positive FI receipt) → affirmative `BlindEligible` → static severe warning → **warning receipt** (own constant/type, request-digest-bound, fail-init caller-owned slot, own CFI step) → discard all failed metadata bytes → clear/reuse page resources → forced transcript → **final-confirm receipt** (distinct domain) → recheck reason + both receipts + exact order → single release. Any cancel/idle/exception/reset destroys the permit. Permit is private, non-`Copy`, request-bound, consumed once.

**Forced transcript schema (exact, static):** persistent `FORCED BLIND / UNVERIFIED` banner; full signer; full raw target (no resolver substitution); numeric chain; **exact raw U256 value**; **exact raw `maxFeePerGas` + `maxPriorityFeePerGas`**; exact gas triple; exact full nonce; **`entry_point` (PA5-5)**; paymaster per owner decision; selector + exact calldata length; complete two-page ERC-8213 digest; final confirmation. Rounded/friendly forms **supplemental only**; if an exact form does not fit → **fatal**. No descriptor text, names, selector labels, or host strings may reach this renderer — enforced **by type**, sharing `blind_sign.rs` primitives with a differential test (PA5-11/CS9).

**Falsifiable acceptance evidence:** dispatcher table test for every proof/render/fatal class incl. fatal-default mutation control; `bind_gate` failure → fatal (not eligible); Bloom FP → filter-positive route, never authority; byte-flip injectivity over value/fee/gas/chain/signer/target/entry_point; short `execTransaction` → fatal; one-element batch → fatal; zero/one/two gas pages + full-buffer + near-match; **scripted-input consent harness** (PA5-6 — the e2e auto-confirm cannot discharge this); retry/interleave/idle/reset permit destruction (**requires `state.rs`**). **Legitimately implementation/production gates:** post-LTO Thumb disassembly + stale-register/spill/branch-fault sweep; static stack + MSPLIM + high-water; NV3007 panel/clipping/scroll capture; usability/habituation evidence.

## 7. Owner decisions required

1. Amend **`CLAUDE.md:14`** trusted-display invariant; **CS2**; companion guide §§1/9/10; companion integration contract; **root-rotation rule 3**; ERC-8176 status owner. Wording: filter-positive calls **never** silently fall through to typed/ERC-20/generic blind — they clear-sign, fatal-refuse, or enter a distinct forced-blind tier. **Forced blind is not clear signing.**
2. **Eligible set**: descriptor-absent/unrooted only (A), or additionally `NoMatchingFormat` (B). **Unresolved between partners.**
3. **Bad/root-misbound proof**: preserve hard refusal (both partners recommend) or affirmatively supersede.
4. **Bloom**: filter-positive semantics vs exact membership.
5. **Paymaster** representation in the forced schema.
6. **Prompt budget** vs host-driven DoS + new state.
7. **ERC-8176 attester threshold** — must be defined and bound to authenticated policy.
8. Accept **PB-UX-012** habituation residual explicitly, or block on usability evidence.

Default and rollback remain **today's refusal** unless and until an authorized owner amends these contracts.

## 8. New cross findings

**XB-1 · Systematic citation mis-pathing · MEDIUM · impairs reproduction.** **9 of 11** paths cited by Partner B do not exist in the frozen target: `secure/src/handlers.rs`, `secure/src/confirm.rs`, `secure/src/tx/erc7730/render/mod.rs`, `secure/src/tx/erc7730/formatter.rs`, `secure/src/tx/erc7730/ir.rs`, `secure/src/tx/erc8213.rs`, `secure/src/tx/known_calls.rs`, `secure/tests/wysiwys_dispatch_differential_tests.rs` (all MISSING); only `secure/src/hw/buttons.rs`, `secure/data/erc7730-known-calls.bloom`, `tools/erc8176_eas_coverage.py` resolve. The symbols are real but live elsewhere (`may_contain` → `pqsigner-erc7730/src/known_calls.rs`; `EXEC_TRANSACTION_MIN_CALLDATA_LEN` → `proto/src/lib.rs:1460`; `format_decimal` → `tx-core/src/eip1559.rs`). **This is not fabrication** — content and line numbers largely check out (B's `handlers.rs:1345` ↔ actual `cmd_sign_userop.rs:1346`), and every B claim I could locate reproduced. It is a **reproducibility defect** against the packet's "exact path plus symbol/string" requirement: PB-AS-009 is **UNRESOLVED partly because I could not follow its citation**. Stage impact: none on architecture conclusions; blocks efficient implementation follow-through. Correction: re-path all citations against the frozen tree.

**XB-2 · PB-BR-010's threshold premise is unsourced · LOW-MEDIUM.** B's "policy requires at least two qualifying attesters per descriptor" carries no citation and I found none in `tools/erc8176_eas_coverage.py` or `docs/erc8176-attestation-status.md`. The defect **survives narrowed and arguably stronger** (the script emits a production-flip recommendation from an implicit, unauthenticated ≥1 threshold), but the stated "two" premise must be sourced or withdrawn. Stage impact: production only.

*No XA-* findings are self-raised; Partner B's counterpart response is the proper channel.*

## 9. Revised stage verdicts

| Stage | Verdict |
|---|---|
| **Architecture** | **NO-GO as frozen.** Conditionally favorable **only** upon the §6/§7 redlines. Both legs independently reached NO-GO. A favorable verdict on the *revised* text grants **no implementation authority** for a materially revised, as-yet-unreviewed artifact — that artifact requires its own exact dual review. |
| **Implementation** | **UNAVAILABLE / not approved** — nothing implemented; PA5-6 and PB-AS-009 are gates before any merge approval. |
| **Merge** | **NO-GO** — no approved architecture, no implementation evidence, no convergence packet. |
| **Production** | **NO-GO / unavailable** — independently blocked by ERC-8176 (PB-BR-010, narrowed) and the firmware-rollback quarantine, both correctly preserved and not weakened by the plan. |
| **Irreversible action** | **Not authorized.** None performed. |

## 10. Honest residual

All FI, stack, UI and silicon reasoning across **both** legs is **source-only** — `RT11` names precisely this as evidence that does not substitute for ARM runtime reality, and it indicts this cross report too. My one executed artifact this leg is the Bloom recomputation. **`state.rs` is unread by both partners**, so the plan's central claim that the permission "dies on every return" is **unverified by the entire pair**, and the LC lens is undischarged — that alone withholds GO even with every redline landed. PB-AS-009 is unresolved. PA5-2's exploit is unverified and I refuted the lanes' own mechanism. `td-2`'s DROP is lane-verified and now B-corroborated but **not partner-reproduced**. My PA5-10 is uncorroborated by B. B's PB-AR-004/005 and PB-DOC-011 are real findings I missed entirely; B's Bloom collision is the strongest single artifact in this pair and it is B's.

**PB-PROC-013 disposition, stated plainly:** cured for the *pairing* by the coordinator's separate receipts; **not cured** on self-attestation — B's "`NOT_EXPOSED` — cannot be truthfully self-attested" applies verbatim to me. Neither partner's model identity is attested by its own report.

The two legs disagree about `NoFormat`, about whether PB-AR-003 blocks, and about mandating a prompt budget. Those are **preserved, not reconciled**. Everything else converged — from two backends, on disjoint evidence — which is the strongest signal this pair produces: the candidate's **shape** survived both adversaries; its **frozen text** did not.

## 11. Final target identity / drift

HEAD `9647b79374d5e2e10445254492308101b8be708b` · status = the two expected docs only · untracked **0** · ignored files **0** · diff `b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25` (plain and `--binary` identical) · worktree read-only. Partner A V5 `4b34ae5f…23a884c` and Partner B V4 `bcb8a52e…5f1110f` **both unchanged**. **NO DRIFT. Target and both frozen reports unmodified.**

END PARTNER A CROSS V1
