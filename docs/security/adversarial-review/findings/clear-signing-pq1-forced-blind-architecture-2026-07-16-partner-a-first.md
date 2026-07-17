# PARTNER A — RAW EXTERNAL FIRST-PASS REPORT (V5, REPLACEMENT)
## PQ1 ERC-7730 Phase-B ARCHITECTURE review — architecture stage only

**This V5 SUPERSEDES V4 in its entirety for pairing.** V4 stays frozen for audit only and must not be paired — I reversed my own V4 headline and withdrew my V4 gas rationale on lane evidence. Partner B unseen and uninferred.

**Verdict: NO-GO as worded; GO after the FIX-NOW redlines.** A wording/mechanism NO-GO, not a rejection of the candidate.

## 1. Receipts — initial and final, identical

HEAD `9647b79374d5e2e10445254492308101b8be708b` ✅ · status = the two expected docs ✅ · untracked 0 ✅ · ignored **files** 0 ✅ · diff `b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25` ✅ (all four variants) · worktree read-only. **NO DRIFT.**

`.serena/` remains an empty directory shell. My file-level ignored digest `e3b0c442…b855` (the empty-string digest) **matches the lanes' `target_ignored_inventory_sha256_final` exactly** — four independent observers now reconcile. Adjudicated immaterial, disclosed not absorbed (BR1-class).

## 2. Supplied evidence — verified, not assumed

All five digests recomputed and **MATCH** (`ca6dad51…`, `8530066b…`, `01718466…`, `83fc8dc3…`, `99d55017…`). Receipts internally coherent and correctly self-limiting ("candidate-evidence inputs only"). I treated all three lanes as **untrusted** and personally re-opened every citation.

## 3. Discovery leg — **AVAILABLE** (3/3 required scopes). V4's failure is cured.

## 4. Findings (every cited artefact personally re-opened)

**PA5-1 · CRITICAL · BLOCKS — a detected fault attack is inside the eligible class.** `cmd_sign_userop.rs:570-577` + the `bind_gate_a/b` arms: `Option<VerifiedDescriptor>` becomes a bit-identical `None` from **four** causes — absent trailer, `verify_erc7730_bundle` Err, and **`bind_gate_a != OK_SENTINEL → None`**, **`bind_gate_b != OK_SENTINEL → None`**. Those last two are the FI/CFI gates: **a successfully detected fault attack is indistinguishable from honest omission.** The plan's "typed blind-eligible reason" is therefore unimplementable at the dispatcher — the information is destroyed one frame earlier — and carving `BlindEligible` out of the catch-all **inverts fail-closed to fail-open for the carved class**.

**PA5-2 · HIGH · BLOCKS — the eligible set contradicts §4 and the in-source doctrine.** `dispatch.rs:216-221`, verbatim: *"once a descriptor has verified and bound to this transaction, a renderer failure is an integrity failure, not permission to downgrade."* All three `RenderErr` variants (`Reject`/`NoFormat`/`PageBudget`) arise only *after* verify+bind, and each `return Err(())`. §5 makes "cannot completely render" eligible; §4 says "overflow refuses"; §5's fatal list names *"mandatory-page overflow"*, which I verified is a **different condition** from `RenderErr::PageBudget`. **No owner named.** `render/mod.rs:31-37` confirms `Reject` fuses internal-invariant failures with attacker-induced mismatch.
**I downgraded the lanes' exploit:** `MAX_ARRAY_RENDER = 8` (`array.rs:43,151`) closes the obvious inflation lever (over-cap → `Reject`, not `PageBudget`). Neither lane noticed. Exploit → **suspicion/unverified**. The **contradiction still blocks** — it's not exploit-dependent.

**PA5-3 · HIGH · BLOCKS** (V4 retained, sharpened) — five `return Err(())` sites make "known tuple never reaches the ERC-20/typed/blind ladder" *structural*; `BlindEligible` degrades it to data-flow directly above `:425`'s selector-name fallback.

**PA5-4 · MEDIUM — habituation is a missing control, not a UX unknown.** `crypto.rs:84`'s limiter sits *inside* signing → a cancelled prompt charges nothing. And ordering is `pick_sign_pages` `:1249` → gas gate `:1346` → confirm `:1388`, so the user can complete the full severe-warning ceremony **and be refused anyway**: unlimited habituation at zero attacker risk. Fixable device-locally → the plan's "UX evidence question" framing is incomplete.

**PA5-5 · MEDIUM — `entry_point` signed but never shown.** Companion-supplied (`:237-238`), folded into the digest (`userop.rs:702`), zero occurrences under `secure/src/tx/display/`. **My extension:** `ENTRY_POINT_V06` exists at `userop.rs:619` but **every** use is inside `#[cfg(test)]` (opens `:941`) or `aa/tests/` — the pin is available and deliberately unenforced.

**PA5-6 · MEDIUM — "both consents are mandatory" is undischargeable.** `confirm.rs:59-65` auto-confirms under `e2e-test`. Assurance hole, not a shipping hole (UI3 is defended).

**PA5-7 · SIMPLIFY — gas idempotence (V4 corrected).** I **withdraw** V4's claim that position/provenance are semantically necessary — `E` is rebuilt from signed locals, so existence is content-sound. The real defect (taxonomy T-7): skip-decision and completion-proof must be **FI-independent A/B evaluations**. Plus: "exactly one exact gas page" is undischargeable by an existence predicate. **Still: delete the renderer's unproven duplicate; keep the FI-proven gate.**

**PA5-8 · MEDIUM** — drift guard misses `erc7730-integration.md`'s tuple SHA, **4,542** tuples, Bloom **28,235/131,072**, **274** omissions → objective (a) unmet.

**PA5-9 · DOWNGRADED — I reverse my V4 headline.** The stale-r0 exploit is **refuted**: its precondition is no intervening value-returning call, and a whole transcript is built between ceremonies. **Independence holds.** Surviving redline: one shared `OK_SENTINEL` (FI6), needs optimized-ELF (FI10). **Not a blocker.**

**PA5-10 · NEW (mine)** — unbounded prompts re-open HIGH-13: `confirm.rs:81-88` refuses to reset the idle timer on entry, but `:118` resets on **any button press** — so companion-induced prompts let the *user* hold the unlocked window open. Reaches the HIGH-13 outcome by a path the fix doesn't cover.

**PA5-11 · NEW (mine)** — the "distinct forced-blind renderer" is a second decoder on the confirm path: **CS9 by definition**, unnamed by the plan and all three lanes.

## 5. Mode walk (full, in the file)

The central fact: **CS2 is "Silent fail-open to blind-sign — a known shape whose proof is stripped, malformed, or fails to render."** The proposal **is** CS2, deliberately performed. The load-bearing word is *"silent"* — the proposal is loud. So this is defensible **only** with a recorded owner amendment to CS2, and PA5-1/2/3 each break that restatement today. Also engaged: CS1/CS8/CS9/CS10; UI1/3/5/6/7; FI6/FI8/FI10; LC6/LC10; RT4/RT8/**RT11**; PC1/PC2 (**is the hatch feature-gated? the plan never says**); PC8/PC10; BR1 (discharged), BR5. Packet drift: it mandates "UC1-UC10" but the playbook defines **UC1-UC5**.

## 6. Failed attacks

Two of mine died (byte-exact premise; stale-r0), one lane's died at my hands (page inflation vs `MAX_ARRAY_RENDER`), plus the forged-page and gas-divergence attacks. Notably the taxonomy lane attacked the *same* gas premise I did, via a different route, and was refuted by the *same* fact — the `erc7730/` directory is an 18-line shim.

## 7. Verdicts

| Stage | Verdict |
|---|---|
| **Architecture** | **NO-GO as worded; GO after the FIX-NOW redlines** |
| **Implementation / Merge** | **UNAVAILABLE** — none exists |
| **Production shipment** | **UNAVAILABLE** — ERC-8176 + rollback quarantine, correctly preserved |

## 8. Residual

All FI reasoning is **source-only — RT11 names exactly this as not-evidence**. **`state.rs` is unread by me and by all three lanes**, so the plan's *central* claim that the permission "dies on every return" is **unverified by anyone in this leg** and the LC lens is undischarged — that alone would hold me from GO even if every redline landed today. Batch path untraced. PA5-2's exploit unverified. `td-2`'s DROP is lane-verified, **not partner-reproduced** — the owner should not treat it as confirmed.

**The defects cluster in prose precision, not design judgment.** The candidate survived my strongest attacks; its conclusions are mostly right even where its arguments are wrong (the session-toggle rationale is factually incorrect while the decision is correct). The honest description of this feature is **"CS2, performed on purpose, loudly, with consent"** — and that deserves a signature, not an implementer's judgement call.

*Partner A V5 — FROZEN. Supersedes V4. Target unmodified; final receipt clean.*
