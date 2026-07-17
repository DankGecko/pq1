//! Verus crash-safety pilot for the page-123 flash journal (PQ1 off-chain sig-counter store).
//!
//! ## WHAT THIS IS — AND IS NOT (read before citing)
//!
//! This is a **fresh pure Verus MODEL** of the log-structured journal — NOT the deployed
//! `secure/src/offchain_state.rs` / `secure/src/hw/flash.rs` (those are unsafe flash-MMIO
//! Rust that Verus cannot verify). So this proves **a crash property of a Rust MODEL of the
//! journal**, under explicit named silicon axioms. The MODEL ↔ firmware correspondence is a
//! **cited-TCB gap** (the same class as the Lean work): it is argued by construction/inspection,
//! not machine-checked. Do not read a theorem here as "Verus proved the page-123 journal
//! crash-safe" — read it as "proved a faithful Rust model crash-safe under AX-*".
//!
//! It **complements** the bounded TLA+/TLC pilot (`contracts/verification/tla/Page123Compaction.tla`):
//! TLC checked small-scope traces (incl. the non-atomic-erase / torn-may-decode negative controls);
//! Verus adds the **all-length** positive theorem (unbounded counts, unbounded slots) under an
//! explicitly ASSUMED atomic-erase precondition. The non-atomic-erase counterexample stays in TLC
//! (Verus proves; it does not search for counterexamples).
//!
//! ## SILICON AXIOMS the safety theorem is CONDITIONAL on (assumed, not proven — STM32U5 flash):
//! * **AX-TORN-SKIP** — a power-interrupted quadword program reads back UNDECODABLE and is skipped
//!   (`parse_entry` → skip; `flash.rs:1419`). Load-bearing: under the alternative "a torn QW may
//!   decode as an arbitrary valid entry" the theorem is FALSE (TLA+ Finding 1). The 16-byte QW
//!   format has NO CRC/commit-marker, so this cannot be discharged from the format — it is silicon.
//! * **AX-QW-WRITE-ONCE / AX-NOR** — program unit = one 128-bit quadword, 1→0-only, a re-program of
//!   a non-blank QW faults (PROGERR); erase unit = the whole 8 KiB page → all-0xFF (Blank).
//! * **AX-ERASE-ATOMIC** — the page erase is one indivisible step (all cells → Blank together). This
//!   is ASSUMED here as an explicit precondition; a torn *partial* erase (physically possible on
//!   brownout) breaks the property and is the TLC pilot's job + `flash.rs:1669`'s commit-marker
//!   residual. NOT proven; explicitly out of this model's positive theorem.
//! * OUT OF SCOPE (availability, not safety): whether a torn-QW ECC read is silent-skippable or
//!   TRAPS (NMI → crash-loop) is genuinely undetermined for STM32U5; the safety model assumes the
//!   silent-skippable branch (AX-TORN-SKIP). The ECC-trap branch is an unresolved availability
//!   residual, deliberately NOT a case in this proof.
use vstd::prelude::*;

verus! {

/// The three durable counter kinds (`flash.rs:1354-1367`): off-chain count, last on-chain
/// UserOp count, and the few-time-key produced-signature tally.
pub enum Ty { Cnt, Uo, Sigs }

/// A 16-byte flash quadword as the reader decodes it (`parse_entry`, `flash.rs:1398-1440`).
/// `Blank` = erased (all-0xFF). `Torn` = a power-interrupted program (AX-TORN-SKIP: undecodable,
/// skipped). `Entry` = a decodable durable record. Counts/slots are unbounded `nat` (all-length).
pub enum Qw {
    Blank,
    Torn,
    Entry { slot: nat, ty: Ty, count: nat },
}

pub open spec fn maxn(a: nat, b: nat) -> nat { if a >= b { a } else { b } }

/// **Recovery projection** = the value a reader reconstructs for `(slot, ty)`: the MAX `count`
/// over all decodable `Entry` cells matching `(slot, ty)`, else 0 (mirrors `scan_page_into_table`'s
/// MAX-merge, `flash.rs:1587-1602`, and `offchain_count_read`). Defined RECURSIVELY over the log
/// PREFIX (drop-last) with `decreases`, so `proj(push)` is one definitional unfold (see `proj_push`).
pub open spec fn proj(log: Seq<Qw>, slot: nat, ty: Ty) -> nat
    decreases log.len(),
{
    if log.len() == 0 {
        0
    } else {
        let base = proj(log.subrange(0, log.len() - 1), slot, ty);
        match log[log.len() - 1] {
            Qw::Entry { slot: s, ty: t, count: c } =>
                if s == slot && t == ty { maxn(c, base) } else { base },
            _ => base,
        }
    }
}

/// **Append lemma.** Appending one quadword updates `proj` by MAX iff it is a matching `Entry`,
/// else leaves it unchanged. Definitional building block for the compaction argument.
pub proof fn proj_push(log: Seq<Qw>, e: Qw, slot: nat, ty: Ty)
    ensures
        proj(log.push(e), slot, ty) == (match e {
            Qw::Entry { slot: s, ty: t, count: c } =>
                if s == slot && t == ty { maxn(c, proj(log, slot, ty)) } else { proj(log, slot, ty) },
            _ => proj(log, slot, ty),
        }),
{
    assert(log.push(e).subrange(0, log.push(e).len() - 1) =~= log);
}

/// **Monotonicity under append.** Appending any quadword never DECREASES `proj` — the durable
/// "counters never go backwards" property, per `(slot, ty)`. Follows from `proj_push`
/// (`max(c, b) >= b`, and a non-matching cell leaves `base`). MODEL statement.
pub proof fn proj_monotone_push(log: Seq<Qw>, e: Qw, slot: nat, ty: Ty)
    ensures proj(log.push(e), slot, ty) >= proj(log, slot, ty),
{
    proj_push(log, e, slot, ty);
}

/// **A written Entry is a durable lower bound.** After appending `Entry(s, t, c)`, `proj(_, s, t) >= c`
/// — once a signature/count is written it never reads back lower (barring erase). The model core of
/// "release implies a prior durable charge" (`flash.rs` §13 bumps before releasing the signature).
pub proof fn proj_entry_lower_bound(log: Seq<Qw>, s: nat, t: Ty, c: nat)
    ensures proj(log.push(Qw::Entry { slot: s, ty: t, count: c }), s, t) >= c,
{
    proj_push(log, Qw::Entry { slot: s, ty: t, count: c }, s, t);
}

/// A quadword is a decodable entry for `slot` (mirrors `parse_entry` decode + slot-key match).
pub open spec fn is_entry_for(qw: Qw, slot: nat) -> bool {
    match qw { Qw::Entry { slot: s, .. } => s == slot, _ => false }
}

/// **Registered** = the reader finds at least one decodable entry for the slot (`is_registered_forward`,
/// `flash.rs:1996-2008`). Slot-0 register marker is a `USEROP` entry with `count == 0`, so registration
/// is entry-existence, not a positive count.
pub open spec fn registered(log: Seq<Qw>, slot: nat) -> bool {
    exists|i: int| 0 <= i < log.len() && is_entry_for(#[trigger] log[i], slot)
}

/// **Anti-vacuity — a positive reachability witness.** A concrete log in which slot 7 is registered
/// AND `proj_sigs == 5`, so the crash theorems are not vacuous over an unreachable/empty state
/// (the Verus analogue of the "assume(false) detonation" check). MODEL statement.
pub proof fn witness_reachable()
    ensures exists|log: Seq<Qw>| registered(log, 7) && proj(log, 7, Ty::Sigs) == 5,
{
    let e = Qw::Entry { slot: 7, ty: Ty::Sigs, count: 5 };
    let log = Seq::empty().push(e);
    proj_push(Seq::empty(), e, 7, Ty::Sigs);
    assert(is_entry_for(log[0], 7));
    assert(registered(log, 7));
    assert(proj(log, 7, Ty::Sigs) == 5);
}

/// **`proj` lower-bounds any contained matching entry.** If cell `i` of `log` is `Entry(s, t, c)`,
/// then `proj(log, s, t) >= c`. Proved by induction over the log prefix (matching `proj`'s recursion):
/// either `i` is the last cell (`proj` unfolds to `max(c, base) >= c`) or it is in the prefix
/// (IH + append-monotonicity). The reusable core of the crash theorem.
pub proof fn proj_ge_at(log: Seq<Qw>, s: nat, t: Ty, c: nat, i: int)
    requires
        0 <= i < log.len(),
        log[i] == (Qw::Entry { slot: s, ty: t, count: c }),
    ensures
        proj(log, s, t) >= c,
    decreases log.len(),
{
    let n = log.len() as int;
    let last = log[n - 1];
    let prefix = log.subrange(0, n - 1);
    assert(log =~= prefix.push(last));
    if i == n - 1 {
        // proj(log,s,t) unfolds on `last == Entry(s,t,c)` to maxn(c, proj(prefix,s,t)) >= c
        proj_push(prefix, last, s, t);
    } else {
        assert(prefix[i] == log[i]);
        proj_ge_at(prefix, s, t, c, i);
        proj_monotone_push(prefix, last, s, t);
    }
}

/// **HEADLINE — SIGS-first compaction-local no-rollback (`INV_SIGS_COMPACTION_LOCAL`), all-length.**
///
/// Models the crash during a compaction replay: `replay` is the canonical re-written page (post
/// atomic-erase — that atomicity is `AX-ERASE-ATOMIC`, assumed), and a power-cut leaves the durable
/// PREFIX `replay[0..k]`. The **SIGS-first** replay order (`flash.rs:1671-1700`) is modeled by: for
/// the slot `s`, its `USEROP_SIGS` cell is at `j0`, and NO cell for `s` precedes `j0`. The theorem:
/// **any crash-prefix that leaves `s` registered — where `s`'s replay carries a `USEROP_SIGS` cell
/// (the `has_userop_sigs` case) — has already made its SIGS durable at the pre-compaction value
/// `v`** — so a torn compaction can never roll such a slot's SIGS below its snapshot. (SCOPE: a slot
/// registered ONLY by the count-0 `USEROP` register marker has no SIGS cell — registered yet outside
/// this theorem, and trivially safe: `proj_sigs` is `0` before and after.) (A crash BEFORE `j0`
/// leaves `s` unregistered → invariant #9 forces a Type-1
/// re-registration; that total-loss branch is the accepted residual, TLA+ Finding 2 — NOT covered
/// here, and correctly so: this is COMPACTION-LOCAL, not global no-rollback.)
///
/// Proof: registration in the prefix exhibits an `s`-cell at some `j < k`; SIGS-first forces
/// `j >= j0`, so the prefix contains cell `j0 = Entry(s, Sigs, v)`; `proj_ge_at` gives `proj >= v`.
/// This is the ALL-LENGTH (unbounded `k`, `replay`, `v`) analogue of the bounded TLC result, and is
/// CONDITIONAL on `AX-TORN-SKIP` (a torn cell is undecodable/skipped, not a rogue valid entry) —
/// under the alternative the property is false (TLA+ Finding 1). MODEL statement, cited-TCB link to
/// the firmware.
pub proof fn sigs_first_no_rollback(replay: Seq<Qw>, s: nat, v: nat, j0: int, k: int)
    requires
        0 <= j0 < replay.len(),
        replay[j0] == (Qw::Entry { slot: s, ty: Ty::Sigs, count: v }),
        forall|i: int| 0 <= i < j0 ==> !is_entry_for(replay[i], s),
        0 <= k <= replay.len(),
        registered(replay.subrange(0, k), s),
    ensures
        proj(replay.subrange(0, k), s, Ty::Sigs) >= v,
{
    let prefix = replay.subrange(0, k);
    assert(prefix.len() == k);
    let j = choose|j: int| 0 <= j < prefix.len() && is_entry_for(#[trigger] prefix[j], s);
    assert(0 <= j < prefix.len() && is_entry_for(prefix[j], s));
    assert(prefix[j] == replay[j]);
    assert(j >= j0) by {
        if j < j0 {
            assert(!is_entry_for(replay[j], s));
        }
    }
    assert(prefix[j0] == replay[j0]);
    proj_ge_at(prefix, s, Ty::Sigs, v, j0);
}

/// **NEGATIVE CONTROL — the SIGS-FIRST order is load-bearing (exhibited counterexample).**
/// Under a SIGS-*LAST* replay order the no-rollback theorem is FALSE: this exhibits a concrete
/// `replay = [Entry(s,Uo,0), Entry(s,Sigs,3)]` (register-marker first, SIGS after — the negative
/// control the TLA+ pilot's `SigsLast` cfg checks) and the crash-prefix `k = 1` in which slot `s` is
/// REGISTERED (by the `USEROP` register marker) yet `proj_sigs = 0 < 3 = preSigs` — a registered
/// slot with its SIGS rolled back. So `sigs_first_no_rollback`'s SIGS-first hypothesis is not
/// vacuous — dropping it makes the conclusion refutable. (Verus proves; it does not search — this is
/// the honest Verus form of the TLC `VIOLATED` negative control: a machine-checked existential.)
pub proof fn sigs_last_rolls_back()
    ensures
        exists|replay: Seq<Qw>, s: nat, k: int|
            #![trigger proj(replay, s, Ty::Sigs), replay.subrange(0, k)]
            0 <= k <= replay.len()
            && registered(replay.subrange(0, k), s)
            && proj(replay, s, Ty::Sigs) > 0
            && proj(replay.subrange(0, k), s, Ty::Sigs) < proj(replay, s, Ty::Sigs),
{
    let s: nat = 7;
    let e_uo = Qw::Entry { slot: s, ty: Ty::Uo, count: 0 };
    let e_sig = Qw::Entry { slot: s, ty: Ty::Sigs, count: 3 };
    let replay = seq![e_uo, e_sig];
    let prefix = replay.subrange(0, 1);

    // proj(replay, 7, Sigs) == 3  (Uo cell then Sigs(3) cell)
    assert(seq![e_uo] =~= Seq::<Qw>::empty().push(e_uo));
    assert(replay =~= seq![e_uo].push(e_sig));
    proj_push(Seq::<Qw>::empty(), e_uo, s, Ty::Sigs);
    proj_push(seq![e_uo], e_sig, s, Ty::Sigs);
    assert(proj(replay, s, Ty::Sigs) == 3);

    // prefix == [Uo(0)] : registered (the Uo cell) but proj_sigs == 0 < 3
    assert(prefix =~= Seq::<Qw>::empty().push(e_uo));
    proj_push(Seq::<Qw>::empty(), e_uo, s, Ty::Sigs);
    assert(proj(prefix, s, Ty::Sigs) == 0);
    assert(is_entry_for(prefix[0], s));
    assert(registered(prefix, s));

    // witnesses (replay, s=7, k=1) satisfy the existential body
    assert(0 <= 1int <= replay.len());
    assert(proj(replay.subrange(0, 1), s, Ty::Sigs) < proj(replay, s, Ty::Sigs));
}

} // verus!
