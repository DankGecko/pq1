/-
EUF-CMA security of SPHINCS+C10.

This file states existential-unforgeability-under-chosen-message-attack
for SPHINCS+C10 as an `axiom`, with explicit citations to the proof that
justifies it.

## Shape (2026-06-14 reconciliation — see docs/EUF_CMA_INCONSISTENCY.md)

The prior shape `∀ vk transcript m s, isForgery → False` was INCONSISTENT:
for any honest key a valid signature *exists* (the honest signer makes one),
so `isForgery` (verify ∧ msg∉transcript) is satisfiable at the EMPTY
transcript by a genuine valid KAT signature, deriving `False`. You cannot
state "no forgery exists" as a true Prop — EUF-CMA is *computational*
(forgeries exist; they are merely infeasible to find without `sk`).

The reconciled shape is the qualitative shadow of the EasyCrypt game with
TWO independent firewalls so a hand-decoded KAT can never re-detonate it:

  1. **Key-bound transcript.** `KeyHistory sk transcript` ties the transcript
     to the key (everything in it was signed by `sk`, and everything `sk`
     signs is in it). Then `KeyHistory sk []` forces `sk` to sign nothing, so
     the empty-transcript witness is UNFORMABLE for any real signing key.
  2. **Reduction conclusion.** The axiom concludes an *opaque* `BreaksHash`
     (a SHA-256 hardness break), NOT `False`. So even a witness formed with a
     mismatched key yields only an unrefutable token, never `False`.
     INVARIANT: `BreaksHash` must NEVER be assumed false (no `¬ BreaksHash`
     anywhere) — that would re-introduce the original inconsistency.

What is LOST vs textbook EUF-CMA: the quantitative `Pr[A wins] ≤ ε` bound and
the PPT/probabilistic adversary (those need a probability backbone, out of
scope and mathlib-free here). theft_free's SAFETY guarantee (conjunct 1) is
EUF-CMA-free regardless; this axiom only threads the cited crypto hardness
into the dependency closure as the honest "a forgery would break SHA-256".

## Why this is an axiom rather than a theorem

To convert it into a `theorem` we would replay the
Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT 2024 EasyCrypt SPHINCS+
proof (~50k lines, multi-person-year) and extend it to WOTS+C/FORS+C — out of
scope. The axiom records the assumption explicitly so it appears in
docs/AXIOMS.md and any auditor sees the cryptographic-security theorem is
*cited*, not *proved* in Lean. The three SHA-256 hardness preconditions are
threaded so all crypto axioms appear in the dep closure of any consumer.

## Citations

* Manuel Barbosa, François Dupressoir, Andreas Hülsing, Matthias Meijers,
  Pierre-Yves Strub, "A Tight Security Proof for SPHINCS+, Formally Verified,"
  IACR ePrint 2024/910, ASIACRYPT 2024, LNCS 15487.
  Companion repo: github.com/MM45/FV-SPHINCSPLUS-EC
* Andreas Hülsing et al., "SPHINCS+C: Compressing SPHINCS+ With (Almost) No
  Cost," NIST PQC2022 Standardization Conference.
* Andreas Hülsing, Mikhail Kudinov, "Recovering the tight security proof of
  SPHINCS+," ASIACRYPT 2022.
-/

import SphincsCVerify.Crypto.Assumptions
import SphincsCVerify.Spec.Signer
import SphincsCVerify.Spec.Signature
import SphincsCVerify.Spec.Hypertree

namespace SphincsCVerify.Crypto

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Signer
open SphincsCVerify.Spec.Hypertree
open SphincsCVerify.Spec.Signature

/-! ## Transcript + the hardness-break token -/

/-- A signing transcript: list of (message, signature) pairs produced by the
    honest signer (the EUF-CMA game's oracle log). -/
def Transcript : Type := List (ByteVec 32 × Hypertree.Signature)

/-- Does the transcript contain a signature on `msgStar`? -/
def transcriptHasMsg (transcript : Transcript) (msgStar : ByteVec 32) : Prop :=
  ∃ s, List.Mem (msgStar, s) transcript

/-- **Opaque SHA-256 hardness break.** The reduction's conclusion: a forgery
    against an honest key on an un-queried message would constitute a break of
    the cited SHA-256 hardness assumptions. Opaque (no constructor / no
    eliminator), so it can be *concluded* but never *refuted*. Firewall #2:
    NEVER assume `¬ BreaksHash` — that re-detonates the inconsistency. -/
opaque BreaksHash : Prop

/-- **Key-bound signing history** (firewall #1 — the EUF-CMA oracle-log
    invariant). `KeyHistory sk transcript` says the transcript IS exactly the
    set of messages `sk` has signed: every recorded pair was produced by `sk`,
    and every message `sk` can sign is recorded. Consequence: `KeyHistory sk []`
    forces `sk` to sign nothing, so a genuine valid signature can never be
    paired with the empty transcript — the original detonator is unformable at
    the type level. -/
structure KeyHistory (sk : SigningKey) (transcript : Transcript) : Prop where
  /-- Everything recorded was honestly signed by `sk`. -/
  mem_signed : ∀ m s, List.Mem (m, s) transcript → Signer.sign sk m = some s
  /-- Everything `sk` signs is recorded (the oracle log is complete). -/
  signed_recorded : ∀ m s, Signer.sign sk m = some s → transcriptHasMsg transcript m

/-- The "wins" predicate: `(msg*, σ*)` is a forgery against `sk`'s honest
    signing history iff (0) the transcript is `sk`'s complete signing log,
    (a) the verifier accepts `(sk.pk, msg*, σ*)`, and (b) `msg*` is NOT in the
    log. Carrying `KeyHistory` as conjunct 0 is firewall #1. -/
def isForgery
    (sk : SigningKey) (transcript : Transcript)
    (msgStar : ByteVec 32) (sigStar : Hypertree.Signature) : Prop :=
  KeyHistory sk transcript
  ∧ Hypertree.verify sk.pkSeed sk.pkRoot msgStar sigStar = true
  ∧ ¬ transcriptHasMsg transcript msgStar

/-! ## The EUF-CMA security axiom (reduction form) -/

/-- **EUF-CMA security of SPHINCS+C10 (reduction form).**

    For an adversary given only the public key and a key-bound signing oracle,
    producing an accepting signature on a message it did not query (a
    `isForgery`) would break one of the cited SHA-256 hardness assumptions
    (`BreaksHash`). This is the qualitative shadow of the Barbosa et al. 2024
    advantage bound: the quantitative `Pr ≤ ε` is not formalised here.

    Consistency: conclusion is the opaque `BreaksHash`, never `False`; and the
    `KeyHistory` conjunct of `isForgery` makes the empty-transcript valid-KAT
    witness unformable. Both firewalls are exercised by the guard lemmas
    below and the regression probe in `scripts/`. -/
axiom EUF_CMA_SPHINCSplusC :
    SM_DT_TCR_F_Shape →
    ITSR_F_Shape →
    hMsg_RO_Shape →
    ∀ (sk : SigningKey) (transcript : Transcript)
      (msgStar : ByteVec 32) (sigStar : Hypertree.Signature),
      isForgery sk transcript msgStar sigStar → BreaksHash

/-! ## Corollaries used downstream -/

/-- **A forgery breaks SHA-256.** Restatement of `EUF_CMA_SPHINCSplusC` for the
    wallet-level non-bypass argument: a forgery against the slot key's honest
    history implies a SHA-256 hardness break. (Threads the three SHA-256
    hardness witnesses into the dep closure.) -/
theorem cannot_forge_without_breaking_SHA256
    (sk : SigningKey) (transcript : Transcript)
    (msgStar : ByteVec 32) (sigStar : Hypertree.Signature)
    (hf : isForgery sk transcript msgStar sigStar) :
    BreaksHash :=
  EUF_CMA_SPHINCSplusC SM_DT_TCR_F ITSR_F hMsg_random_oracle
    sk transcript msgStar sigStar hf

/-! ## Self-audit guard lemmas (structural regression fence)

These compile-fail if `KeyHistory` is ever weakened back to a free list — the
exact change that would re-open the empty-transcript detonator. They close
over only {propext, Quot.sound}. -/

/-- Firewall #1: a key with an EMPTY honest history signs nothing. -/
theorem keyHistory_empty_signs_nothing
    (sk : SigningKey) (h : KeyHistory sk []) (m : ByteVec 32) (s : Hypertree.Signature) :
    Signer.sign sk m ≠ some s := by
  intro hsign
  obtain ⟨s', hmem⟩ := h.signed_recorded m s hsign
  cases hmem

/-- Firewall #1: an honestly-signed message is never a forgery against the
    key's own history (the empty-transcript valid-KAT detonator is unformable). -/
theorem honest_sig_not_forgery
    (sk : SigningKey) (t : Transcript) (h : KeyHistory sk t)
    (m : ByteVec 32) (s : Hypertree.Signature) (hsign : Signer.sign sk m = some s) :
    ¬ isForgery sk t m s := by
  intro hforge
  exact hforge.2.2 (h.signed_recorded m s hsign)

end SphincsCVerify.Crypto
