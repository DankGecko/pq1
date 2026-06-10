You are closing a single Lean 4 proof obligation in the PQSigner §33
firmware-verification project (extracted Rust → Lean via Aeneas). The
Lean KERNEL re-checks your work, so a wrong proof simply fails to
compile — produce only proofs that `lake build` accepts.

## Hard rules
- Work ONLY inside `contracts/verification/extracted/`. Do NOT touch any
  other file, and do NOT edit the extracted `Extracted/*/Funs.lean` /
  `Types.lean` (generated code) or the SphincsCVerify project.
- Replace EXACTLY the one `sorry` / target named below with a real
  proof. Do not weaken the theorem statement, add axioms, or introduce
  new `sorry`s anywhere.
- The proof MUST build (`lake build <module>`) AND its axiom closure
  must stay within `[propext, Classical.choice, Quot.sound]` plus the
  already-cited content axioms (`keccak256_pure`). Run
  `#print axioms <thm>` to confirm — NO `sorryAx`.
- Prefer the established tactics in this project (below). When you need
  a Mathlib lemma you don't know the name of, use `exact?` / `apply?` /
  `rw?` / `simp?` to discover it rather than guessing.

## Proven patterns already in `Extracted/ForsLoop.lean` (reuse them)
- Loops: `apply Aeneas.Std.loop.spec_decr_nat (measure := …) (inv := …)`;
  step the iterator with `let* ⟨o, iter1, hpost⟩ ← next_usize_spec it`
  then `rcases hpost with ⟨ho,hle⟩ | ⟨b,it',heq,hb',hlt,hend',hstart⟩`.
- Monadic execution: `step*` (auto-discharges most bounds/panic goals);
  close side goals with `scalar_tac`. Unfold the irreducible C10 params
  with `simp only [params.K, params.A, params.H]` BEFORE `step*` so
  `scalar_tac` can see their literal values.
- Byte/array writes: `SetSliceLemmas` (setSlice!→concatenation);
  `List.set_getElem!_eq` / `List.set_getElem!_ne` for `Array.update`.
- Casts: `UScalar.cast_val_eq`; checked arith specs are `@[step]`.

## The target
