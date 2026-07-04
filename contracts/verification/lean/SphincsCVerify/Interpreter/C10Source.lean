/-
SphincsCVerify.Interpreter.C10Source — the PINNED source text of the deployed
verifier's assembly interior, and the FAITHFUL parse target `c10ProgramFull`.

`c10Source` is EXACTLY lines 37-230 of
`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol` — the interior of the
`verify(...)` `assembly { ... }` block (not the wrapper braces) — embedded as a
raw string literal, byte-for-byte including each line's trailing newline.
`scripts/check_c10_source_pin.py` (wired into `make verify-transcription` and
the `a31-transcription.yml` CI job) asserts this literal equals
`sed -n '37,230p'` of the `.sol` so the literal cannot drift from the file
(and regenerates it with `--write` after a legitimate `.sol` change).

`c10ProgramFull` is what a FAITHFUL parse of that source produces: exactly
`c10Program` (the hand transcription the kernel proof `execC10Asm_eq`
consumes) with its two — and only two — documented normalizations undone:

  (N1) the 4 error-string `mstore`s inside the sig-length gate body
       (`.sol` L44-47) are RESTORED before the `.revert` (c10Program elides
       them — they cannot affect the Bool verdict);
  (N2) `valid := eq(currentNode, root)` (`.sol` L228) is the `.setv`
       reassignment it is in the Yul (Solidity's `returns (bool valid)`
       pre-declares it; c10Program models the first write as `.letv`).

These are the same two rules the Python structural checker
(`scripts/check_c10_transcription_ast.py`) documents; the kernel theorem
`parse_c10 : parseYul c10Source = some c10ProgramFull` (Interpreter/C10Parse.lean)
+ the elision bridge `execFrom_c10ProgramFull_eq` (ibid.) replace trusting
those rules with a machine-checked equivalence. `c10ProgramFull` is built from
shared pieces of `c10Program` itself (`take`/`drop` slices pinned by the
kernel-checked decomposition `c10Program_decomp`), so it CANNOT silently drift
from the transcription: any edit to `c10Program`'s shape breaks the `rfl`.

Mathlib-free (Lean core only); no `sorry`/`admit`/`axiom`/`native_decide`.
-/

import SphincsCVerify.Interpreter.C10Program

namespace SphincsCVerify.Interpreter.C10

/-! ## The pinned source (SPHINCsC10Asm.sol L37-230, byte-exact) -/

/-- EXACT bytes of `SPHINCsC10Asm.sol` lines 37-230 (the `assembly { }`
    interior). Pinned to the file by `scripts/check_c10_source_pin.py`;
    do NOT edit by hand — regenerate with `--write`. -/
def c10Source : String := r#"            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
            // Scratch slot for SHA-256 precompile output. Sits above every
            // other memory region the verifier touches (WOTS endpoints at
            // 0x80 + 42*32 = 0x5C0 is the highest legitimate write).
            let OUT := 0x600

            if iszero(eq(sig.length, 4008)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            // Audit I-2: enforce the N-mask layout (top 16 bytes set,
            // bottom 16 bytes zero) on `pkSeed` / `pkRoot` directly in
            // the verifier, instead of relying on every caller (today
            // only `PQMultiOwnable._addOwnerAtIndex`) to pre-validate.
            // Returning `false` rather than reverting keeps the
            // existing "verifier never reverts on key-shape" contract
            // intact for upstream wrappers that use `try / catch`.
            if iszero(eq(and(pkSeed, N_MASK), pkSeed)) {
                mstore(0x00, 0)
                return(0x00, 0x20)
            }
            if iszero(eq(and(pkRoot, N_MASK), pkRoot)) {
                mstore(0x00, 0)
                return(0x00, 0x20)
            }

            let seed := pkSeed
            let root := pkRoot
            mstore(0x00, seed)

            // H_msg (domain-separated, 160 bytes)
            let R := and(calldataload(sig.offset), N_MASK)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            pop(staticcall(gas(), 0x02, 0x00, 0xA0, OUT, 32))
            let digest := mload(OUT)

            // htIdx = (digest >> 143) & (2^18-1)
            let htIdx := and(shr(143, digest), 0x3FFFF)

            // FORS+C (K=13, A=11)
            let dVal := digest
            // Forced-zero: last index (i=12) at bits 132..142
            if and(shr(132, dVal), 0x7FF) { revert(0, 0) }

            let sigBase := sig.offset
            // K-1=12 normal trees
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 11), dVal), 0x7FF) // 11-bit indices
                let secretVal := and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK)
                // FORS forest bound to hypertree leaf position: htIdx in the
                // ADRS tree field (bits 160..223). Mirrors the Rust signer's
                // make_adrs(0, ht_idx, FORS_TREE, ...). Without it the FORS
                // forest is shared across all 2^18 positions and forgeable.
                let leafAdrs := or(shl(160, htIdx), or(shl(128, 3), or(shl(96, i), treeIdx)))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                pop(staticcall(gas(), 0x02, 0x00, 0x60, OUT, 32))
                let node := and(mload(OUT), N_MASK)

                let treeAdrsBase := or(shl(160, htIdx), or(shl(128, 3), shl(96, i)))
                let pathIdx := treeIdx
                // AUTH_START=224, auth per tree = 11*16 = 176
                let authPtr := add(sigBase, add(224, mul(i, 176)))

                // Walk A=11 auth path levels
                for { let h := 0 } lt(h, 11) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    mstore(0x20, or(treeAdrsBase, or(shl(32, add(h, 1)), parentIdx)))
                    // Branchless Merkle swap
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    pop(staticcall(gas(), 0x02, 0x00, 0x80, OUT, 32))
                    node := and(mload(OUT), N_MASK)
                    pathIdx := parentIdx
                }
                mstore(add(0x80, shl(5, i)), node)
            }

            // Last tree (forced-zero)
            {
                let lastSecret := and(calldataload(add(sigBase, add(16, shl(4, 12)))), N_MASK) // 16+12*16=208
                mstore(0x20, or(shl(160, htIdx), or(shl(128, 3), shl(96, 12))))
                mstore(0x40, lastSecret)
                // 0x80 + 12*0x20 = 0x80 + 0x180 = 0x200
                pop(staticcall(gas(), 0x02, 0x00, 0x60, OUT, 32))
                mstore(0x200, and(mload(OUT), N_MASK))
            }

            // Compress 13 roots: sha256(seed || rootsAdrs || 13 roots)
            // = 32 + 32 + 13*32 = 480 = 0x1E0
            // rootsAdrs also carries htIdx in the tree field (position binding).
            mstore(0x20, or(shl(160, htIdx), shl(128, 4)))
            for { let i := 0 } lt(i, 13) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            pop(staticcall(gas(), 0x02, 0x00, 0x1E0, OUT, 32))
            let forsPk := and(mload(OUT), N_MASK)

            // Hypertree (D=2, subtree_h=9, w=8, l=43, target_sum=205)
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 2336 // HT_START

            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x1FF) // 2^9 - 1
                idxTree := shr(9, idxTree)

                let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))
                // countOff = sigOff + l*N = sigOff + 688
                let countOff := add(sigOff, 688)
                let count := shr(224, calldataload(add(sigBase, countOff)))

                mstore(0x00, seed)
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                pop(staticcall(gas(), 0x02, 0x00, 0x80, OUT, 32))
                let d := mload(OUT)

                // Validate digit sum = 205 (43 base-8 digits, 3 bits each)
                let digitSum := 0
                for { let ii := 0 } lt(ii, 43) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 3), d), 0x7))
                }
                if iszero(eq(digitSum, 205)) { revert(0, 0) }

                // 43 WOTS chains (w=8: max 7 steps per chain)
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 3), d), 0x7)
                    let steps := sub(7, digit)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    let chainBase := and(
                        or(wotsAdrs, shl(64, i)),
                        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF
                    )

                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        mstore(0x20, or(chainBase, shl(32, add(digit, step))))
                        mstore(0x40, val)
                        pop(staticcall(gas(), 0x02, 0x00, 0x60, OUT, 32))
                        val := and(mload(OUT), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // PK compression: sha256(seed || pkAdrs || 43 endpoints)
                // = 32 + 32 + 43*32 = 1440 = 0x5A0
                let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 43) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                pop(staticcall(gas(), 0x02, 0x00, 0x5A0, OUT, 32))
                let wotsPk := and(mload(OUT), N_MASK)

                // Merkle auth path (9 levels)
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := add(sigBase, authOff)

                for { let h := 0 } lt(h, 9) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(merklePtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, mIdx)
                    mstore(0x20, or(
                        and(treeAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000),
                        or(shl(32, add(h, 1)), parentIdx)
                    ))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    pop(staticcall(gas(), 0x02, 0x00, 0x80, OUT, 32))
                    merkleNode := and(mload(OUT), N_MASK)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(authOff, 144) // 9*16
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
"#

/-! ## The faithful parse target -/

/-- The FULL body of the sig-length gate (`.sol` L43-49): the 4 error-string
    `mstore`s (revert-payload assembly, incl. the `"Invalid sig length"`
    string as its left-aligned 32-byte word) + the `revert`. `c10Program`
    elides the `mstore`s (N1). -/
def errBody : List Stmt :=
  [ .mstore (.lit 0x00) (.lit 0x08c379a000000000000000000000000000000000000000000000000000000000)
  , .mstore (.lit 0x04) (.lit 0x20)
  , .mstore (.lit 0x24) (.lit 18)
  , .mstore (.lit 0x44) (.lit 0x496e76616c696420736967206c656e6774680000000000000000000000000000)
  , .revert ]

/-- Statements 0-1 of `c10Program` (`let N_MASK`, `let OUT`). -/
def c10Pre : List Stmt := c10Program.take 2

/-- The sig-length gate condition (`.sol` L43). -/
def lenGate : Expr := .iszero (.bin .eq .sigLength (.lit 4008))

/-- Statements 3-28 of `c10Program` (everything between the sig-length gate
    and the `valid` binding — the entire verifier body). -/
def c10Mid : List Stmt := (c10Program.drop 3).take 26

/-- The `valid` expression (`.sol` L228). -/
def validExpr : Expr := .bin .eq (.var "currentNode") (.var "root")

/-- Statements 30-31 of `c10Program` (`mstore(0x00, valid)`, `return`). -/
def c10Tail : List Stmt := c10Program.drop 30

/-- **Kernel-checked decomposition of `c10Program`.** Pins the shared pieces
    (`c10Pre`/`c10Mid`/`c10Tail` slices AND the literally-restated `lenGate` /
    `validExpr` / gate-body / `.letv "valid"`), so `c10ProgramFull` below
    cannot drift from the transcription: any shape edit to `c10Program`
    breaks this `rfl`. -/
theorem c10Program_decomp :
    c10Program
      = c10Pre ++ (.ifnz lenGate [.revert]
          :: (c10Mid ++ (.letv "valid" validExpr :: c10Tail))) := rfl

/-- The faithful parse of `c10Source`: `c10Program` with (N1) the error-string
    `mstore`s restored and (N2) `valid := …` as the `.setv` it is in the Yul.
    `parse_c10` (Interpreter/C10Parse.lean) proves `parseYul c10Source = some
    c10ProgramFull` in the kernel; `execFrom_c10ProgramFull_eq` (ibid.) proves
    it verdict-equal to `c10Program` for every oracle/signature/state. -/
def c10ProgramFull : List Stmt :=
  c10Pre ++ (.ifnz lenGate errBody
      :: (c10Mid ++ (.setv "valid" validExpr :: c10Tail)))

-- Shape smoke-checks (compile-time).
#guard c10Program.length == 32
#guard c10ProgramFull.length == 32
#guard c10Source.length == 9256   -- ASCII source: chars = bytes

end SphincsCVerify.Interpreter.C10
