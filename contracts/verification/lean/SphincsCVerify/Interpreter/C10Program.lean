/-
SphincsCVerify.Interpreter.C10Program — the deployed `SPHINCsC10Asm.sol` Yul,
transcribed statement-for-statement into the `Interpreter.Yul` AST.

This is the **transcription** half of the full-(a) interpreter-refinement plan
(see `docs/A3_1_CLOSURE_PATH.md` §8): `c10Program : List Stmt` is a faithful,
line-by-line mirror of the `verify(...)` assembly block in
`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol` (the codehash-pinned
deployed verifier). Inline `-- L<n>` comments tie each fragment to the `.sol`
source line. `execC10Asm` runs it under the *real* computable `Spec.Sha256Impl`
SHA-256 as the `0x02` precompile oracle, so the whole verifier is **executable**.

The point of THIS module + the `InterpMain` runner is the advisor's load-bearing
condition: **reproduce the existing KAT 10/10 + bulk 384/384 + mutant/near-miss
corpus THROUGH `execC10Asm`, asserting agreement with `Spec.Signature.verify`** —
*before* any phase-refinement proof. That agreement is the empirical
interpreter↔bytecode bridge and gives the eventual transcription axiom the same
backing the current A3.1 axiom has.

Modeling notes (all faithful for this Yul; see §8 "honesty nudges"):
  * `sig.offset` = 0, `sig.length` = 4008 (our `ByteVec SignatureLen` blob);
    `calldataload` = `loadWord32` (zero-pads past the blob, matching the spec).
  * `pkSeed`/`pkRoot`/`message` enter as the function's *parameter bindings*
    (initial env), so `c10Program` is a true constant = the Yul.
  * `revert(...)` → the Bool verdict `false` (matches how callers + the spec treat
    a reverting verifier); `return(0x00,0x20)` → `mem[0x00] == 1`.
  * Error-string `mstore`s before a `revert` are elided (irrelevant to the Bool).
-/

import SphincsCVerify.Interpreter.Yul
import SphincsCVerify.Interpreter.Sha256Bridge
import SphincsCVerify.Spec.Sha256Impl
import SphincsCVerify.Spec.Params

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify.Interpreter
open SphincsCVerify.Spec (ByteVec)

/-! ## Expression helpers — argument order matches Yul exactly
(`shl a b = b << a`, `shr a b = b >> a`: first arg is the shift amount). -/

private def lit (k : Nat) : Expr := .lit k
private def var (s : String) : Expr := .var s
private def cl (off : Expr) : Expr := .calldataload off
private def ml (off : Expr) : Expr := .mload off
private def isz (a : Expr) : Expr := .iszero a
private def eAdd (a b : Expr) : Expr := .bin .add a b
private def eSub (a b : Expr) : Expr := .bin .sub a b
private def eMul (a b : Expr) : Expr := .bin .mul a b
private def eAnd (a b : Expr) : Expr := .bin .band a b
private def eOr  (a b : Expr) : Expr := .bin .bor a b
private def eXor (a b : Expr) : Expr := .bin .bxor a b
private def eShl (a b : Expr) : Expr := .bin .shl a b   -- Yul shl(a,b) = b << a
private def eShr (a b : Expr) : Expr := .bin .shr a b   -- Yul shr(a,b) = b >> a
private def eEq  (a b : Expr) : Expr := .bin .eq a b
private def eLt  (a b : Expr) : Expr := .bin .lt a b

/-! ## The masks, copied verbatim from `SPHINCsC10Asm.sol`. -/

/-- L37: top 16 bytes set, bottom 16 zero. -/
private def NMASK : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
/-- L76: 32 bytes of 0xFF (H_msg domain separator). -/
private def ALLFF : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
/-- L180: keep WOTS chain ADRS layer/tree/keypair, mask out chain idx low word. -/
private def CHAINBASE_MASK : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF
/-- L213: keep hypertree Merkle ADRS high fields, mask out the leaf index. -/
private def TREEADRS_MASK : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000

/-! ## The transcription: `verify(pkSeed, pkRoot, message, sig)` (`.sol` L36–231). -/

/-- The deployed `SPHINCsC10Asm.verify` Yul, statement-for-statement. -/
def c10Program : List Stmt :=
  [ -- L37,41: scratch constants
    .letv "N_MASK" (lit NMASK)
  , .letv "OUT" (lit 0x600)
    -- L43-49: sig length must be 4008 (our ByteVec guarantees it; dead branch)
  , .ifnz (isz (eEq .sigLength (lit 4008))) [ .revert ]
    -- L58-65: pkSeed / pkRoot must already be in N-mask shape, else return false
  , .ifnz (isz (eEq (eAnd (var "pkSeed") (var "N_MASK")) (var "pkSeed")))
      [ .mstore (lit 0x00) (lit 0), .ret (lit 0x00) ]
  , .ifnz (isz (eEq (eAnd (var "pkRoot") (var "N_MASK")) (var "pkRoot")))
      [ .mstore (lit 0x00) (lit 0), .ret (lit 0x00) ]
    -- L67-69
  , .letv "seed" (var "pkSeed")
  , .letv "root" (var "pkRoot")
  , .mstore (lit 0x00) (var "seed")
    -- L72-78: H_msg (domain-separated, 160 bytes)
  , .letv "R" (eAnd (cl .sigOffset) (var "N_MASK"))
  , .mstore (lit 0x20) (var "root")
  , .mstore (lit 0x40) (var "R")
  , .mstore (lit 0x60) (var "message")
  , .mstore (lit 0x80) (lit ALLFF)
  , .sha256 (lit 0x00) (lit 0xA0) (var "OUT")
  , .letv "digest" (ml (var "OUT"))
    -- L81: htIdx = (digest >> 143) & (2^18-1)
  , .letv "htIdx" (eAnd (eShr (lit 143) (var "digest")) (lit 0x3FFFF))
    -- L84-86: FORS+C; forced-zero last index (bits 132..142) must be 0
  , .letv "dVal" (var "digest")
  , .ifnz (eAnd (eShr (lit 132) (var "dVal")) (lit 0x7FF)) [ .revert ]
    -- L88
  , .letv "sigBase" .sigOffset
    -- L90-122: K-1 = 12 normal FORS trees
  , .forRange "i" (lit 12)
      [ .letv "treeIdx" (eAnd (eShr (eMul (var "i") (lit 11)) (var "dVal")) (lit 0x7FF))
      , .letv "secretVal"
          (eAnd (cl (eAdd (var "sigBase") (eAdd (lit 16) (eShl (lit 4) (var "i"))))) (var "N_MASK"))
      , .letv "leafAdrs"
          (eOr (eShl (lit 160) (var "htIdx"))
            (eOr (eShl (lit 128) (lit 3))
              (eOr (eShl (lit 96) (var "i")) (var "treeIdx"))))
      , .mstore (lit 0x20) (var "leafAdrs")
      , .mstore (lit 0x40) (var "secretVal")
      , .sha256 (lit 0x00) (lit 0x60) (var "OUT")
      , .letv "node" (eAnd (ml (var "OUT")) (var "N_MASK"))
      , .letv "treeAdrsBase"
          (eOr (eShl (lit 160) (var "htIdx"))
            (eOr (eShl (lit 128) (lit 3)) (eShl (lit 96) (var "i"))))
      , .letv "pathIdx" (var "treeIdx")
      , .letv "authPtr" (eAdd (var "sigBase") (eAdd (lit 224) (eMul (var "i") (lit 176))))
        -- L109-120: walk A = 11 auth-path levels
      , .forRange "h" (lit 11)
          [ .letv "sibling" (eAnd (cl (eAdd (var "authPtr") (eShl (lit 4) (var "h")))) (var "N_MASK"))
          , .letv "parentIdx" (eShr (lit 1) (var "pathIdx"))
          , .mstore (lit 0x20)
              (eOr (var "treeAdrsBase")
                (eOr (eShl (lit 32) (eAdd (var "h") (lit 1))) (var "parentIdx")))
            -- branchless Merkle swap
          , .letv "s" (eShl (lit 5) (eAnd (var "pathIdx") (lit 1)))
          , .mstore (eXor (lit 0x40) (var "s")) (var "node")
          , .mstore (eXor (lit 0x60) (var "s")) (var "sibling")
          , .sha256 (lit 0x00) (lit 0x80) (var "OUT")
          , .setv "node" (eAnd (ml (var "OUT")) (var "N_MASK"))
          , .setv "pathIdx" (var "parentIdx")
          ]
      , .mstore (eAdd (lit 0x80) (eShl (lit 5) (var "i"))) (var "node")
      ]
    -- L124-132: last FORS tree (forced-zero), a `{ }` scope
  , .block
      [ .letv "lastSecret"
          (eAnd (cl (eAdd (var "sigBase") (eAdd (lit 16) (eShl (lit 4) (lit 12))))) (var "N_MASK"))
      , .mstore (lit 0x20)
          (eOr (eShl (lit 160) (var "htIdx"))
            (eOr (eShl (lit 128) (lit 3)) (eShl (lit 96) (lit 12))))
      , .mstore (lit 0x40) (var "lastSecret")
      , .sha256 (lit 0x00) (lit 0x60) (var "OUT")
      , .mstore (lit 0x200) (eAnd (ml (var "OUT")) (var "N_MASK"))
      ]
    -- L137-142: compress 13 FORS roots (480 bytes)
  , .mstore (lit 0x20) (eOr (eShl (lit 160) (var "htIdx")) (eShl (lit 128) (lit 4)))
  , .forRange "i" (lit 13)
      [ .mstore (eAdd (lit 0x40) (eShl (lit 5) (var "i"))) (ml (eAdd (lit 0x80) (eShl (lit 5) (var "i")))) ]
  , .sha256 (lit 0x00) (lit 0x1E0) (var "OUT")
  , .letv "forsPk" (eAnd (ml (var "OUT")) (var "N_MASK"))
    -- L145-147: hypertree
  , .letv "currentNode" (var "forsPk")
  , .letv "idxTree" (var "htIdx")
  , .letv "sigOff" (lit 2336)
    -- L149-226: D = 2 hypertree layers
  , .forRange "layer" (lit 2)
      [ .letv "idxLeaf" (eAnd (var "idxTree") (lit 0x1FF))
      , .setv "idxTree" (eShr (lit 9) (var "idxTree"))
      , .letv "wotsAdrs"
          (eOr (eShl (lit 224) (var "layer"))
            (eOr (eShl (lit 160) (var "idxTree")) (eShl (lit 96) (var "idxLeaf"))))
      , .letv "countOff" (eAdd (var "sigOff") (lit 688))
      , .letv "count" (eShr (lit 224) (cl (eAdd (var "sigBase") (var "countOff"))))
      , .mstore (lit 0x00) (var "seed")
      , .mstore (lit 0x20) (var "wotsAdrs")
      , .mstore (lit 0x40) (var "currentNode")
      , .mstore (lit 0x60) (var "count")
      , .sha256 (lit 0x00) (lit 0x80) (var "OUT")
      , .letv "d" (ml (var "OUT"))
        -- L166-170: WOTS+C digit-sum gate (43 base-8 digits sum to 205)
      , .letv "digitSum" (lit 0)
      , .forRange "ii" (lit 43)
          [ .setv "digitSum"
              (eAdd (var "digitSum") (eAnd (eShr (eMul (var "ii") (lit 3)) (var "d")) (lit 0x7))) ]
      , .ifnz (isz (eEq (var "digitSum") (lit 205))) [ .revert ]
        -- L173-190: 43 WOTS chains
      , .letv "wotsPtr" (eAdd (var "sigBase") (var "sigOff"))
      , .forRange "i" (lit 43)
          [ .letv "digit" (eAnd (eShr (eMul (var "i") (lit 3)) (var "d")) (lit 0x7))
          , .letv "steps" (eSub (lit 7) (var "digit"))
          , .letv "val" (eAnd (cl (eAdd (var "wotsPtr") (eShl (lit 4) (var "i")))) (var "N_MASK"))
          , .letv "chainBase"
              (eAnd (eOr (var "wotsAdrs") (eShl (lit 64) (var "i"))) (lit CHAINBASE_MASK))
          , .forRange "step" (var "steps")
              [ .mstore (lit 0x20) (eOr (var "chainBase") (eShl (lit 32) (eAdd (var "digit") (var "step"))))
              , .mstore (lit 0x40) (var "val")
              , .sha256 (lit 0x00) (lit 0x60) (var "OUT")
              , .setv "val" (eAnd (ml (var "OUT")) (var "N_MASK"))
              ]
          , .mstore (eAdd (lit 0x80) (eShl (lit 5) (var "i"))) (var "val")
          ]
        -- L194-200: WOTS PK compression (43 endpoints, 1440 bytes)
      , .letv "pkAdrs"
          (eOr (eShl (lit 224) (var "layer"))
            (eOr (eShl (lit 160) (var "idxTree"))
              (eOr (eShl (lit 128) (lit 1)) (eShl (lit 96) (var "idxLeaf")))))
      , .mstore (lit 0x20) (var "pkAdrs")
      , .forRange "i" (lit 43)
          [ .mstore (eAdd (lit 0x40) (eShl (lit 5) (var "i"))) (ml (eAdd (lit 0x80) (eShl (lit 5) (var "i")))) ]
      , .sha256 (lit 0x00) (lit 0x5A0) (var "OUT")
      , .letv "wotsPk" (eAnd (ml (var "OUT")) (var "N_MASK"))
        -- L203-222: Merkle auth path (9 levels)
      , .letv "authOff" (eAdd (var "countOff") (lit 4))
      , .letv "treeAdrs"
          (eOr (eShl (lit 224) (var "layer"))
            (eOr (eShl (lit 160) (var "idxTree")) (eShl (lit 128) (lit 2))))
      , .letv "merkleNode" (var "wotsPk")
      , .letv "mIdx" (var "idxLeaf")
      , .letv "merklePtr" (eAdd (var "sigBase") (var "authOff"))
      , .forRange "h" (lit 9)
          [ .letv "sibling" (eAnd (cl (eAdd (var "merklePtr") (eShl (lit 4) (var "h")))) (var "N_MASK"))
          , .letv "parentIdx" (eShr (lit 1) (var "mIdx"))
          , .mstore (lit 0x20)
              (eOr (eAnd (var "treeAdrs") (lit TREEADRS_MASK))
                (eOr (eShl (lit 32) (eAdd (var "h") (lit 1))) (var "parentIdx")))
          , .letv "s" (eShl (lit 5) (eAnd (var "mIdx") (lit 1)))
          , .mstore (eXor (lit 0x40) (var "s")) (var "merkleNode")
          , .mstore (eXor (lit 0x60) (var "s")) (var "sibling")
          , .sha256 (lit 0x00) (lit 0x80) (var "OUT")
          , .setv "merkleNode" (eAnd (ml (var "OUT")) (var "N_MASK"))
          , .setv "mIdx" (var "parentIdx")
          ]
      , .setv "currentNode" (var "merkleNode")
      , .setv "sigOff" (eAdd (var "authOff") (lit 144))
      ]
    -- L228-230
  , .letv "valid" (eEq (var "currentNode") (var "root"))
  , .mstore (lit 0x00) (var "valid")
  , .ret (lit 0x00)
  ]

/-! ## Executable entry point -/

/-- The `0x02` SHA-256 precompile, instantiated with the project's *computable*
    FIPS-180-4 reference (`Spec.Sha256Impl`). No new axiom: this is the same
    function the spec's `sha256` is definitionally equal to. -/
def c10Oracle (l : List UInt8) : ByteVec 32 :=
  ⟨Spec.Sha256Impl.sha256Bytes l.toArray, Spec.Sha256Impl.sha256Bytes_size _⟩

/-- Run the transcribed verifier. `pkSeed`/`pkRoot`/`message` enter as the
    function's parameter bindings (their big-endian words); the signature blob is
    the calldata. Result is the Bool verdict, with `revert`→`false`. This is the
    function the refinement will prove equal to `Spec.Signature.verify`. -/
def execC10Asm (pkSeed pkRoot message : ByteVec 32)
    (sig : ByteVec Spec.SignatureLen) : Bool :=
  let env0 : VarEnv :=
    setVar (setVar (setVar (fun _ => 0) "pkSeed" (wordOf pkSeed))
      "pkRoot" (wordOf pkRoot)) "message" (wordOf message)
  execFrom c10Oracle sig c10Program env0 (fun _ => 0)

end SphincsCVerify.Interpreter.C10
