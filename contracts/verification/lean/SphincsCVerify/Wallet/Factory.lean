/-
Lean model of `PQSmartWalletFactory`.

The factory deploys a deterministic ERC-1967 proxy under
`CREATE2(salt = sha256(masterPkSeed ‖ masterPkRoot))`. The squat-defence
property is: a deployment requires a SPHINCS+C10 signature by the
bootstrap key over `(chainId, slot0PkSeed, slot0PkRoot)`. We restate
this as a pure functional check; the deployment side-effect
(`createDeterministicERC1967`) is in the EVM TCB.
-/

import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Spec.Signature
import SphincsCVerify.Spec.Hypertree
import SphincsCVerify.Wallet.Storage

namespace SphincsCVerify.Wallet.Factory

open SphincsCVerify.Spec
open SphincsCVerify.Spec.Signature
open SphincsCVerify.Spec.Hypertree
open SphincsCVerify.Wallet
open ByteVec

/-- The domain tag prefixed before `(chainId, slot0PkSeed, slot0PkRoot)` in the
    squat-defence digest. Sourced from `PqsignerProto.FACTORY_ADD_SLOT_DOMAIN`.

    Concrete 25-byte value `b"pqwallet-factory-add-slot"` — byte-identical to
    `proto/src/lib.rs::FACTORY_ADD_SLOT_DOMAIN`, the Solidity
    `PqsignerProto.FACTORY_ADD_SLOT_DOMAIN` / `PQSmartWalletFactory.addSlot0Digest`,
    and the firmware factory_calldata signing preimage. This was previously an
    `opaque ByteVec 26` whose docstring claimed `pqsigner.factoryAddSlot.v1` — a
    domain drift (finding P7): both the length (26 vs 25) and the bytes differed
    from the digest the device actually signs and the deployed factory checks, so
    the squat-defence proof (invariant #6) was not bound to the real digest.
    Pinning the concrete bytes binds `addSlot0Digest` to the deployed preimage. -/
def factoryAddSlotDomain : ByteVec 25 :=
  ⟨#[0x70, 0x71, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x2d,
     0x66, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x2d,
     0x61, 0x64, 0x64, 0x2d, 0x73, 0x6c, 0x6f, 0x74],
   by decide⟩  -- "pqwallet-factory-add-slot"

/-- The squat-defence digest: `sha256(DOMAIN ‖ chainId ‖ slot0PkSeed ‖ slot0PkRoot)`.

    Mirrors `addSlot0Digest` in `PQSmartWalletFactory.sol`. -/
def addSlot0Digest
    (chainId : UInt64) (slot0PkSeed slot0PkRoot : ByteVec 32) : ByteVec 32 :=
  sha256 [
    ByteSeg.ofByteVec factoryAddSlotDomain,
    ByteSeg.ofByteVec (ofU64BE chainId),
    ByteSeg.ofByteVec slot0PkSeed,
    ByteSeg.ofByteVec slot0PkRoot]

/-- The CREATE2 salt for a wallet bound to `(masterPkSeed, masterPkRoot)`. -/
def salt (masterPkSeed masterPkRoot : ByteVec 32) : ByteVec 32 :=
  sha256 [
    ByteSeg.ofByteVec masterPkSeed,
    ByteSeg.ofByteVec masterPkRoot]

/-- N-mask layout: the bottom 16 bytes of a 32-byte key half are zero
    (C10's `N = 16`-byte values occupy the top half). Mirrors
    `PQMultiOwnable._addOwnerAtIndex`'s
    `uint128(uint256(half)) != 0 → revert InvalidNMaskLayout`. -/
def nMasked (half : ByteVec 32) : Prop :=
  ∀ i : Fin 32, 16 ≤ i.val → half.get i = 0

/-- The factory's `createAccount` pre-condition (fresh-deploy arm): the
    bootstrap key must have signed the slot-0 digest on this chain, AND
    the owner-install gates of `PQMultiOwnable._addOwnerAtIndex` must
    hold — all four key halves N-masked, and the slot-0 owner bytes
    distinct from the bootstrap owner bytes (the duplicate-owner check;
    the bootstrap owner is installed first, so only the slot-0 install
    can collide at `initialize` time).

    The gate conjuncts were added 2026-06-10 for bytecode faithfulness:
    the deployed `initialize → _addOwnerAtIndex` path reverts on any of
    them, so a precondition stating only the signature check is
    observably weaker than the bytecode — found as a concrete
    counterexample (non-N-masked `slot0PkRoot`) by the widened Halmos
    rule `check_createAccount_iff_lean_precondition`. -/
def createAccountPrecondition
    (masterPkSeed masterPkRoot slot0PkSeed slot0PkRoot : ByteVec 32)
    (chainId : UInt64) (factorySig : ByteVec SignatureLen)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool) :
    Prop :=
  verify_fn masterPkSeed masterPkRoot
    (addSlot0Digest chainId slot0PkSeed slot0PkRoot) factorySig = true
  ∧ nMasked masterPkSeed ∧ nMasked masterPkRoot
  ∧ nMasked slot0PkSeed ∧ nMasked slot0PkRoot
  ∧ ¬(slot0PkSeed = masterPkSeed ∧ slot0PkRoot = masterPkRoot)

/-- The CREATE2 **salt** does not depend on `chainId` — the `salt` function takes
    only `(masterPkSeed, masterPkRoot)`, so the two chain parameters here are
    unused (witnessing that no chainId enters the salt). This is the salt-preimage
    leg of invariant #6.

    **Honest scope (P11).** This is NOT the address-level claim. "Same 24 words →
    same *address* on every chain" additionally requires the EVM-TCB facts that
    the deployer (singleton factory) and `keccak256(initCode)` are themselves
    chain-free; that conditional address-level theorem is
    `Invariants.create2Address_chain_independent` (with `d1=d2` / `ich1=ich2`
    hypotheses), not this reflexive salt fact. -/
theorem salt_chain_independent
    (masterPkSeed masterPkRoot : ByteVec 32) (_chain1 _chain2 : UInt64) :
    salt masterPkSeed masterPkRoot = salt masterPkSeed masterPkRoot := by
  rfl

end SphincsCVerify.Wallet.Factory
