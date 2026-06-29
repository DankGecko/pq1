// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {HalmosWalletBase} from "./HalmosWalletBase.sol";

/// @notice Halmos symbolic-execution rules for the **EIP-1271** entry point
///         `PQSmartWallet.isValidSignature` / `_erc1271IsValidSignatureNowCalldata`,
///         executed against the deployed runtime bytecode. This is the
///         **net-new** surface that the A3.2 wallet harnesses
///         (`HalmosValidateUserOp` / `HalmosExecute`) do NOT cover: the
///         off-chain signature path (forbids-bootstrap, Solady
///         `replaySafeHash` nesting, the `0x1626ba7e` magic return, view-only).
///         It gives the **bytecode analogue** of the Lean model theorem
///         `Wallet/Invariants.lean::eip1271_forbids_bootstrap` (assurance-case
///         node G8), which until now bound only the Lean model.
///
///         **Scope / disclosed ceiling (matches A3.2 exactly — do not overclaim).**
///         `_erc1271IsValidSignatureNowCalldata` reads `ownerAtIndex(ownerIndex)`,
///         a dynamic-bytes getter that `NotConcreteError`s on a *symbolic*
///         non-installed index (the same Halmos engine ceiling disclosed for
///         A3.2's unset partition). So:
///           * `check_isValidSignature_forbids_bootstrap` is a genuine ∀ over
///             `hash` + the symbolic verifier answer: `ownerIndex == 0` is
///             rejected BEFORE the `ownerAtIndex` read and BEFORE the keccak
///             `replaySafeHash`, so it sidesteps both the getter ceiling and
///             symbolic keccak — a clean bytecode proof of the G8 headline.
///           * the non-bypass rule sweeps the INSTALLED slot index 1 (concrete
///             rep), like A3.2 rule 1c; the unset partition stays concrete-reps,
///             NOT a symbolic ∀.
///         keccak (`replaySafeHash`) stays uninterpreted throughout (the honest
///         hash boundary); SHA-256 is never on this path.
///
///         Run: `halmos --contract HalmosIsValidSignature`.
contract HalmosIsValidSignature is HalmosWalletBase {
    bytes4 internal constant MAGIC = 0x1626ba7e; // ERC-1271 success
    bytes4 internal constant FAILV = 0xffffffff; // ERC-1271 failure

    function setUp() public {
        wallet = _deployWalletSha256Free();
        // No 0x02 stub: the EIP-1271 path hashes only via keccak
        // (`replaySafeHash`), never SHA-256, and keccak stays the
        // uninterpreted Halmos hash boundary.
    }

    /// @dev ABI-encode a SignatureWrapper(ownerIndex, 4008-byte inner sig) —
    ///      the exact 4128-byte shape `_erc1271IsValidSignatureNowCalldata`
    ///      decodes (96 header + 4032 padded inner).
    function _wrap(uint256 ownerIndex) internal pure returns (bytes memory) {
        return abi.encode(ownerIndex, new bytes(4008));
    }

    // ──────────────────────────────────────────────────────────────────
    // G8 headline on bytecode (≡ Lean `eip1271_forbids_bootstrap`):
    // the bootstrap key (ownerIndex 0) is NEVER accepted off-chain, for
    // any message hash and any (symbolic) verifier answer. Rejected before
    // the ownerAtIndex read + verify call, so this is a clean ∀.
    // ──────────────────────────────────────────────────────────────────
    function check_isValidSignature_forbids_bootstrap(bytes32 hash) public {
        bool verifierResult = svm.createBool("verifierResult_1271bootstrap");
        c10.setValid(verifierResult);

        bytes4 ret = wallet.isValidSignature(hash, _wrap(0));

        assertTrue(ret != MAGIC, "G8 bytecode: EIP-1271 accepted bootstrap key (ownerIndex 0)");
    }

    // ──────────────────────────────────────────────────────────────────
    // Non-bypass (≡ Lean I-1 for the off-chain path): isValidSignature
    // returns the magic ONLY if the (symbolic) verifier accepted. Swept
    // over the INSTALLED slot index 1 (concrete rep — the ownerAtIndex
    // getter NotConcreteErrors on a symbolic unset index, the A3.2 ceiling).
    // ──────────────────────────────────────────────────────────────────
    function check_isValidSignature_nonbypass_slot1(bytes32 hash) public {
        bool verifierResult = svm.createBool("verifierResult_1271slot1");
        c10.setValid(verifierResult);

        bytes4 ret = wallet.isValidSignature(hash, _wrap(1));

        if (ret == MAGIC) {
            assertTrue(verifierResult, "G8 bytecode: EIP-1271 magic without verifier accept (slot 1)");
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // View-only: the off-chain path bumps NO on-chain counter (it is a
    // `view` entry; this proves on bytecode that no storage write sneaks in).
    // ──────────────────────────────────────────────────────────────────
    function check_isValidSignature_no_counter_bump(bytes32 hash) public {
        bool verifierResult = svm.createBool("verifierResult_1271view");
        c10.setValid(verifierResult);

        uint256 b0 = wallet.bootstrapUses();
        uint256 s1 = wallet.slotUses(1);

        wallet.isValidSignature(hash, _wrap(1));

        assertEq(wallet.bootstrapUses(), b0, "G8 bytecode: EIP-1271 bumped bootstrapUses");
        assertEq(wallet.slotUses(1), s1, "G8 bytecode: EIP-1271 bumped slotUses");
    }
}
