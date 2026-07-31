// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice A minimal ERC-6492 "deploy-then-verify" validator, implementing the
///         EIP's prepare-then-check semantics directly.
///
///         WHY NOT `SignatureCheckerLib.isValidERC6492SignatureNow*`. Both of
///         Solady's entry points delegate the actual work to a canonical
///         singleton — the reverting verifier at `0x00007bd7…1626Ba7e` for the
///         side-effect-free variant, the non-reverting one at
///         `0x0000bc37…1626ba7E` for the other. Neither exists in a fresh
///         Foundry EVM, and when the singleton is absent both variants simply
///         return **false**. That is a trap: every negative assertion written
///         against them passes for the wrong reason, and the suite reads green
///         while proving nothing about the wallet. (This was observed, not
///         assumed: the first draft of ERC6492Replay.t.sol had two such
///         vacuous passes.)
///
///         So this contract does what the EIP describes and what the real
///         consumers (Ambire's `UniversalSigValidator`, viem's `verifyMessage`,
///         Solady's singleton) do:
///
///           1. if the signature does not end with `EIP6492_MAGIC`, it is an
///              ordinary EIP-1271 signature — check it directly;
///           2. otherwise decode `(factory, factoryCalldata, innerSignature)`,
///              call the factory to prepare the account (a revert here is fatal
///              — a blob whose deploy step cannot run must not validate), then
///           3. run `isValidSignature(hash, innerSignature)` against the now
///              prepared address and compare with the 0x1626ba7e magic.
///
///         Test-only. Deliberately does not implement the ecrecover fallback or
///         the revert-to-undo trick: this repo has no ECDSA signer (invariant
///         #5), and undoing the deploy is the caller's business in a test.
contract ERC6492Verifier {
    bytes32 internal constant EIP6492_MAGIC =
        0x6492649264926492649264926492649264926492649264926492649264926492;
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;

    /// @notice True when `signature` ends with the ERC-6492 magic suffix.
    function isWrapped(bytes calldata signature) public pure returns (bool) {
        if (signature.length < 32) return false;
        return bytes32(signature[signature.length - 32:]) == EIP6492_MAGIC;
    }

    /// @notice Deploy-then-verify. Returns false rather than reverting on any
    ///         failure, so a test can assert refusal without `try/catch` noise.
    function isValidSig(address signer, bytes32 hash, bytes calldata signature)
        external
        returns (bool)
    {
        bytes calldata inner = signature;
        if (isWrapped(signature)) {
            (address factory, bytes memory factoryCalldata, bytes memory innerSig) =
                abi.decode(signature[:signature.length - 32], (address, bytes, bytes));

            if (signer.code.length == 0) {
                (bool ok,) = factory.call(factoryCalldata);
                // A blob whose own deploy instructions revert (wrong chainId,
                // bad bootstrap signature, hostile factory) must NOT validate.
                if (!ok) return false;
                // The prepare step must have produced code at the address the
                // signature claims. A factory that deploys somewhere else has
                // not prepared *this* signer.
                if (signer.code.length == 0) return false;
            }
            return _check(signer, hash, innerSig);
        }
        return _check(signer, hash, inner);
    }

    function _check(address signer, bytes32 hash, bytes memory sig) internal view returns (bool) {
        (bool ok, bytes memory ret) = signer.staticcall(
            abi.encodeWithSelector(MAGIC_VALUE, hash, sig)
        );
        if (!ok || ret.length < 32) return false;
        return abi.decode(ret, (bytes4)) == MAGIC_VALUE;
    }
}
