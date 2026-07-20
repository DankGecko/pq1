# Uniswap Permit2 EIP-712 semantic evidence

This compact offline bundle pins the official Uniswap Permit2 source at the
lightweight deployment-address tag
`0x000000000022D473030F116dDEE9F6B43aC78BA3`, commit
`cc306b601f172c51bc04334a109e98340456620b`. It covers only the three EIP-712
types currently curated for PQ1: `PermitSingle`, `PermitBatch`, and
`PermitTransferFrom`.

The archived source fixes the exact domain and type graphs. Permit2 uses the
domain name `Permit2`, the current chain ID, and `address(this)`; it does not
put a version in the domain. The integration test recomputes every relevant
type hash and binds the same type strings and field paths to both production
descriptor copies.

`PermitSingle` and `PermitBatch` create reusable allowances. Their signed
amount is a `uint160`; only its exact maximum is non-decrementing in
`AllowanceTransfer`. A signed expiration of zero is stored as the current
block timestamp, not rendered as the Unix epoch. The signed allowance nonce is
checked and then incremented.

`PermitTransferFrom` is different. Its signature binds the token, a maximum
amount, `msg.sender` as spender, an unordered nonce, and a deadline. The
spender later supplies `transferDetails.to` and
`transferDetails.requestedAmount` outside the signed EIP-712 struct. The latter
must be at most the signed maximum, and consuming the nonce makes the permit
one-time. Therefore the descriptor says “authorize one-time token pull” and
“maximum transfer”; it does not promise an exact recipient or exact transfer
amount.

Signature verification also has a precise limitation. Permit2 takes the ECDSA
branch when `claimedSigner.code.length == 0` and calls ERC-1271 only when the
claimed signer already has deployed code. This pinned source contains no
ERC-6492 unwrap path. Counterfactual contract accounts therefore do not gain
ERC-1271 handling through this implementation, while deployed wallet code and
state remain live validation inputs.

No runtime is archived here. Latest-state runtime samples were available, but
they lacked block-number and block-hash receipts. Treating them as immutable
deployment evidence would overstate what was collected. The official tag pins
source semantics and the canonical address; it does not prove code or state on
any chain declared by the descriptor. In particular, this bundle makes no
availability claim for deprecated Mumbai chain 80001.

Primary source: <https://github.com/Uniswap/permit2/tree/cc306b601f172c51bc04334a109e98340456620b>

The ordinary integration test is fully offline. This evidence grants no
production-shipment, fallback, or blind-signing authority.
