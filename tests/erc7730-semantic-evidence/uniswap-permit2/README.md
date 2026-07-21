# Uniswap Permit2 EIP-712 semantic evidence

This offline bundle pins the official Uniswap Permit2 source at the lightweight
deployment-address tag
`0x000000000022D473030F116dDEE9F6B43aC78BA3`, commit
`cc306b601f172c51bc04334a109e98340456620b`. It covers only the three EIP-712
types currently curated for PQ1: `PermitSingle`, `PermitBatch`, and
`PermitTransferFrom`.

## Fixed Ethereum deployment identity

At Ethereum block 25,581,839 (`0x186590f`, hash
`0xaf33a385…f94169`), raw dRPC and Tenderly responses agree on the complete
block header, the 9,152-byte runtime at the tagged address, and the result of
`DOMAIN_SEPARATOR()` (`0x866a5aba…e3f28`). The code and call requests use the
same EIP-1898 `blockHash` with `requireCanonical: true`. The checked-in request
and both complete responses (canonically key- and batch-ordered by the
collector so provider JSON serialization does not churn receipts) are under
`rpc/raw/`; the runtime extracted from the dRPC response is under `runtime/`.

The archived Ethereum Blockscout report is independently address-scoped and is
classified `partially_verified` by Blockscout (the package does not promote
that label to fully verified). Its deployed bytecode is nevertheless
byte-identical to both fixed-block RPC observations. Its source fields match
the semantic source files fetched from the official Uniswap tag, and its ABI
fixes the exact tuple component names and types for the two `permit` overloads
and the single-token `permitTransferFrom` overload. The official GitHub tag-ref
and commit records also bind the address-shaped lightweight tag to the archived
commit and tree.

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

The offline integration test binds these records to both production descriptor
copies, the three exact primary-type hashes, every generated deployment IR,
and a Merkle-verified Ethereum leaf. It also drives the production V3 renderer
once for each of the three admitted types using hash-bound nested data; the
existing secure renderer suite retains the exhaustive mutation and page-budget
tests. This evidence does not admit another Permit2 type or another chain.

## Honest boundary

The fixed block proves one historical Ethereum-mainnet runtime and domain
separator. It is not monitoring for future code or state changes, and it does
not establish any other chain declared by the descriptor. In particular, this
bundle makes no availability claim for deprecated Mumbai chain 80001. Permit2
execution still depends on live nonces, deadlines, allowances, balances, token
behavior, contract-wallet code, and transaction ordering.

Primary source: <https://github.com/Uniswap/permit2/tree/cc306b601f172c51bc04334a109e98340456620b>

Collection is reproducible with `./collect.sh`; ordinary integration tests are
fully offline. This evidence grants no production-shipment, fallback, or
blind-signing authority.
