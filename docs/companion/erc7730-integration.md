# ERC-7730 firmware integration — current status

This path is retained for old links, but it is **not the normative companion
implementation guide**. Use
[`companion-erc7730-implementation-guide.md`](companion-erc7730-implementation-guide.md)
for the current `P730` catalogue, trailer framing, lookup rules, and command
examples. Historical phase documents under `docs/archive/` describe retired
wire layouts and fallback policies and must not be implemented.

Current security contract:

- The host compiler emits IR schema v3. Its fixed header is 134 bytes; the
  authoritative layout and caps are in `pqsigner-erc7730/src/ir.rs`.
- The verifier, binding logic, ABI resolver, page substrate, and full renderer
  are host-linkable pure logic in `pqsigner-erc7730/`. Secure world calls that
  same implementation through thin re-exports.
- Every supplied bundle is Merkle-verified against the firmware-pinned root and
  bound to the signed chain/deployment/domain before rendering.
- ERC-20 metadata is consumed only after a second, surface-specific attribution
  check against the signed direct target, exact ERC-7730 `tokenPath`, verified
  Safe target, or verified pinned MultiSend record. Unverified Safe bytes grant
  no authority. Bound non-native token amounts, arrays, and tickers always show
  the full contract address; identity-page exhaustion refuses.
- The vendored security corpus also produces a pinned known-call filter over
  every parsable registry-declared contract tuple, including declarations from
  descriptors rejected by the strict renderer. Such a tuple needs independently
  authenticated semantics: normally a valid, bound, completely renderable
  descriptor; the explicitly enumerated Safe exception is strict native ERC-20
  decoding with exact chain/contract-bound Merkle metadata, re-attributed per
  direct call or MultiSend record. Without either, signing hard-refuses and
  never downgrades to typed or blind signing. Only a genuinely absent tuple may
  use the generic display ladder; Bloom false positives conservatively refuse.
- The current regenerated development catalogue has **420 leaves**, root
  `048fd2f1ff61942027ffa248f7d26fdbe9d8e2f02e9ad6478ad6714cb96ab142`,
  and **4,542 exact known-call tuples**. The tuple-set receipt is SHA-256
  `96ea46d23d2f321a81030b77a61a243a003c1ceb6d0dca8df32ba838bcc0c88b`;
  Bloom occupancy is 28,235 / 131,072 bits under a hard 25% generation cap.
  These receipts detect input/artifact drift. They do not turn Bloom insertion
  into a proof of parser completeness: an independent types-only ABI parser,
  raw/resolved declaration tests, real tuple-array witnesses, and fail-closed
  selector derivation cover that boundary.
- Known/verified render errors—including no matching format, non-canonical ABI
  framing, unsupported dynamics, or page-budget exhaustion—hard-refuse.
  `MAX_PAGES` is currently 31; code constants, not old prose, are authoritative.
- Contract selector preflight is independent of renderer field-name policy. It
  canonicalizes Solidity ABI aliases (`uint`, `int`, `byte`, `fixed`,
  `ufixed`), accepts legal `$` identifiers, whitespace, and nested tuple-array
  suffixes, and aborts catalogue generation on any deployed format whose
  selector cannot be derived confidently (including selector-only hex keys).
- EIP-712 lookup is an exact four-part match: chain, verifying contract,
  recomputed domain separator, and full 32-byte primary type hash found inside
  authenticated IR. The entry-level type hash is only the first-surviving
  format's sorting/diagnostic hint; multi-format leaves require scanning their
  complete format tables.
- The drift-gated review records all **274** current descriptor/format
  omissions by exact reason. Endpoint-only array/packed-route token paths,
  runtime-dead opaque semantic bytes, hidden operands, and unsupported framing
  remain known but cannot acquire trusted display authority.
- The renderer's local stack sentinel is only a corruption tripwire. It is not
  proof that arbitrary stack overrun is detected; ARM link/resource reporting
  and reviewed worst-case stack analysis remain separate evidence.

Provenance is deliberately pre-production:

- No ERC-8176/EAS attestation verifier is implemented today. The generated
  catalogue provenance is `dev-unattested`.
- Non-test development firmware that embeds that root must show the
  `DEV UNATTESTED` warning page. Production-shaped builds reject the root at
  compile time and `make prod-erc7730-provenance-check` independently refuses
  it. A future verified root must remove the dev-warning feature coupling in
  the same reviewed rotation.
- There is no gateway command that reports the current root and no separately
  authenticated release-metadata channel yet. During bring-up, bind the
  companion blob to the exact firmware build out of band. Production remains
  blocked by both the provenance gate and the independent firmware-rollback
  quarantine.
- Wire v2 slot rotation remains quarantined: it may return a Type-1 signature
  without the exact 64-byte public key needed to construct its signed calldata.
  Seedless companions keep `FLAG_REGISTER_SLOT` clear, reject any nonzero
  Type-1 result, and do not retry. Initial slot-0 deployment is the separate
  factory path.

Sources of truth:

- `docs/companion/companion-erc7730-implementation-guide.md`
- `pqsigner-erc7730/src/{ir,bundle,binding,known_calls}.rs`
- `pqsigner-erc7730/src/display/`
- `dbgen/src/erc7730.rs`
- `secure/src/tx/erc7730.rs`
- `secure/src/db_roots.rs`
- `secure/data/erc7730.review.txt`
