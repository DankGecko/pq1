# FlyingTulip SessionManager semantic evidence

This package binds PQ1's FlyingTulip SessionManager calldata routes and EIP-712
`Session` typed data to seven fixed-block direct deployments. The two surfaces
share source/runtime authority but keep separate descriptor and admission
boundaries.

## EIP-712 Session admission

PQ1 admits exactly one type graph:

```text
Session(address owner,address delegate,uint48 validAfter,uint48 validUntil,uint32 maxCalls,uint16 maxFeeBps,AssetLimit[] limits,bytes32 salt)AssetLimit(address token,uint256 limit)
```

The verified sources define both this exact type string and
`AssetLimit(address token,uint256 limit)`, hash every ordered limit, apply
`_hashTypedDataV4`, verify the owner signature, and pass the exact values to the
common session-creation path. That path enforces the source's owner, delegate,
validity, call-cap, fee-cap, and unique nonzero-token constraints before
storing the session. Every signed terminal is displayed, including every
limit's token and value.

Admission is partitioned by the constructor-bound domain:

- `FT SessionManager`, version `1`: Ethereum
  `0xF9f3…60f8` and Sonic `0x109A…Bdff`.
- `ftUSD SessionManager`, version `1`: Ethereum
  `0x2DaF…5dC9`, BNB `0xC85C…7A42`, Sonic
  `0x2DaF…5dC9` and `0x52Ef…0734`, and Avalanche
  `0x1765…AC54`.

PQ1 deliberately narrows the source-supported array topology. It renders
exactly one through six ordered `limits` entries. An empty array or seven or
more entries is a fatal refusal, with no raw, fallback, or blind-signing
downgrade. The verified source has no explicit length bound and permits an
empty array, so this is a compatibility narrowing, not a claim about source
rejection. Wrong domain, deployment, or primary type likewise refuses.

This evidence does not authorize the separate `CancelOrder` or
`TpslGroupCancel` messages merely because their registry descriptor names the
`FT SessionManager` domain. The verified SessionManager source contains
neither type nor verification path.

## Calldata routes

Four curated routes expose every signed operand: three all-static routes and
one bounded sole-dynamic-array route:

- `revokeSession(bytes32)` shows the exact session ID. The verified source
  requires an existing session and its stored owner as caller, then marks it
  revoked.
- `setAllowedTarget(address,bool)` shows the exact target and both `Allow` and
  `Disallow`. It is current-manager-owner-only, rejects the zero target, and
  stores the exact boolean.
- `setAllowedTargets(address[],bool)` shows the explicit target count, every
  target address, and the shared `Allow` or `Disallow` choice. The verified
  source applies `_setAllowedTarget` to each element in order under
  `onlyOwner`; an empty list is a no-op, and any zero target reverts the whole
  transaction. PQ1 deliberately hard-refuses lists longer than eight rather
  than truncate a signed tail.
- `transferOwnership(address)` is labelled as a pending-owner update. Under
  OpenZeppelin `Ownable2Step`, it sets or replaces `pendingOwner`; zero cancels
  a pending handoff, and current ownership changes only through
  `acceptOwnership()`.

The descriptor's existing `acceptOwnership()` and `renounceOwnership()` routes
remain admitted. Five tuple-array or signature-bearing routes remain
registry-known hard refusals: `createSession`, `createSessionBySig`,
`invalidateNonceBySig`, `revokeSessionBySig`, and `validateAndConsume`.

## Source and deployment binding

The full Sourcify `fields=all` responses are archived for the two exact build
families:

- **current family:** six 7,732-byte deployments. Ethereum and BNB have exact
  creation/runtime matches. Masking only the seven Sourcify-declared 32-byte
  immutable spans makes all six decoded runtimes SHA-256
  `b83ed0508ae63363153a93612a8b61968277602febfa92ddae1cfbb81a51fd6c`.
- **FT family:** the Ethereum `0xF9f3…60f8` deployment is a separate exact
  7,853-byte Sourcify match. Its same normalization is SHA-256
  `a86db0d2fffd878154e062f7e36d2b378e8c0fe7f4f5ed96ed2159d26cd04aa7`.

Both use solc `0.8.30+commit.73712a01`, via-IR, optimizer 200, Cancun EVM,
and no appended CBOR/metadata hash. Their top-level source differs only in
import formatting/path and the EIP-712 domain name; the relevant route bodies,
canonical ABI, and inherited `Ownable`/`Ownable2Step` source are identical.

Seven complete fixed-block runtimes and a two-provider-per-network receipt are
archived. Supported EIP-1967 implementation/admin/beacon slot reads were zero.
BNB MeowRPC supplied independent header/runtime agreement but not historical
storage; BlastAPI supplied the BNB zero-slot result, and Sourcify independently
classifies that exact deployment as nonproxy. Exact source/runtime identity,
not slot zeros alone, carries the historical direct-code classification.

The Sourcify files contain the exact raw response body plus one final repository
newline. `manifest.json` pins both the checked-in file hash and the original
response-body hash; runtime entries separately pin text-file SHA-256, decoded
bytecode SHA-256, and Keccak-256.

Primary records:

- https://sourcify.dev/server/v2/contract/1/0x2DaF4B445E7d659100b22a15c3EeB10e64ac5dC9?fields=all
- https://sourcify.dev/server/v2/contract/1/0xF9f3ddF2E96Cabef94e2634c326DC6dde99360f8?fields=all
- https://sourcify.dev/server/v2/contract/56/0xC85CB743f72B3a9Bb594Faa7d46EE1EFC61b7A42?fields=all

This is historical source and fixed-block evidence. It is not live monitoring
and grants no transaction-success, future-code, production, shipment,
fallback, or blind-signing authority.
