# Historical Groth16 clear-sign architecture

> Retired on 2026-06-30. This document preserves the former design and
> its old commands as audit history only; none applies to the current tree.
> Current behavior is documented in `docs/archive/zk-clear-sign-retirement.md`
> and the native decoder documentation.

## ZK Clear Signing — RETIRED (2026-06-30)

> **This subsystem has been removed.** The on-device Groth16 / BLS12-381
> ZK clear-sign verifier is gone; the clear-sign trust model is now
> **native on-device decode** for every shape (Safe, CoW Swap, ERC-7730,
> ERC-20, typed-call), anchored in firmware-pinned Merkle roots. The only
> path the ZK verifier still served — Aave v3 `borrow`/`repay` — was
> ported to the native ERC-7730 descriptor with no clear-sign regression.
> See `docs/archive/zk-clear-sign-retirement.md`. The historical
> description below is retained for context only.

For supported DeFi protocols (Aave V3, CowSwap `setPreSignature`, and
CowSwap EIP-712 `GPv2Order` typed-data signing), the secure world
refused to display a "human-readable" action string on the trusted UI
unless a **Groth16 zero-knowledge proof** cryptographically certified
that the string was a faithful interpretation of the raw bytes being
signed. This closed a long-standing trust hole in hardware wallets:
the companion app on the host is free to render `swap 1 ETH for
3000 USDC` while the chip is asked to sign a calldata blob that
actually drains the caller's balance to an attacker. (That same
guarantee is now provided by decoding the calldata on-device directly,
rather than by verifying an off-device proof about it.)

The architecture followed the [ZKNOX clear-signing
proposal](https://zknox.org). The Aave V3 circuit was a byte-identical copy
of [ZKNoxHQ/ZKlarity](https://github.com/ZKNoxHQ/ZKlarity); the CowSwap
circuits were written in-tree. Proving ran off-device, on either a
watchtower service or the user's companion; the wallet only ever ran the
**verifier**, which was small enough (`#![no_std]`, no `alloc`) to fit
inside the secure world.

The wallet supports two distinct sign-time payload shapes:

| Command | Payload | Wraps | Signed bytes |
|---|---|---|---|
| `CMD_CLEAR_SIGN` (5) | proof ‖ calldata(164) ‖ readable(64) ‖ tx_len ‖ EIP-1559 envelope ‖ vk_bundle | EIP-1559 transaction | `keccak256(unsigned_envelope)` |
| `CMD_CLEAR_SIGN_MSG` (6) | proof ‖ canonical(164) ‖ readable(64) ‖ vk_bundle | EIP-712 typed data (no on-chain tx) | `keccak256(0x1901 ‖ domain_separator ‖ struct_hash)` |

The **M4 / EIP-712 path** sidesteps keccak-in-circom by hashing the
canonical bytes with Poseidon inside the circuit and recomputing the
EIP-712 keccak digest natively in the secure world from the **same
164-byte buffer** the proof bound. The circuit only needs to certify
the human-readable summary; the firmware does the EIP-712 keccak
work at zero proving cost. The EIP-712 dispatch is generic: each
protocol implements `Eip712Protocol` in a sibling submodule under
`secure/src/tx/eip712/` and registers itself in the static
`PROTOCOLS` table; adding a second EIP-712 protocol is a sibling
file plus a VK row, no edits to `nsc.rs`. See `secure/src/tx/eip712/` and
**[docs/companion/m4-cowswap-eip712-impl.md](../companion/m4-cowswap-eip712-impl.md)** for
implementation notes; **[docs/archive/m4-cowswap-eip712.md](../archive/m4-cowswap-eip712.md)**
captures the original handoff design sketch.

### Verification chain

The full VK pool lives in **non-secure firmware rodata**
(`nonsecure/src/vk_db.bin`, `include_bytes!`d into the NS image).
The secure world only embeds a single 32-byte Merkle root in
`secure/src/db_roots.rs::VK_DB_ROOT`. At sign time the non-secure
world walks its local index by `(chain_id, contract)`, reads the
matching 960-byte VK + the pre-computed Merkle proof for its leaf
position, and forwards the bundle to the secure world.

```
NS World                                Secure World
────────                                ────────────
1. Local lookup on (chain_id, tx.to)    VK_DB_ROOT [u8; 32]
   in `nonsecure/src/vk_db.rs` →        embedded in secure image
   leaf_index, vk_bytes (960 B),
   merkle_proof[depth × 32 B]

2. Build clear-sign payload:
     [  0..384)   Groth16 proof (π.A ‖ π.B ‖ π.C)
     [384..548)   Aave V3 calldata (164 B, right-zero-padded)
     [548..612)   readable string (64 B, null-padded)
     [612..616)   tx_len (u32 LE)
     [616..)      EIP-1559 tx envelope
     then:
     [bundle_len u32 LE]
     [vk_bundle:
        chain_id (8 B) ‖ contract (20 B) ‖ vk_bytes (960 B)
        ‖ leaf_index (4 B) ‖ proof_depth (4 B)
        ‖ merkle_proof (depth × 32 B)
     ]

3. CMD=CLEAR_SIGN, ARG0=&payload  ──►  SysTick fires
   ARG1=&sig_buf, ARG2=total_len
                                       a. Validate payload pointer + length,
                                          reject overlap with shared mailbox
                                       b. Copy entire payload into a secure-stack
                                          buffer (TOCTOU defense)
                                       c. Parse the EIP-1559 envelope FIRST,
                                          extract chain_id, to, value, data
                                       d. Cross-check:
                                            tx.to.is_some()
                                            tx.value.is_zero()
                                            payload.calldata[..tx.data.len()]
                                               == tx.data
                                            payload.calldata[tx.data.len()..]
                                               == [0; ...] (padding)
                                          FAIL any → CryptoError
                                       e. Re-derive canonical leaf bytes from
                                          the bundle: (chain_id ‖ contract
                                          ‖ vk_bytes)
                                       f. leaf_hash = sha256(0x00 ‖ canonical)
                                          walk the Merkle proof, hashing
                                          pairwise with 0x01 || left || right,
                                          using bit i of leaf_index to pick
                                          left/right at each level
                                          final hash != VK_DB_ROOT → reject
                                          also cross-check bundle.chain_id +
                                          bundle.contract match parsed tx
                                       g. Deserialize the VK (now trusted) and
                                          the proof from the payload
                                       h. H_tx  = Poseidon(calldata, 164)
                                          H_str = Poseidon(readable, 64)
                                          (Poseidon over the BLS12-381 scalar
                                          field, alpha=5, Hades — matches
                                          ZKlarity's poseidon-bls12381 npm
                                          package bit-for-bit)
                                       i. vk_x = IC[0] + H_tx·IC[1] + H_str·IC[2]
                                       j. Verify Groth16 equation:
                                            e(π.A, π.B) · e(-α, β)
                                          · e(-vk_x, γ) · e(-π.C, δ) == 1 ∈ GT
                                          (4 individual pairings — no
                                          multi_miller_loop, so no alloc)
                                          FAIL → CryptoError, "ZK INVALID"
                                          OK   → continue
                                       k. Render `readable` on the trusted UI
                                          (3 pages: header, action string,
                                          confirm prompt). User long-presses
                                          R to confirm or L to cancel
                                       l. Parse + sign the EIP-1559 envelope
                                          (same flow as CMD_SIGN steps 5–10)
                                       m. RESULT=Ok, DONE=1
4. Read RESULT=Ok                ◄──
   Read 17 088-byte signature
   from sig_buf
```

### What this gives you

- **The display is cryptographically bound to the calldata.** The
  Poseidon hashes over the calldata and the readable string are the
  Groth16 public inputs. A proof exists *only* if a circuit-defined
  ABI-interpretation function maps that exact calldata to that exact
  string. Substituting either side invalidates the pairing equation.
- **The VK is authenticated against a secure-flash Merkle root.** The
  full VK pool ships in non-secure rodata, but the secure world only
  trusts a VK after re-deriving the leaf hash from the supplied bytes
  and walking the Merkle proof up to `VK_DB_ROOT`. The trust anchor
  is the firmware-signing key itself — the release reviewer compares
  `secure/data/vks.review.txt` (a build-artifact manifest of
  `(chain_id, contract, sha256(vk))` triples) against on-chain
  governance values before signing the release. Adding a new protocol
  requires a firmware update that bumps the root.
- **The NS side cannot forge a VK substitution.** If a hostile
  non-secure world sends a different VK for a pinned contract, the
  Merkle proof over the substituted bytes won't match the embedded
  root and the request is rejected before Groth16 ever runs.
- **The bundle cannot be replayed for the wrong transaction.** The
  bundle's `(chain_id, contract)` fields are cross-checked against the
  parsed envelope's `tx.chain_id` and `tx.to` after Merkle verification,
  so a valid VK for Aave V3 on Mainnet cannot be attached to a tx
  targeting a different chain or a different contract.
- **The signing key never depends on the proof's correctness.** A
  failing proof returns `CryptoError` *before* the entropy is even read
  from the secure element. The seed and SLH-DSA path are unchanged.

### Why classical, when everything else is post-quantum?

Groth16 and Poseidon over BLS12-381 are **classical** — a CRQC that
breaks the discrete log over BLS12-381's pairing-friendly curves could
forge a Groth16 proof for an arbitrary `(calldata, readable)` pair.

We accept this for now because:

1. **The ZK layer cannot leak the seed.** It only gates *what gets
   displayed before signing*. The classical assumptions are the same as
   they would be without the proof — the user is back to "trust the
   companion's display string".
2. **No PQ ZK proof system fits today.** Hash-based STARKs (Plonky3,
   Risc0) produce proofs that are O(100 KB) and verifiers that need
   alloc; lattice-based SNARKs are not yet practical for circuits the
   size of Aave V3 calldata parsing. The migration target is an
   STARK-based verifier once the proof + verifier sizes fit in the
   firmware budget.
3. **The display string is short-lived.** Even a successful forgery is
   only useful in the few seconds between the user reading the OLED and
   pressing confirm. There is no harvest-now-decrypt-later attack on a
   ZK display proof.

### Sizes (today, Aave V3 supply circuit)

| Field | Size | Notes |
|---|---|---|
| Verification key | 960 B | α(96) + β(192) + γ(192) + δ(192) + `IC[0..2]` (288) — ships in NS rodata |
| Groth16 proof | 384 B | π.A(96) ‖ π.B(192) ‖ π.C(96), uncompressed |
| Calldata window | 164 B | matches ZKlarity circuit `MAX_CALLDATA` |
| Readable string | 64 B | matches ZKlarity circuit `STRING_LEN` |
| VK DB Merkle root | 32 B | embedded in secure flash via `db_roots::VK_DB_ROOT` |
| VK Merkle proof | depth × 32 B | ≤ 32 levels; 5 pinned Aave V3 deployments today → proof_depth ≤ 3 |
| Verify time (host) | ~3.3 ms | measured via `cargo run -p zk-test`; the `bls12_381` crate's pairing in pure Rust |
| Verify time (QEMU) | seconds | dominated by software BLS12-381 pairing on Cortex-M33 |

### Host-side parity test (`zk-test` crate)

`zk-test` is a host-only crate (`std`, real `bls12_381` from crates.io)
that imports the **same** `poseidon_constants.rs` and `test_vectors.rs`
files as the secure world, plus its own private copy of the reference
Aave V3 VK (independent of the firmware DB so it's stable across
Merkle-root changes). It runs the entire verifier chain on
`proof_supply.json` (a real Aave V3 supply proof generated by
ZKlarity's prover) and asserts:

1. Our Poseidon output for a known input matches `poseidon-bls12381`'s
   output bit-for-bit.
2. Groth16 verification of `proof_supply.json` returns true.

This catches divergence between the secure world's Poseidon
implementation and the reference circuit *without* the multi-minute
QEMU emulation cost of running BLS12-381 pairings on a soft-Cortex-M33.

```bash
cargo run -p zk-test --release
# → Poseidon: ok (matches poseidon-bls12381 reference)
# → Groth16 : ok in 3.3ms
```

### Automated end-to-end test (`make e2e`)

`make e2e` is a non-interactive test suite that builds both worlds
with a special `e2e-test` cargo feature and runs the full gateway
flow in QEMU with stdin closed. The feature:

- Replaces the first-boot wizard with deterministic provisioning from
  a fixed test mnemonic (`abandon`×23 + `art`) and PIN `00000000`
- Sets `PIN_VERIFIED` + `MASTER_SECRET` directly so the gateway is
  callable on boot
- Short-circuits every `confirm()` dialog to auto-return `Confirmed`
- Logs the chosen `TxKind` variant for every `cmd_sign` / `cmd_clear_sign`
  so the host harness can assert routing

It walks four scenarios back-to-back and greps the QEMU stdout for
both `[S][e2e] dispatch = <variant>` and `[E2E] <name> = PASS` lines
for every one:

| Scenario | Gateway | Expected TxKind |
|---|---|---|
| value_transfer | `CMD_SIGN` | `ValueTransfer` |
| erc20_known (USDC mainnet, bundle attached) | `CMD_SIGN` | `Erc20Known` |
| blind_sign (Uniswap router selector only) | `CMD_SIGN` | `ContractCall` |
| zk_clear_sign (Aave V3 supply, VK bundle attached) | `CMD_CLEAR_SIGN` | `ZkClearSign` |
| cowswap_pre_sign (GPv2Settlement.setPreSignature, in-tree circuit, VK bundle) | `CMD_CLEAR_SIGN` | `ZkClearSign` |
| cowswap_eip712_order (GPv2Order EIP-712 typed data, in-tree M4 circuit, VK bundle) | `CMD_CLEAR_SIGN_MSG` | `ZkClearSignMsg` |

The runner exits 0 only if every assertion holds. Total runtime
~20 seconds including QEMU's software BLS12-381 pairing.

The `e2e-test` feature is **never** enabled in production builds;
`secure/Cargo.toml` documents it as "NEVER ship in production: it
disables every meaningful trust gate."

### Tool: `tools/export_zk_constants.js`

Generates `secure/src/zk/poseidon_constants.rs` from the
`poseidon-bls12381` npm package's round constants and MDS matrices.
Run only when bumping the upstream package — the generated file is
checked in so the secure-world build does not require Node.js.

## Building the ERC20 + VK databases

The two on-device databases (ERC20 metadata, ZK clear-signing VKs)
are built by the `dbgen` workspace crate from JSON source files
checked into `secure/data/`. This section documents the source
schema, the tooling, the generated artifacts, the trust-anchor
workflow, and the sanity guards. For a quick-start "how do I add a
token" guide see the corresponding section in the top-level README.

### Source-data layout

```
secure/data/
├── erc20.json              # curated ERC20 metadata — sorted by (chain_id, address)
├── vks.json                # VK manifest (one block per protocol + its deployments)
├── vks/                    # raw 960-byte Groth16 verification keys
│   ├── aave_v3_pool.vk.bin
│   └── cowswap_set_pre_signature.vk.bin
└── vks.review.txt          # GENERATED — build-traceability manifest (checked in)
```

VKs are produced by the in-tree Circom pipeline under `circuits/`
(see `circuits/README.md` and `circuits/UPSTREAM.md`). The host-side
driver `tools/build_vks.sh` compiles the `.circom` sources, runs the
`snarkjs` trusted setup, and writes the 960-byte files into
`secure/data/vks/`. `cargo run -p dbgen` then folds them into the
Merkle-rooted firmware DB. The two pipelines are decoupled: `dbgen`
is cargo-only and does not shell out to Node or circom, so a clean
clone with only cargo can rebuild the firmware DB from the committed
`.vk.bin` files.

#### `secure/data/erc20.json`

A JSON array of records, one per `(chain_id, contract)` the wallet
should recognise. All fields are required except `flags`.

```json
[
  { "chain_id": 1, "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "name": "USD Coin", "symbol": "USDC", "decimals": 6 },
  { "chain_id": 8453, "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "name": "USD Coin", "symbol": "USDC", "decimals": 6 }
]
```

| Field | Type | Constraint |
|---|---|---|
| `chain_id` | u64 | EIP-155 chain id, matches what the EIP-1559 envelope encodes |
| `address` | hex string | 20 bytes, with or without `0x` prefix; case insensitive |
| `name` | UTF-8 string | 1–255 bytes. `dbgen` hard-errors if longer |
| `symbol` | UTF-8 string | 1–255 bytes |
| `decimals` | u8 | Token decimals used by `U256::format_decimal_fixed` |
| `flags` | u8 (optional, default 0) | Reserved per-entry flags |

#### `secure/data/vks.json`

A JSON array where each element describes one protocol (i.e. one
circuit + VK) plus every chain/contract deployment that shares that
VK. Dedup happens at the protocol level: the Aave V3 Pool circuit
covers four actions (supply / borrow / repay / withdraw) via an
internal `action_type` mux and is identical across
Mainnet/Base/Arbitrum/Optimism/Polygon, so all five deployments ride
on a single 960-byte entry in the VK pool. Similarly the CowSwap
`setPreSignature` VK covers every chain where `GPv2Settlement` is
deployed at the canonical CREATE2 address.

```json
[
  {
    "protocol": "aave-v3-pool-v1",
    "vk_file": "aave_v3_pool.vk.bin",
    "deployments": [
      { "chain_id": 1,     "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        "label": "Aave V3 Pool, Mainnet" },
      { "chain_id": 8453,  "address": "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
        "label": "Aave V3 Pool, Base" }
    ]
  },
  {
    "protocol": "cowswap-set-pre-signature-v1",
    "vk_file": "cowswap_set_pre_signature.vk.bin",
    "deployments": [
      { "chain_id": 1,   "address": "0x9008D19f58AAbD9eD0D60971565AA8510560ab41",
        "label": "GPv2Settlement, Mainnet" }
    ]
  }
]
```

`vk_file` is a path relative to `secure/data/vks/` pointing at a raw
960-byte Groth16 VK blob. `dbgen` rejects any file that's not exactly
`VK_BLOB_LEN` bytes (960). The `label` is purely cosmetic and only
appears in the release-review manifest.

### Canonical leaf encoding

The Merkle leaf hash for each entry is `sha256(0x00 || canonical)`,
where `canonical` is the exact byte sequence reconstructed at both
ends of the wire. The dbgen writer emits these bytes into the tree;
the secure-world verifier re-emits the same bytes from the bundle
received via the gateway before hashing. Both implementations share
the layout via `sphincs_tz_shared::db_format` constants.

**ERC20 canonical leaf:**

```
chain_id      u64 LE            (8 B)
contract      [u8; 20]          (20 B)
decimals      u8                (1 B)
name_len      u8                (1 B)
name          [u8; name_len]
symbol_len    u8                (1 B)
symbol        [u8; symbol_len]
```

**VK canonical leaf:**

```
chain_id      u64 LE            (8 B)
contract      [u8; 20]          (20 B)
vk_bytes      [u8; 960]         (960 B)
```

Internal Merkle nodes use `sha256(0x01 || left || right)`. The
`0x00`/`0x01` domain separation prefix stops an attacker who controls
the entry encoding from crafting bytes that look like an
internal-node concatenation, which would otherwise break
second-preimage resistance for the tree.

### dbgen pipeline

`cargo run -p dbgen` (a new workspace member) runs a single
host-side pipeline that produces all four generated outputs:

```
secure/data/erc20.json                     ─┐
                                            ├─► erc20::build_db()
                                            │    ├─ parse + validate rows
                                            │    ├─ sort by (chain_id, contract)
                                            │    ├─ intern name + symbol into pool
                                            │    ├─ compute leaf hashes from canonical encoding
                                            │    ├─ build Merkle tree (pad to pow-2 by dup)
                                            │    └─ emit blob + per-entry proofs
                                            ▼
                                  nonsecure/src/erc20_db.bin   (include_bytes! in NS)
                                  ERC20_DB_ROOT: [u8; 32]      (→ secure/src/db_roots.rs)

secure/data/vks.json                       ─┐
secure/data/vks/*.vk.bin                    ├─► vks::build_db()
                                            │    ├─ load each VK, validate 960 B
                                            │    ├─ dedup VKs by sha256(vk_bytes)
                                            │    ├─ flatten (chain_id, contract) → vk_id
                                            │    ├─ same canonical leaf + Merkle build
                                            │    └─ emit blob + per-entry proofs + review text
                                            ▼
                                  nonsecure/src/vk_db.bin      (include_bytes! in NS)
                                  VK_DB_ROOT: [u8; 32]         (→ secure/src/db_roots.rs)
                                  secure/data/vks.review.txt   (human-reviewable manifest)
```

All four outputs are **checked into the repo** so downstream builds
need only `cargo` (no Node.js, no network access). Rerun `dbgen`
whenever the JSON source changes, and commit the regenerated
outputs alongside the source diff.

### Blob format (generated on-disk layout)

Both blobs share a 32-byte header, a sorted entry array, a
secondary pool (strings for ERC20, VK bytes for VK), and a
per-entry proofs section. Constants live in
`shared/src/db_format.rs`.

**`erc20_db.bin` (`b"ERC2"`):**

```
Header (32 B):
  magic        [u8; 4] = b"ERC2"
  version      u32 LE  = 1
  flags        u32 LE
  entry_cnt    u32 LE
  pool_off     u32 LE    // byte offset of string pool from blob start
  pool_size    u32 LE
  proof_depth  u32 LE    // sibling hashes per proof (= log2(padded n))
  proofs_off   u32 LE    // byte offset of per-entry proofs array

Entries (entry_cnt × 40 B, sorted by (chain_id, contract)):
  chain_id     u64 LE
  contract     [u8; 20]
  name_off     u32 LE     // offset into string pool
  symbol_off   u32 LE
  decimals     u8
  flags        u8
  _pad         [u8; 2]

String pool:
  Length-prefixed: [u8 len][bytes]. Strings are interned at build
  time so "USD Coin" appears once even if 10 chains have a USDC.

Proofs:
  entry_cnt × (proof_depth × 32 B). Proof[i] is the list of sibling
  hashes from leaf i up to the root, ordered leaf-up. The direction
  at each level is implicit from the bits of i.
```

**`vk_db.bin` (`b"VKDB"`):**

Same header shape with `VK_BLOB_LEN = 960`. Entries are 32 B each
(`chain_id`, `contract`, `vk_id: u8`, `vk_sha_pfx: [u8; 3]` — a
defense-in-depth SHA-256 prefix the verifier cross-checks against
the pool entry it indexes). The secondary pool holds `vk_count ×
960` bytes of unique VKs. The `vk_sha_pfx` catches any drift
between the entry's `vk_id` and the pool contents that survived
dbgen's internal checks.

### Round-trip self-test

After writing a blob, `dbgen` immediately opens it through its
host-side mirror of the runtime parser, re-derives the canonical
leaf bytes for every source row, walks the appended Merkle proof up
to the just-computed root, and asserts match. Any drift between the
writer and the reader — which would silently break the secure-world
verifier — fails `dbgen` loudly with a precise error pointing at the
specific row.

The parser mirror lives in `dbgen/src/{erc20.rs,vks.rs}` as
`HostErc20Db` and `HostVkDb`. It deliberately mimics the structure
the **non-secure-side** parser (`nonsecure/src/erc20_db.rs`,
`nonsecure/src/vk_db.rs`) uses so the two can't drift.

### Secure-side Merkle verifier

`secure/src/erc20/merkle.rs` exposes one function, shared by both
DBs:

```rust
pub fn verify_proof(
    canonical: &[u8],
    leaf_index: usize,
    proof_bytes: &[u8],
    proof_depth: usize,
    expected_root: &[u8; 32],
) -> bool;
```

It walks the supplied sibling hashes from `sha256(0x00 || canonical)`
to the root, picking left/right at each level by bit `i` of
`leaf_index`. No heap, no allocation, no panics on bad input — a
bad bundle just returns `false` and the gateway surfaces
`CryptoError` to NS.

### Stale-blob protection

`nonsecure/build.rs` panics at compile time if either of its
`include_bytes!`'d blobs doesn't start with the expected magic. The
common failure mode — "edited `erc20.json`, forgot to run `dbgen`"
— fails the build with a clear "run `cargo run -p dbgen`" message
instead of silently shipping stale data.

```rust
// nonsecure/build.rs
check_db_magic("src/erc20_db.bin", b"ERC2");
check_db_magic("src/vk_db.bin", b"VKDB");
```

The secure-side counterpart is implicit: `secure/src/db_roots.rs`
is generated by `dbgen` as regular Rust source, so any format
mismatch would be caught by the compiler rather than by magic-byte
sniffing.

### Release-review workflow (VK DB only)

`dbgen` also writes `secure/data/vks.review.txt`, a
human-readable manifest that lists the VK DB Merkle root plus every
`(protocol, chain_id, contract, sha256(vk))` triple in the DB:

```
=== ZK Clear-Signing VK Manifest (firmware build artifact) ===
...
Merkle root (VK_DB_ROOT) = 89ccb93ed5034a90b48ae07bc10694e2ab7da74b8f8cef3af840d563b943f12a

aave-v3-pool-v1
  sha256(vk) = f36a73b5bb084a9800ceff63e33e061d182af2b09f6bcef20d441c68fd80292e
  chain      1, contract 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 (Aave V3 Pool, Mainnet)
  chain   8453, contract 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5 (Aave V3 Pool, Base)
  ...
cowswap-set-pre-signature-v1
  sha256(vk) = 5114d50fc022a64aaa199dec0c130a4b27e859714d5f03ba14ef5a8406c1a236
  chain      1, contract 0x9008D19f58AAbD9eD0D60971565AA8510560ab41 (GPv2Settlement, Mainnet)
  ...
```

**This file is a pure build-traceability artifact.** It records
which `(chain_id, contract, sha256(vk))` triples were folded into
`VK_DB_ROOT` for a given release, so the release reviewer can diff
successive releases and notice any unexpected additions. The trust
chain is entirely offline:

```
firmware-signing key
      ↓  signs
firmware release (containing VK_DB_ROOT in secure flash)
      ↓  anchors
VK_DB_ROOT                          [32 bytes in secure/src/db_roots.rs]
      ↓  Merkle-proves
(chain_id, contract, vk_bytes)      [NS-supplied bundle at sign time]
      ↓  Groth16-verifies
proof π binds calldata → readable   [displayed on trusted UI]
```

There is **no** on-chain `clearSigningVKHash` comparison anywhere in
this project. The wallet trusts its own Merkle root, the reviewer
trusts the firmware-signing key, and neither the firmware nor the
tooling ever reads from an RPC. If a future plan wants to add an
optional governance-comparison script as a reviewer convenience, it
will be a strict opt-in on top of this hardware-only baseline.

Release-signing checklist simply becomes:

```
[ ] git diff secure/data/vks.review.txt
    — confirm that every added or modified row corresponds to a
      Circom circuit you actually intended to add in this release,
      authored in circuits/, and that no unexpected rows appeared.
    — no external lookups required.
```

### Putting it all together

```bash
# 1a. Edit ERC20 source data
$EDITOR secure/data/erc20.json

# 1b. OR: author a new ZK clear-signing circuit and produce its VK
$EDITOR circuits/circuits.json                         # add a row
mkdir -p circuits/myproto/myaction
$EDITOR circuits/myproto/myaction/circuit.circom       # write the circuit
head -c 32 /dev/urandom > circuits/myproto/myaction/contribution.seed
tools/build_vks.sh myproto_myaction                    # compile → .vk.bin
$EDITOR secure/data/vks.json                           # add deployment rows

# 2. Regenerate all four outputs
cargo run -p dbgen

# 3. Review the diff (build-traceability only — no external lookups)
git diff secure/data/vks.review.txt

# 4. Sanity-build both worlds (magic-bytes validator runs here)
make all

# 5. Run the scripted e2e suite
make e2e

# 6. Commit source + all regenerated outputs atomically
git add circuits/ secure/data/ nonsecure/src/{erc20,vk}_db.bin \
        secure/src/db_roots.rs secure/src/zk/vk_data.rs
git commit -m "..."
```

See `circuits/README.md` for the full circuit-authoring workflow
and `circuits/UPSTREAM.md` for the provenance of any Circom sources
imported from third-party repositories.
