# VULN — CowSwap ZK clear-signing: byte-pack commitment is not byte-binding (proof forgery)

**Severity:** Critical (full WYSIWYS break — sign a different order than displayed)
**Component:** `circuits/lib/poseidon_bytes.circom :: PackBytes31 / PoseidonBytes`
(consumed by `circuits/cowswap/eip712_order/circuit.circom`, and identically by
`set_pre_signature/circuit.circom :: CsPackBytes31` and the Aave v1 circuit)
**Found:** 2026-06-12 (ZK clear-signing soundness audit — circom byte-range review)
**Status:** **RESOLVED 2026-06-12** — per-byte range checks added to all three
byte-commitment packers + all three VKs regenerated + firmware DB constants
(`VK_DB_ROOT`, `vk_db.bin`, `vk_data.rs`) regenerated + the aave proof vector
regenerated. Pre-deployment (no devices, no on-chain funds), so VKs were
overwritten freely. Empirically verified: an out-of-range witness byte
(`canonical[i] = 256`) now fails witness generation (`Num2Bits_0` assert), while
a legitimate v3 order proof + the aave supply proof both still verify through the
firmware's own Groth16 verifier.

## Resolution (2026-06-12)

1. **Root cause (in-circuit).** `Num2Bits(8)` is now applied to every input byte
   of the three byte-commitment packers BEFORE the base-256 fold, forcing the
   packing injective over true bytes so `Poseidon(pack(.)) === H_tx` ⇒ the
   witness bytes equal the firmware's real bytes:
   - `circuits/lib/poseidon_bytes.circom :: PackBytes31` — covers
     `cowswap_eip712_order` (direct CoW **and** the Safe-wrapped presign path,
     which reuses the same VK via `verify_clear_sign_proof_v3`).
   - `circuits/cowswap/set_pre_signature/circuit.circom :: CsPackBytes31`.
   - `circuits/aave_v3/clear_signing_proof.circom :: PackBytes31`.
   Every calldata/canonical/readable byte flows through one of these, so the
   range check transitively covers all downstream decoders (registry address
   pack, `Uint256BytesToField`, ABI slot decoders) — no separate fixes needed.

2. **VK regeneration.** All three circuits recompiled (circom 2.2.3, bls12381),
   re-run through `groth16 setup` (pot14 for set_pre_signature/aave, pot16 for
   eip712_order) + seed-pinned `zkey contribute`; new `.vk.bin` extracted; new
   `circuit_final.zkey` committed (added `circuits/aave_v3/contribution.seed` for
   reproducibility, matching the cowswap pattern). Constraint counts after the
   fix: eip712_order 21027 (< 2^16), set_pre_signature 4937, aave 9049 (both
   < 2^14).

3. **Firmware constants.** `cargo run -p dbgen` regenerated `VK_DB_ROOT`
   (→ `1380fc86…`), `nonsecure/src/vk_db.bin`, `vks.review.txt`;
   `vk_bin_to_rust.js` regenerated `secure/src/zk/vk_data.rs` (aave host VK).
   The aave `TEST_PROOF_A/B/C` in `secure/src/zk/test_vectors.rs` were
   regenerated against the new zkey; `TEST_H_TX`/`TEST_H_STR` are unchanged
   (same in-range bytes hash identically). `cargo run -p zk-test` and the 59
   `zk_under_test::pure_tests` all pass.

The original analysis (kept below) describes the attack the fix closes.

---

**Distinct from:** `docs/security/VULN-cowswap-zk-amount-overflow.md`. That one was the
`raw_amount * scale_factor` field-wrap inside `FormatTrimmedAmount` and was fixed
with `Num2Bits(190)` on the *value*. This one is upstream of all field decoding:
the byte→field **packing** that produces `H_tx` never constrains its bytes to
`[0,256)`, so the commitment is not binding at the byte level at all. The 190-bit
amount fix does **not** close it.

## TL;DR

`H_tx` is computed as `Poseidon( pack31(canonical_bytes) )`, where `pack31`
folds each 31-byte block with `acc <== acc*256 + byte`. The circuit **never
range-checks `byte ∈ [0,256)`**. The firmware computes the *same* hash over a
genuine `[u8;204]`. Because the byte signals are unconstrained field elements
and `256` is invertible mod `r`, a malicious companion can present an
in-circuit `canonical` whose out-of-range "bytes" pack to the **same 7 field
elements** as a *different, real, on-chain* `canonical`. Poseidon then matches,
the proof verifies, and:

- the circuit proves the benign `readable` faithfully describes the **witness**
  order (USDC→WETH, 0.20 / 0.0004), so the device shows that headline;
- the firmware binds and pre-signs the **malicious** order (e.g. WBTC→junk,
  draining the Safe), because `H_tx` is computed from the malicious bytes the
  companion actually handed it.

User sees "SELL 0.20 USDC for ≥ 0.0004 WETH"; user signs "SELL <all my WBTC>".

## Root cause (the missing constraint)

`circuits/lib/poseidon_bytes.circom`:

```circom
template PackBytes31(N_BLOCKS) {
    ...
    for (var b = 0; b < N_BLOCKS; b++) {
        acc[b][0] <== 0;
        for (var i = 0; i < 31; i++) {
            acc[b][i+1] <== acc[b][i] * 256 + bytes[b * 31 + i];  // <-- bytes[] never range-checked
        }
        fields[b] <== acc[b][31];
    }
}
```

There is no `Num2Bits(8)` (nor `LessThan(.., 256)`) on `bytes[*]`. The only
`Num2Bits(8)` anywhere in the order circuit is on the *top byte of each amount*
inside `Uint256BytesToField` (line 80) — it constrains 2 bits of 1 byte of the
two amount fields, nothing else.

Firmware side (`secure/src/zk/poseidon.rs :: poseidon_bytes`, and
`groth16.rs :: verify_clear_signing_proof_v3`):

```rust
let h_tx = poseidon_bytes(canonical, 204);          // canonical: &[u8;204]
groth16_verify_3pub(proof, vk, h_tx, h_str, erc20_poseidon_root);
```

`h_tx` is the base-256 integer (per 31-byte block) of *true* bytes, supplied as
the public input `pub0`. So the verifier pins `fields[b] = base256(real_bytes_b)`.
The circuit only forces `pack31(witness) === fields`. Since Poseidon is
collision-resistant, the **packed fields** must coincide — but the **bytes**
need not, because the packing map `(GF(r))^31 → GF(r)` is wildly non-injective
once bytes may exceed 255.

## Why it's exploitable, not just non-injective

The four fields the device renders straight from `canonical` — `receiver`
`[48..68)`, `feeAmount` `[132..164)`, `validTo` `[164..168)`, `appData`
`[172..204)` — are referenced **nowhere** in the circuit except via the Poseidon
packing (verified: only `kind/partial/balances`, the two amounts, the two
tokens, and `chain_id` carry in-circuit constraints). The circuit comment even
says these rely on "`H_tx` binding." They don't — `H_tx` isn't byte-binding.

On the **witness** side those four fields are invisible (never displayed), so
they are pure scratch space: the prover may set them to any field elements. They
give one free, unconstrained packing knob in every block **except B3**.

### Block map (31 bytes each; 204 → 7 blocks)

| Blk | Bytes        | Contents                                                   | Witness slack |
|-----|--------------|------------------------------------------------------------|---------------|
| B0  | c[0..31)     | chain_id, sellToken, buyToken[0..3)                        | via buyToken split with B1 |
| B1  | c[31..62)    | buyToken[3..20), **receiver[0..14)**                       | receiver (free) |
| B2  | c[62..93)    | **receiver[14..20)**, sellAmount[0..25)                    | receiver (free) |
| B3  | c[93..124)   | sellAmount[25..32), buyAmount[0..24)                       | **none** |
| B4  | c[124..155)  | buyAmount[24..32), **feeAmount[0..23)**                    | fee (free) |
| B5  | c[155..186)  | **fee[23..32), validTo, appData[0..14)**, kind/partial/bal | fee/validTo/appData (free) |
| B6  | c[186..217)  | **appData[14..32)**, zero-pad                              | appData (free) |

For a contiguous field whose *packed* value is pinned (chain_id, each token,
each amount), its contribution to any overlapping block is also pinned — block
packing and field packing are both base-256 over the same bytes, differing only
by a constant power-of-256, so "compensation that preserves the field also
preserves the block." Hence slack must come from the genuinely *unconstrained*
fields, which is exactly receiver / fee / validTo / appData.

Every block has such slack **except B3** (sellAmount tail + buyAmount head are
both packed-pinned on both sides). B3 therefore forces
`base256(witness B3) == base256(malicious B3)`, and since both use real bytes
there, it requires the two orders to **agree on those 31 bytes**. That is the
only coupling — and it is trivially arrangeable.

## Concrete construction

Pick:

- **Malicious order** (bound + pre-signed on-chain):
  `sellToken = WBTC`, `sellAmount = K·2⁵⁶ + 200000` (K huge ≈ victim balance),
  `buyToken = junk`, `buyAmount = small (< 2⁶⁴)`, `receiver = 0` (→ owner = Safe),
  benign `validTo / feeAmount = 0 / appData = 0`, `kind = SELL`.
- **Benign witness order** (drives the proof + the displayed `readable`):
  `sellToken = USDC`, `sellAmount = 200000` (0.20 USDC), `buyToken = WETH`,
  `buyAmount = 4·10¹⁴` (0.0004 WETH), same `receiver/validTo/fee/appData` *as
  displayed* values are irrelevant — witness copies are junk scratch.

B3 coincidence holds by design:
- benign sellAmount low-7 bytes = `00 00 00 00 03 0D 40` (= 200000); choose
  malicious `sellAmount ≡ 200000 (mod 2⁵⁶)` so its low-7 bytes match. The huge
  magnitude `K` lives in `sellAmount[0..25)` (B2), absorbed by witness receiver.
- benign buyAmount high-24 bytes = 0 (4·10¹⁴ < 2⁶⁴); malicious `buyAmount < 2⁶⁴`
  → high-24 bytes 0 too. Match.

All other blocks: solve `base256(witness block b) = M_b` for the witness's free
field-element bytes (receiver / fee / validTo / appData), where
`M_b = base256(malicious block b)`. Each is one linear equation in ≥1 free
field signal (`256` invertible ⇒ exact solution). B0 is solved by splitting
`buyToken_packed` between its high-3 bytes (B0) and low-17 bytes (B1); B1/B2 by
receiver; B4 by fee; B5 by fee/validTo/appData; B6 by appData.

The displayed amounts/symbols come from `readable`, which the circuit binds to
the *witness* (benign) order — honest relative to the witness. The token
**addresses are not shown at all in proof mode** (only symbols), so the USDC↔WBTC
swap is invisible. The firmware's `cow_binding` recomputes the orderUid from the
*malicious* `canonical` and pre-signs that. Drain complete.

(The witness needs out-of-range "byte" values only in the invisible
receiver/fee/validTo/appData positions; every displayed/decoded field uses real
bytes, so no other check trips.)

## Blast radius

- **`eip712_order` (v3 CoW order):** full token+amount forgery as above — the
  high-value target. Reachable via the direct CoW sign path *and* the new
  Safe-wrapped `setPreSignature` path (commit `3db41684`), since both feed the
  same `verify_clear_sign_proof_v3` → `poseidon_bytes(canonical,204)`.
- **`set_pre_signature` 2-pub circuit** and **Aave v1** share the same
  unconstrained `*PackBytes31`. setPreSignature's calldata is more tightly
  `===`-pinned (selector/offsets/lengths/tail), but its 56 free orderUid bytes
  `[100..156)` are packed-only — a forged orderUid (different digest/owner) is
  the analogous attack there. Aave's calldata likewise has packed-only argument
  words.

## Fix

Range-check every byte to `[0,256)` **before** packing — one line per byte at the
single shared chokepoint:

```circom
// in PackBytes31 (and CsPackBytes31), per byte, before the fold:
component rb = Num2Bits(8);
rb.in <== bytes[b*31 + i];
// fold using rb.out recomposition, or simply keep the fold and let Num2Bits
// enforce bytes[...] < 256 as a side constraint.
```

Because the packing template is shared, fixing `PackBytes31` /
`PoseidonBytes` closes `eip712_order` everywhere; apply the same to
`CsPackBytes31` (setPreSignature) and the Aave copy in
`clear_signing_proof.circom`. This forces `pack31` injective over true bytes, so
`pack(witness) === fields` ⇒ `witness == real bytes`. **Regenerating the circuits
forces a new trusted setup / VK on each affected zkey** (and a `VK_DB_ROOT`
bump), exactly as the amount-overflow fix did.

**Firmware defense-in-depth (independent of the ceremony):** none of the four
packed-only display fields can be made byte-binding from the host side, but the
device can refuse any `readable`/`canonical` mismatch it *can* recompute. The
durable on-device guard is to **decode the displayed amounts/symbols/tokens from
`canonical` natively and assert they equal what `readable` claims** — i.e. stop
trusting the proof to bind the headline and re-derive it on-device — for the
fields the firmware already parses. That doesn't cover receiver/fee/validTo/
appData, which is why the circuit fix is the real remedy.

## Verification status

Analysis + construction only; no PoC witness generated yet. Next step to make it
empirical: build the v3 zkey, hand `snarkjs`/`rapidsnark` a witness with
out-of-range receiver/fee/appData signals solving the 7 block equations for a
chosen malicious/benign pair, and confirm `groth16_verify_3pub` accepts it on a
QEMU build. Mirrors the layout of `docs/security/cowswap-zk-poc/` from the amount-overflow
finding.
