# Verification Target Catalog — 2026-06-12

> Output of a 5-area deep repo sweep (sphincs-core, eth-encoding, derivation/
> mnemonic, parsers/merkle, existing-verification-state), ranked by
> **mathematical correctness value** — where implementation bugs hide in the
> arithmetic and can be mechanically proven absent — NOT by security impact
> (owner directive). Feeds goals.leanloop.toml one target at a time.

## Area summaries

**sphincs-core** — The sphincs-c10 crate implements C10 SPHINCS+ signatures: WOTS+C (count-grinding base-w digit sum checks), FORS+C (13 Merkle trees with R-grinding forced-zero constraint), and a 2-layer hypertree (D=2, SUBTREE_H=9). Correctness risks concentrate in base-w digit extraction (off-by-one in bit indexing, big-endian byte layout), checksum/digit-sum arithmetic (TARGET_SUM=205, accumulation overflows), tree index arithmetic (bit shifts, masking, parent/sibling computation), and authentication path reconstruction (loop invariants, height-to-index bijections). Aeneas can extract the core logic (all safe sequential Rust; Fisher-Yates already in-tree), but ground truth varies: FORS index extraction is partially proven (ForsLoop.lean covers panic-freedom); WOTS has a hand-written spec in Lean (Wots.lean); address packing (make_adrs) is extracted+proven in AdrsEquiv.lean. Remaining targets are unproven arithmetic properties.

**eth-encoding** — The PQSigner tx-core and aa crates implement Ethereum ABI/RLP encoders and EIP-4337/EIP-712 hashers that convert user transactions into digests for post-quantum signing. These are the firmware's interface to on-chain contract logic. Mathematical correctness is critical: RLP parsing has classic boundary-condition bugs (55-byte threshold, length-of-length encoding, canonical form), ABI encoding involves 32-byte alignment and offset arithmetic, and the userOpHash doubles over keccak-256 with precise byte layout. Already-proven targets (compute_user_op_hash, write helpers) show the extraction pipeline works and Aeneas can handle these patterns. Unproven: RLP parser (all functions), EIP-1559 parser, U256 arithmetic, EIP-712 domain derivation, batch calldata reconstruction (currently excluded from extraction), and the wiring between firmware-reconstructed preimages and on-chain verifiers.

**derivation-encoding** — This area computes key derivation from BIP-39 entropy through layered KDFs to SPHINCS+C10 signing keys, encodes 24-word mnemonics as 256 bits + 8-bit checksum into 11-bit word indices, and manages wire-format serialization of sign requests (bit-packed flags, fixed-size offsets, length calculations). Correctness risks concentrate in: (1) 11-bit bit-packing (off-by-one in read/write_11_bits for the entropy-checksum boundary), (2) N-mask application to pk_seed (bottom 16 bytes must stay zero), (3) flags bitfield extraction (account_index and slot_index bit shifts), (4) manifest CRC-32 and digest computation (preimage assembly, byte ordering), (5) BIP-39 checksum validation (Sha256 on entropy then XOR with first byte). The recovered seed and slot derivation chains feed every SPHINCS+ signature, making this the absolute critical path for wallet recovery and key material generation.

**parsers-merkle** — The tx/ and pqsigner-erc7730/ crates are host-side parsers and Merkle verifiers for trust bundles (ERC20 metadata, names, selectors, ERC7730 descriptors). They employ intricate mathematical structures: Merkle tree walking with leaf-index bit-selection, base-w TLV decoding, length-prefixed buffer parsing with strict bounds checking, and context-binding cross-checks. Correctness risks concentrate in bit-twiddling (leaf_index >> shifts, idx & 1 conditions), off-by-one buffer arithmetic, length computation chains (cumulative offset calculations), canonical byte reconstruction order, and endianness handling (LE vs BE).

**verification-state** — The PQSigner_OS firmware implements SPHINCS+C10 post-quantum signatures with several mathematical layers: bit-level index extraction (read_bits_le), FORS tree position binding (htIdx), WOTS+C count grinding, address structure packing, and userOp hash reconstruction. The existing verification covers panic-freedom of the FORS index path and address byte-layout equivalence to spec. Remaining high-value correctness targets involve: (1) functional correctness of the bit-reader accumulator (the loop invariant for read_bits_le), (2) WOTS+C digit extraction and target-sum semantics, (3) tree-index arithmetic in merkle/hypertree composition, (4) userOp buffer layout-to-hash equivalence, and (5) FORS grind_r termination + randomizer properties.

## Prioritized targets

### 1. sphincs-c10/src/fors.rs::read_bits_le — functional correctness (dedupes sphincs-core read_bits_le + verification-state FUNCTIONAL CORRECTNESS entries)

- **Prove:** For 0 < num_bits <= 57 and bit_offset <= 248: extracted read_bits_le digest off num = SphincsCVerify.Util.Bits.readBitsLe (the exact LE bit-window value), strengthening the existing post from `result < 2^num_bits` to `result = bitwise_extract`.
- **Why bug-prone:** Big-endian byte indexing (`31 - bit_offset/8`), `wrapping_sub` byte walk, per-byte shift placement and final mask all interact in one accumulator loop; the proof is a genuine loop-induction where disjoint-OR must be rewritten as ADD at every step — exactly the class of bit math where off-by-ones hide.
- **Ground truth:** Lean spec SphincsCVerify/Util/Bits.lean::readBitsLe (lines 37-44); 10 (message, expectedDigestHex, expectedHtIdx) KAT triples in contracts/verification/lean/SphincsCVerify/KatVectors.lean.
- **Builds on:** Extracted/ForsLoop.lean (panic-freedom + in-range, all @[step], sorry-free) + Extracted/Bits.lean::lor_eq_add_disjoint (PROVEN 2026-06-11) + the explicit invariant roadmap in Extracted/ForsExtractWIP.lean lines 17-28. Extraction already wired via `make extract-fors-index`.
- **Effort:** days (was 'weeks' in the survey, but the blocking lemma landed 2026-06-11)
- **First step:** Create contracts/verification/extracted/Extracted/ForsExtract.lean stating `read_bits_le_functional` with the strengthened loop post from ForsExtractWIP.lean (`val.val = <partial LE byte-window> ∧ val.val < 256^start`), sorry'd; then uncomment/fill the prepared `Extracted.ForsExtract` [[goal]] stub in contracts/verification/goals.leanloop.toml and run `leanloop run --manifest goals.leanloop.toml`.

### 2. sphincs-c10/src/fors.rs::extract_fors_indices + extract_ht_index — functional composition + vendored-spec bridge (dedupes 3 survey entries; range/panic-freedom already proven)

- **Prove:** extract_ht_index digest = (digest_le >>> 143) &&& 0x3FFFF and extract_fors_indices[i] = (digest_le >>> (i*11)) &&& 0x7FF for all i < 13, matching Spec extractHtIndex/extractForsIndices, capped by a `firmware_extract_ht_index_matches_vendored` SpecBridge theorem (firmware-level CWE-347 close).
- **Why bug-prone:** The composition pins the K*A=143 / A=11 / H=18 offset arithmetic and the u64->u32 truncating casts; an off-by-one in any constant silently rebinds FORS positions while still passing range checks.
- **Ground truth:** SphincsCVerify/Util/Bits.lean::extractForsIndices (60-62) + extractHtIndex (64-66); KatVectors.lean expectedHtIdx values; matches the Yul `and(shr(143, digest), 0x3FFFF)` on-chain.
- **Builds on:** Rank 1 (read_bits_le functional) + Extracted/SpecBridge.lean ADRS precedent (firmware_make_adrs_matches_vendored) + Extracted/ForsLoop.lean in-range theorems.
- **Effort:** days
- **First step:** Vendor Spec/Fors.lean's htIdx extraction into Extracted/SpecVendored.lean and state a sorry'd `firmware_extract_ht_index_matches_vendored` in Extracted/SpecBridge.lean mirroring the make_adrs bridge, leaving rank 1's lemma as its single open premise.

### 3. aa/src/eip1271.rs::domain_separator (line 101) + personal_sign_prefixed_hash (119) + replay_safe_hash (162)

- **Prove:** Byte-exact preimage layout: domain_separator's 160-byte buffer (typehash || nameHash || versionHash || chainId-left-padded || address-at-[140..160)), the `\x19Ethereum Signed Message:\n` + decimal_str prefix, and replay_safe_hash's two-stage nesting (`\x19\x01 || ds || structHash`) each equal a pure Lean byte-list spec in front of opaque keccak256_pure calls — the Solady nesting order proven, not tested.
- **Why bug-prone:** Three fixed-offset buffer assemblies plus a hand-rolled usize->ASCII decimal converter with a digit-reversal loop; word-slot constants (96+24, 128+12) and the nesting order are pure offset arithmetic with no type-level guard.
- **Ground truth:** EIP-712 spec + Solady ERC1271 PersonalSign branch; repo tests replay_safe_hash_matches_solady_nesting / personal_sign_replay_safe_hash in aa/src/eip1271.rs tests.
- **Builds on:** The COMPLETED userOpHash byte-layout proof (Extracted/UserOpEquivByteLayout.lean specInner/specOuter + compute_user_op_hash_spec) — same crate, same keccak256_pure axiom (the only whitelisted axiom), same SetSliceLemmas method. Cheapest path to a new end-to-end theorem.
- **Effort:** days
- **First step:** Add `--start-from 'pqsigner_aa::eip1271::replay_safe_hash'` (pulling in domain_separator + personal_sign_prefixed_hash) to a new extract-aa-eip1271 target in contracts/verification/Makefile cloned from extract-aa-userop, commit Extracted/Eip1271/Funs.lean, and state specInner/specOuter-style byte-list specs.

### 4. sphincs-c10/src/wots.rs::extract_digits (line 16) — dedupes sphincs-core #1 and the digits half of verification-state #9

- **Prove:** Functional equivalence: extract_digits digest = [readBitsLe digest (i*LOG_W) LOG_W for i < 43] with every digit < W=8, matching SphincsCVerify.Util.Bits.extractDigits (already proven correct in isolation in Bits.lean).
- **Why bug-prone:** The 3-bit window spans byte boundaries with a separate two-byte-read branch (`bit_in_byte + LOG_W <= 8` guard, hi-byte shift `8 - bit_in_byte`); the digit range bound is also the load-bearing premise that makes pk_from_sig's `(W-1) - digit` subtraction non-wrapping.
- **Ground truth:** SphincsCVerify/Util/Bits.lean::extractDigits (49-51, spec proven in isolation); contracts/smart-wallet/test/c10_test_vectors.json + sphincs-c10/tests/gen_test_vectors.rs byte-equality KATs.
- **Builds on:** The extract-fors-index Makefile pattern + ForsLoop.lean's @[step] battery + rank 1's accumulator technique (same readBitsLe spec family).
- **Effort:** days (extraction is hours; the proof is a direct method transfer from rank 1's accumulator induction)
- **First step:** Add an `extract-wots-digits` target to contracts/verification/Makefile mirroring extract-fors-index (`--start-from 'sphincs_c10::wots::extract_digits'`), commit Extracted/Wots/Funs.lean, and copy ForsLoop.lean's terminates/in-range battery as the first sorry-free milestone.

### 5. sphincs-c10/src/wots.rs::pk_from_sig (line 137)

- **Prove:** Verifier-side WOTS equivalence to Spec/Wots.lean::pkFromSig: digit-sum != TARGET_SUM=205 returns the zero pubkey; otherwise each chain is advanced exactly (W-1)-digit[i] steps then th_multi-compressed — with the unsigned subtraction proven non-underflowing from rank 4's digit-range lemma.
- **Why bug-prone:** `(W - 1) as u32 - digits[i] as u32` silently wraps to ~2^32 if any digit exceeds 7, and the digit-sum gate must be exact (sum check, not range check); correctness rests on a deep premise chain (extract_digits -> range -> no-underflow -> chain count).
- **Ground truth:** SphincsCVerify/Spec/Wots.lean::pkFromSig (54-76, step-for-step mirror of the Rust); sign/verify round-trip KATs in contracts/smart-wallet/test/c10_test_vectors.json and sphincs-c10/tests/signing_suite.rs.
- **Builds on:** Rank 4 digit-range lemma + Spec/Wots.lean + the keccak256_pure opaque-function pattern (UserOp/FunsExternal.lean) reused for chain_hash/th_multi.
- **Effort:** days
- **First step:** Extend the wots extraction scope to pk_from_sig with chain_hash/th_multi declared opaque in a new Extracted/Wots/FunsExternal.lean (clone the keccak256_pure pattern, add the new symbols to the leanloop.toml axiom_whitelist), then state the digit-sum-gate + no-underflow theorem consuming rank 4.

### 6. sphincs-c10/src/merkle.rs::verify_auth_path (line 137) — dedupes sphincs-core #8 and verification-state #6

- **Prove:** Loop invariant: after h iterations, node = parent of (original leaf, auth_path[0..h]) at height h with index idx >> h (left/right selected by bit h of idx); the final node equals Spec/Hypertree.lean's reconstructRoot output for all leaf_idx < 2^SUBTREE_H.
- **Why bug-prone:** Parent/sibling selection via `idx & 1` and `idx >>= 1` is classic fence-post territory — one flipped branch or one extra shift verifies a mirrored tree; nothing bounds leaf_idx at entry, so the invariant must carry the index bound.
- **Ground truth:** SphincsCVerify/Spec/Hypertree.lean reconstructRoot/verifyAuthPath specs; KatVectors.lean (pkSeed, pkRoot, signature, expectValid) vectors embed real XMSS auth paths.
- **Builds on:** Spec/Hypertree.lean (spec already written) + the established extraction harness + opaque-hash pattern from rank 5.
- **Effort:** days
- **First step:** Add an `extract-merkle-verify` Makefile target (`--start-from 'sphincs_c10::merkle::verify_auth_path'`) with th_pair opaque in FunsExternal, then state the height-h loop-invariant lemma against Spec/Hypertree.lean's reconstructRoot.

### 7. tx-core/src/rlp.rs::bytes_to_u64 (line 158) + bytes_to_u256 (line 174)

- **Prove:** Exact canonical BE decode: returns the big-endian Nat value iff input is canonical (len <= 8 / <= 32, empty encodes 0, no leading zero byte), error otherwise; the `acc << 8` accumulation and 32-byte left-pad are overflow-free and byte-exact.
- **Why bug-prone:** Leading-zero rejection and length thresholds are the canonical-RLP boundary conditions where every historical RLP bug lives; the same accumulator-loop-equals-BE-value induction as rank 1, in a new crate.
- **Ground truth:** Ethereum RLP spec (Yellow Paper §B); tx-core/tests/rlp_decoder.rs positive + negative vectors; cross-impl anchors (go-ethereum, viem).
- **Builds on:** Nothing proven yet in tx-core — this is the deliberate beachhead that wires the tx-core crate into the Aeneas harness with the smallest possible proof.
- **Effort:** hours
- **First step:** Add an `extract-txcore-rlp` Makefile target (`--start-from 'pqsigner_tx_core::rlp::bytes_to_u64' --start-from 'pqsigner_tx_core::rlp::bytes_to_u256'`), commit Extracted/Rlp/Funs.lean, and write a Lean `beBytesToNat` spec + canonicality predicate to prove the accumulator loops against.

### 8. tx-core/src/rlp.rs::decode_item (line 35)

- **Prove:** Acceptance iff canonical: decode_item returns (Item, consumed) iff the input prefix is canonical RLP (55-byte short/long threshold, len_of_len in 1..=8, no leading zeros in length fields, minimal single-byte form), with `consumed` exactly the encoded length — and rejects everything else with the matching RlpError variant.
- **Why bug-prone:** Six distinct boundary checks (lines 46, 60, 69, 78, 88-89, 97-99) plus checked_add header+payload arithmetic; a single >= vs > flip accepts non-canonical encodings that hash differently from what the EVM signs.
- **Ground truth:** Yellow Paper §B canonical-form rules; rich negative-vector suite in tx-core/tests/rlp_decoder.rs; round-trip property pinned by tests.
- **Builds on:** Rank 7's extraction wiring and beBytesToNat spec (length-field decode reuses it directly).
- **Effort:** days
- **First step:** Write a canonical-RLP inductive predicate in a new Spec/Rlp.lean and state `decode_item_accepts_iff_canonical` over the rank-7 extraction; port ~10 negative vectors from tx-core/tests/rlp_decoder.rs into a Lean KAT list as the falsification harness.

### 9. bip39/src/full.rs::write_11_bits (line 427) + the 11-bit read path / Mnemonic::to_entropy (line 211)

- **Prove:** Round-trip: for all idx in [0,24) and w < 2^11, reading back after write_11_bits recovers w with all other bits unchanged; composed: to_entropy inverts from_entropy and the checksum byte comparison (SHA256(entropy)[0]) is exact.
- **Why bug-prone:** Three conditional byte writes per 11-bit word (byte, byte+1, byte+2 fence-posts) and a `24 - shift - BITS_PER_WORD` offset formula — the canonical setting for frame-preservation bugs that corrupt adjacent words only for specific indices.
- **Ground truth:** Official BIP-39 test vectors imported in bip39/tests/vectors.rs; round-trip tests in bip39/tests/positive_api.rs and prefix5_roundtrip.rs.
- **Builds on:** SetSliceLemmas.lean byte-window lemmas transfer; otherwise a fresh, very small extraction crate.
- **Effort:** hours
- **First step:** Add an `extract-bip39-bits` Makefile target scoped to the pack/unpack helpers, then state the Lean round-trip theorem `∀ idx < 24, w < 2048, read (write buf idx w) idx = w` plus untouched-bit frame preservation.

### 10. tx-core/src/eip1559.rs::U256::saturating_mul_u64

- **Prove:** Exact saturating multiply: result = min(self * rhs, 2^256 - 1) as Nat, overflow flag set iff self * rhs >= 2^256, and the per-byte u128 carry accumulator never overflows (max ~2^80).
- **Why bug-prone:** Reversed-iteration byte-wise multiply with carry threading (`prod >> 8`) is a textbook carry-propagation induction; overflow detection via only the final carry is correct but non-obviously so.
- **Ground truth:** tx-core/tests/u256_arithmetic.rs + inline eip1559.rs tests (saturating_mul_basic, saturating_mul_overflow_saturates); EVM uint256 semantics.
- **Builds on:** Rank 7's tx-core extraction wiring (same crate, add one --start-from).
- **Effort:** hours
- **First step:** Add U256::saturating_mul_u64 to the extract-txcore-rlp scope, write the Nat-level Lean spec `mulSat a b = (min (a*b) (2^256-1), a*b ≥ 2^256)`, and prove by induction over the 32 reversed limbs.

### 11. tx/src/erc20/merkle.rs::verify_proof (line 34)

- **Prove:** Membership-walk correctness: the computed hash after proof_depth levels from (leaf, leaf_index) equals the root iff the tuple is a valid membership path under leaf_hash = sha256(0x00||leaf) / node_hash = sha256(0x01||l||r), and the entry check `proof_bytes.len() == proof_depth * 32` exactly equals the bytes the loop consumes.
- **Why bug-prone:** Same `idx >>= 1` / `idx & 1` walk as rank 6 plus a length-equals-consumption side condition: if the exact-length check and loop ever disagree, a malformed proof with trailing or missing siblings is accepted; this one function underpins all four trust-bundle verifiers (erc20/names/selectors/7730).
- **Ground truth:** tx/tests/positive_merkle.rs (singleton, 2/3-leaf padded, 32-leaf, max-depth-32 trees) + dbgen cross-implementation in tx/tests/common/mod.rs::build_tree.
- **Builds on:** Rank 6's Merkle index-walk lemmas (restated for the sha256 domain-separated scheme) + opaque-sha256 boundary from rank 5.
- **Effort:** days
- **First step:** Add an `extract-tx-merkle` Makefile target for tx::erc20::merkle::verify_proof with the two sha256 hash constructors opaque, and restate rank 6's invariant plus a `bytes_consumed = proof_depth * 32` lemma.

### 12. fw-manifest/src/lib.rs::signed_preimage (line 187) + compute_signed_digest (line 208)

- **Prove:** Byte layout: the preimage is exactly 75 bytes = "PQFW_V1"(7) || fw_version BE(4) || secure_hash(32) || nonsecure_hash(32) in that order for all inputs, and compute_signed_digest = SHA256 of exactly that byte list (hash opaque).
- **Why bug-prone:** Pure offset arithmetic (ver_off/sec_off/ns_off chaining) on a frozen 75-byte format that the entire FW-update trust chain reconstructs from (version, elf-hashes) — a one-byte layout drift breaks auditor reconstruction silently.
- **Ground truth:** Manifest spec in the file header (the CLAUDE.md-frozen 75-byte preimage); layout test at fw-manifest lib.rs:774-782 (signed_preimage_layout), digest test 791-793, panic-freedom property test 890-900.
- **Builds on:** SetSliceLemmas.lean + the AdrsEquiv byte-layout method — this is the same proof shape as the already-closed make_adrs_spec, on a different crate.
- **Effort:** hours
- **First step:** Add an `extract-fwmanifest-preimage` Makefile target scoped to signed_preimage/compute_signed_digest, then state `signed_preimage_spec` as a literal 75-byte list equation in the AdrsEquiv style.

## Phase plan

**now** — Every target extends an artifact that is already extracted, spec'd, or just unblocked (lor_eq_add_disjoint landed 2026-06-11; userOpHash byte-layout method is complete and reusable) — this phase converts the FORS panic-freedom result into full functional correctness (closing CWE-347 at the firmware level) and clones two proven methods onto adjacent code with near-zero harness work.
- 1: fors::read_bits_le functional
- 2: extract_fors_indices/extract_ht_index composition + SpecBridge
- 3: eip1271 byte layouts
- 4: wots::extract_digits extraction + range

**next** — Introduces the opaque-hash boundary pattern (chain_hash/th_multi/th_pair as whitelisted axioms, mirroring keccak256_pure) to climb the SPHINCS verifier-side composition one layer, and opens the tx-core beachhead where the canonical-RLP acceptance theorem is the single most bug-rich parser proof in the catalog.
- 5: wots::pk_from_sig
- 6: merkle::verify_auth_path
- 7: rlp bytes_to_u64/u256
- 8: rlp decode_item

**later** — Cheap byte-layout and arithmetic wins across the remaining crates, then the weeks-effort composition targets (hypertree end-to-end, grinding loops stated as partial-correctness postconditions only — probabilistic termination of find_count/grind_r and fisher_yates uniformity are explicitly non-goals for LeanLoop since they are not falsifiable Lean obligations).
- 9: bip39 11-bit round-trip
- 10: U256::saturating_mul_u64
- 11: tx erc20 verify_proof
- 12: fw-manifest signed_preimage
- deferred residue: find_count partial correctness, grind_r forced-zero postcondition, hypertree sign/verify composition, eip1559::parse, reconstruct_execute_batch_calldata (needs §33 P2 refactor)

## KAT / test-vector anchors (for `leanloop kat`)

- Ranks 1-2 (read_bits_le / FORS indices): contracts/verification/lean/SphincsCVerify/KatVectors.lean already carries 10 (message, expectedDigestHex, expectedHtIdx) triples in Lean form — directly executable by `leanloop kat` against the functional specs with zero conversion work; the same digests anchor per-index extract_fors_indices checks.
- Ranks 4-5 (extract_digits / pk_from_sig) and rank 6 + later hypertree: contracts/smart-wallet/test/c10_test_vectors.json pins full (pkSeed, pkRoot, message, signature, expectValid) sign/verify round-trips whose blobs embed the WOTS digits, counts, and XMSS auth paths; sphincs-c10/tests/gen_test_vectors.rs can regenerate them. Caveat from the verification-state survey: the KATs carry pre-cooked (count, digest, sigma) triples but NOT the ground-truth count find_count would recompute — regenerate via gen_test_vectors.rs before stating a find_count KAT.
- Already-proven precedent (userOpHash): /home/nicola/repos/PQSigner_OS/test_userop.json (userOpBench: sender, nonce, gas fields, digest) is the existing kat anchor for compute_user_op_hash_spec and the template for converting JSON vectors into Lean KAT lists.
- Rank 3 (eip1271): aa/src/eip1271.rs inline tests (replay_safe_hash_matches_solady_nesting, personal_sign_replay_safe_hash, replay_safe_hash_never_returns_input) pin Solady-nesting bytes — port the asserted hashes into a Lean KAT list (keccak evaluated host-side since keccak256_pure is opaque).
- Ranks 7-8, 10 (tx-core): tx-core/tests/rlp_decoder.rs (positive AND negative canonical-form vectors — the negatives are the valuable half for the iff-theorem), u256_arithmetic.rs, and keccak256_kat.rs port mechanically; eip1559_parser.rs vectors become the later-phase parse() anchors.
- Rank 9 (bip39): bip39/tests/vectors.rs imports the official BIP-39 (entropy, mnemonic) vector set — the strongest external ground truth in the whole catalog; prefix5_roundtrip.rs adds firmware_fingerprint_lines round-trips.
- Rank 11 (tx merkle): tx/tests/positive_merkle.rs trees (singleton / 2-leaf / 3-leaf padded / 32-leaf / depth-32) plus the dbgen cross-implementation give both KAT roots and a second-implementation oracle.
- Rank 12 (fw-manifest): the 75-byte layout test (lib.rs:774-782), digest test (791-793) and the crc32 standard vector crc32_ieee("123456789") == 0xCBF43926 (line 669) are single-line Lean KAT facts.
