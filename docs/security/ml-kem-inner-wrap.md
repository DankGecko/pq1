# ML-KEM-1024 inner wrap — design + status

**Invariant #3 (PQ confidentiality of SE traffic). Closes the documented
Harvest-Now-Decrypt-Later (HNDL) residual.**

## Threat

The dual-SE entropy halves (`half_O` on OPTIGA, `half_E` on SE050) cross I²C
under the secure elements' *classical* channels — OPTIGA Shielded Connection
(AES-128-CCM-8) and SE050 SCP03 (AES-CMAC/CBC). Those channels' session keys
derive from classical primitives (ECDH / static AES). A **Harvest-Now,
Decrypt-Later** adversary records the bus today and decrypts once a CRQC exists
— and for a wallet holding long-term funds, need not be present at decryption
time. This is the dominant PQ residual (README §threat-model): *"until the
inner wrap lands, the SE channels carry plaintext halves under the classical
SE-vendor AE layers."*

## Design — KEM-DEM "encrypt-to-self"

The MCU (secure world) holds ONE ML-KEM-1024 (FIPS 203) keypair. Each half is
sealed with **ML-KEM-1024 + AES-256-GCM** *before* it touches I²C, so the
classical SE channel carries only PQ-opaque ciphertext.

```
seal(seed, m, pt):                       open(seed, ct‖aead):
  dk = ML-KEM.from_seed(seed)              dk = ML-KEM.from_seed(seed)
  ek = dk.encapsulation_key()              K  = ML-KEM.Decaps(dk, ct)
  (ct, K) = ML-KEM.Encaps(ek; m)           pt = AES-256-GCM.Open(K, ct‖aead)
  aead = AES-256-GCM.Seal(K, pt)           return pt
  store ct ‖ aead on the SE
```

`K` (32-byte ML-KEM shared secret) is the AES-256 key. A fresh `K` is produced
for **every** seal (the encapsulation message `m` is fresh TRNG), so the
`(key, nonce)` pair is unique even with a fixed all-zero GCM nonce — textbook
KEM-DEM. ML-KEM decapsulation uses *implicit rejection* (never errors — a bad
ciphertext yields a pseudo-random `K`); the **GCM tag** is the authenticator,
so a tampered `ct`, tampered `aead`, or wrong device `seed` all fail at `open`.

Wire layout of the stored blob: `ct (1568) ‖ gcm_ct (pt_len) ‖ tag (16)`. For a
32-byte half: **1616 bytes**. AAD = `b"pqsigner-inner-wrap-v1"` (domain sep).

### Key derivation — refinement of the "stored sk" plan

The README originally framed this as *"factory generates + HUK-SAES-wraps the
ML-KEM keypair, sk stored in secure flash."* We instead **derive the keypair
deterministically from a HUK-bound 64-byte seed each boot** (`ml-kem`'s
`DecapsulationKey::from_seed`, the FIPS-203 `d‖z` seed = the canonical sk
serialization). This is strictly stronger: nothing lattice-secret is *stored* in
plaintext, on a bus, or on an SE — the "sk" is `hw::huk::derive_device_key`
output, per-die and deterministic across boots (exactly the "seal-at-write,
unseal-at-read" property HUK already guarantees). Recovering a half therefore
requires physical extraction of the *specific* U585 die + a working RDP-2 break
+ HUK extraction — and even then only one half, the other being on the other SE
under a different ciphertext gated by that SE's retry counter.

## Crypto agility

ML-KEM protects only the *confidentiality of stored halves*. The signing key
never depends on lattices (SPHINCS+C10, SHA-256 only). If ML-KEM is ever broken,
only this inner-wrap layer migrates — signatures and firmware verification are
unaffected (README §"why hash-based signatures for the actual money").

## Implementation status (pieces)

| # | Piece | Status |
|---|-------|--------|
| 1 | **`pqsigner-pq-seal` primitive** — ML-KEM-1024 + AES-256-GCM `seal`/`open`, deterministic keypair from a 64-byte seed, no_std/thumbv8m-clean, 8 KATs (round-trip, no-leak, tamper-ct, tamper-aead, wrong-seed, determinism, fresh-randomness, bounds) | ✅ **done** |
| 2 | Firmware wiring — derive the seed via `hw::huk`, draw `m` from the TRNG, `seal`/`open` at the dual-SE store/read boundary (`secure/src/dual_se.rs`) | ⏳ next |
| 3 | SE object sizing + provisioning — the stored blob grows 32 B → 1616 B per half; confirm OPTIGA `0xF1D1` / SE050 binary-object capacity, adjust object metadata | ⏳ |
| 4 | Migrate OPTIGA/SE050 reads onto the wrap; trace-verify the seed never appears in plaintext on either bus | ⏳ |

## Follow-ups (hardware / acceptance)

- **Binary size:** `ml-kem` pulls `sha3 0.11` (Keccak) — a *second* hash stack
  alongside the firmware's SHA-256. Measure the flash delta in piece 2; if it
  matters, evaluate sharing the U585 HASH peripheral / a no-sha3 path.
- **Constant-time / SCA:** `ml-kem` is RustCrypto-ACVP-validated but not
  formally CT. On-target NIST-vector validation + a constant-time inspection of
  the Decaps inner loops + an FI-lab pass on Decaps remain (README §acceptance,
  work-todo). `cargo-checkct` / `haybale-pitchfork` over the Decaps path is the
  host-side leg.
- **Zeroization:** `seal`/`open` zeroize the shared secret `K` and (on tag
  failure) the output buffer; the `ml-kem` `zeroize` feature is enabled so the
  `dk` material zeroizes on drop.
