# Ledger Donjon Rust SCA/CT tooling — cargo-checkct + Muscat

Two Ledger-Donjon tools brought up 2026-06-16 to complement the in-tree
`rainbow`/`lascar`/`scared` SCA workflow. Both proven on **real** PQ-Signer data.

- **`cargo-checkct`** — constant-time *verifier*. Compiles a driver to a bare-metal
  ELF and runs **binsec** relational symbolic execution to *prove* (for all secret
  values) that no conditional branch and no memory-access address depends on a
  secret. The only tool we found that targets the shipped **thumbv8m** ISA (Binsec/Rel
  alone has no ARMv8-M decoder; `ct_analyzer` is a source/asm-pattern pre-filter).
- **Muscat** — multithreaded Rust SCA *analysis* library (CPA / DPA / SNR / NICV /
  Welch-T-test / elastic alignment). Donjon's successor to `lascar` (now "legacy").
  Consumes `.npy` trace tensors — same data the `tools/sca` rainbow harnesses emit.

See `docs/security-tooling-sota-2026-06.md` §1/§4 + work-todo §18b/§34.

---

## 1. cargo-checkct

### Install (one-time; binsec is the heavy part)

binsec is OCaml (not on crates.io / nixpkgs), built from source via opam. On a host
with `sudo apt`, the upstream README's `opam install … ; dune build` is simplest. On
this host (no sudo) it was installed via nix + a local opam root — full recipe in
`~/checkct_env.sh` (sourceable; sets nix PATH, OPAMROOT, the `checkct` opam switch, and
the gmp store paths). Summary:

```bash
# the tool itself (pure Rust)
git clone https://github.com/Ledger-Donjon/cargo-checkct ~/repos/cargo-checkct
cd ~/repos/cargo-checkct && cargo build --release      # -> target/release/cargo-checkct

# backend: binsec 0.10.0 + unisim_archisec 0.0.10 (OCaml 4.14.2 opam switch + bitwuzla SMT)
#   opam switch create checkct ocaml-base-compiler.4.14.2
#   opam install dune dune-site menhir grain_dypgen ocamlgraph zarith toml bitwuzla
#   (clone+`dune build @install && dune install` unisim_archisec @0.0.10 then binsec @0.10.0)
# pinned nightly driver toolchain:
rustup component add rust-src --toolchain nightly-2026-04-06
rustup target add thumbv8m.main-none-eabi --toolchain nightly-2026-04-06
```

> **Upstream bug (worked around in `.cargo/config.toml`):** recent nightlies turned
> `panic_immediate_abort` from a build-std *feature* into a panic strategy. The template
> still lists it as a feature and fails to build `core`. Fix applied here: drop the
> feature, add `rustflags = ["-Zunstable-options", "-Cpanic=immediate-abort"]`. Worth a PR.

### Run

```bash
source ~/checkct_env.sh && export PATH="$HOME/.cargo/bin:$PATH"
cd <repo-root>
cargo-checkct run --dir tools/sca --timeout 300     # finds tools/sca/checkct/
```

`--dir` is the directory *containing* a folder literally named `checkct/`. The vendored
workspace `tools/sca/checkct/` path-deps `sphincs-c10` (repo-relative) and
`checkct_macros` (assumes `~/repos/cargo-checkct` is a sibling of this repo — adjust the
path in `driver/Cargo.toml` otherwise).

> **In-repo cargo-config gotcha (fixed in `.cargo/config.toml`):** because this workspace
> lives inside the PQSigner repo, cargo merges the repo-root `.cargo/config.toml`. The root
> sets `target.thumbv8m.main-none-eabi.rustflags`, which cargo uses **instead of** (never
> merged with) a `[build] rustflags` — so the required `-Cpanic=immediate-abort` would be
> silently dropped, bloating `.text` with panic machinery and crashing binsec with
> `Fatal error: exception Not_found`. The flags are therefore defined under
> `[target.thumbv8m.main-none-eabi]` here (closer config wins) and carry the inherited
> `--build-id=none` forward. Verified: with the fix the in-repo build's `.text` (0x26c4)
> and verdict are byte-identical to a standalone build.

### How secrets are marked

No attributes/config on the crate under test — it's a **driver harness**
(`driver/src/driver.rs`): one `#[checkct]` fn, fill buffers with `PrivateRng` (SECRET) or
`PublicRng` (PUBLIC), then call the function under test. `cargo-checkct add -n <name>`
scaffolds more drivers (one per function/scenario). Output: `SECURE` (exit 0) or
`INSECURE` with the exact leaking instruction address(es).

### Verified result — `fisher_yates` (thumbv8m), the CT-1 cross-check

```
[checkct:result] Instruction 0x00020376 has control flow leak
[checkct:result] Instruction 0x000206da has memory access leak
[checkct:result] Instruction 0x000206e4 has memory access leak
Program status is : insecure   (517/518 control-flow + 5359/5361 memory-access checks pass)
```

**Interpretation (the INSECURE verdict is BY DESIGN, not a failure):**
- It **confirms the CT-1 fix**: the disasm at the swap is pure `lsrs/cmp` (`lsrs r3,#0x10`
  = the Lemire `>>16`) — **no `UDIV`, no new secret-dependent branch**. CT-1's goal
  (kill the variable-latency divider) holds at the machine level.
- The 3 flagged instructions are the *inherent* leaks of any in-place Fisher-Yates:
  `0x206da/0x206e4` = the `buf[j]` swap (secret-indexed memory **address**), and
  `0x20376` = the zero-seed identity fast-path branch (`if nonzero==0`, on an OR-fold of
  the seed — never taken in production since the TRNG seed is non-zero).
- The shuffle **deliberately** uses the address channel and relies on *statistical*
  trace-misalignment (43!/13! search space), **not** bitwise constant-time — so a strict
  checkct proof of the shuffle will always be INSECURE. A green run would require an
  oblivious/sort-based shuffle, which we explicitly chose not to build.

### Where a GREEN checkct run is meaningful (recommended next drivers)
`cargo-checkct add -n <name>` + a driver that marks the right secret:
- **`sphincs_c10::verify`** — inputs are public ⇒ positive-control / regression gate (expect SECURE).
- **WOTS/FORS chain hashing** with `sk_seed` secret — a SECURE verdict = a real CT proof
  of the core signing hash path (chain *lengths* are public digits; secret chain *values*
  flow through hashes without secret-indexed access).
- **KDF / CMAC wrapper** — checkct cannot see the **SAES/HASH/PKA hardware** (binsec models
  only the CPU). Drive the *software mirror* the SCA targets already use
  (`tools/sca/saes_kdf_target` mirrors `secure/src/cmac.rs::cmac_generic` under software AES);
  mark the key/label secret. Proves the wrapper's CPU work constant-time.
- **`pqsigner-domain` KDF** (HMAC-SHA512/PBKDF2) — mark `bip39_seed`/`entropy`; expect SECURE
  (SHA-2/HMAC are inherently CT) — a guard against secret-indexed code creeping in.

**Scope limit:** checkct catches secret-dependent **branches** and **addresses**, *not*
variable-latency instructions (e.g. it would not by itself have caught CT-1's `UDIV`
timing — `ct_analyzer` + the M33 divider knowledge did). It is complementary to the
rainbow timing/DPA sweeps, not a replacement.

---

## 2. Muscat

### Build + run

```bash
cd ~/repos/muscat && cargo build --release --examples     # ~10s, no extra system deps
# harness (vendored copy in tools/sca/muscat/pqsigner_tvla_cpa.rs — keep a copy in
# ~/repos/muscat/examples/ to build it as an example):
cp tools/sca/muscat/pqsigner_tvla_cpa.rs ~/repos/muscat/examples/    # + the [[example]] stanza
TRACES_DIR=<dir-with-traces.npy> cargo run --release --example pqsigner_tvla_cpa
#   env knobs: CPA_TARGET_BYTE, T_THRESHOLD (default 4.5), BATCH_SIZE
```

The harness reads `traces.npy` (uint8 `[n, samples]`, the rainbow `mem_address`
Hamming-weight channel), `classes.npy` (bool/uint8 `[n]`, the fixed/random TVLA flag),
`plaintexts.npy` (uint8 `[n, k]`, the msg bytes); runs **Welch's T-test (TVLA)** then a
**CPA** pass. No gnuplot dependency (unlike the bundled examples).

### Feeding it the existing rainbow traces

```bash
# 1. (re)generate the shuffle trace set with the EXISTING tooling:
make -C tools/sca f9-scared-collect          # -> tools/sca/out/f9_traces.npz
# 2. convert .npz -> the 3 .npy Muscat reads (mmap-streamed, multi-GB safe):
python3 tools/sca/muscat/npz_to_npy.py tools/sca/out/f9_traces.npz /tmp/f9_muscat
# 3. run:
cd ~/repos/muscat && TRACES_DIR=/tmp/f9_muscat cargo run --release --example pqsigner_tvla_cpa
```

`tools/sca/muscat/gen_pqsigner_shape.py` synthesises a PQ-Signer-shaped trace set (with a
ground-truth leaky-S-box) to self-test the harness without running rainbow (CI smoke).

### Verified results
- Synthetic ground truth: TVLA `max|t|=62.8` fires on the injected samples; CPA recovers
  the injected key `0x2b`.
- **Real `f9_traces.npz`** (sca_c10_sign_shuffled, post-F-16/CT-1), windowed to the first
  200k of 10M samples: TVLA `max|t|=3.24` (< 4.5) = **the F-16 shuffle holding** in that
  window. (The lascar full-10M baseline peak `max|t|≈4.93` sits later in the trace —
  convert all 10M samples to reproduce the exact published number.) Muscat reproduces the
  lascar/scared verdict on identical data.

### Red-teaming the shuffle (next)
For a real CPA *attack* on the shuffle (not just the structural screen), swap the
`leakage_model` in `pqsigner_tvla_cpa.rs` to a FORS-leaf-index model (the C10 sign is not a
single-S-box AES). The shuffle defends by randomising temporal order, so a successful
first-order CPA would need shuffle-permutation hypotheses or higher-order DPA — Muscat
gives the first-order CPA + TVLA screen; a low-corr/flat result is the countermeasure
holding.

**Scope limit:** this is the emulated `mem_address` (access-address Hamming-weight)
channel. A flat TVLA rules out data-dependent memory *addresses* at audit-grade
emulation; it does **not** rule out register-*value* power/EM leakage or the SAES analog
surface — those need on-silicon SCA with a scope (ChipWhisperer, §SOTA-report §4).

---

## Vendored files
- `tools/sca/checkct/` — the cargo-checkct driver workspace (fisher_yates driver). `target/` gitignored.
- `tools/sca/muscat/pqsigner_tvla_cpa.rs` — the TVLA+CPA harness (also lives in `~/repos/muscat/examples/`).
- `tools/sca/muscat/npz_to_npy.py` — `f9_traces.npz` → `traces/classes/plaintexts.npy` converter.
- `tools/sca/muscat/gen_pqsigner_shape.py` — synthetic-trace generator for CI self-test.
