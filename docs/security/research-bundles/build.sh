#!/usr/bin/env bash
# Generate self-contained research bundles for AI deep-research sessions.
#
# Each bundle file is a standalone attachment: upload it to Claude web
# (or similar) as a single file, paste nothing else, and the session
# starts with all the context it needs.
#
# Run from repo root:  bash docs/security/research-bundles/build.sh
# Or from this dir:    ./build.sh

set -euo pipefail

# Locate repo root regardless of where script is invoked
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUT_DIR="$SCRIPT_DIR"

cd "$REPO_ROOT"

# -------- shared helpers --------

# Rebase repository-root Markdown destinations without modifying examples.
# A real CommonMark parser validates each candidate replacement. Its built-in
# fixture runs on every invocation so code/HTML examples cannot silently turn
# into generated links.
rebase_markdown_links() {
  local src="$1"
  python3 - "$src" <<'PY'
import sys

try:
    from markdown_it import MarkdownIt
except ImportError as error:
    raise SystemExit(
        "research-bundle generation requires the CommonMark parser "
        "markdown-it-py (Debian/Ubuntu: python3-markdown-it)"
    ) from error


MD = MarkdownIt("commonmark")
SOURCE_PREFIX = "docs/"
BUNDLE_PREFIX = "../../../docs/"
ROOT_FILES = {
    "AGENTS.md": "../../../AGENTS.md",
    "DIY.md": "../../../DIY.md",
}


def destination_suffix(value: str, base: str):
    """Return a destination's query/fragment suffix, or None if unrelated."""
    if value == base:
        return ""
    if value.startswith(base) and value[len(base) : len(base) + 1] in {"?", "#"}:
        return value[len(base) :]
    return None


def normalized_root_file_destination(value: str):
    for source, bundled in ROOT_FILES.items():
        for base in (source, bundled):
            suffix = destination_suffix(value, base)
            if suffix is not None:
                return ("repo-root-file", source, suffix)
    return None


def normalized_destination(value: str):
    if value.startswith(SOURCE_PREFIX):
        return ("repo-doc", value[len(SOURCE_PREFIX) :])
    if value.startswith(BUNDLE_PREFIX):
        return ("repo-doc", value[len(BUNDLE_PREFIX) :])
    root_file = normalized_root_file_destination(value)
    if root_file is not None:
        return root_file
    return value


def token_signature(token):
    attrs = []
    for key, value in sorted(token.attrs.items()):
        if key in {"href", "src"}:
            value = normalized_destination(value)
        attrs.append((key, value))
    children = tuple(token_signature(child) for child in (token.children or ()))
    # Inline-token content duplicates the parsed child stream, including raw
    # destinations. Children are authoritative. Code, HTML, and fence tokens
    # have no children, so their content remains a byte-for-byte comparison.
    content = "" if token.children is not None else token.content
    return (
        token.type,
        token.tag,
        token.nesting,
        tuple(attrs),
        content,
        token.markup,
        token.info,
        token.block,
        token.hidden,
        children,
    )


def document_signature(text: str):
    return tuple(token_signature(token) for token in MD.parse(text))


def root_destinations(text: str):
    found = []

    def visit(token):
        for key in ("href", "src"):
            value = token.attrs.get(key)
            if value is not None and (
                value.startswith(SOURCE_PREFIX)
                or any(
                    destination_suffix(value, source) is not None
                    for source in ROOT_FILES
                )
            ):
                found.append(value)
        for child in token.children or ():
            visit(child)

    for token in MD.parse(text):
        visit(token)
    return found


def rebase(text: str) -> str:
    baseline = document_signature(text)
    rewritten = text
    replacements = [
        ("](docs/", "](../../../docs/"),
        *[(f"]({source}", f"]({bundled}") for source, bundled in ROOT_FILES.items()],
    ]

    # Test each literal candidate independently. Keep it only when the parsed
    # document proves that the sole semantic change is a repository-root link
    # or image destination. Candidates inside malformed syntax, code, nested
    # fences, or raw HTML are preserved rather than guessed about.
    for needle, replacement in replacements:
        search_from = 0
        while True:
            position = rewritten.find(needle, search_from)
            if position < 0:
                break
            trial = rewritten[:position] + replacement + rewritten[position + len(needle) :]
            if document_signature(trial) == baseline:
                rewritten = trial
                search_from = position + len(replacement)
            else:
                search_from = position + len(needle)

    remaining = root_destinations(rewritten)
    if remaining:
        raise ValueError(
            "unsupported live repository-root Markdown destination(s): "
            + ", ".join(sorted(set(remaining)))
        )
    if document_signature(rewritten) != baseline:
        raise AssertionError("Markdown link rebasing changed document semantics")
    return rewritten


fixture = """[live](docs/a.md) and [`label`](docs/b.md#x)
[agents](AGENTS.md) and [diy](DIY.md)
[agents fragment](AGENTS.md#entry) [agents query](AGENTS.md?raw=1)
[agents both](AGENTS.md?raw=1#entry) [diy fragment](DIY.md#build)
`[inline](docs/no-inline.md)` and ``[wide](docs/no-wide.md)``
`[root inline](AGENTS.md#no-inline)` and ``[root wide](DIY.md?raw=1#no-wide)``
`unmatched

[after unmatched](docs/after-unmatched.md)
```md
[fenced](docs/no-fence.md)
[root fenced](AGENTS.md#no-fence)
```
~~~text
[tilde](docs/no-tilde.md)
[root tilde](DIY.md?raw=1#no-tilde)
~~~
> ~~~
> [quoted fence](docs/no-quoted-fence.md)
> ~~~
- ~~~
  [listed fence](docs/no-listed-fence.md)
  ~~~

outside list

    [indented](docs/no-indent.md)
<pre>
[raw pre](docs/no-pre.md)
</pre>
<code>
[raw code block](docs/no-code-block.md)
</code>

<code>[inline html](docs/inline-html.md)</code>
[url](https://example.com/docs/x) [anchor](#docs/x) [relative](other.md)
"""
expected = """[live](../../../docs/a.md) and [`label`](../../../docs/b.md#x)
[agents](../../../AGENTS.md) and [diy](../../../DIY.md)
[agents fragment](../../../AGENTS.md#entry) [agents query](../../../AGENTS.md?raw=1)
[agents both](../../../AGENTS.md?raw=1#entry) [diy fragment](../../../DIY.md#build)
`[inline](docs/no-inline.md)` and ``[wide](docs/no-wide.md)``
`[root inline](AGENTS.md#no-inline)` and ``[root wide](DIY.md?raw=1#no-wide)``
`unmatched

[after unmatched](../../../docs/after-unmatched.md)
```md
[fenced](docs/no-fence.md)
[root fenced](AGENTS.md#no-fence)
```
~~~text
[tilde](docs/no-tilde.md)
[root tilde](DIY.md?raw=1#no-tilde)
~~~
> ~~~
> [quoted fence](docs/no-quoted-fence.md)
> ~~~
- ~~~
  [listed fence](docs/no-listed-fence.md)
  ~~~

outside list

    [indented](docs/no-indent.md)
<pre>
[raw pre](docs/no-pre.md)
</pre>
<code>
[raw code block](docs/no-code-block.md)
</code>

<code>[inline html](../../../docs/inline-html.md)</code>
[url](https://example.com/docs/x) [anchor](#docs/x) [relative](other.md)
"""
assert rebase(fixture) == expected, "Markdown link-rebaser self-test failed"

with open(sys.argv[1], encoding="utf-8", newline="") as handle:
    sys.stdout.write(rebase(handle.read()))
PY
}

# Append a code file to a bundle with a markdown heading + fenced block.
# Args: $1=bundle_path $2=source_path $3=language (rust|md|toml|...)
append_code() {
  local bundle="$1" src="$2" lang="${3:-rust}"
  if [[ ! -f "$src" ]]; then
    echo "WARNING: $src not found, skipping" >&2
    return 0
  fi
  {
    printf '\n\n### `%s`\n\n' "$src"
    printf '```%s\n' "$lang"
    cat "$src"
    printf '\n```\n'
  } >> "$bundle"
}

# Append a markdown file as-is (no code fence) under a heading.
append_markdown() {
  local bundle="$1" src="$2"
  if [[ ! -f "$src" ]]; then
    echo "WARNING: $src not found, skipping" >&2
    return 0
  fi
  {
    printf '\n\n### From `%s`\n\n' "$src"
    # Root documents (notably README.md) use repository-root `docs/...`
    # destinations. Once embedded here, those paths would resolve below
    # docs/security/research-bundles/. Rebase only live Markdown destinations;
    # fenced, inline, and indented code remains byte-identical.
    rebase_markdown_links "$src"
    printf '\n'
  } >> "$bundle"
}

# Write the condensed project-context preamble used by every bundle.
# Kept DRY in one place; if the project evolves, edit here.
write_preamble() {
  local bundle="$1"
  cat >> "$bundle" <<'EOF'

---

## Project context (condensed; current sources are linked in each bundle)

**What this is.** PQSigner OS: a post-quantum ERC-4337 smart-wallet
firmware for STM32U585 (Cortex-M33 + ARM TrustZone) on the
B-U585I-IOT02A Discovery board. Only external interface is USB-C. No
Bluetooth, no UART, no debug access in production (RDP Level 2
planned).

**Secure elements.** **Dual**-SE architecture, not single:
- **NXP SE050** (I2C1, addr `0x48`, EAL6+): stores `half_E` of XOR-
  split BIP-39 entropy. Hardware PIN gate via UserID (10 attempts).
- **Infineon OPTIGA Trust M V3** (I2C1, addr `0x30`, EAL6+): stores
  `half_O`. Shielded Connection (AES-128-CCM-8) for bus encryption.

Both chips are mandatory. Neither alone reveals any bit of the seed —
only `half_O XOR half_E = entropy`.

**Why signing must run on the Cortex-M33, not the SE.** Bootstrap and
slot signatures both use the project's **SPHINCS+C10** hash-based
post-quantum scheme; there is no classical or ML-DSA signer. No
commercial secure element currently computes it. The SEs are gated
storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets, transaction decoding, and the trusted
NV3007 LCD UI. Non-secure world owns USB transport. Crossings go through
the fixed NSC gateway with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/security/brownout-hardening.md` for the full plan.

**VBAT.** Production hardware uses a **0.47 F supercap** (not a
battery) on VBAT via Schottky from Vdd. Bounded retention (~12-24 h
after unplug). The dev board has an unpopulated CR1220 holder whose
pads can be reused for a tack-soldered supercap during validation.
Indefinite-retention tamper monitoring during long cold storage is
explicitly out of scope — the 24-word BIP-39 backup is the long-term
security anchor.

**Accepted trade-offs (research that contradicts these is not useful):**
1. Seed transits STM32 SRAM during signing. Unavoidable until SE can
   do SLH-DSA.
2. SE050's value is hardware PIN gate + XOR storage, not "seed never
   leaves silicon." Don't suggest "do all signing on SE050" — it
   can't.
3. USB-C is the only external interface.
4. Out of scope: EAL6+ invasive decapping attacks.

**Dark Skippy and similar nonce-exfil attacks do NOT apply.** Hash-
based SLH-DSA has no nonce. Don't chase this.

**Current SCP03 lifecycle.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Factory defaults are not an acceptable production state:
the factory transport credentials are derived from the per-device OTP master
burned for that handoff. After RDP2 self-lock and the BHK first write, the
implemented first-field candidate rotates SE050 SCP03/admin credentials to
the final BHK axis and rotates the OPTIGA E140 PBS to the final DHUK derivation
bound to a fresh TRNG salt persisted in the page-127 journal. Page 126 holds
only the DHUK-wrapped BHK. This candidate is not a production-approved
ceremony: authenticated per-unit handoff and authenticate-before-rotate,
durable old/new/KVN recovery, the exact E140 lifecycle-versus-final-rotation
order, and silicon receipts remain OPEN.

---

## Style guidance

- Cite specific RM0456 / AN5342 / ES0499 / UM11225 / Infineon doc
  sections where possible. Prefer "per AN5342" over inventing
  revision numbers you aren't sure of.
- Say "I don't know" on things not answerable from public sources,
  rather than guessing.
- Give concrete, implementable code / register values — hand-wave
  recommendations without specifics are not useful.
- Respect the architecture above. Suggestions that require signing
  on the SE are category errors for this project.

---

EOF
}

# ===============================================================
# BUNDLE A — Fault-injection resistance
# ===============================================================

make_bundle_a() {
  local bundle="$OUT_DIR/A-fault-injection.md"
  cat > "$bundle" <<'EOF'
# Research Prompt A — Fault-Injection Resistance for PQ Signing + PIN Path

## Research question

Given the 2024-2025 state of voltage / EMFI / laser fault injection
against STM32 Cortex-M33 designs, what is the minimum set of
**software** glitch countermeasures we should add to these three flows:

1. The seed XOR-reconstruction code path in `DualSecureElement::unlock`
   (reads half_O and half_E from the two SEs, reconstructs full
   entropy, derives master_secret, caches encrypted blob).
2. The SPHINCS+C10 double-compute, byte-compare, and verify-before-release
   chain in `secure/src/crypto.rs` — assess the existing CFI/sentinel
   structure against realistic single- and multi-fault models.
3. The PIN-lockout trigger in `cmd_request_unlock.rs` — a single-
   glitch inversion of the "remaining == 0" check currently blocks
   the factory-reset path.

Give **concrete Rust code patterns** (redundant volatile reads,
complement-storage, magic-constant comparisons, random-delay
templates, NCC-Group-style double-check idioms). For each pattern,
identify which fault classes it defends against (single voltage
glitch, double voltage, EMFI, LFI) and which it doesn't. Rank by
cost/benefit. Out of scope: hardware countermeasures.

Reference the actual code inlined below. Point to specific line numbers
in your recommendations.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant code\n'
  } >> "$bundle"
  append_code "$bundle" "secure/src/dual_se.rs" rust
  append_code "$bundle" "secure/src/nsc/cmd_request_unlock.rs" rust
  append_code "$bundle" "secure/src/nsc/state.rs" rust
  append_code "$bundle" "secure/src/crypto.rs" rust
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# BUNDLE B — Production key management
# ===============================================================

make_bundle_b() {
  local bundle="$OUT_DIR/B-key-management.md"
  cat > "$bundle" <<'EOF'
# Research Prompt B — Transport-to-First-Field SCP03/PBS Lifecycle

## Research question

Design and attack a production provisioning + first-field lifecycle:

1. The factory installs and locks only per-device SE transport and
   attestation state, then ships at RDP0 so the owner can verify the MCU
   before first power. It does not install the final pairing secret, perform
   the BHK first write, create the wallet seed, or set RDP2.
2. On first field boot, the secure-application `rdp2-self-lock` candidate
   self-locks RDP2, performs the BHK first write, and journal-rotates the
   transport credentials to BHK-rooted SE050 keys and a fresh-TRNG-salted
   DHUK OPTIGA PBS before the seed wizard. The code exists but is not an
   approved production ceremony.
3. Page 126 stores only the DHUK-wrapped BHK; page 127 owns the append-only
   first-boot journal and persisted salt. Require authenticated per-device
   handoff and authenticate-before-rotate, then prove old/new/KVN recovery,
   power-cut safety, and the exact E140 lifecycle ordering without inventing
   an HUK-wrapped SCP03/PBS secret blob.
4. Establish verifiable per-device attestation binding the physical SE050
   and OPTIGA UIDs to the STM32 UID so swap attacks fail at boot.

Constraints: authenticate-before-rotate, old/new/KVN recovery, the exact E140
ratchet-versus-final-PBS ordering, and silicon receipts are OPEN and
owner-gated. Do not infer authority for an irreversible ceremony from this
research prompt.

Deliverables: protocol/state diagram, durable-state sketch, power-cut matrix,
and the minimum STM32U585 SAES API usage pattern. Clearly separate measured
facts, current code, proposed ceremony steps, and still-open silicon gates.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant code and design\n'
  } >> "$bundle"
  append_code "$bundle" "secure/src/se050/scp03.rs" rust
  append_code "$bundle" "secure/src/optiga/shield.rs" rust
  append_code "$bundle" "secure/src/hw/flash.rs" rust
  append_markdown "$bundle" "docs/secure-elements/se050-factory-reset.md"
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# BUNDLE C — SLH-DSA side-channel landscape
# ===============================================================

make_bundle_c() {
  local bundle="$OUT_DIR/C-slhdsa-side-channel.md"
  cat > "$bundle" <<'EOF'
# Research Prompt C — SLH-DSA Side-Channel Landscape on Cortex-M33

## Research question

What side-channel attacks (power, EM, cache, timing, μarch) have been
demonstrated or are theoretically plausible against hash-based
signature schemes (SPHINCS+ / SLH-DSA) on ARM Cortex-M33-class chips?

Specifically:

1. Does the published academic literature include practical SLH-DSA
   SCA key-recovery attacks? If so, what are the noise thresholds
   (number of traces, signal-to-noise ratios, distance constraints)?
   If not, what's the closest analogue (SPHINCS-variant attacks,
   generic hash-based-sig attacks, WOTS chain extraction)?
2. Which specific operations within an SLH-DSA signature are the
   most leak-prone? (Candidates: FORS leaf computation exposing SK
   bits; WOTS chain walks exposing step counts; HT layer transitions;
   PRF evaluations consuming the master seed.)
3. Is the SHA-256 hardware accelerator on STM32U585 (HASH peripheral)
   SCA-hardened? If we route SLH-DSA's hashing through it instead of
   software SHA-256, does that eliminate the main leak surface or
   just move it?
4. Our design rotates the main signer every ~2^20 signatures. Is
   that already beyond the SCA trace-count threshold for practical
   recovery, or do we need tighter rotation?
5. With the all-C10 parameter choice fixed, which implementation-level
   countermeasures materially improve the SCA posture? Do not reopen a
   SHA2-128f/192f migration or imply that changing parameters alone closes
   leakage.

Deliverables: catalogued threat list with severity + mitigation per
item, plus specific recommendations on per-signer rotation cadence
and whether to route hashing through the HASH peripheral.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant code\n'
  } >> "$bundle"
  append_code "$bundle" "secure/src/crypto.rs" rust
  append_code "$bundle" "secure/src/nsc/cmd_sign_userop.rs" rust
  append_code "$bundle" "secure/Cargo.toml" toml
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# BUNDLE D — USB stack hardening
# ===============================================================

make_bundle_d() {
  local bundle="$OUT_DIR/D-usb-hardening.md"
  cat > "$bundle" <<'EOF'
# Research Prompt D — USB Stack Hardening for USB-C-Only Hardware Wallet

## Research question

Audit the known attack surface of USB-stack implementations on STM32
Cortex-M MCUs and recommend hardening for our situation (USB-C only,
custom USB stack handling both HID with Ledger-compatible APDU framing
and a PQSigner-native protocol on a vendor class).

Specifically:

1. Known CVEs and proof-of-concept exploits against STM32 USB
   peripherals 2023-2025 (STM32Cube USB libraries, RTOS drivers, HID
   descriptor parsers). Include Colin O'Flynn's EMFI-on-USB work and
   descendants. Distinguish what applies to our custom stack vs what
   only affects STM32Cube.
2. Highest-risk USB descriptor parsing paths for a custom stack that
   handles HID + custom vendor protocol. Common lurking bugs
   (endpoint count overflow, string descriptor length misparse,
   SETUP-stage DMA corruption, etc.).
3. Minimum set of sanity checks between the USB ISR and our firmware's
   APDU handler to resist malformed/adversarial host behaviour.
4. Architectural evaluation: is there a defensible argument for
   implementing USB in a separate co-processor (tiny MCU beside the
   STM32 with a serial shim) to shrink attack surface on the
   crypto-hosting chip? What do real production wallets do?

Deliverables: CVE catalogue with applicability notes, ranked hardening
checklist, architectural recommendation on co-processor USB.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant code and design\n'
  } >> "$bundle"
  append_code "$bundle" "secure/src/hw/usb_hw.rs" rust
  append_code "$bundle" "nonsecure/src/usb/mod.rs" rust
  append_code "$bundle" "nonsecure/src/usb/transport.rs" rust
  append_code "$bundle" "nonsecure/src/usb/hid.rs" rust
  append_code "$bundle" "nonsecure/src/usb/commands.rs" rust
  append_markdown "$bundle" "docs/companion/usb-protocol-v2.md"
  append_markdown "$bundle" "docs/hardware/usb-hid-setup.md"
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# BUNDLE E — Supply-chain + provisioning attestation
# ===============================================================

make_bundle_e() {
  local bundle="$OUT_DIR/E-supply-chain.md"
  cat > "$bundle" <<'EOF'
# Research Prompt E — Supply Chain and Provisioning Attestation

## Research question

Map the supply-chain + provisioning threat model for a hardware wallet
using SE050 + OPTIGA on TrustZone STM32U585, shipping through
conventional retail / e-commerce, and recommend a provisioning +
attestation protocol that defeats each attacker class.

Specifically:

1. Counterfeit STM32U5 supply in 2024-2025: are there confirmed
   clones (GD32/CS32/APM32 style) in the U5 family yet, or only
   older F/L-series? What boot-time probes reliably detect clones?
2. NXP's SE050 UID cert chain up to NXP root CA: how reliable for
   anti-clone? Threat model for SE050 extraction + re-implantation
   in a different physical wallet.
3. Same question for OPTIGA Trust M cert chain.
4. What do Ledger, Trezor, Coinkite, Foundation etc. do at
   provisioning to attest "genuine factory-sealed device" to a
   customer opening the box? Known failure modes (historical + 2024-
   2025).
5. Given our dual-SE architecture, is there an additional attestation
   advantage from cross-binding SE050-UID + OPTIGA-UID + STM32-UID
   in a signed manifest that must match at every boot?

Deliverables: ranked attacker list (opportunistic re-seller;
sophisticated interdictor; nation-state with factory access), the
attestation protocol that defeats each, and a specific "box-opening"
user ceremony that demonstrates genuineness without requiring the
customer to run an independent tool.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant design docs (code footprint small — feature not implemented)\n'
  } >> "$bundle"
  append_markdown "$bundle" "CLAUDE.md"
  append_markdown "$bundle" "docs/security/HARDENING.md"
  append_markdown "$bundle" "docs/security/production-security.md"
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# BUNDLE F — Trezor Safe 7 comparison
# ===============================================================

make_bundle_f() {
  local bundle="$OUT_DIR/F-trezor-safe-7-comparison.md"
  cat > "$bundle" <<'EOF'
# Research Prompt F — PQSigner OS vs Trezor Safe 7: Architecture Comparison

## Research question

Using the PQSigner OS architecture described below and inlined in full,
produce a detailed, evidence-based comparison with the **Trezor Safe 7**
(SatoshiLabs, announced Oct 2025). Do not treat this as marketing
copy — treat it as a security engineering review. Where Trezor Safe 7
is better, say so explicitly. Where PQSigner is better, say so
explicitly. Where both have open problems, name them.

Compare across these dimensions, in this order:

1. **Secure-element strategy**
   - Trezor Safe 7 reportedly uses a Tropic Square **TROPIC01** secure
     element alongside an MCU; document the exact role it plays
     (storage only? PIN gate? signing? entropy source?). Cite Trezor /
     Tropic documentation.
   - Compare to PQSigner's **dual-SE** architecture (NXP SE050 +
     Infineon OPTIGA Trust M V3), XOR-split entropy, hardware PIN
     gates on both chips.
   - Is dual-SE net-better than single-SE-with-open-design? Name
     concrete attack classes where each wins.

2. **Cryptographic algorithms (signing + key derivation)**
   - Trezor Safe 7: what curves / signature schemes does it support on-
     device? Any post-quantum scheme today, announced, or on roadmap?
   - PQSigner: SPHINCS+C10 for bootstrap and slot transactions, with no
     classical signer anywhere. ERC-4337 smart-account model (no EOA;
     slot keys register on-chain while the bootstrap key is immutable).
   - Evaluate the classical-vs-PQ trade-off honestly: Trezor's curve
     choices are battle-tested and ubiquitous; PQSigner's PQ choices
     are NIST-finalized but rare in production wallets and much larger
     signatures (4,008 bytes vs 64 bytes).

3. **Seed storage, recovery, and derivation**
   - Trezor Safe 7 seed storage location + PIN-lockout policy + Shamir
     / SLIP-39 support + passphrase support.
   - PQSigner: 24-word BIP-39 entropy XOR-split across two SEs, re-
     derived into SRAM each unlock, zeroized on lock/timeout. No
     SLIP-39, no passphrase (yet).
   - Recovery semantics: what does "restore from backup" look like on
     each? How is the PQ recovery contract preserved (same 24 words →
     same PQ keys)?

4. **PIN security and lockout**
   - Trezor Safe 7 PIN gate: software counter, SE counter, or MCU-
     enforced? Max-attempts behaviour?
   - PQSigner: every attempted PIN is pre-committed to MCU flash page 124,
     OPTIGA E120 is a silicon-monotonic lifetime counter, and SE050 UserID
     independently enforces max 10. Boot reconciliation is directional:
     E120 ahead of page 124 fails closed; a page-124 lead is retained rather
     than rolled back. The true cold-reboot receipt for both directions is
     still OPEN and must not be inferred from an in-run cache-reset harness.

5. **Firmware update model and verifiability**
   - Trezor Safe 7 firmware update: signed by whom, with what keys,
     verified by which chip? Rollback protection?
   - PQSigner target: a production-gated immutable FSBL verifies a vendor
     SPHINCS+C10 firmware manifest and displays an 8-BIP-39-word SHA-256
     fingerprint on the NV3007 LCD. The current legacy bench FSBL exercises
     the display path but is not an immutable production trust root; geometry,
     WRP/factory, resource, rollback-backend, and silicon gates remain open.
     The secure runtime shows the same advisory fingerprint. Firmware updates
     use the authenticated streaming update commands.
   - Pros/cons of each model for a paranoid user.

6. **Supply chain + attestation ("is my new box genuine?")**
   - Trezor Safe 7 out-of-box attestation: what does the device prove
     to Trezor Suite on first connection? Historical Trezor
     attestation failures (incl. anti-clone bypasses). Any FIDO-like
     signed-UID chain?
   - PQSigner: dual-SE UID cert chains (NXP root + Infineon root) +
     STM32-UID cross-binding planned (work-todo #22). Current state
     is: no attestation implemented yet.
   - Which design better defeats an interdiction attacker (repackaging
     Mallory)?

7. **Physical / side-channel security posture**
   - Trezor Safe 7 tamper detection, glitch protection, ECC on SRAM,
     BOR/PVD, anti-SCA claims.
   - PQSigner: Stage 1 brownout hardening landed (reset-cause class,
     verified flash writes); stages 2-5 planned (BOR/PVD/IWDG/TAMP/ECC
     config, fault-injection countermeasures, SLH-DSA SCA hardening).
     Explicitly not yet: hardware-level tamper switches, active mesh,
     decap defence.
   - Which design gets to production first on this axis?

8. **Open-source / reproducibility / external review**
   - Trezor's long-standing open-source firmware and third-party audit
     record — cite actual audit reports.
   - PQSigner: fully open-source (no NDA components in the firmware
     code path), BUT depends on closed-source SE firmware on SE050 +
     OPTIGA Trust M. Reproducible-build mechanics and CI gates exist; the
     production packaging/signing ceremony and shipment remain quarantined.
   - What does "verifiable hardware wallet" actually mean in each
     case?

9. **Smart-contract / AA / MPC integration posture**
   - Trezor Safe 7's support for smart-contract wallets today (Safe,
     Argent, ERC-4337 passkey/4337 signers). Does it clear-sign any
     AA structures or just EIP-712?
   - PQSigner: native ERC-4337 smart account with PQ-only signers and
     on-device native ERC-7730, Safe, MultiSend, and CoW decoding;
     deterministic CREATE2 address on all chains from bootstrap PK.
   - Which is the better on-ramp for the smart-wallet / AA world?

10. **UX / ergonomics honestly**
    - Signature size (PQSigner 4,008 bytes per C10 signature vs 64 bytes) — ergonomic
      fallout on USB latency, mempool propagation, L2 inclusion cost.
    - User prompts per transaction, number of button presses, display
     constraints (PQSigner: NV3007 LCD; Trezor Safe 7: 1.54"
      color touchscreen).
    - Recovery ceremony complexity. Backup verification flow.

11. **What Trezor does that PQSigner should steal (concrete list)**
    - Specific design patterns, audit artefacts, or UX flows from
      Trezor that PQSigner should copy, with citations.

12. **What PQSigner does that Trezor can't easily adopt**
    - Things structurally locked out by Trezor's architecture (dual-SE
      retrofit, PQ-only signing, on-device AA / native clear-signing,
      etc.).

Deliverables:
- A table summarising each dimension ("Trezor Safe 7 | PQSigner OS |
  winner | confidence").
- For every claim about Trezor Safe 7, cite a Trezor blog post, wiki
  page, GitHub repo, audit report, CVE, or trusted-third-party
  teardown. Do not invent specs.
- If Trezor Safe 7 details are not public enough to answer a question,
  say so explicitly and downgrade confidence.

**Style / ground rules.**
- No marketing voice. "Safer in X sense, weaker in Y sense" is the
  target tone.
- PQSigner's accepted trade-offs (see preamble) are not up for
  re-litigation. "Just use secp256k1" is not a valid critique.
- "Trezor Safe 7 has not disclosed this publicly" is a perfectly
  acceptable answer — please use it where true.
- Cite specific documents, not general web searches.
- Note that Trezor Safe 7 launched on 2025-10-13; materials older
  than that describe earlier Trezor models (One, Model T, Safe 3,
  Safe 5) and may not apply.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant docs and code\n'
  } >> "$bundle"
  append_markdown "$bundle" "README.md"
  append_markdown "$bundle" "CLAUDE.md"
  append_markdown "$bundle" "docs/security/HARDENING.md"
  append_markdown "$bundle" "docs/security/brownout-hardening.md"
  append_markdown "$bundle" "docs/security/production-security.md"
  append_code "$bundle" "secure/src/dual_se.rs" rust
  append_code "$bundle" "secure/src/nsc/mod.rs" rust
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# run
# ===============================================================

echo "Generating research bundles from $REPO_ROOT"
echo

make_bundle_a
make_bundle_b
make_bundle_c
make_bundle_d
make_bundle_e
make_bundle_f

echo
echo "Done. Upload any single bundle file to Claude web and paste nothing"
echo "else — each bundle is self-contained. The question is at the top."
