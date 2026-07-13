//! TLV parameter parser for the ERC-7730 IR's per-field parameter blob.
//!
//! `FieldEntry::param_off` is a `u16` offset into `Erc7730Ir::pool`.
//! When non-zero, the byte at that offset is a single-byte length
//! prefix, followed by `len` bytes of TLV entries:
//!
//! ```text
//!   [u8 blob_len]              <- pool[param_off]
//!   [u8 kind][u8 payload_len][payload]*   <- pool[param_off + 1 ..]
//! ```
//!
//! Tag space (host-emitter constants, mirrored byte-for-byte from
//! `dbgen::erc7730::PARAM_*`):
//!
//! | Tag  | Meaning              | Payload shape                              |
//! |------|----------------------|--------------------------------------------|
//! | 0x30 | `token_path`         | path-bytecode program (≤255 B)             |
//! | 0x31 | `token`              | 20 B address                               |
//! | 0x32 | `threshold`          | 32 B BE u256                               |
//! | 0x33 | `message`            | ASCII (≤254 B)                             |
//! | 0x34 | `addr_types`         | 1 B bitset                                 |
//! | 0x35 | `addr_sources`       | 1 B bitset                                 |
//! | 0x36 | `date_encoding`      | 1 B (0=timestamp, 1=blockheight)           |
//! | 0x37 | `enum_ref`           | 2 B BE pool offset of enum row             |
//! | 0x38 | `decimals`           | 1 B u8                                     |
//! | 0x39 | `base`               | ASCII unit-suffix (≤254 B)                 |
//! | 0x3A | `prefix`             | 1 B u8                                     |
//! | 0x3B | `suffix`             | ASCII (≤254 B)                             |
//! | 0x3C | `nested_selector`    | 4 B function selector                      |
//! | 0x3D | `nested_callee`      | raw compiled `calleePath` program           |
//! | 0x3E | `fallback_label`     | ASCII (≤254 B)                             |
//! | 0x3F | `visibility`         | 1 B (Visibility byte value), optionally    |
//! |      |                      | followed by a Phase 5 value-list sub-TLV.  |
//! | 0x43 | `dynamic_kind`       | 1 B (`1=string`, `2=bytes`)                |
//!
//! Wire-stable.
//!
//! Unknown tags are rejected — a hostile descriptor that smuggles an
//! unknown tag must NOT silently render: it might describe semantics
//! the renderer can't honour.

use crate::ir::{Erc7730Ir, Visibility};

use super::RenderErr;

// Re-export the tag constants so the formatter dispatcher (Step 3) and
// other intra-module consumers don't have to keep them in sync by
// hand. Wire-stable.
pub const PARAM_TOKEN_PATH: u8 = 0x30;
pub const PARAM_TOKEN: u8 = 0x31;
pub const PARAM_THRESHOLD: u8 = 0x32;
pub const PARAM_MESSAGE: u8 = 0x33;
pub const PARAM_ADDR_TYPES: u8 = 0x34;
pub const PARAM_ADDR_SOURCES: u8 = 0x35;
pub const PARAM_DATE_ENCODING: u8 = 0x36;
pub const PARAM_ENUM_REF: u8 = 0x37;
pub const PARAM_DECIMALS: u8 = 0x38;
pub const PARAM_BASE: u8 = 0x39;
pub const PARAM_PREFIX: u8 = 0x3A;
pub const PARAM_SUFFIX: u8 = 0x3B;
pub const PARAM_NESTED_SELECTOR: u8 = 0x3C;
pub const PARAM_NESTED_CALLEE: u8 = 0x3D;
pub const PARAM_FALLBACK_LABEL: u8 = 0x3E;
pub const PARAM_VISIBILITY: u8 = 0x3F;
/// Constant annotation string for a path-less field (`{value,label,format}`
/// with no path). The renderer shows the literal descriptor-pinned string.
pub const PARAM_CONST_VALUE: u8 = 0x40;
/// Format-level flag (emitted by `dbgen` on an EIP-712 format's first field)
/// marking that the primary type carries a nested struct member — a single
/// opaque `hashStruct` word the renderer cannot expand. When set, the
/// renderer rejects the WHOLE format, so a nested member (and any `address`
/// inside it) is never partially clear-signed or painted as a garbage word.
/// The secure dispatcher hard-refuses that verified/known tuple rather than
/// downgrading it (`VULN-erc7730-eip712-nested-struct-address-hide`, on-device
/// belt behind the build-time visibility gate).
pub const PARAM_NESTED_STRUCT: u8 = 0x41;
/// A `tokenAmount`'s `nativeCurrencyAddress` sentinel (20 B). When the field's
/// resolved token address equals this sentinel, the amount is rendered as the
/// chain's NATIVE currency (18 decimals, `native_ticker(chain_id)`) instead of
/// an ERC-20 lookup — so an ETH leg (`0xEeee…`/`0x0`) shows "1.5 ETH" rather than
/// a raw `! raw, dec=?` integer (ERC-7730 `nativeCurrencyAddress`).
pub const PARAM_NATIVE_CURRENCY: u8 = 0x42;
/// Compiler-authenticated ABI kind for a dynamic leaf. The path bytecode only
/// says "follow this offset"; without this tag the device cannot distinguish a
/// human string from arbitrary bytes. Missing/unknown kinds therefore decline.
pub const PARAM_DYNAMIC_KIND: u8 = 0x43;
pub const DYNAMIC_KIND_STRING: u8 = 0x01;
pub const DYNAMIC_KIND_BYTES: u8 = 0x02;

/// `dbgen::erc7730::DATE_ENC_TIMESTAMP` — unix-seconds u64.
pub const DATE_ENC_TIMESTAMP: u8 = 0x00;
/// `dbgen::erc7730::DATE_ENC_BLOCKHEIGHT` — render as decimal block id.
pub const DATE_ENC_BLOCKHEIGHT: u8 = 0x01;

/// Address-type bitset bits (matches `dbgen::erc7730::ADDR_TYPE_*`).
pub const ADDR_TYPE_WALLET: u8 = 0x01;
pub const ADDR_TYPE_EOA: u8 = 0x02;
pub const ADDR_TYPE_CONTRACT: u8 = 0x04;
pub const ADDR_TYPE_NFT_COLLECTION: u8 = 0x08;
pub const ADDR_TYPE_TOKEN: u8 = 0x10;
pub const ADDR_TYPE_COLLECTION: u8 = 0x20;

/// Parsed view of one field's TLV blob. All slices borrow from
/// `ir.pool`; the struct itself is stack-only.
///
/// `Default` is hand-rolled because `pqsigner_erc7730::ir::Visibility`
/// does not implement `Default` (the host-side enum has no canonical
/// "zero" value at the type level — Phase 4 chooses `Always` here, which
/// matches the on-wire default of "no VISIBILITY TLV present").
#[allow(dead_code)] // most fields are read by Step 3's formatter dispatch
pub struct ParamSet<'a> {
    pub token_path: Option<&'a [u8]>,
    pub token: Option<&'a [u8; 20]>,
    pub threshold: Option<&'a [u8; 32]>,
    pub message: Option<&'a [u8]>,
    pub addr_types: Option<u8>,
    pub addr_sources: Option<u8>,
    pub date_encoding: Option<u8>,
    pub enum_ref: Option<u16>,
    pub decimals: Option<u8>,
    pub base: Option<&'a [u8]>,
    pub prefix: Option<u8>,
    pub suffix: Option<&'a [u8]>,
    pub nested_selector: Option<&'a [u8; 4]>,
    pub nested_callee: Option<&'a [u8]>,
    pub fallback_label: Option<&'a [u8]>,
    /// Constant annotation string for a path-less field. When `Some`, the
    /// renderer shows this literal text instead of resolving a path.
    pub const_value: Option<&'a [u8]>,
    /// Always populated. Defaults to `Always` when no VISIBILITY TLV is
    /// present.
    pub visibility: Visibility,
    /// Sub-TLV for `IfNotIn` / `MustMatch` value lists (Phase 5+).
    /// Phase 4 only sees this when the VISIBILITY TLV's payload is
    /// longer than 1 byte; current `dbgen` only emits a 1-byte payload.
    pub visibility_values: Option<&'a [u8]>,
    /// Set (to the raw `PARAM_NESTED_STRUCT` payload) when this field is a
    /// nested-EIP-712 struct anchor. The payload's leading version byte selects
    /// the shape: `0x01` = the bare belt marker (an unsupported nested member
    /// the device declines the WHOLE format for —
    /// `VULN-erc7730-eip712-nested-struct-address-hide`); `0x03` = the
    /// structured v0x03 descent block (`word_pos | type_hash | member_count |
    /// flags | addr_word_bmp | sub_fields`, parsed by the nested renderer).
    /// Until the belt is inverted (Phase 5 Commit D), the caller declines on
    /// EITHER form — the fail-safe.
    pub nested_struct: Option<&'a [u8]>,
    /// A `tokenAmount`'s native-currency sentinel address (`PARAM_NATIVE_CURRENCY`,
    /// 20 B). `Some` when the descriptor declares `nativeCurrencyAddress`; the
    /// renderer treats a resolved token equal to it as the chain native currency.
    pub native_currency: Option<&'a [u8; 20]>,
    /// ABI type of a dynamic `FollowOffset` leaf. This is emitted by dbgen from
    /// the canonical function signature, never inferred from payload bytes.
    pub dynamic_kind: Option<u8>,
}

impl<'a> Default for ParamSet<'a> {
    fn default() -> Self {
        ParamSet {
            token_path: None,
            token: None,
            threshold: None,
            message: None,
            addr_types: None,
            addr_sources: None,
            date_encoding: None,
            enum_ref: None,
            decimals: None,
            base: None,
            prefix: None,
            suffix: None,
            nested_selector: None,
            nested_callee: None,
            fallback_label: None,
            const_value: None,
            visibility: Visibility::Always,
            visibility_values: None,
            nested_struct: None,
            native_currency: None,
            dynamic_kind: None,
        }
    }
}

/// Parse a TLV parameter blob located at `param_off` inside the IR's
/// metadata pool. Returns the default [`ParamSet`] (everything `None`,
/// visibility `Always`) when `param_off == 0`.
pub fn parse<'a>(ir: &Erc7730Ir<'a>, param_off: u16) -> Result<ParamSet<'a>, RenderErr> {
    let mut p = ParamSet::default();
    p.visibility = Visibility::Always;

    if param_off == 0 {
        return Ok(p);
    }

    let off = param_off as usize;
    let blob_len = *ir
        .pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 bad param blob"))? as usize;
    let body = ir
        .pool
        .get(off + 1..off + 1 + blob_len)
        .ok_or(RenderErr::Reject("7730 bad param blob"))?;

    let mut cursor = 0usize;
    // Tags 0x30..=0x43 fit in this bitmap. Singleton parameter TLVs are
    // canonical: accepting duplicates would make meaning order-dependent and
    // previously let a short visibility duplicate retain the first tag's tail.
    let mut seen_tags = 0u32;
    while cursor < body.len() {
        if cursor + 2 > body.len() {
            return Err(RenderErr::Reject("7730 truncated tlv"));
        }
        let tag = body[cursor];
        let len = body[cursor + 1] as usize;
        cursor += 2;
        if cursor + len > body.len() {
            return Err(RenderErr::Reject("7730 tlv overrun"));
        }
        let payload = &body[cursor..cursor + len];
        cursor += len;

        if !(PARAM_TOKEN_PATH..=PARAM_DYNAMIC_KIND).contains(&tag) {
            return Err(RenderErr::Reject("7730 unknown tlv tag"));
        }
        let bit = 1u32 << (tag - PARAM_TOKEN_PATH);
        if seen_tags & bit != 0 {
            return Err(RenderErr::Reject("7730 duplicate tlv tag"));
        }
        seen_tags |= bit;

        match tag {
            PARAM_TOKEN_PATH => p.token_path = Some(payload),
            PARAM_TOKEN => {
                p.token = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad token"))?,
                );
            }
            PARAM_NATIVE_CURRENCY => {
                p.native_currency = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad native ccy"))?,
                );
            }
            PARAM_DYNAMIC_KIND => {
                if payload.len() != 1
                    || !matches!(payload[0], DYNAMIC_KIND_STRING | DYNAMIC_KIND_BYTES)
                {
                    return Err(RenderErr::Reject("7730 bad dynamic kind"));
                }
                p.dynamic_kind = Some(payload[0]);
            }
            PARAM_THRESHOLD => {
                p.threshold = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad threshold"))?,
                );
            }
            PARAM_MESSAGE => p.message = Some(payload),
            PARAM_ADDR_TYPES => {
                if payload.len() != 1 {
                    return Err(RenderErr::Reject("7730 bad addr-types"));
                }
                p.addr_types = Some(payload[0]);
            }
            PARAM_ADDR_SOURCES => {
                if payload.len() != 1 {
                    return Err(RenderErr::Reject("7730 bad addr-sources"));
                }
                p.addr_sources = Some(payload[0]);
            }
            PARAM_DATE_ENCODING => {
                if payload.len() != 1 {
                    return Err(RenderErr::Reject("7730 bad date enc"));
                }
                p.date_encoding = Some(payload[0]);
            }
            PARAM_ENUM_REF => {
                if payload.len() != 2 {
                    return Err(RenderErr::Reject("7730 bad enum ref"));
                }
                p.enum_ref = Some(u16::from_be_bytes([payload[0], payload[1]]));
            }
            PARAM_DECIMALS => {
                if payload.len() != 1 {
                    return Err(RenderErr::Reject("7730 bad decimals"));
                }
                p.decimals = Some(payload[0]);
            }
            PARAM_BASE => p.base = Some(payload),
            PARAM_PREFIX => {
                if payload.len() != 1 {
                    return Err(RenderErr::Reject("7730 bad prefix"));
                }
                p.prefix = Some(payload[0]);
            }
            PARAM_SUFFIX => p.suffix = Some(payload),
            PARAM_NESTED_SELECTOR => {
                p.nested_selector = Some(
                    payload
                        .try_into()
                        .map_err(|_| RenderErr::Reject("7730 bad nested selector"))?,
                );
            }
            PARAM_NESTED_CALLEE => {
                if payload.is_empty() {
                    return Err(RenderErr::Reject("7730 bad nested callee"));
                }
                p.nested_callee = Some(payload);
            }
            PARAM_FALLBACK_LABEL => p.fallback_label = Some(payload),
            PARAM_CONST_VALUE => p.const_value = Some(payload),
            PARAM_NESTED_STRUCT => {
                // A leading version byte selects the shape. `0x01` = bare belt
                // marker; `0x03` = structured v0x03 descent block. Any other
                // leading byte (or an empty payload) fails closed. The payload
                // is stored raw; the renderer's belt declines on either form
                // until Phase 5 Commit D inverts it to descend on `0x03`.
                match payload.first() {
                    Some(0x01) if payload.len() == 1 => p.nested_struct = Some(payload),
                    Some(0x03) => p.nested_struct = Some(payload),
                    _ => return Err(RenderErr::Reject("7730 bad nested-struct marker")),
                }
            }
            PARAM_VISIBILITY => {
                if payload.is_empty() {
                    return Err(RenderErr::Reject("7730 empty visibility"));
                }
                p.visibility = Visibility::try_from(payload[0])
                    .map_err(|_| RenderErr::Reject("7730 bad visibility"))?;
                if payload.len() > 1 {
                    p.visibility_values = Some(&payload[1..]);
                }
            }
            _ => return Err(RenderErr::Reject("7730 unknown tlv tag")),
        }
    }

    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Erc7730Ir, Visibility, HEADER_LEN, SCHEMA_VER};

    /// Build a minimal IR blob with the supplied pool bytes.
    fn ir_with_pool(pool: &[u8]) -> std::vec::Vec<u8> {
        let pool_len = pool.len() as u16;
        let mut buf = std::vec![0u8; HEADER_LEN];
        buf[0] = SCHEMA_VER;
        buf[1] = 0x01; // CTX_CONTRACT
        buf[2..10].copy_from_slice(&1u64.to_be_bytes());
        buf[126..128].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        buf[128..130].copy_from_slice(&((HEADER_LEN as u16) + pool_len).to_be_bytes());
        buf[130..132].copy_from_slice(&pool_len.to_be_bytes());
        buf[132..134].copy_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(pool);
        buf.push(0u8); // format count
        buf
    }

    #[test]
    fn zero_offset_returns_default() {
        let bytes = ir_with_pool(&[]);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 0).unwrap();
        assert_eq!(p.visibility, Visibility::Always);
        assert!(p.decimals.is_none());
        assert!(p.token.is_none());
    }

    #[test]
    fn parses_decimals_and_token() {
        // pool layout starting at offset 1 of `ir.pool` (filler at 0):
        //   filler [0xFF]
        //   blob_len = 25 (= 3 + 2 + 20)
        //   0x38 0x01 0x06                  (decimals=6, 3 bytes)
        //   0x31 0x14 <20 bytes>            (token=0xAB.., 2 + 20 bytes)
        let mut pool = std::vec![0xFFu8];
        pool.push(25);
        pool.extend_from_slice(&[0x38, 0x01, 0x06]);
        pool.extend_from_slice(&[0x31, 0x14]);
        pool.extend_from_slice(&[0xABu8; 20]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.decimals, Some(6));
        assert_eq!(p.token, Some(&[0xAB; 20]));
        assert_eq!(p.visibility, Visibility::Always);
    }

    #[test]
    fn parses_visibility_never() {
        let pool = std::vec![0xFFu8, 3, 0x3F, 0x01, 0x01];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.visibility, Visibility::Never);
        assert!(p.visibility_values.is_none());
    }

    #[test]
    fn parses_nested_struct_marker() {
        // 0x41 [0x01] → nested_struct flag set (VULN-erc7730-eip712-nested-
        // struct-address-hide on-device belt).
        let pool = std::vec![0xFFu8, 3, 0x41, 0x01, 0x01];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(
            p.nested_struct,
            Some(&[0x01u8][..]),
            "bare marker stores its payload"
        );
    }

    #[test]
    fn parses_nested_struct_v3_block() {
        // 0x41 [0x03 ...] → the structured v0x03 block is stored raw for the
        // nested renderer (leading version byte 0x03).
        let pool = std::vec![0xFFu8, 4, 0x41, 0x02, 0x03, 0x00];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(
            p.nested_struct,
            Some(&[0x03u8, 0x00][..]),
            "v0x03 block stored raw"
        );
    }

    #[test]
    fn default_has_no_nested_struct_flag() {
        let bytes = ir_with_pool(&[]);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(parse(&ir, 0).unwrap().nested_struct.is_none());
    }

    #[test]
    fn rejects_malformed_nested_struct_marker() {
        // Wrong payload (0x00 instead of 0x01) must fail closed.
        let pool = std::vec![0xFFu8, 3, 0x41, 0x01, 0x00];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(parse(&ir, 1).is_err(), "bad marker payload rejected");
    }

    #[test]
    fn parses_visibility_with_value_list_phase_5_extension() {
        // 0x3F TLV payload length 4: [vis=MustMatch] + 3-byte sub-TLV.
        let pool = std::vec![
            0xFFu8, // filler
            6,      // blob_len
            0x3F, 0x04, 0x04, 0xAA, 0xBB, 0xCC, // VISIBILITY = MustMatch + values
        ];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.visibility, Visibility::MustMatch);
        assert_eq!(p.visibility_values, Some(&[0xAA, 0xBB, 0xCC][..]));
    }

    #[test]
    fn rejects_truncated_tlv() {
        // blob_len = 2 declares two bytes ([tag,payload_len]) but no
        // payload byte. The cursor walks past `2` declaring 1 byte of
        // payload and finds the body exhausted.
        let pool = std::vec![0xFFu8, 2, 0x38, 0x01];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn rejects_unknown_tag() {
        let pool = std::vec![0xFFu8, 3, 0x7F, 0x01, 0x00];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn out_of_range_offset_rejected() {
        let bytes = ir_with_pool(&[]);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 200), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn rejects_bad_decimals_width() {
        let pool = std::vec![0xFFu8, 4, 0x38, 0x02, 0x06, 0x00];
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn rejects_bad_token_width() {
        // PARAM_TOKEN payload must be 20 bytes; supplying 19 trips the
        // try_into → Reject path.
        let mut pool = std::vec![0xFFu8, 21, 0x31, 0x13];
        pool.extend_from_slice(&[0xAA; 19]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn parses_multiple_interleaved_tlvs() {
        // A realistic param blob: token + decimals + fallback_label +
        // visibility=Optional. Tests cursor advancement across mixed
        // payload sizes and confirms the parser doesn't drop later
        // tags after an earlier wide payload.
        let mut pool = std::vec![0xFFu8]; // filler at offset 0
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&[PARAM_TOKEN, 0x14]);
        body.extend_from_slice(&[0xCC; 20]);
        body.extend_from_slice(&[PARAM_DECIMALS, 0x01, 0x12]);
        let label = b"unlimited";
        body.push(PARAM_FALLBACK_LABEL);
        body.push(label.len() as u8);
        body.extend_from_slice(label);
        body.extend_from_slice(&[PARAM_VISIBILITY, 0x01, 0x02]); // Optional

        pool.push(body.len() as u8);
        pool.extend_from_slice(&body);

        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.token, Some(&[0xCC; 20]));
        assert_eq!(p.decimals, Some(0x12));
        assert_eq!(p.fallback_label, Some(&label[..]));
        assert_eq!(p.visibility, Visibility::Optional);
        assert!(p.visibility_values.is_none());
    }

    #[test]
    fn rejects_blob_extending_past_pool() {
        // blob_len = 200 but pool only holds 50 bytes after the length
        // byte. Parser must refuse rather than read past the end.
        let mut pool = std::vec![0xFFu8, 200];
        pool.extend_from_slice(&[0x00; 50]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert!(matches!(parse(&ir, 1), Err(RenderErr::Reject(_))));
    }

    #[test]
    fn parses_max_payload_tlv() {
        // Single TLV with a 252-byte payload (max single-TLV size in
        // a 254-byte blob: 1 tag + 1 len + 252 payload = 254).
        let mut pool = std::vec![0xFFu8, 254, PARAM_MESSAGE, 252];
        pool.extend_from_slice(&[0x41u8; 252]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.message.map(|m| m.len()), Some(252));
    }

    #[test]
    fn parses_nested_selector_and_callee() {
        // For the Calldata formatter the descriptor supplies the
        // expected inner selector + callee address.
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&[PARAM_NESTED_SELECTOR, 0x04, 0xa9, 0x05, 0x9c, 0xbb]);
        body.extend_from_slice(&[PARAM_NESTED_CALLEE, 0x14]);
        body.extend_from_slice(&[0xDD; 20]);
        let mut pool = std::vec![0xFFu8, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.nested_selector, Some(&[0xa9, 0x05, 0x9c, 0xbb]));
        assert_eq!(p.nested_callee, Some(&[0xDD; 20][..]));
    }

    #[test]
    fn parses_phase5_visibility_value_list() {
        // VISIBILITY TLV with `MustMatch` byte followed by a 6-byte
        // sub-TLV (3 elements × 2-byte values). The on-wire format
        // doesn't fix the sub-TLV shape yet; the parser just stashes
        // the trailing bytes for the Phase 5 visibility evaluator.
        let mut pool = std::vec![0xFFu8, 9, PARAM_VISIBILITY, 7];
        pool.extend_from_slice(&[0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.visibility, Visibility::MustMatch);
        assert_eq!(
            p.visibility_values,
            Some(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF][..])
        );
    }

    #[test]
    fn parses_const_value() {
        // PARAM_CONST_VALUE carries the resolved constant-annotation string.
        let label = b"Wrapped stETH";
        let mut body = std::vec::Vec::new();
        body.push(PARAM_CONST_VALUE);
        body.push(label.len() as u8);
        body.extend_from_slice(label);
        let mut pool = std::vec![0xFFu8, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let p = parse(&ir, 1).unwrap();
        assert_eq!(p.const_value, Some(&label[..]));
        assert!(p.token_path.is_none());
    }

    #[test]
    fn parses_authenticated_dynamic_kind() {
        let body = [PARAM_DYNAMIC_KIND, 1, DYNAMIC_KIND_STRING];
        let mut pool = std::vec![0xFF, body.len() as u8];
        pool.extend_from_slice(&body);
        let bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert_eq!(
            parse(&ir, 1).unwrap().dynamic_kind,
            Some(DYNAMIC_KIND_STRING)
        );
    }

    #[test]
    fn rejects_invalid_or_duplicate_dynamic_kind() {
        for body in [
            std::vec![PARAM_DYNAMIC_KIND, 1, 0xFF],
            std::vec![
                PARAM_DYNAMIC_KIND,
                1,
                DYNAMIC_KIND_STRING,
                PARAM_DYNAMIC_KIND,
                1,
                DYNAMIC_KIND_BYTES,
            ],
        ] {
            let mut pool = std::vec![0xFF, body.len() as u8];
            pool.extend_from_slice(&body);
            let bytes = ir_with_pool(&pool);
            let ir = Erc7730Ir::parse(&bytes).unwrap();
            assert!(parse(&ir, 1).is_err());
        }
    }
}

#[cfg(kani)]
mod kani_harnesses {
    //! Bounded verification of the ERC-7730 TLV parameter parser over
    //! symbolic (companion-supplied) descriptor-pool bytes.
    //!
    //! The parser reads ONLY `ir.pool`, so each harness constructs an
    //! `Erc7730Ir` whose other fields are dummy and whose `pool` is the
    //! symbolic byte array — isolating `parse` from the IR header parser
    //! (covered separately by `ir::kani_harnesses::erc7730_ir_parse_panic_free`).
    //!
    //! Bound (honest): the per-tag soundness harnesses are EXHAUSTIVE over
    //! a single TLV entry's content (symbolic tag / length / payload bytes,
    //! payload bounded to the in-pool capacity). Multi-entry *cursor-tiling
    //! fidelity* (entry N+1 begins exactly where N ended, no overlap/gap
    //! across records) is closed only for panic / slice-OOB freedom by
    //! `params_parse_panic_free`, NOT for full multi-record value soundness
    //! — the same scoping the SOTA doc applies to multiSend layer-2.

    use super::*;
    use crate::ir::ContextKind;

    /// Build an `Erc7730Ir` whose only meaningful field is `pool`. Every
    /// other field is a fixed dummy: `parse` never reads them.
    fn mk_ir(pool: &[u8]) -> Erc7730Ir<'_> {
        Erc7730Ir {
            schema_ver: 0,
            context_kind: ContextKind::Contract,
            chain_id: 0,
            contract: [0u8; 20],
            descriptor_hash: [0u8; 32],
            domain_separator: [0u8; 32],
            owner: &[],
            contract_name: &[],
            pool,
            formats: &[],
            raw: &[],
        }
    }

    /// Panic / arithmetic-overflow / slice-OOB freedom for the whole
    /// multi-TLV walk over an arbitrary pool, an arbitrary in-bounds pool
    /// length, AND an arbitrary `param_off` (so a hostile offset cannot
    /// panic the parser either). This is the "dynamic offsets/lengths stay
    /// in-bounds — no read past end" property over the cursor loop; Kani's
    /// default checks discharge it. Bound: N-byte pool, loop unwound to N/2+1.
    #[kani::proof]
    #[kani::unwind(10)]
    fn params_parse_panic_free() {
        const N: usize = 16;
        let pool: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let off: u16 = kani::any();
        let ir = mk_ir(&pool[..len]);
        let _ = parse(&ir, off);
    }

    // ---- per-tag soundness (offset PINNED at param_off = 1) -------------
    //
    // Layout for `param_off = 1`, single TLV occupying the whole blob:
    //   pool[0]            filler (param_off points at pool[1])
    //   pool[1] = blob_len = 2 + L
    //   pool[2] = tag
    //   pool[3] = L (payload_len)
    //   pool[4 .. 4+L]     payload
    // `assume(pool[1] == 2 + L)` makes the single TLV span the whole body;
    // `assume(4 + L <= N)` keeps the payload in-pool so the only reject is
    // the per-tag width/value gate (body-overflow rejects are the
    // panic-free harness's job). All assertions reconstruct the expected
    // value from the ORIGINAL `pool` at the fixed offset — never from the
    // parser's cursor — so they cannot pass by re-checking the parser
    // against itself.

    /// `enum_ref` (0x37): accept ⟺ exactly 2 payload bytes, and the stored
    /// value is the big-endian u16 of those bytes read at the fixed offset.
    #[kani::proof]
    #[kani::unwind(4)]
    fn params_enum_ref_width_and_value_sound() {
        const N: usize = 10;
        let pool: [u8; N] = kani::any();
        let l = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + l);
        kani::assume(4 + l <= N);
        kani::assume(pool[2] == PARAM_ENUM_REF);
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(p) => {
                assert!(l == 2);
                assert_eq!(p.enum_ref, Some(u16::from_be_bytes([pool[4], pool[5]])));
            }
            Err(_) => assert!(l != 2),
        }
    }

    /// `decimals` (0x38): accept ⟺ exactly 1 payload byte, and the stored
    /// value is that byte read at the fixed offset.
    #[kani::proof]
    #[kani::unwind(4)]
    fn params_decimals_width_and_value_sound() {
        const N: usize = 8;
        let pool: [u8; N] = kani::any();
        let l = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + l);
        kani::assume(4 + l <= N);
        kani::assume(pool[2] == PARAM_DECIMALS);
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(p) => {
                assert!(l == 1);
                assert_eq!(p.decimals, Some(pool[4]));
            }
            Err(_) => assert!(l != 1),
        }
    }

    /// `token` (0x31): accept ⟺ exactly 20 payload bytes, and the stored
    /// `&[u8; 20]` is the verbatim 20-byte window at the fixed offset.
    ///
    /// The structural bytes are assigned directly and a single symbolic byte
    /// index proves all 20 payload positions. This is equivalent to whole-slice
    /// equality without bit-blasting a symbolic 20-byte `memcmp`.
    #[kani::proof]
    #[kani::unwind(6)]
    fn params_token_width_and_value_sound() {
        const N: usize = 24;
        let mut pool: [u8; N] = kani::any();
        let l: usize = kani::any();
        kani::assume(l <= 20);
        pool[0] = 0xFF;
        pool[1] = (2 + l) as u8;
        pool[2] = PARAM_TOKEN;
        pool[3] = l as u8;
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(p) => {
                assert!(l == 20);
                let k: usize = kani::any();
                kani::assume(k < 20);
                assert!(p.token.is_some());
                assert!(p.token.unwrap()[k] == pool[4 + k]);
            }
            Err(_) => assert!(l != 20),
        }
    }

    /// `visibility` (0x3F): accept ⟺ non-empty payload AND a first byte in
    /// the valid Visibility range (≤ 4). On accept the variant equals
    /// `Visibility::try_from(payload[0])` and the value-list tail (Phase 5)
    /// is exactly `payload[1..]` when longer than one byte. This is the
    /// "reject out-of-range enum selector" property for the visibility byte.
    ///
    /// Unwind 10 covers the `memcmp` for the (≤ 5-byte) `visibility_values`
    /// slice comparison plus the one-iteration single-TLV walk.
    #[kani::proof]
    #[kani::unwind(10)]
    fn params_visibility_gate_and_value_sound() {
        const N: usize = 10;
        let pool: [u8; N] = kani::any();
        let l = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + l);
        kani::assume(4 + l <= N);
        kani::assume(pool[2] == PARAM_VISIBILITY);
        let ir = mk_ir(&pool);
        match parse(&ir, 1) {
            Ok(p) => {
                assert!(l >= 1);
                assert!(pool[4] <= 4);
                assert_eq!(p.visibility, Visibility::try_from(pool[4]).unwrap());
                if l > 1 {
                    assert_eq!(p.visibility_values, Some(&pool[5..4 + l]));
                } else {
                    assert_eq!(p.visibility_values, None);
                }
            }
            Err(_) => assert!(l == 0 || pool[4] > 4),
        }
    }

    // ---- self-anchored non-vacuity controls ----------------------------

    /// Positive control: a concrete, canonical multi-TLV blob
    /// (decimals + token + visibility=Never) is ACCEPTED and decodes to
    /// exactly the expected fields. Without this every biconditional Ok
    /// branch above could in principle be vacuous; this witnesses that the
    /// parser genuinely accepts a realistic descriptor.
    ///
    /// Unwind 24: the 20-byte `memcmp` for the token value comparison
    /// dominates; the three-entry TLV walk is well within this bound.
    #[kani::proof]
    #[kani::unwind(24)]
    fn params_accepts_concrete() {
        // Whole array pre-seeded with the token payload byte (0xAB); the
        // structural bytes are then patched in. No harness-side loop.
        let mut pool = [0xABu8; 30];
        pool[0] = 0xFF; // filler
        pool[1] = 28; // blob_len = 3 (decimals) + 22 (token) + 3 (visibility)
        pool[2] = PARAM_DECIMALS;
        pool[3] = 1;
        pool[4] = 6;
        pool[5] = PARAM_TOKEN;
        pool[6] = 20;
        // pool[7..27] already 0xAB (token payload)
        pool[27] = PARAM_VISIBILITY;
        pool[28] = 1;
        pool[29] = Visibility::Never as u8;
        let ir = mk_ir(&pool);
        let p = parse(&ir, 1).expect("canonical multi-TLV param blob must decode");
        assert_eq!(p.decimals, Some(6));
        assert_eq!(p.token, Some(&[0xAB; 20]));
        assert_eq!(p.visibility, Visibility::Never);
        assert_eq!(p.visibility_values, None);
    }

    /// On-point negative: a tag outside the contiguous known tag range is
    /// REJECTED regardless of its symbolic payload — a hostile
    /// descriptor cannot smuggle an unknown TLV past the renderer.
    #[kani::proof]
    #[kani::unwind(4)]
    fn params_rejects_unknown_tag() {
        // Large enough to encode the widest adjacent known tag (the 20-byte
        // native-currency address), so the property cannot pass merely because
        // every high-tag payload is structurally truncated.
        const N: usize = 24;
        let pool: [u8; N] = kani::any();
        let l = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + l);
        kani::assume(4 + l <= N);
        let tag = pool[2];
        // "Unknown" = outside the CONTIGUOUS known-tag range
        // `[0x30, PARAM_DYNAMIC_KIND]`.
        // NB: the top bound is the HIGHEST known tag, not 0x3F — new tags were added
        // above the original 0x30..=0x3F block (`PARAM_CONST_VALUE` 0x40 in b37a052f,
        // `PARAM_NESTED_STRUCT` 0x41 in 2f4cc810), so a stale bound wrongly classifies
        // a known tag as unknown and the harness fails on a tag the parser correctly
        // accepts. Keep this in sync with the highest `PARAM_*` constant.
        kani::assume(tag < PARAM_TOKEN_PATH || tag > PARAM_DYNAMIC_KIND);
        let ir = mk_ir(&pool);
        assert!(parse(&ir, 1).is_err());
    }

    /// On-point negative: a VISIBILITY TLV whose first byte is out of the
    /// valid range (> 4) is REJECTED. This is exactly the "NS supplies an
    /// out-of-range visibility selector" threat the gate exists to stop.
    #[kani::proof]
    #[kani::unwind(4)]
    fn params_rejects_visibility_byte_gt_4() {
        const N: usize = 8;
        let pool: [u8; N] = kani::any();
        let l = pool[3] as usize;
        kani::assume((pool[1] as usize) == 2 + l);
        kani::assume(4 + l <= N);
        kani::assume(l >= 1);
        kani::assume(pool[2] == PARAM_VISIBILITY);
        kani::assume(pool[4] > 4);
        let ir = mk_ir(&pool);
        assert!(parse(&ir, 1).is_err());
    }
}
