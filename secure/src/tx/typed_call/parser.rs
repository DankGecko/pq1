//! Re-export shim: the pure text-signature tokenizer now lives in the
//! host-compilable `pqsigner-tx` crate so it can be bounded-verified
//! with Kani alongside the ABI walker (`cargo kani -p pqsigner-tx`).
//!
//! Consumes the verified `text_sig` slot of a [`crate::selectors::SelectorMeta`]
//! (e.g. `transfer(address,uint256)`) and produces a fixed-shape
//! representation usable by the ABI walker in [`super::abi`].
//!
//! Whitelist parity with `tools/build_selectors_json.py` is **load-bearing**:
//! the curator only admits text_sigs the Python validator accepts, so
//! the firmware-side parser MUST accept the same set and reject the
//! same set. Any expansion (e.g. a new fixed-bytesN width, a new uint
//! width) has to land in the Python validator and `pqsigner-tx`'s
//! `typed_call::parser` in the same change.
//!
//! The unit tests stay HERE (not in `pqsigner-tx`) because
//! `round_trip_curated_selectors_json` resolves
//! `secure/data/selectors.json` via `CARGO_MANIFEST_DIR`; they exercise
//! the re-exported items, so they keep pinning the parser's behaviour.

#![allow(dead_code)]

pub(crate) use pqsigner_tx::typed_call::parser::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_simple() {
        let p = parse_text_sig(b"transfer(address,uint256)").unwrap();
        assert_eq!(p.name, b"transfer");
        assert_eq!(p.arg_count, 2);
        assert!(matches!(p.arena.get(p.args[0]), TypeRef::Address));
        assert!(matches!(p.arena.get(p.args[1]), TypeRef::Uint(256)));
    }

    #[test]
    fn zero_args() {
        let p = parse_text_sig(b"foo()").unwrap();
        assert_eq!(p.name, b"foo");
        assert_eq!(p.arg_count, 0);
    }

    #[test]
    fn bare_uint_int_resolve_to_256() {
        let p = parse_text_sig(b"f(uint,int)").unwrap();
        assert!(matches!(p.arena.get(p.args[0]), TypeRef::Uint(256)));
        assert!(matches!(p.arena.get(p.args[1]), TypeRef::Int(256)));
    }

    #[test]
    fn dynamic_array() {
        let p = parse_text_sig(b"g(uint256[])").unwrap();
        match p.arena.get(p.args[0]) {
            TypeRef::Array { elem, fixed_len: None } => {
                assert!(matches!(p.arena.get(*elem), TypeRef::Uint(256)));
            }
            other => panic!("expected dynamic array, got {:?}", other),
        }
    }

    #[test]
    fn fixed_array() {
        let p = parse_text_sig(b"h(uint256[8])").unwrap();
        match p.arena.get(p.args[0]) {
            TypeRef::Array { elem, fixed_len: Some(8) } => {
                assert!(matches!(p.arena.get(*elem), TypeRef::Uint(256)));
            }
            other => panic!("expected fixed array of 8, got {:?}", other),
        }
    }

    #[test]
    fn nested_array() {
        // uint256[10][] = dynamic array of (fixed array of 10 uint256).
        // The Python validator strips suffixes from the right, so the
        // outermost wrapper is `[]` (the LAST suffix). That makes the
        // outer Array dynamic and its element a fixed-10 Array.
        let p = parse_text_sig(b"f(uint256[10][])").unwrap();
        match p.arena.get(p.args[0]) {
            TypeRef::Array { elem, fixed_len: None } => match p.arena.get(*elem) {
                TypeRef::Array { elem: inner, fixed_len: Some(10) } => {
                    assert!(matches!(p.arena.get(*inner), TypeRef::Uint(256)));
                }
                other => panic!("expected fixed[10], got {:?}", other),
            },
            other => panic!("expected dynamic[], got {:?}", other),
        }
    }

    #[test]
    fn tuple() {
        let p = parse_text_sig(b"f((address,uint256))").unwrap();
        match p.arena.get(p.args[0]) {
            TypeRef::Tuple { fields, len: 2 } => {
                assert!(matches!(p.arena.get(fields[0]), TypeRef::Address));
                assert!(matches!(p.arena.get(fields[1]), TypeRef::Uint(256)));
            }
            other => panic!("expected tuple, got {:?}", other),
        }
    }

    #[test]
    fn bytesn_widths() {
        for n in 1..=32u8 {
            let s = format!("f(bytes{})", n);
            let p = parse_text_sig(s.as_bytes())
                .unwrap_or_else(|| panic!("bytes{} should parse", n));
            assert!(matches!(p.arena.get(p.args[0]), TypeRef::BytesN(m) if *m == n));
        }
    }

    #[test]
    fn rejects_oversized_bytesn() {
        assert!(parse_text_sig(b"f(bytes33)").is_none());
        assert!(parse_text_sig(b"f(bytes0)").is_none());
    }

    #[test]
    fn rejects_bad_uint_width() {
        assert!(parse_text_sig(b"f(uint7)").is_none());
        assert!(parse_text_sig(b"f(uint264)").is_none());
        assert!(parse_text_sig(b"f(uint009)").is_none());
    }

    #[test]
    fn rejects_empty_tuple() {
        assert!(parse_text_sig(b"f(())").is_none());
    }

    #[test]
    fn rejects_unbalanced_parens() {
        assert!(parse_text_sig(b"f(uint256").is_none());
        assert!(parse_text_sig(b"f(uint256))").is_none());
    }

    #[test]
    fn rejects_no_open_paren() {
        assert!(parse_text_sig(b"foo").is_none());
    }

    #[test]
    fn rejects_bad_name() {
        assert!(parse_text_sig(b"9foo(uint256)").is_none());
        assert!(parse_text_sig(b"foo bar(uint256)").is_none());
        assert!(parse_text_sig(b"(uint256)").is_none());
    }

    #[test]
    fn rejects_unknown_primitive() {
        assert!(parse_text_sig(b"f(function)").is_none());
        assert!(parse_text_sig(b"f(fixed128x18)").is_none());
    }

    #[test]
    fn arg_cap() {
        // 17 args > MAX_ARGS=16.
        let mut s = String::from("f(");
        for i in 0..17 {
            if i > 0 {
                s.push(',');
            }
            s.push_str("uint256");
        }
        s.push(')');
        assert!(parse_text_sig(s.as_bytes()).is_none());
    }

    #[test]
    fn nesting_cap() {
        // 9-deep nested tuple ⇒ depth > MAX_NESTING.
        let mut s = String::from("f(");
        for _ in 0..9 {
            s.push('(');
        }
        s.push_str("uint256");
        for _ in 0..9 {
            s.push(')');
        }
        s.push(')');
        assert!(parse_text_sig(s.as_bytes()).is_none());
    }

    /// Round-trip every entry in secure/data/selectors.json against the
    /// firmware-side parser. Mirrors the gate the Python curator
    /// applies, so any drift (e.g. firmware accepting more or fewer
    /// types) trips this test loudly. Run as part of
    /// `cargo test -p sphincs-tz-secure --tests`.
    #[test]
    fn round_trip_curated_selectors_json() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/data/selectors.json");
        let text = std::fs::read_to_string(path)
            .expect("selectors.json missing — run `make selectors-json`?");
        let mut count = 0usize;
        let mut failed: Vec<String> = Vec::new();
        for sig in iter_text_sigs(&text) {
            count += 1;
            if parse_text_sig(sig.as_bytes()).is_none() {
                failed.push(sig.to_string());
                if failed.len() >= 10 {
                    break;
                }
            }
        }
        assert!(count > 0, "no entries scanned in selectors.json");
        assert!(
            failed.is_empty(),
            "parser rejected {} curator-accepted entries (showing up to 10): {:?}",
            failed.len(),
            failed,
        );
    }

    /// Trivial JSON-line scanner: yields every value of the
    /// "text_sig": "..." key. Avoids pulling serde_json into
    /// dev-dependencies for a one-shot fixture.
    fn iter_text_sigs(text: &str) -> impl Iterator<Item = &str> {
        text.lines().filter_map(|line| {
            let key = "\"text_sig\":";
            let i = line.find(key)?;
            let rest = &line[i + key.len()..];
            let q1 = rest.find('"')?;
            let after = &rest[q1 + 1..];
            let q2 = after.find('"')?;
            Some(&after[..q2])
        })
    }

    // ---------------------------------------------------------------
    // Frozen-constants regression tests.
    //
    // Caps are part of the slice's contract: the Python curator in
    // tools/build_selectors_json.py is configured to admit only
    // signatures the firmware parser will accept. Any silent change to
    // these constants would let the curator hand the firmware a sig
    // the firmware then rejects — breaking text-sig dispatch on every
    // chain that uses the affected selector. Pin them here so any
    // future tweak is a conscious break.
    // ---------------------------------------------------------------

    #[test]
    fn positive_constants_are_frozen() {
        assert_eq!(MAX_ARGS, 16, "MAX_ARGS frozen — curator parity");
        assert_eq!(MAX_TYPE_ARENA, 32, "MAX_TYPE_ARENA frozen — curator parity");
        assert_eq!(MAX_NESTING, 8, "MAX_NESTING frozen — curator parity");
        assert_eq!(MAX_TUPLE_FIELDS, 8, "MAX_TUPLE_FIELDS frozen — curator parity");
    }

    // ---------------------------------------------------------------
    // Positive coverage extension — every primitive width.
    // ---------------------------------------------------------------

    #[test]
    fn positive_every_uint_width_accepted() {
        for bits in (8..=256).step_by(8) {
            let s = format!("f(uint{})", bits);
            let p = parse_text_sig(s.as_bytes())
                .unwrap_or_else(|| panic!("uint{} must parse", bits));
            match p.arena.get(p.args[0]) {
                TypeRef::Uint(n) if usize::from(*n) == bits => {}
                other => panic!("uint{} parsed as {:?}", bits, other),
            }
        }
    }

    #[test]
    fn positive_every_int_width_accepted() {
        for bits in (8..=256).step_by(8) {
            let s = format!("f(int{})", bits);
            let p = parse_text_sig(s.as_bytes())
                .unwrap_or_else(|| panic!("int{} must parse", bits));
            match p.arena.get(p.args[0]) {
                TypeRef::Int(n) if usize::from(*n) == bits => {}
                other => panic!("int{} parsed as {:?}", bits, other),
            }
        }
    }

    #[test]
    fn positive_name_with_underscores_digits() {
        let p = parse_text_sig(b"_safeBatchTransfer42_v1(address,uint256)").unwrap();
        assert_eq!(p.name, b"_safeBatchTransfer42_v1");
    }

    #[test]
    fn positive_lone_underscore_name() {
        let p = parse_text_sig(b"_(uint256)").unwrap();
        assert_eq!(p.name, b"_");
    }

    #[test]
    fn positive_solidity_keyword_as_name_allowed() {
        // The whitelist is for *type* tokens, not function names. A
        // function literally named `bool` is legal Solidity-ABI text.
        let p = parse_text_sig(b"bool(uint256)").unwrap();
        assert_eq!(p.name, b"bool");
    }

    #[test]
    fn positive_max_args_accepted() {
        let mut s = String::from("f(");
        for i in 0..MAX_ARGS {
            if i > 0 {
                s.push(',');
            }
            s.push_str("uint256");
        }
        s.push(')');
        let p = parse_text_sig(s.as_bytes()).expect("exactly MAX_ARGS must parse");
        assert_eq!(p.arg_count, MAX_ARGS);
    }

    #[test]
    fn positive_max_tuple_fields_accepted() {
        let mut s = String::from("f((");
        for i in 0..MAX_TUPLE_FIELDS {
            if i > 0 {
                s.push(',');
            }
            s.push_str("uint256");
        }
        s.push_str("))");
        let p = parse_text_sig(s.as_bytes()).expect("MAX_TUPLE_FIELDS must parse");
        match p.arena.get(p.args[0]) {
            TypeRef::Tuple { len, .. } => assert_eq!(*len as usize, MAX_TUPLE_FIELDS),
            other => panic!("expected tuple, got {:?}", other),
        }
    }

    #[test]
    fn positive_max_nesting_arrays_accepted() {
        // 8 levels of `[]` — the deepest `parse_type` sees depth==8
        // which is still `<= MAX_NESTING`.
        let mut s = String::from("f(uint256");
        for _ in 0..(MAX_NESTING as usize) {
            s.push_str("[]");
        }
        s.push(')');
        assert!(
            parse_text_sig(s.as_bytes()).is_some(),
            "exactly MAX_NESTING levels of array must parse"
        );
    }

    // ---------------------------------------------------------------
    // Negative coverage — name validation.
    // ---------------------------------------------------------------

    #[test]
    fn negative_name_with_hyphen_rejected() {
        // Function name must be `[A-Za-z_][A-Za-z0-9_]*` — hyphens are
        // a common transliteration of Python/JS APIs and must NOT be
        // admitted, otherwise the firmware would dispatch by a selector
        // the on-chain ABI cannot match.
        assert!(parse_text_sig(b"safe-mint(uint256)").is_none());
    }

    #[test]
    fn negative_name_with_dot_rejected() {
        assert!(parse_text_sig(b"foo.bar(uint256)").is_none());
    }

    #[test]
    fn negative_non_ascii_in_name_rejected() {
        // The curator emits ASCII-only text_sigs; anything with the
        // high bit set is attacker-crafted. is_ascii_alphabetic() must
        // reject 0xC3, 0x80, …
        let mut bytes = b"f".to_vec();
        bytes.push(0xC3); // multibyte UTF-8 lead — non-ASCII
        bytes.push(0xA9);
        bytes.extend_from_slice(b"(uint256)");
        assert!(parse_text_sig(&bytes).is_none());
    }

    #[test]
    fn negative_empty_input_rejected() {
        assert!(parse_text_sig(b"").is_none());
    }

    #[test]
    fn negative_open_paren_first_byte_rejected() {
        // open == 0 ⇒ empty name ⇒ reject.
        assert!(parse_text_sig(b"(uint256)").is_none());
    }

    // ---------------------------------------------------------------
    // Negative coverage — primitive whitelist.
    // ---------------------------------------------------------------

    #[test]
    fn negative_deprecated_byte_alias_rejected() {
        // Solidity 0.8 dropped the `byte` alias for `bytes1`. The
        // whitelist is intentionally narrower than Solidity's full
        // grammar — the curator never emits `byte`, so firmware never
        // should accept it.
        assert!(parse_text_sig(b"f(byte)").is_none());
    }

    #[test]
    fn negative_fixed_types_rejected() {
        // `fixed` / `ufixed` are reserved but unimplemented in Solidity;
        // the curator doesn't emit them. Refuse so an attacker can't
        // smuggle in an unrenderable type to force blind-sign fallback
        // on an otherwise typed-call signature.
        assert!(parse_text_sig(b"f(fixed)").is_none());
        assert!(parse_text_sig(b"f(ufixed)").is_none());
        assert!(parse_text_sig(b"f(fixed128x18)").is_none());
        assert!(parse_text_sig(b"f(ufixed256x80)").is_none());
    }

    #[test]
    fn negative_function_type_rejected() {
        assert!(parse_text_sig(b"f(function)").is_none());
    }

    #[test]
    fn negative_uintn_with_trailing_letter_rejected() {
        // strip_prefix matches "uint" then `parse_uint_width` chokes on
        // the non-digit byte. Catches an attacker trying "uint8a" hoping
        // we accept the prefix.
        assert!(parse_text_sig(b"f(uint8a)").is_none());
        assert!(parse_text_sig(b"f(int8X)").is_none());
        assert!(parse_text_sig(b"f(bytes1x)").is_none());
    }

    #[test]
    fn negative_uintn_non_multiple_of_8_rejected() {
        for bad in [1u16, 7, 9, 15, 17, 100, 255] {
            let s = format!("f(uint{})", bad);
            assert!(
                parse_text_sig(s.as_bytes()).is_none(),
                "uint{} (not multiple of 8) must reject",
                bad,
            );
        }
    }

    #[test]
    fn negative_uintn_width_overflow_rejected() {
        // uint264 / uint512 / uint99999 — all over 256.
        assert!(parse_text_sig(b"f(uint264)").is_none());
        assert!(parse_text_sig(b"f(uint512)").is_none());
        assert!(parse_text_sig(b"f(uint99999)").is_none());
        // u32 overflow inside parse_uint_width.
        assert!(parse_text_sig(b"f(uint99999999999)").is_none());
    }

    #[test]
    fn negative_uintn_leading_zero_rejected() {
        // Curator emits canonical decimal; "uint008" is non-canonical.
        assert!(parse_text_sig(b"f(uint008)").is_none());
        assert!(parse_text_sig(b"f(uint0)").is_none());
        assert!(parse_text_sig(b"f(uint00)").is_none());
        // Bare "uint" still resolves to Uint(256) — distinct from "uint0".
        assert!(parse_text_sig(b"f(uint)").is_some());
    }

    #[test]
    fn negative_bytesn_out_of_range_rejected() {
        assert!(parse_text_sig(b"f(bytes33)").is_none());
        assert!(parse_text_sig(b"f(bytes0)").is_none());
        assert!(parse_text_sig(b"f(bytes999)").is_none());
        assert!(parse_text_sig(b"f(bytes01)").is_none()); // leading zero
    }

    // ---------------------------------------------------------------
    // Negative coverage — whitespace must NOT be silently tolerated.
    // The on-chain selector is keccak256 over the canonical (no-space)
    // text_sig. Any tolerance for spaces would let firmware accept a
    // non-canonical string whose selector differs from what the dapp
    // signed.
    // ---------------------------------------------------------------

    #[test]
    fn negative_internal_space_in_type_rejected() {
        assert!(parse_text_sig(b"f(uint 256)").is_none());
    }

    #[test]
    fn negative_space_after_comma_rejected() {
        assert!(parse_text_sig(b"f(uint256, uint256)").is_none());
    }

    #[test]
    fn negative_trailing_space_in_type_rejected() {
        assert!(parse_text_sig(b"f(uint256 )").is_none());
    }

    #[test]
    fn negative_space_in_name_rejected() {
        assert!(parse_text_sig(b"foo bar(uint256)").is_none());
    }

    // ---------------------------------------------------------------
    // Negative coverage — comma / bracket structure.
    // ---------------------------------------------------------------

    #[test]
    fn negative_leading_comma_rejected() {
        assert!(parse_text_sig(b"f(,uint256)").is_none());
    }

    #[test]
    fn negative_trailing_comma_rejected() {
        assert!(parse_text_sig(b"f(uint256,)").is_none());
    }

    #[test]
    fn negative_double_comma_rejected() {
        assert!(parse_text_sig(b"f(uint256,,uint256)").is_none());
    }

    #[test]
    fn negative_lone_comma_arg_rejected() {
        assert!(parse_text_sig(b"f(,)").is_none());
    }

    #[test]
    fn negative_unmatched_array_brackets_rejected() {
        assert!(parse_text_sig(b"f(uint256[)").is_none());
        assert!(parse_text_sig(b"f(uint256])").is_none());
        assert!(parse_text_sig(b"f(uint256[[)").is_none());
        // The walker would call `find_matching_open_bracket` and find
        // nothing pairing, returning None.
        assert!(parse_text_sig(b"f(uint256][)").is_none());
    }

    #[test]
    fn negative_empty_array_inner_rejected() {
        // `[]` with no element type. inner.is_empty() must be rejected.
        assert!(parse_text_sig(b"f([])").is_none());
        assert!(parse_text_sig(b"f([5])").is_none());
    }

    #[test]
    fn negative_array_bound_overflow_rejected() {
        // parse_u32_decimal must reject anything that overflows u32.
        assert!(parse_text_sig(b"f(uint256[4294967296])").is_none()); // 2^32
        assert!(parse_text_sig(b"f(uint256[9999999999])").is_none());
    }

    #[test]
    fn negative_array_bound_leading_zero_rejected() {
        assert!(parse_text_sig(b"f(uint256[01])").is_none());
        assert!(parse_text_sig(b"f(uint256[00])").is_none());
        // Bare "[0]" — parse_u32_decimal disallows acc==0.
        assert!(parse_text_sig(b"f(uint256[0])").is_none());
    }

    #[test]
    fn negative_array_bound_non_digit_rejected() {
        assert!(parse_text_sig(b"f(uint256[1a])").is_none());
        assert!(parse_text_sig(b"f(uint256[ 5])").is_none());
        assert!(parse_text_sig(b"f(uint256[+5])").is_none());
        assert!(parse_text_sig(b"f(uint256[-5])").is_none());
    }

    #[test]
    fn negative_nesting_above_cap_rejected() {
        // 9 levels of `[]` → recurses to depth=9 → `> MAX_NESTING`.
        let mut s = String::from("f(uint256");
        for _ in 0..((MAX_NESTING as usize) + 1) {
            s.push_str("[]");
        }
        s.push(')');
        assert!(
            parse_text_sig(s.as_bytes()).is_none(),
            "{} levels of nesting must exceed MAX_NESTING",
            (MAX_NESTING as usize) + 1,
        );
    }

    #[test]
    fn negative_tuple_fields_above_cap_rejected() {
        // (MAX_TUPLE_FIELDS + 1) fields must reject.
        let mut s = String::from("f((");
        for i in 0..(MAX_TUPLE_FIELDS + 1) {
            if i > 0 {
                s.push(',');
            }
            s.push_str("uint256");
        }
        s.push_str("))");
        assert!(parse_text_sig(s.as_bytes()).is_none());
    }

    #[test]
    fn negative_arena_exhaustion_rejected() {
        // 4 args of 8-nested `T[]` = 4 * 9 = 36 arena allocations,
        // which exceeds MAX_TYPE_ARENA (32). Confirms the arena cap
        // is enforced independent of the nesting + arg caps.
        let mut arg = String::from("uint256");
        for _ in 0..(MAX_NESTING as usize) {
            arg.push_str("[]");
        }
        let s = format!("f({0},{0},{0},{0})", arg);
        assert!(
            parse_text_sig(s.as_bytes()).is_none(),
            "{} arena allocs must exceed MAX_TYPE_ARENA={}",
            4 * (MAX_NESTING as usize + 1),
            MAX_TYPE_ARENA,
        );
    }

    #[test]
    fn negative_unbalanced_parens_extras_rejected() {
        // Extra `(` deep inside body — TopLevelSplit reports depth!=0.
        assert!(parse_text_sig(b"f((uint256)").is_none());
        // Extra `)` mid-body.
        assert!(parse_text_sig(b"f(uint256))").is_none());
        // Mid-body `)` before final `)` — TopLevelSplit sees depth<0.
        assert!(parse_text_sig(b"f()uint256)").is_none());
    }

    #[test]
    fn negative_missing_trailing_paren_rejected() {
        assert!(parse_text_sig(b"f(uint256").is_none());
        assert!(parse_text_sig(b"f(uint256]").is_none());
    }

    #[test]
    fn negative_no_paren_at_all_rejected() {
        assert!(parse_text_sig(b"transferuint256").is_none());
    }

    #[test]
    fn negative_empty_tuple_rejected() {
        assert!(parse_text_sig(b"f(())").is_none());
    }

    // ---------------------------------------------------------------
    // Assumption-pinning: the parser MUST refuse to mutate the arena
    // for an input that ultimately fails. (If it did, an iterative
    // caller could exhaust the arena and starve later parses — but
    // each parse_text_sig call constructs a fresh arena, so this is
    // really a "fresh state per call" guarantee.)
    // ---------------------------------------------------------------

    #[test]
    fn positive_fresh_arena_per_call() {
        // Two back-to-back parses of MAX_ARGS each must both succeed.
        for _ in 0..3 {
            let mut s = String::from("f(");
            for i in 0..MAX_ARGS {
                if i > 0 {
                    s.push(',');
                }
                s.push_str("uint256");
            }
            s.push(')');
            assert!(parse_text_sig(s.as_bytes()).is_some());
        }
    }

    // ---------------------------------------------------------------
    // Name slice is borrowed from input (no copy, no allocation).
    // ---------------------------------------------------------------

    #[test]
    fn positive_name_slice_borrows_from_input() {
        let input: &[u8] = b"transfer(address,uint256)";
        let p = parse_text_sig(input).unwrap();
        // The returned `name` must live inside the input slice — both
        // by pointer identity and by value.
        assert_eq!(p.name.as_ptr(), input.as_ptr());
        assert_eq!(p.name, b"transfer");
    }
}
