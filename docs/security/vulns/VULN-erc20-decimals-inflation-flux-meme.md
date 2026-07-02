# VULN — ERC‑20 decimals inflation ships a magnitude‑hiding drain (HIGH, WYSIWYS)

**Severity:** HIGH (display < signed magnitude; full‑balance drain rendered as dust)
**Status:** OPEN (found 2026‑06‑28, commit `01981a14`)
**Class:** WYSIWYS magnitude‑hiding — same family as the native‑value / Safe‑inner‑raw‑amount HIGHs, but data‑sourced rather than logic‑sourced.

## Summary

The firmware's trusted‑display amount formatter renders `amount / 10^decimals`, where
`decimals` comes from the firmware‑pinned ERC‑20 metadata DB (`secure/data/erc20.json`,
Merkle‑rooted into the image as `db_roots::ERC20_DB_ROOT`). The DB is built by
`tools/build_erc20_db.py`, which takes each token's `decimals` **verbatim from third‑party
token lists** (CoinGecko / Li.Fi / 1inch / Sushi / Uniswap / …) with **no on‑chain
`decimals()` cross‑check** (acknowledged in `tx/src/erc20/bundle.rs:79‑83`). The only guard
is `MAX_DISPLAY_DECIMALS = 36`, which rejects absurd values but accepts an in‑range‑but‑wrong
`decimals`.

When a shipped token's DB `decimals` is **larger** than its true on‑chain value, every amount
of that token renders **10^(DB − real)× too small**. A full‑balance transfer is then shown as
a dust amount (with the correct symbol, reinforcing the deception), and the user confirms a
drain believing it is negligible.

## Confirmed instances (on‑chain `decimals()` verified)

| token | address (chain 1) | DB decimals | real decimals | understatement |
|-------|-------------------|-------------|---------------|----------------|
| FLUX  | `0x720CD16b011b987Da3518fbf38c3071d4F0D1495` | 18 | **8** | 10^10× |
| MEME  | `0xD5525D397898e5502075Ea5E830d8914f6F0affe` | 18 | **8** | 10^10× |

(Found by cross‑checking the shipped DB against `build/token_lists/*` — flagged where shipped
decimals exceeded the source plurality — then confirming the true value on‑chain. The
cross‑source scan only catches tokens where the *sources disagree*; tokens where *all* third‑party
lists carry the same wrong value would ship wrong and go undetected here, so the true affected
population is ≥ 2 and can only be bounded by an on‑chain scan of all 17,952 entries.)

## Exploit (no fault injection, standard path)

1. Victim holds e.g. 50,000 FLUX. Real decimals = 8 ⇒ base units = `50_000 × 10^8 = 5×10^12`.
2. Malicious companion submits `CMD_SIGN_USEROP` with inner calldata
   `transfer(attacker, 5_000_000_000_000)` to the FLUX contract (drain entire balance).
3. Dispatch reaches the direct ERC‑20 branch (`display::pick_sign_pages_inner`), the bundle
   address‑matches `tx.to` (`direct_erc20_meta_matches`), so `render_erc20_known_pages` renders
   the amount with the DB's `decimals = 18`:
   `5×10^12 / 10^18 = 0.000005` → screen shows **“Send 0.000005 FLUX”**.
4. `0.000005 ≥ 10^-6`, so it is **non‑zero** at the 6‑fractional‑digit display width — the
   `reject_zero_collapse` guard (which only fires when a non‑zero amount rounds to all‑zeros)
   does **not** trigger. No loud marker.
5. The symbol shown is the correct “FLUX”, so the user recognises their token and confirms a
   transfer that looks like dust but signs away their whole balance.

Reachable identically on the CoW leg path (`decode_leg` → `write_cow_leg_amount`) and the
ERC‑7730 `tokenAmount` path (`render_token_amount` bound case) — all consume `meta.decimals`
verbatim.

## Why the existing guards don't catch it

- `MAX_DISPLAY_DECIMALS = 36` (`erc20/bundle.rs`) — only rejects absurd, not 18‑vs‑8.
- zero‑collapse guard — only fires when the amount rounds to exactly 0.000000; an understated
  dust amount ≥ 0.000001 sails through.
- `direct_erc20_meta_matches` / per‑record re‑match — these fix *which token's* metadata is
  applied (the v1_ms class). Here the attribution is *correct* (it really is FLUX); the
  **decimals within the correct entry** are wrong.

## Fix

1. **Immediate (data):** correct FLUX/MEME (and re‑scan all entries) and regenerate
   `ERC20_DB_ROOT`.
2. **Systemic (build):** `build_erc20_db.py` must verify each token's `decimals` against an
   on‑chain `decimals()` call (or a multi‑source agreement gate that *rejects* disagreements
   rather than silently picking one) before admitting it to the DB. This is the documented
   OPEN mitigation referenced in `bundle.rs` and the `project_erc20_decimals_unbounded_wysiwys`
   memory.
3. **Defence‑in‑depth (firmware):** the firmware cannot know the true decimals, but it can
   refuse/loud‑flag when a *known‑draining‑shaped* amount (large base integer) renders below a
   "dust" threshold for a token whose decimals it can't independently corroborate — i.e. widen
   the zero‑collapse guard to a "suspiciously‑small for a large raw integer" guard.
