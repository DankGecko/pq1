# c01 — non-constant-time tag compare

**Class:** constant-time (timing side channel).
**Where:** `verify_tag`, the `if ... { return false }` early exit.
**Why it's exploitable:** the number of loop iterations equals the index of the
first differing byte, so timing the call leaks that index. Byte-at-a-time tag
recovery → MAC/tag forgery.
**Fix:** accumulate differences and compare once, branchlessly —
`subtle::ConstantTimeEq::ct_eq` (what `secure/` uses for every secret compare).
