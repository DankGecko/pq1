# c02 — faultable single-check key gate

**Class:** fault-injection.
**Where:** `gated_release`, the lone `if ok` guard.
**Why:** one skipped/glitched instruction (the branch, or the boolean) releases
the key. A random fault is *more* likely to bypass a single check than to be
caught by it.
**Fix:** redundant recomputation + Hamming-distant sentinels gated through a
step counter (`secure/src/fi.rs` `CfiCounter`, `check_true_into_sentinel`),
i.e. verify twice and release only on the exact OK sentinel — the
double-compute -> byte-compare -> verify-before-release chain used on every
Type-1/Type-2 signature.
