# ERC-7730 accepted-family semantic evidence

[`accepted-family-inventory.json`](accepted-family-inventory.json) accounts for
every source descriptor that emits at least one leaf in the production
catalogue. The dbgen test rebuilds that catalogue and rejects missing,
duplicate, stale, or miscounted records.

The unit is a **source descriptor family**, not a deployment leaf. In
particular, `pinned-evidence` means only that the named package covers the
explicit subset stated in its `scope`; it does not promote every leaf emitted
by that source. `shared-standard-implementation` means that all accepted
formats are inherited unchanged from the shared ERC-4626 rendering template;
it is not proof that any deployed contract conforms to ERC-4626. Everything
else remains a `lower-priority-residual` assigned to one of the proposed
successor issues in the inventory.

The inventory is an accounting and review-routing control. It grants no new
descriptor, signing, fallback, blind-signing, production, or shipment
authority.
