# Proposal to change the reserved cycles limit of the ckBTC archive canister

Target canister: `nbsys-saaaa-aaaar-qaaga-cai`

New reserved cycles limit: `1_000_000_000_000_000_000`

Previous ckBTC archive proposal: https://dashboard.internetcomputer.org/proposal/140950

---

## Motivation
Raise the `reserved_cycles_limit` of the ckBTC archive canister from its current value of `5_000_000_000_000` (5T cycles, the default) to `1_000_000_000_000_000_000`.

Under subnet storage pressure any memory growth is charged against this limit, and once the limit is reached the canister can no longer grow. The new limit is above the largest reservation the protocol could ever demand on this subnet, so it should not need revisiting.

Raising the limit neither reserves nor spends any cycles, and reservations remain bounded by the canister's actual cycles balance.
