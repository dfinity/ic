# Proposal to change the memory allocation of the ckUSDC archive canister

Target canister: `t4dy3-uiaaa-aaaar-qafua-cai`

New memory allocation: `2_147_483_648`

Previous ckUSDC archive proposal: https://dashboard.internetcomputer.org/proposal/143939

---

## Motivation
Set the `memory_allocation` of the ckUSDC archive canister from its current value of `0` (best-effort) to `2_147_483_648` (2 GiB). The current value can be obtained by calling the [`canister_status`](https://dashboard.internetcomputer.org/canister/r7inp-6aaaa-aaaaa-aaabq-cai#canister_status) endpoint of the NNS root canister.

With a best-effort allocation, every memory growth on a subnet above its storage reservation threshold has to reserve cycles up front, and is rejected once the canister's `reserved_cycles_limit` is exhausted. With a reserved allocation the amount charged is the change in `max(allocation, usage)`, which stays constant while usage is below the allocation, so growth within the allocation reserves nothing and cannot be rejected on those grounds.

Block archiving is currently disabled on this ledger, so the archive is not growing and this allocation is precautionary: it is in place for when archiving is switched back on. 2 GiB matches the allocation the ckBTC archive already has. Note that a full archive node holds more than this — `node_max_memory_size_bytes` is 3 GiB of block data alone — so archive allocations will need revisiting as part of re-enabling archiving.

The canister currently uses 140 MiB, so this leaves 1.86 GiB of headroom. Setting an allocation is itself charged a reservation proportional to the subnet's storage saturation at the time; the fiduciary subnet is currently far below its 750 GiB reservation threshold, so this proposal reserves no cycles. A reserved allocation is charged whether or not it is used, at roughly 26.2T cycles per GiB per year on this 34-node subnet — about 52.4T cycles per year for the full 2 GiB. The canister is already billed for the memory it uses, since storage is charged on `max(allocation, usage)`, so the incremental cost is that of the currently-unused headroom.
