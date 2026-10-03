# Proposal to change the memory allocation of the ckETH index canister

Target canister: `s3zol-vqaaa-aaaar-qacpa-cai`

New memory allocation: `4_294_967_296`

Previous ckETH index proposal: https://dashboard.internetcomputer.org/proposal/143930

---

## Motivation
Set the `memory_allocation` of the ckETH index canister from its current value of `0` (best-effort) to `4_294_967_296` (4 GiB). The current value can be obtained by calling the [`canister_status`](https://dashboard.internetcomputer.org/canister/r7inp-6aaaa-aaaaa-aaabq-cai#canister_status) endpoint of the NNS root canister.

With a best-effort allocation, every memory growth on a subnet above its storage reservation threshold has to reserve cycles up front, and is rejected once the canister's `reserved_cycles_limit` is exhausted. With a reserved allocation the amount charged is the change in `max(allocation, usage)`, which stays constant while usage is below the allocation, so growth within the allocation reserves nothing and cannot be rejected on those grounds.

The index mirrors every block the ledger produces and never archives any of them, so it grows for as long as the ledger does. 4 GiB matches the allocation the ckBTC index already has.

The canister currently uses 508 MiB, so this leaves 3.50 GiB of headroom. Setting an allocation is itself charged a reservation proportional to the subnet's storage saturation at the time; the fiduciary subnet is currently far below its 750 GiB reservation threshold, so this proposal reserves no cycles. A reserved allocation is charged whether or not it is used, at roughly 26.2T cycles per GiB per year on this 34-node subnet — about 104.8T cycles per year for the full 4 GiB. The canister is already billed for the memory it uses, since storage is charged on `max(allocation, usage)`, so the incremental cost is that of the currently-unused headroom.
