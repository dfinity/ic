# Proposal to change the memory allocation of the ckBTC minter canister

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

New memory allocation: `1_073_741_824`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/143837

---

## Motivation
Set the `memory_allocation` of the ckBTC minter canister from its current value of `0` (best-effort) to `1_073_741_824` (1 GiB). The current value can be obtained by calling the [`canister_status`](https://dashboard.internetcomputer.org/canister/r7inp-6aaaa-aaaaa-aaabq-cai#canister_status) endpoint of the NNS root canister.

With a best-effort allocation, every memory growth on a subnet above its storage reservation threshold has to reserve cycles up front, and is rejected once the canister's `reserved_cycles_limit` is exhausted. With a reserved allocation the amount charged is the change in `max(allocation, usage)`, which stays constant while usage is below the allocation, so growth within the allocation reserves nothing and cannot be rejected on those grounds.

The canister currently uses 544 MiB, so a 1 GiB allocation leaves 480 MiB of headroom (1.88x current usage). The minter's memory has been unchanged for over a month, so 1 GiB is ample.

Setting an allocation is itself charged a reservation proportional to the subnet's storage saturation at the time. The fiduciary subnet is currently far below its 750 GiB reservation threshold, so this proposal reserves no cycles; the same change made while the subnet is under storage pressure would demand a large reservation and could be rejected outright. A reserved allocation is charged whether or not it is used, at roughly 26.2T cycles per GiB per year on this 34-node subnet, so about 26.2T cycles per year for this 1 GiB allocation.
