# Proposal to change the memory allocation of the ckBTC ledger canister

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

New memory allocation: `1_073_741_824`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/143757

---

## Motivation
Set the `memory_allocation` of the ckBTC ledger canister from its current value of `0` (best-effort) to `1_073_741_824` (1 GiB). The current value can be obtained by calling the [`canister_status`](https://dashboard.internetcomputer.org/canister/r7inp-6aaaa-aaaaa-aaabq-cai#canister_status) endpoint of the NNS root canister.

With a best-effort allocation, every memory growth on a subnet above its storage reservation threshold has to reserve cycles up front, and is rejected once the canister's `reserved_cycles_limit` is exhausted. With a reserved allocation the amount charged is the change in `max(allocation, usage)`, which stays constant while usage is below the allocation, so growth within the allocation reserves nothing and cannot be rejected on those grounds.

The canister currently uses 241 MiB, so a 1 GiB allocation leaves 783 MiB of headroom (4.26x current usage). The ledger holds unarchived blocks in stable structures and block archiving is currently disabled, so its usage will keep stepping upwards. The allocation takes growth off the reservation path only while usage stays below it: once usage exceeds `1_073_741_824` bytes, further growth is reservation-charged again. The headroom is therefore finite and needs monitoring, since stable memory grows in large steps rather than smoothly — the most recent step added 180 MiB in about five hours, although the ~21,000 unarchived blocks accumulated since then have required no further growth.

Setting an allocation is itself charged a reservation proportional to the subnet's storage saturation at the time. The fiduciary subnet is currently far below its 750 GiB reservation threshold, so this proposal reserves no cycles; the same change made while the subnet is under storage pressure would demand a large reservation and could be rejected outright. A reserved allocation is charged whether or not it is used, at roughly 26.2T cycles per GiB per year on this 34-node subnet.
