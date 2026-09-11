# Proposal to change the memory allocation of the ckBTC archive canister

Target canister: `nbsys-saaaa-aaaar-qaaga-cai`

New memory allocation: `2_147_483_648`

Previous ckBTC archive proposal: https://dashboard.internetcomputer.org/proposal/143835

---

## Motivation
Set the `memory_allocation` of the ckBTC archive canister from its current value of `0` (best-effort) to `2_147_483_648` (2 GiB). The current value can be obtained by calling the [`canister_status`](https://dashboard.internetcomputer.org/canister/r7inp-6aaaa-aaaaa-aaabq-cai#canister_status) endpoint of the NNS root canister.

With a best-effort allocation, every memory growth on a subnet above its storage reservation threshold has to reserve cycles up front, and is rejected once the canister's `reserved_cycles_limit` is exhausted. With a reserved allocation the amount charged is the change in `max(allocation, usage)`, which stays constant while usage is below the allocation, so growth within the allocation reserves nothing and cannot be rejected on those grounds.

The canister currently uses 924 MiB, so a 2 GiB allocation leaves 1,124 MiB of headroom (2.22x current usage). Block archiving is currently disabled, so the archive receives no new blocks and its usage is presently static; a 1 GiB allocation would already cover it (the archive has no `pre_upgrade` hook, and its `post_upgrade` merely reads the stable-structure headers, so even an upgrade allocates essentially nothing). The larger 2 GiB allocation is chosen so the reservation still holds if block archiving is re-enabled in the future and the archive resumes growing, avoiding a follow-up proposal under possible subnet pressure.

Setting an allocation is itself charged a reservation proportional to the subnet's storage saturation at the time. The fiduciary subnet is currently far below its 750 GiB reservation threshold, so this proposal reserves no cycles; the same change made while the subnet is under storage pressure would demand a large reservation and could be rejected outright. A reserved allocation is charged whether or not it is used, at roughly 26.2T cycles per GiB per year on this 34-node subnet — about 52.4T cycles per year for the full 2 GiB. The canister is already billed for the memory it uses, since storage is charged on `max(allocation, usage)`, so the incremental cost introduced by this proposal is only that of the roughly 1,124 MiB of currently-unused headroom being reserved: about 28.7T cycles per year.
