# Proposal to change the memory allocation of the ckETH minter canister

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

New memory allocation: `1_073_741_824`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/143932

---

## Motivation
Set the `memory_allocation` of the ckETH minter canister from its current value of `0` (best-effort) to `1_073_741_824` (1 GiB). The current value can be obtained by calling the [`canister_status`](https://dashboard.internetcomputer.org/canister/r7inp-6aaaa-aaaaa-aaabq-cai#canister_status) endpoint of the NNS root canister.

With a best-effort allocation, every memory growth on a subnet above its storage reservation threshold has to reserve cycles up front, and is rejected once the canister's `reserved_cycles_limit` is exhausted. With a reserved allocation the amount charged is the change in `max(allocation, usage)`, which stays constant while usage is below the allocation, so growth within the allocation reserves nothing and cannot be rejected on those grounds.

The minter is not on the path this is aimed at: spam against a ledger does not grow minter state. 1 GiB matches the allocation the ckBTC minter already has, and is ample against present usage. This single minter serves ckETH and every ckERC20 token.

The canister currently uses 45 MiB, so this leaves 979 MiB of headroom. Setting an allocation is itself charged a reservation proportional to the subnet's storage saturation at the time; the fiduciary subnet is currently far below its 750 GiB reservation threshold, so this proposal reserves no cycles. A reserved allocation is charged whether or not it is used, at roughly 26.2T cycles per GiB per year on this 34-node subnet — about 26.2T cycles per year for the full 1 GiB. The canister is already billed for the memory it uses, since storage is charged on `max(allocation, usage)`, so the incremental cost is that of the currently-unused headroom.
