# Proposal to change the memory allocation of the ckBTC ledger canister

Target canister: `mxzaz-hqaaa-aaaar-qaada-cai`

New memory allocation: `10_737_418_240`

Previous ckBTC ledger proposal: https://dashboard.internetcomputer.org/proposal/143900

---

## Motivation
Set the `memory_allocation` of the ckBTC ledger canister from its current value of `1_073_741_824` (1 GiB) to `10_737_418_240` (10 GiB). The current value can be obtained by calling the [`canister_status`](https://dashboard.internetcomputer.org/canister/r7inp-6aaaa-aaaaa-aaabq-cai#canister_status) endpoint of the NNS root canister.

With a best-effort allocation, every memory growth on a subnet above its storage reservation threshold has to reserve cycles up front, and is rejected once the canister's `reserved_cycles_limit` is exhausted. With a reserved allocation the amount charged is the change in `max(allocation, usage)`, which stays constant while usage is below the allocation, so growth within the allocation reserves nothing and cannot be rejected on those grounds.

The ledger is the canister whose growth this is aimed at. A maximum-size `icrc2_approve` occupies about 1 kB of a ledger's stable memory — the block itself plus the allowance and expiration entries it creates — so a sustained stream of them is what consumes the allocation. 10 GiB covers roughly a day of such a stream at 100 transactions per second, which is intended as time to notice and respond rather than as a limit an attacker cannot reach.

The canister currently uses 257 MiB, so this leaves 9.75 GiB of headroom. Setting an allocation is itself charged a reservation proportional to the subnet's storage saturation at the time; the fiduciary subnet is currently far below its 750 GiB reservation threshold, so this proposal reserves no cycles. A reserved allocation is charged whether or not it is used, at roughly 26.2T cycles per GiB per year on this 34-node subnet — about 261.9T cycles per year for the full 10 GiB. The canister is already billed for the memory it uses, since storage is charged on `max(allocation, usage)`, so the incremental cost is that of the currently-unused headroom.
