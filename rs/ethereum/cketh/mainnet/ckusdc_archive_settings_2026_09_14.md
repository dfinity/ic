# Proposal to change the reserved cycles limit of the ckUSDC archive canister

Target canister: `t4dy3-uiaaa-aaaar-qafua-cai`

New reserved cycles limit: `1_000_000_000_000_000_000`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/143807

---

## Motivation
Raise the `reserved_cycles_limit` of the ckUSDC archive canister from its current value of `5_000_000_000_000` (5T cycles, the default) to `1_000_000_000_000_000_000`. The current value can be obtained by calling the [`canister_status`](https://dashboard.internetcomputer.org/canister/r7inp-6aaaa-aaaaa-aaabq-cai#canister_status) endpoint of the NNS root canister.

Under subnet storage pressure, any memory growth is charged against this limit, and once the limit is reached the canister can no longer grow. The 5T default is small relative to what the protocol can demand: at the worst-case reservation rate on the 34-node fiduciary subnet, roughly 249T cycles per GiB, it covers only about 20 MiB of growth, so a canister can be blocked from growing long before its cycles balance is at issue. The new limit is above the largest reservation the protocol could ever demand on this subnet, so it should not need revisiting.

Raising the limit neither reserves nor spends any cycles, and reservations remain bounded by the canister's actual cycles balance.

The ckUSDC archive is managed by the ledger suite orchestrator (`vxkom-oyaaa-aaaar-qafda-cai`), but NNS root (`r7inp-6aaaa-aaaaa-aaabq-cai`) is a co-controller, so this proposal changes the setting directly rather than through the orchestrator.
