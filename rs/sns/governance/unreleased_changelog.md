# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* New proposal types `TakeCanisterSnapshot` and `LoadCanisterSnapshot` (topic: Dapp canister
  management), the SNS counterparts of the NNS proposals with the same names. They can only
  target registered dapp canisters, and a snapshot ID must belong to the target canister. A
  successful `TakeCanisterSnapshot` records the new snapshot in the new `ProposalData` field
  `success_value`. For now, these proposals are only available as a preview (in builds with
  `feature = "test"`).
* New optional field `take_canister_snapshot` in `UpgradeSnsControlledCanister`. When set,
  Governance first has Root take a snapshot of the target canister, records it in
  `success_value`, and only then upgrades the canister. If the snapshot cannot be taken (e.g. the
  canister already has the maximum number of snapshots, and no `replace_snapshot` was given, or
  Root does not support snapshots yet), the proposal fails and the canister is not upgraded. The
  canister can later be restored to its pre-upgrade state with `LoadCanisterSnapshot`. Also only
  available as a preview for now.
* A `TakeCanisterSnapshot` or `UpgradeSnsControlledCanister` proposal whose `replace_snapshot` is a
  snapshot that a pending (open, or adopted but not yet executed) `LoadCanisterSnapshot` proposal
  would load is refused, both when it is submitted and when it is executed. That way, a rollback
  cannot lose its snapshot to a concurrent replacement.

## Changed

## Deprecated

## Removed

## Fixed

## Security
