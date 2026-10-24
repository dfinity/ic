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

## Changed

## Deprecated

## Removed

## Fixed

## Security
