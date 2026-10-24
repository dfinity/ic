# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* New methods `take_canister_snapshot` and `load_canister_snapshot`. Like
  `change_canister`, they can only be called by SNS Governance, which uses them
  to execute the (new) `TakeCanisterSnapshot` and `LoadCanisterSnapshot`
  proposals, and to take a snapshot of a dapp canister right before upgrading it,
  when an `UpgradeSnsControlledCanister` proposal asks for that.

## Changed

## Deprecated

## Removed

## Fixed

## Security
