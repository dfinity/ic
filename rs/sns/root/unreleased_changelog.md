# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* New methods `take_canister_snapshot` and `load_canister_snapshot`. Like
  `change_canister`, they can only be called by SNS Governance. Governance will
  use them for canister snapshot proposals (e.g. to roll a dapp canister back
  to how it was before an upgrade).

## Changed

## Deprecated

## Removed

## Fixed

## Security
