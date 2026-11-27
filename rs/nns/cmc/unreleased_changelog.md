# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* When several subnets are eligible for a new canister, `create_canister` and
  `notify_create_canister` still pick one uniformly at random, but the same
  `raw_rand` randomness can now pick a different subnet than before.

## Deprecated

## Removed

## Fixed

## Security
