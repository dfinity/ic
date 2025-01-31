# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added the `query_stats` field for the `canister_status` method.

## Changed

* The `LogVisibility` returned from `canister_status` has one more variant `allowed_viewers`,
  consistent with the corresponding management canister API. Calling `canister_status` for a
  canister with such a log visibility setting will no longer panic.

## Deprecated

## Removed

## Fixed

## Security
