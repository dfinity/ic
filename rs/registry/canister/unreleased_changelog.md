# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* `do_split_subnet` now writes the destination subnet's `CatchUpPackageContents` record with CUP type
  `CupType::SubnetSplitting` (with the same `destination_subnet_id` as the source's record) instead of
  `CupType::Genesis`, such that replicas don't build a registry CUP out of it.

## Deprecated

## Removed

## Fixed

## Security
