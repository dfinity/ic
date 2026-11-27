# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Enabled subnet splitting: the `split_subnet` endpoint, called by `SplitSubnet` proposals, now
  splits a subnet instead of rejecting every request.

## Changed

* The invariant requiring that every subnet's `CatchUpPackageContents` record has a `cup_type` set
  now also requires that `cup_type` is decodable.

## Deprecated

## Removed

## Fixed

## Security
