# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

## Deprecated

## Removed

* The deprecated `height`, `time` and `state_hash` fields of `CatchUpPackageContents`. Where
  applicable, their equivalents are now found in `cup_type`: a `CupType::Recovery` record carries
  them in its `RecoveryArgs`, and the height of a `CupType::Genesis` CUP is always 0.

## Fixed

## Security
