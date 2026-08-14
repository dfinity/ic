# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

## Deprecated

## Removed

## Fixed

* `validate_assign_noid_payload` no longer panics when a node provider has
  `id = None`. It now skips such providers safely, preventing all
  `AddNodeOperator` proposal submissions from being blocked.

## Security
