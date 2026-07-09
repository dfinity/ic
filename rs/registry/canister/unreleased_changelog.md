# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* `delete_subnet` may now delete any non-System subnet, lifting the previous
  restriction to `CloudEngine` subnets. Authorization by subnet type:
  System subnets (e.g. the NNS) may never be deleted; the engine controller
  canister may only delete `CloudEngine` subnets; governance may delete any
  non-System subnet.

## Deprecated

## Removed

## Fixed

## Security
