# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added a new `NnsFunction` variant `MergeSubnets`, which proposes to merge a
  subnet into another subnet: in the routing table, reassigns all canister
  ranges hosted by the source subnet to the destination subnet. The source
  subnet is not deleted.

## Changed

## Deprecated

## Removed

## Fixed

## Security
