# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added a new `NnsFunction` variant `MergeSubnets`, which proposes to merge a
  subnet into another subnet: the canister ID ranges of the source subnet are
  merged into the canister ID range set of the destination subnet, so that all
  canisters that used to be hosted by the source subnet are routed to the
  destination subnet. Only the routing table is updated: neither subnet record
  is modified and the source subnet is not deleted.

## Changed

## Deprecated

## Removed

## Fixed

## Security
