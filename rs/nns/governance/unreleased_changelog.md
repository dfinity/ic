# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added a new `NnsFunction` variant `MergeSubnets`, which proposes to merge a
  subnet into another subnet: the canister ID ranges of the source subnet are
  merged into the canister ID range set of the destination subnet, a recovery
  catch-up package is created for the destination subnet (whose state is
  expected to have been extended with the state of the canisters of the source
  subnet) and the destination subnet is brought back online.

## Changed

## Deprecated

## Removed

## Fixed

## Security
