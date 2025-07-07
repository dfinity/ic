# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

## Changed

* Root now gets the NNS subnet via `get_subnet_for_canister` instead of getting the routing table bytes from the
  registry. This change is needed, as the routing table records will be sharded into multiple records moving forward.

## Deprecated

## Removed

## Fixed

## Security
