# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

## Changed

* The Governance canister will fetch rewards from the new Node Rewards Canister instead of from Registry.

## Deprecated

## Removed

* All the `_pb` methods are removed as they already always panic, as well as decoding the init arg
  as protobuf.

## Fixed

## Security
