# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

* The RoutingTable is now also broken up into `canister_range_*` records, instead of only in a single
  `routing_table` record. This will allow clients to migrate to the new format incrementally.

## Changed

## Deprecated

## Removed

## Fixed

## Security
