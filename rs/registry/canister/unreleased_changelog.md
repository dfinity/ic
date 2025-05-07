# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

* Added new endpoint for `migrate_canisters` which is only callable by governance, and updates the routing table for
  the provided canisters when called so that requests will be routed to a different subnet. This will be used to support
  the broader canister migrations feature.

## Changed

## Deprecated

## Removed

## Fixed

## Security
