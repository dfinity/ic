# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

NNS Root now returns the field `memory_metrics` from the `canister_status` API.

## Changed

## Unreleased

## Deprecated

## Removed

## Fixed

- A lock was added to `change_canister` to prevent two simultaneous upgrade operations from being executed  
  at the same time. The second upgrade will now fail immediately instead of attempting to run, which prevents
  dangerous edge cases where the canister is restarted by one operation while being upgraded by another.

## Security
