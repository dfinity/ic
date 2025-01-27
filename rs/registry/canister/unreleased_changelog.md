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

### Backfill node_reward_type for existing nodes

A one-time migration to fill in the `node_reward_type` field for existing nodes was added.  Previously, there was no
on-chain connection between the specific nodes and their reward types.  This data came from off-chain sources
at DFINITY.  In the future, the `node_reward_type` will be used to determine the reward type for each node, and
it will be a required field for node registration in the IC.

## Security
