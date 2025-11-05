# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

## Changed

## Deprecated

* Deprecated node_allowance field in favor of max_rewardable_nodes in
  `add_node`. https://github.com/dfinity/ic/pull/7404

## Removed

## Fixed

* Previously, a lock was released only in the happy case (during minting node provider rewards).

## Security
