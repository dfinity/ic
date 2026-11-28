# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* `recover_subnet` only accepts a `state_hash` that is exactly 32 bytes long, which is the length
  of every state hash a replica computes. A payload whose `state_hash` has any other length fails
  to decode, so the proposal fails instead of writing a recovery CUP whose state hash cannot match
  any replica's state.

## Deprecated

## Removed

* The `update_node_operator_config_directly` method. It let a node provider reassign one of its
  node operators to another node provider without an NNS proposal. It has never been used on
  mainnet. Changing a node operator's node
  provider now always requires an `UpdateNodeOperatorConfig` proposal.

## Fixed

## Security
