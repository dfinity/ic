# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* The field `node_reward_type` in AddNodePayload is now required to be populated with a valid node_reward_type when
  adding a node (in `do_add_node`) if a node_rewards table record is present in the registry.

## Deprecated

## Removed

## Fixed

## Security
