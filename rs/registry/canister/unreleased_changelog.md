# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

- `add_node_operator` and `update_node_operator_config` methods both support a new field `max_rewardable_nodes`,
  with the same structure as `rewardable_nodes`, but with a different purpose. This field will set the upper limit
  on the number of nodes that can be rewarded for a given node operator for the next version of Node Provider Rewards.

* The RoutingTable is now also broken up into `canister_ranges_*` records, instead of only in a single
  `routing_table` record. This will allow clients to migrate to the new format incrementally, as both will continue
  to be available until all known clients have migrated to the new format, at which point `routing_table` will be
  removed.

## Changed

## Deprecated

## Removed

## Fixed

## Security
