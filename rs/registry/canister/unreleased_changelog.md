# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

## Deprecated

## Removed

* The deprecated `height`, `time` and `state_hash` fields of `CatchUpPackageContents`. Where
  applicable, their equivalents are now found in `cup_type`: a `CupType::Recovery` record carries
  them in its `RecoveryArgs`, and the height of a `CupType::Genesis` CUP is always 0.

## Fixed

* Routing table shards (the `canister_ranges_*` keys) now stay consistent when a routing table
  update produces a canister ID range that spans an existing shard key, e.g. when a canister is
  migrated back to its original subnet and its range is merged with the neighbouring ranges, or
  when canister ID ranges are rerouted. Previously, such a range was stored in one shard while the
  spanned shard key was kept, so `get_subnet_for_canister` could report that no subnet is assigned
  for canister IDs in that range. The spanned shard key is now dropped, and the registry invariants
  check that the entries of every shard lie between its own shard key and the next one.

## Security

* `update_node_operator_config_directly` no longer lets a node provider hand one of its node
  operators to an arbitrary principal. The new node provider must already be the node provider of
  some node operator record, i.e. a principal the NNS introduced through an `AddNodeOperator` or
  `UpdateNodeOperatorConfig` proposal. Assigning a node operator to a brand-new node provider now
  requires an `UpdateNodeOperatorConfig` proposal. Previously, a node provider could move a node
  operator to any principal it chose, and back again, without any NNS involvement, which affects
  which node provider a day's node performance is attributed to for node rewards.
