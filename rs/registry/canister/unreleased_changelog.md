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

## Security

* `update_node_operator_config_directly` no longer lets a node provider hand one of its node
  operators to an arbitrary principal. The new node provider must already be the node provider of
  some node operator record, i.e. a principal the NNS introduced through an `AddNodeOperator` or
  `UpdateNodeOperatorConfig` proposal. Assigning a node operator to a brand-new node provider now
  requires an `UpdateNodeOperatorConfig` proposal. Previously, a node provider could move a node
  operator to any principal it chose, and back again, without any NNS involvement, which affects
  which node provider a day's node performance is attributed to for node rewards.
