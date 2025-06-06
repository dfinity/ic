# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

- `add_node_operator` and `update_node_operator_config` methods both support a new field `max_rewardable_nodes`,
  with the same structure as `rewardable_nodes`, but with a different purpose. This field will set the upper limit
  on the number of nodes that can be rewarded for a given node operator for the next version of Node Provider Rewards.

## Changed

* When performing "large" mutations (greater than approximately 1.3 MiB),
  chunking is used. This has no effect on how mutations are written. Rather,
  this affects how large mutations and records are read. For non-large
  mutations, this has no effect. Chunking means that to fetch a large mutation
  or record, clients must make follow up `get_chunk` canister method calls.
  Because of this requirement, this is a breaking change (for clients who read
  large mutations/records). This breaking change and how clients migrate was
  [announced at the end of March in a forum][chunking] (and various other
  channels). This release marks the end of the "migration window" described in
  the aforelinked forum post.

[chunking]: https://forum.dfinity.org/t/breaking-registry-changes-for-large-records/42893?u=daniel-wong

## Deprecated

## Removed

## Fixed

## Security
