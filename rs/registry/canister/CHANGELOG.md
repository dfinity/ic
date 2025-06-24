# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-06-20: Proposal 137081

https://dashboard.internetcomputer.org/proposal/137081

### Changed

* The `check_routing_table_invariants` method now checks the new canister_ranges_
  and ensures they match the `routing_table` record. The old invariant check will be
  removed once `routing_table` is removed.


# 2025-06-13: Proposal 136988

http://dashboard.internetcomputer.org/proposal/136988

## Added

- The RoutingTable is now also broken up into `canister_ranges_*` records, instead of only in a single
  `routing_table` record. This will allow clients to migrate to the new format incrementally, as both will continue
  to be available until all known clients have migrated to the new format, at which point `routing_table` will be
  removed.

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


# 2025-06-06: Proposal 136894

http://dashboard.internetcomputer.org/proposal/136894

## Added

- `add_node_operator` and `update_node_operator_config` methods both support a new field `max_rewardable_nodes`,
  with the same structure as `rewardable_nodes`, but with a different purpose. This field will set the upper limit
  on the number of nodes that can be rewarded for a given node operator for the next version of Node Provider Rewards.


# 2025-05-16: Proposal 136695

http://dashboard.internetcomputer.org/proposal/136695

## Changed

* The field `node_reward_type` in AddNodePayload is now required to be populated with a valid node_reward_type when
  adding a node (in `do_add_node`) if a node_rewards table record is present in the registry.


# 2025-05-10: Proposal 136581

http://dashboard.internetcomputer.org/proposal/136581

## Added

* Added new endpoint for `migrate_canisters` which is only callable by governance, and updates the routing table for
  the provided canisters when called so that requests will be routed to a different subnet. This will be used to support
  the broader canister migrations feature.

* Started populating `timestamp_seconds` fields.

## Changed

* The `create_subnet` and `recover_subnet` calls are using the `reshare_chain_key` endpoint rather than the old `compute_initial_i_dkg_dealings` endpoint. With this change, recovery of vetkeys is supported.


# 2025-05-02: Proposal 136428

https://dashboard.internetcomputer.org/proposal/136428

No behavior changes. When there are large registry records, then, the new code
here will behave differently (per [this forum post]), but there is currently no
way to generate such records.

[this forum post]: https://forum.dfinity.org/t/breaking-registry-changes-for-large-records/42893

# 2025-04-25: Proposal 136371

http://dashboard.internetcomputer.org/proposal/136371

## Changed

* `get_node_providers_monthly_xdr_rewards` can now take an optional paramter to specify the Registry version to use when
  calculating the rewards.

# 2025-03-28: Proposal 136007

https://dashboard.internetcomputer.org/proposal/136007

This is a maintenance upgrade.

# 2025-03-21: Proposal 135934

https://dashboard.internetcomputer.org/proposal/135934

No "real" behavior changes. This is just a maintenance upgrade.

Technically, there is a new get_chunk method, but it does not actually do anything useful yet. Watch this space.


# 2025-02-13: Proposal 135300

https://dashboard.internetcomputer.org/proposal/135300

## Fixed

### Disable replacement of nodes that are active in subnets

Direct node replacements of nodes that are active in a subnet may result in unexpected behavior and potential problems in the current Consensus code.
So to be on the safe side we need to disable the functionality on the Registry side until the rest of the core protocol can handle it safely.


# 2025-02-07: Proposal 135207

http://dashboard.internetcomputer.org/proposal/135207

## Changed

### Migrate Registry to use ic_stable_structures' MemoryManager

This update migrates registry from using dfn_core to using virtual memory regions provided by ic_stable_structures
MemoryManager.  This allows in the future to migrate the Registry records into stable memory.

### Automatically replace the nodes when an active API boundary node is replaced

`add_node` will now also automatically replace a node if it is being redeployed and has
been active as an API boundary node before. It will fail if the redeployed node does not
meet the requirements for an API boundary node (i.e., is configured with a domain name).

## Deprecated

The legacy ECDSA-specific fields are no longer supported in Registry canister's subnet operations
(creation, updating, recovery). Please use the more expressive chain key configuration keys:

* `ecdsa_config` → `chain_key_config`
* `ecdsa_key_signing_enable` → `chain_key_signing_enable`
* `ecdsa_key_signing_disable` → `chain_key_signing_disable`

## Fixed

### Backfill node_reward_type for existing nodes

A one-time migration to fill in the `node_reward_type` field for existing nodes was added.  Previously, there was no
on-chain connection between the specific nodes and their reward types.  This data came from off-chain sources
at DFINITY.  In the future, the `node_reward_type` will be used to determine the reward type for each node, and
it will be a required field for node registration in the IC.


# 2025-01-20: Proposal 134904

http://dashboard.internetcomputer.org/proposal/134904

## Changed

### Support for node redeployment and replacement even if the node is in a subnet

During node redeployments support for replacing an existing node with the same
IP address even if the existing node is currently in a subnet.
The new node id will be added to the subnet and the old node id will be removed
from the subnet without any intervention being required from the users or the community.

Previously, an additional NNS proposal for removing and replacing the old node in
the subnet was required to enable redeployments for such nodes.
Such behavior is conservative and not strictly necessary since the subnet
decentralization is not affected when the new node has all properties
identical as the old node, which is the case if the IPv6 address is unchanged.


END
