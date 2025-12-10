# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-12-05: Proposal 139679

http://dashboard.internetcomputer.org/proposal/139679

## Changed

* When performing subnet creation, subnet update, or subnet recovery, it is now allowed to omit the `KeyConfig`'s `pre_signatures_to_create_in_advance` field for keys that do not have pre-signatures. Currently only vetKD keys do not have pre-signatures (unlike Ecdsa/Schnorr keys). When the field is omitted, it is automatically set to zero.

### Fixed

* Repair a handful or so of broken node operator records.


# 2025-11-28: Proposal 139576

http://dashboard.internetcomputer.org/proposal/139576

## Added

### Node Swaps

All node operators can now swap nodes on non-system subnets; later, swapping will be enabled on all subnets.

### Other

* Temporary logging for when add_node traps.

* Migration Swiss subnet Node Operators max_rewardable_nodes to btreemap! {"type3.1" => 1} as requested by
  Alexander Ufimtsev.


# 2025-11-14: Proposal 139405

http://dashboard.internetcomputer.org/proposal/139405

## Added

### Node Swaps

DFINITY's node operators can now swap nodes on non-system subnets; later, swapping nodes will gradually become available to all node operators.


# 2025-11-07: Proposal 139312

http://dashboard.internetcomputer.org/proposal/139312

## Changed

* `max_rewardable_nodes` is used to limit the number of nodes that
   a node provider can have in the system instead of `node_allowance`.
   The main differences between these are

    1. In the new way, each type of node has a separate limit.

    2. The old way kept track of how many AVAILABLE slots there are.
       The new way specifies how many slots there are IN TOTAL,
       regardless of whether those slots are currently used.

##  Added

* Added rate limiting for add_node based on IP address.


# 2025-10-31: Proposal 139210

http://dashboard.internetcomputer.org/proposal/139210

## Changed

* Allow unassigned nodes to have nonempty ssh_node_state_write_access.

  * Why: Previously, it was believed that there is no way that a nonempty
    ssh_node_state_write_access could be used constructively, but after
    consulting the Consensus team, we (the Governance team) learned that this is
    not true. In particular, it could be useful during a subnet recovery, even
    though this capability generally wouldn't be used during a "typical" subnet
    recovery.


# 2025-10-24: Proposal 139085

http://dashboard.internetcomputer.org/proposal/139085

## Added

* New set_subnet_operational_level method. This is only callable by
  Governance. Currently, Governance has no active code path (in release builds)
  that calls this method. However, once the SetSubnetOperationalLevel proposal
  type is enabled, this will effectively become an active feature. This will be
  used in a slightly improved subnet recovery procedure. Thus, this would only
  be used in rare extraordinary situations.

## Changed

* `ssh_node_state_write_access` can have at most 50 elements. Previously, there
  was no limit. (This brings this field in line with other ssh_*_access fields.)

# 2025-10-17: Proposal 138992

https://dashboard.internetcomputer.org/proposal/138992

## Changed

Swapping out a node, if the subnet is halted in the registry, is disabled.

# 2025-10-10: Proposal 138914

http://dashboard.internetcomputer.org/proposal/138914

## Added

- Added `registry_latest_version` as an exposed metric at http endpoint `/metrics`.

## Changed

- Added rate limiting to certain registry operations.

# 2025-10-03: Proposal 138825

http://dashboard.internetcomputer.org/proposal/138825

## Fixed

- The `migrate_canisters` endpoint recertifies registry.

# 2025-09-26: Proposal 138718

http://dashboard.internetcomputer.org/proposal/138718

## Added

- Whitelisted the migration canister to call `migrate_canisters`

# 2025-09-05: Proposal 138371

http://dashboard.internetcomputer.org/proposal/138371

## Added

* New update method that will be used for node swapping feature.
* `migrate_canisters` returns the new registry version.

# 2025-08-22: Proposal 138164

http://dashboard.internetcomputer.org/proposal/138164

## Removed

* The single entry routing table is no longer updated when there are changes to the routing table.

# 2025-08-15: Proposal 137917

http://dashboard.internetcomputer.org/proposal/137917

## Added

- Added AMD SEV launch measurements to ReplicaVersionRecord, replacing the previous
  `guest_launch_measurement_sha256_hex` field with a new `guest_launch_measurements` field that can contain multiple
  measurements with metadata.

## Removed

- Removed the `guest_launch_measurement_sha256_hex` field from ReplicaVersionRecord in favor of the
  `guest_launch_measurements` field.

# 2025-07-18: Proposal 137500

https://dashboard.internetcomputer.org/proposal/137500

Back fill some node records with reward type.

# 2025-07-11: Proposal 137347

http://dashboard.internetcomputer.org/proposal/137347

## Changed

* `create_subnet` now returns the new subnet's ID.

# 2025-07-06: Proposal 137254

http://dashboard.internetcomputer.org/proposal/137254

## Added

* There is now a `canister_cycles_cost_schedule` field in `CreateSubnetPayload`
  and `SubnetRecord`. This isn't used yet, but it will be in the not too distant
  future, for [subnet rental].

[subnet rental]: https://dashboard.internetcomputer.org/proposal/128820

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

* The `create_subnet` and `recover_subnet` calls are using the `reshare_chain_key` endpoint rather than the old
  `compute_initial_i_dkg_dealings` endpoint. With this change, recovery of vetkeys is supported.

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

Direct node replacements of nodes that are active in a subnet may result in unexpected behavior and potential problems
in the current Consensus code.
So to be on the safe side we need to disable the functionality on the Registry side until the rest of the core protocol
can handle it safely.

# 2025-02-07: Proposal 135207

http://dashboard.internetcomputer.org/proposal/135207

## Changed

### Migrate Registry to use ic_stable_structures' MemoryManager

This update migrates registry from using dfn_core to using virtual memory regions provided by ic_stable_structures
MemoryManager. This allows in the future to migrate the Registry records into stable memory.

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

A one-time migration to fill in the `node_reward_type` field for existing nodes was added. Previously, there was no
on-chain connection between the specific nodes and their reward types. This data came from off-chain sources
at DFINITY. In the future, the `node_reward_type` will be used to determine the reward type for each node, and
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
