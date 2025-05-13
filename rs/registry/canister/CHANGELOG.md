# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


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
