# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE

## Changed

## Deprecated

## Fixed

### Update the correct node operator ID in do_remove_node_directly

Fix for the do_remove_node_directly function to update the correct node operator ID record.
In the past the caller_id and the node_operator_id for the node were always the same.
However, since #3285 the caller_id and the node_operator_id for the removed node may differ,
and this introduces a bug in this edge case.

The bug resulted in a node reward discrepancy for a few operator records, identified in the
regular administrative checks before the reward distribution and [described in the forum](https://forum.dfinity.org/t/issue-with-node-provider-rewards/41109/2) and
mitigated with a few NNS proposals referenced in the forum thread.


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
