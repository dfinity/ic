# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

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

## Removed

## Fixed

### Backfill node_reward_type for existing nodes

A one-time migration to fill in the `node_reward_type` field for existing nodes was added.  Previously, there was no
on-chain connection between the specific nodes and their reward types.  This data came from off-chain sources
at DFINITY.  In the future, the `node_reward_type` will be used to determine the reward type for each node, and
it will be a required field for node registration in the IC.

## Security
