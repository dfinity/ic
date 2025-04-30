# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

## Changed

## Deprecated

## Removed

## Fixed

* Fixed a bug with the registry client that prevented the canister from reading registry data when there were deletions.
* Limit 'get_node_providers_monthly_xdr_rewards' to only be callable from NNS Governance.
* Use `StableBTreeMap::init` instead of `::new` for registry state.

## Security
