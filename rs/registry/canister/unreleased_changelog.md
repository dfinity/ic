# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* The firewall rule endpoints (`add_firewall_rules`, `remove_firewall_rules`, and
  `update_firewall_rules`) now accept a new `cloud_engines` scope
  (`FirewallRulesScope::CloudEngines`). Firewall rules registered under this scope are
  applied by assigned cloud engine nodes.

## Changed
* Tightened chain-key config validation and invariants:
  `pre_signatures_to_create_in_advance` must be non-zero for keys that require pre-signatures,
  and must be `None` for keys that do not.

## Deprecated

## Removed
* Removed the completed `fix_vetkd_pre_signatures_field` post-upgrade data migration and its
  migration-specific unit test.
* The `BlessedReplicaVersions` list is no longer updated with changes to elected versions.

## Fixed

## Security
