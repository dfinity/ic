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

## Deprecated

## Removed

## Fixed

## Security
