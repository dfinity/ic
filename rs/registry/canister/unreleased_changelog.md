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

* The `features` field in `create_subnet` and `update_subnet` now has each
  sub-field (`canister_sandboxing`, `http_requests`, `sev_enabled`) typed as
  `opt bool` instead of `bool`. Omitting a sub-field (i.e., passing `null`)
  leaves the corresponding feature at its default value. This is a
  backward-compatible Candid interface change.

## Deprecated

## Removed

## Fixed

## Security
