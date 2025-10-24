# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

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

## Deprecated

## Removed

## Fixed

## Security
