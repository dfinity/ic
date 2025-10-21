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

## Deprecated

## Removed

## Fixed

## Security
