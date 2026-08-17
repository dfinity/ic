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

* `insert_upgrade_path_entries` now actually replaces an SNS-specific
  emergency upgrade step when called again for the same SNS and starting
  version, instead of silently keeping the old step while reporting
  success.

## Security
