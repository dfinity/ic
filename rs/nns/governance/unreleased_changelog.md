# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

- Support for `snapshot_visibility` in `UpdateCanisterSettings` proposals.
- Proposal type `DeleteSubnet`, currently limited to CloudEngine subnets. 
- Tag neurons that have the maximum dissolve delay of 8 years with their bonus base
  (`eight_year_gang_bonus_base_e8s`), in preparation for the dissolve delay bonus
  grandfathering when the maximum dissolve delay is reduced to 2 years.

## Changed

## Deprecated

## Removed

## Fixed

## Security
