# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

## Deprecated

## Removed

* Removed the one-time eight year gang bonus base migrations (both the strict
  and the relaxed second round). The migrations have already run on mainnet,
  so the migration code, feature flags, and supporting tests are no longer
  needed. Proto field numbers `31` (`eight_year_gang_bonus_migration_done`)
  and `33` (`relaxed_eight_year_gang_bonus_migration_done`) are now reserved.

## Fixed

## Security
