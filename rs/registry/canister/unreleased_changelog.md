# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* The `cup_type` backfill migration is now applied in several atomic batches of bounded size (invariants are
  still checked once, on the whole migration), instead of as one single mutation, so that a large migration
  cannot exceed the limit on the size of an atomic mutation.

## Deprecated

## Removed

## Fixed

## Security
