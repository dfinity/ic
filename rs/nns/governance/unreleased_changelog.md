# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

- Added Performance Base Rewards integration tests to verify correct reward calculations over multiple reward periods.
  These tests ensure that the performance-based reward system functions as intended under different scenarios.

## Changed

## Deprecated

## Removed

## Fixed

- Add default case for start_date fetching in Performance Based Rewards. This is done to ensure that a valid start date
  is always returned, even when no previous rewards exist.

## Security
