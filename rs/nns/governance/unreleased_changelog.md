# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

- Proposal type `DeleteSubnet`, currently limited to CloudEngine subnets.
- Tag neurons that have the maximum dissolve delay of 8 years with their bonus base
  (`eight_year_gang_bonus_base_e8s`), in preparation for the dissolve delay bonus
  grandfathering when the maximum dissolve delay is reduced to 2 years.
- Expose data that will be used to determine the bonus that "8 year gang" neurons
  will receive, starting in the near future. This data consists of the staked amount
  in neurons with 8 year dissolve delay at the beginning of Mission 70. This will be
  used in the near future to determine voting power (and consequently, voting rewards),
  once other aspects of voting power/rewards are in production.

## Changed

## Deprecated

## Removed

## Fixed

## Security
