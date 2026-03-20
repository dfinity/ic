# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

- `CreateServiceNervousSystem` proposals no longer reject SNS configurations
  where the sum of developer-allocated tokens exceeds
  `swap_distribution.total_e8s`. With the Neurons' Fund discontinued, this
  validation is no longer needed.

## Deprecated

## Removed

## Fixed

## Security
