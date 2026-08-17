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

* `get_available_sns_subnet` now rotates through all configured SNS subnets
  (round-robin, based on the number of SNSs already deployed) instead of
  always deploying new SNSes to the first subnet in `sns_subnet_ids`.

## Security
