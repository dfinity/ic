# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* Task execution metrics are added for `neuron_data_validation` and
  `unstake_maturity_of_dissolved_neurons` timer tasks.

## Deprecated

## Removed

## Fixed

* The `account_identifier_to_disburse_to` in the maturity disbursement now contains a 32-byte
  address rather than the 28-byte one without checksum.

## Security
