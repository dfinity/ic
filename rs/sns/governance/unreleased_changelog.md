# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

RegisterExtension proposals can now be used in the test version of SNS Governance; submitting
these proposals on mainnet is still disabled until further notice.

## Changed

## Deprecated

## Removed

## Fixed

Fixed a bug due to which governance cached metrics could be recomputed once every 10 seconds
rather than with the intended rate of once per hour.

Fixed multiple issues in `disburse_neuron` functionality:

- Fixed a bug that could allow an SNS Neuron to burn fees that would have been refunded after proposal acceptance.
- Fees are now only recorded as burned when they exceed the transaction fee threshold and are actually burned.
- Added comprehensive tests to ensure the correct behavior in the future.

## Security
