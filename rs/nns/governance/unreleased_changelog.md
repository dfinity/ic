# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* ManageNetworkEconomics proposals can now modify deep fields one at a time.
  Previously, this was only possible for top level fields.

* Added validation for ManageNetworkEconomics proposals. Previously, there was
  none. The result must have all the following properties:

  * All "optional" fields are actually set.

  * `maximum_icp_xdr_rate >= minimum_icp_xdr_rate`

  * Decimal fields have parsable `human_readable` values.

  * `one_third_participation_milestone_xdr < full_participation_milestone_xdr`

## Deprecated

## Removed

## Fixed

## Security
