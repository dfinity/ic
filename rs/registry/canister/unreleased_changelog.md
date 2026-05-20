# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added
* Added an optional field `initial_dkg_subnet_id` to `SplitSubnetPayload` and `FulfillSubnetRentalRequest`,
  which allows the proposer to choose which subnet should be responsible for generating the initial key
  material of the split or rented subnet.
* Added `vcpu_type` to `GuestLaunchMeasurementMetadata` to record the virtual CPU type used for a guest launch measurement.

## Changed
* Updated the response text of some failed registry mutations. "Blessed" -> "Elected".

## Deprecated

## Removed

## Fixed

## Security
