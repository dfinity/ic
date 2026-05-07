# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added
* Added an optional field `initial_dkg_subnet_id` to `SplitSubnetPayload` and `FulfillSubnetRentalRequest`,
  which allows the proposer to choose which subnet should be responsible for generating the initial key
  material of the split or rented subnet.

## Changed

* **SEV on existing subnets:** Reverted — `sev_enabled` can once again only be set at subnet creation;
  any update_subnet proposal that would change the effective `sev_enabled` value (in either direction,
  including via wholesale `features` replacement with `sev_enabled` left unset) is rejected.

## Deprecated

## Removed

## Fixed

## Security
