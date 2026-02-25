# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* **SEV invariant:** Enforced that SEV-enabled subnets contain only SEV-enabled nodes (i.e., nodes with a chip ID in their node record).
* New invariant to check that subnet admins can be non-empty only for rented subnets.
* New endpoint to update the subnet admins field in the SubnetRecord.
* Rate limit the number of subnet admin updates that can happen for a subnet.

## Changed

* **SEV on existing subnets:** Enabled SEV activation for existing subnets. Once enabled, SEV cannot be disabled.

## Deprecated

## Removed

## Fixed

## Security
