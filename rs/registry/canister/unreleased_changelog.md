# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Adding support for recalling replica versions for subnets.
* CloudEngines can have a Free cycles cost schedule. 
* **SEV invariant:** Enforced that SEV-enabled subnets contain only SEV-enabled nodes (i.e., nodes with a chip ID in their node record).
* New invariant to check that subnet admins can be non-empty only for rented subnets.
* New endpoint to update the subnet admins field in the SubnetRecord.

## Changed

* **SEV on existing subnets:** Enabled SEV activation for existing subnets. Once enabled, SEV cannot be disabled.
* During node registration, IDKG keys now must be generated and provided by the replica. Previously these keys were optional.

## Deprecated

## Removed

## Fixed

## Security
