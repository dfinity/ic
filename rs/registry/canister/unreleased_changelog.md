# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Rate limit the number of subnet admin updates that can happen for a subnet.
* Subnet deletion endpoint. Limited to CloudEngine subnets. 

## Changed

* During node registration, IDKG keys now must be generated and provided by the replica. Previously these keys were optional.

## Deprecated

## Removed

## Fixed

## Security
