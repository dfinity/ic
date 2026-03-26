# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Subnet deletion endpoint. Limited to CloudEngine subnets. 
* Added an optional field `maximum_state_delta` to `ResourceLimits` in `CreateSubnetPayload` which, when present,
  sets a soft limit on the maximum (replicated) state *delta* (kept in main memory) in bytes.

## Changed

## Deprecated

## Removed

## Fixed

## Security
