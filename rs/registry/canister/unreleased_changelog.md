# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Subnet deletion endpoint. Limited to CloudEngine subnets. 
* Implemented the `do_split_subnet` method
* Added an optional field `maximum_state_delta` to `ResourceLimits` in `CreateSubnetPayload` which, when present,
  sets a soft limit on the maximum (replicated) state *delta* (kept in main memory) in bytes.
* Added an optional field `resource_limits` to `UpdateSubnetPayload` which, when present,
  sets all subnet resource limits to the provided values.
* New invariant ensuring that cloud engines contain only nodes with `type4` reward type and that
  non-cloud engines do not contain any nodes with `type4` reward type.

## Changed

## Deprecated

## Removed

## Fixed

## Security
