# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added `maximum_query_instructions` and `maximum_composite_query_instructions` fields
  to the subnet record's `ResourceLimits`, allowing the query instruction limits to
  be configured per subnet via `create_subnet` and `update_subnet`. A value of `0`
  (or unset) means the replica's default is used.

## Changed

## Deprecated

## Removed

## Fixed

## Security
