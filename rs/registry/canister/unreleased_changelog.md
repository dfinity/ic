# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added a `maximum_query_instructions` field to the subnet record's `ResourceLimits`,
  allowing the query instruction limit to be configured per subnet via `create_subnet`
  and `update_subnet`. It applies both to a single (non-composite) query method execution
  and to the total across a composite query call graph. A value of `0` (or unset) means
  the replica's default is used.

## Changed

## Deprecated

## Removed

## Fixed

## Security
