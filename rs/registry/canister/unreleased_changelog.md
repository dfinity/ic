# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added
* Added an optional field `resource_limits` to `CreateSubnetPayload` which, when present,
  sets limits on resource usage (e.g., memory usage) of the created subnet.

* Rate limit the number of subnet admin updates that can happen for a subnet.

### Node operator migration

Node providers can now migrate nodes from one node operator to another within the same data center without reinstalling nodes or disrupting subnet membership. The source and destination node operators must belong to the same node provider.

If the destination node operator does not yet exist, it is created automatically, effectively allowing a node provider to rotate to a fresh node operator identity.

## Changed

## Deprecated

## Removed

## Fixed

## Security
