# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added
Added an optional field `max_ingress_bytes_per_block` to `CreateSubnetPayload`
and `UpdateSubnetPayload` which, when present, will set a limit on how big the ingress payload can
be in blocks produced by the created/updated subnet.

## Changed

## Deprecated

## Removed

## Fixed

## Security
