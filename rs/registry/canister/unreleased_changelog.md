# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* `UpdateSubnet` can now enable SEV on an existing subnet, not only at subnet creation. Disabling SEV
  is still rejected, and enabling it only succeeds if the subnet's nodes all have a chip ID and its
  GuestOS version has launch measurements, as the SEV invariants demand.

## Deprecated

## Removed

## Fixed

## Security
