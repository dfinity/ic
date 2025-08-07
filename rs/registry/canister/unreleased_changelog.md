# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

- Added AMD SEV launch measurements to ReplicaVersionRecord, replacing the previous
  `guest_launch_measurement_sha256_hex` field with a new `guest_launch_measurements` field that can contain multiple
  measurements with metadata.

## Changed

## Deprecated

## Removed

- Removed the `guest_launch_measurement_sha256_hex` field from ReplicaVersionRecord in favor of the
  `guest_launch_measurements` field.

## Fixed

## Security
