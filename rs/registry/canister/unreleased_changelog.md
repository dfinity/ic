# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Enforce that every `hostos_version_id` matches its `HostosVersionRecord`'s registry key.

## Changed

* The engine controller canister may now set the state limits in `UpdateSubnet`'s `resource_limits`
  (`maximum_state_size`, `maximum_state_delta`) on CloudEngine subnets. A limit it leaves unset keeps
  its current value instead of being reset, and the query limits remain governance-only.

* `UpdateSubnet` can now enable SEV on an existing subnet, not only at subnet creation. Disabling SEV
  is still rejected, and enabling it only succeeds if the subnet's nodes all have a chip ID and its
  GuestOS version has launch measurements, as the SEV invariants demand.
* `replica_version_id` on `ReplicaVersionRecord` is no longer optional in code.
  Setting this field has been mandatory for some time, and any previous records
  with unset values have been backfilled.

## Deprecated

## Removed

## Fixed

## Security
