# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added an optional field `initial_dkg_subnet_id` to `CreateSubnetPayload` and `RecoverSubnetPayload`
  which, when present, determines the subnet to which the resulting `SetupInitialDKG` management
  canister call should be routed.
* Added type4.1 through type4.5 node reward types for cloud-engine sub-variants.

## Changed

## Deprecated

## Removed

## Fixed

## Security
