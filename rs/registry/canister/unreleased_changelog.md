# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added a new endpoint `set_default_initial_dkg_subnet` to the registry
  canister, which sets (or removes, if `subnet_id` is `null`) the registry key
  `default_initial_dkg_subnet_id`. When set, `SetupInitialDKG` management
  canister calls that do not specify a subnet id explicitly are routed to the
  configured subnet instead of the calling subnet (NNS).
* Added an optional `subnet_admins` field to `UpdateSubnetPayload`, allowing NNS
  proposals to set, replace, or clear the list of admins of a subnet. `None`
  leaves the existing list unchanged; `Some(vec![])` clears it; `Some(vec![..])`
  replaces it.
* Added `vcpu_type` to `GuestLaunchMeasurementMetadata` to record the virtual CPU type used for a guest launch measurement.

## Changed

* The `create_subnet` and `delete_subnet` endpoints can now be called by the
  engine controller canister (`si2b5-pyaaa-aaaaa-aaaja-cai`) in addition to the
  governance canister.
* **SEV on existing subnets:** Reverted — `sev_enabled` can once again only be set at subnet creation;
  any update_subnet proposal that would change the effective `sev_enabled` value (in either direction,
  including via wholesale `features` replacement with `sev_enabled` left unset) is rejected.
* Moved the max-10 cap on `subnet_admins` from a check local to
  `update_subnet_admins` into a registry invariant, so the cap is now enforced
  uniformly on every mutation that touches a subnet record.

## Deprecated

## Removed

## Fixed

## Security
