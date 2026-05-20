# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added `vcpu_type` to `GuestLaunchMeasurementMetadata` to record the virtual CPU type used for a guest launch measurement.

## Changed

* **SEV on existing subnets:** Reverted — `sev_enabled` can once again only be set at subnet creation;
  any update_subnet proposal that would change the effective `sev_enabled` value (in either direction,
  including via wholesale `features` replacement with `sev_enabled` left unset) is rejected.

## Deprecated

## Removed

## Fixed

## Security
