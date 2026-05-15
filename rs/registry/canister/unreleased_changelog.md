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
  configured subnet instead of the calling subnet (which historically has been
  the NNS subnet).
* Extended the subnet invariants so that whenever the registry key
  `default_initial_dkg_subnet_id` is set, the configured subnet must exist in
  the subnet list. As a side effect, the subnet currently configured as the
  default initial DKG subnet cannot be deleted without first unsetting (or
  changing) the registry key.
* `recover_subnet` now rejects proposals that target the currently-configured
  default initial DKG subnet without specifying `initial_dkg_subnet_id`
  explicitly. A subnet cannot be relied upon to produce its own initial DKG
  transcript, so the recovered subnet must not also be the implicit
  destination of the resulting `SetupInitialDKG` call.

## Changed

## Deprecated

## Removed

## Fixed

## Security
