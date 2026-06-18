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
* Added a new endpoint `get_subnet` to the registry canister, returning the subnet record
  of a given subnet.

## Changed

* Temporarily bypass the `max_rewardable_nodes` quota check in `add_node` for
  node reward types `type4.1` through `type4.4` (implemented by treating their
  effective quota as unbounded), allowing node providers to register an
  arbitrary number of such nodes. `type4.5` is explicitly excluded and remains
  subject to the standard quota.

  Motivation: node providers are starting to deploy gen4 hardware now, but the
  reward canister currently still treats `type4.5` rewards as `type1.1`, which
  means we cannot yet meaningfully size `max_rewardable_nodes` quotas for the
  `type4.x` family. Enforcing the quota in the meantime would block legitimate
  gen4 onboarding. The quota check will be restored once the reward-side
  handling of `type4.5` is fixed (see CLO-15).
* One-time post-upgrade migration converting the reward type of 100 currently
  unassigned nodes from `type1.1` to `type4.5`. The migration only mutates nodes
  whose reward type is still `type1.1`, so it is idempotent across upgrades.
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
