# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* A hardcoded allowlist of trusted node providers is now granted elevated
  (10x) node operator and node provider rate limits. The elevated limits apply
  to all node operator operations (node add/remove and the direct node config
  updates), mirroring the scope of the standard node operator rate limiter.
  This is a temporary measure to allow these providers to onboard nodes in bulk
  (e.g. on-demand cloud provisioning). All other node providers remain subject
  to the standard limits, and the per-IP `add_node` rate limit continues to
  apply to everyone.
* `change_subnet_membership` may now be called by the engine controller canister
  in addition to the governance canister. When invoked by the engine controller,
  the target subnet must be of type `CloudEngine`; governance retains
  unrestricted access to any subnet.

## Deprecated

## Removed

## Fixed

## Security
