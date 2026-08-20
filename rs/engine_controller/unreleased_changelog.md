# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* New `change_subnet_membership` update method that proxies to the registry's
  `change_subnet_membership` endpoint. The registry restricts this to
  `CloudEngine` subnets when the caller is the engine controller canister.

## Changed

* `update_subnet` no longer forces the engine controller's authorized caller
  (super admin) into the `subnet_admins` list. The supplied list is now
  forwarded to the registry as-is.

## Deprecated

## Removed

## Fixed

* `create_engine` no longer forces the engine controller's authorized caller
  (super admin) into the `subnet_admins` list. The supplied list is now
  forwarded to the registry as-is.

## Security
