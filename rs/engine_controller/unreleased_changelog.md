# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* New `create_canister` update method that creates an empty canister on a
  cloud engine subnet, controlled by the given `controllers` only. Only a
  canister on the NNS subnet may create canisters on another subnet, so this
  lets the authorized caller put canisters on the engines it creates. The
  target must be a `CloudEngine` subnet in the registry.

* `create_engine` takes an optional `resource_limits` (`maximum_state_size`,
  `maximum_state_delta`), forwarded to the new subnet's `CreateSubnetPayload`.
  Omitted, the subnet keeps the protocol defaults as before.

* New `change_subnet_membership` update method that proxies to the registry's
  `change_subnet_membership` endpoint. The registry restricts this to
  `CloudEngine` subnets when the caller is the engine controller canister.

## Changed

* `update_subnet` no longer forces the engine controller's authorized caller
  (super admin) into the `subnet_admins` list. The supplied list is now
  forwarded to the registry as-is.

* `update_subnet` accepts the new `UpdateSubnetPayload.cooling_down` field, so
  the engine controller can make a cloud engine subnet cool down (and stop
  cooling down again). Its scope is now `subnet_admins`, `is_halted` and
  `cooling_down`; every other field is still rejected.

* `update_subnet` accepts the state limits in `resource_limits`
  (`maximum_state_size`, `maximum_state_delta`), so the engine controller can
  resize a cloud engine subnet's state limits after its nodes change. The query
  limits are still rejected.

## Deprecated

## Removed

## Fixed

* `create_engine` no longer forces the engine controller's authorized caller
  (super admin) into the `subnet_admins` list. The supplied list is now
  forwarded to the registry as-is.

## Security
