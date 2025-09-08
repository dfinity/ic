# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* The neuron `Split` command accepts an optional `memo` field that can be used to derive the neuron
  subaccount, rather than generating a random one.

## Changed

* The protobuf-encoded `Storable` implementations are changed to `Unbounded`.

## Deprecated

## Removed

* The `IcpXdrConversionRate` proposal is now obsolete and cannot be submitted.

## Fixed

## Security
