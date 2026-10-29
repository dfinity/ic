# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

- Added the optional `minimum_incoming_canister_call_cycles` and
  `status_visibility` fields to `CanisterSettings` in the Candid API. The first
  sets the minimum number of cycles that calls from other canisters must attach,
  and the second sets who may read the canister's status. Until now, the cycles
  minting canister ignored these two settings, so a new canister always got
  their default values. This is a non-breaking change impacting the types
  `CreateCanisterArg` and `NotifyCreateCanisterArg` and the endpoints
  `create_canister` and `notify_create_canister`.

## Changed

## Deprecated

## Removed

## Fixed

- Failed ICP burns are now retried after successful CMC notification processing instead of only being logged.

## Security
