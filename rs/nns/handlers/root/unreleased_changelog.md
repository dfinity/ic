# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added `take_canister_snapshot`, and `load_canister_snapshot` methods. These
  are only callable by the Governance canister though. What these do is
  proxy/immediately forward to methods of the same name in the Management
  (pseudo-)canister.

## Changed

## Deprecated

## Removed

## Fixed

## Security
