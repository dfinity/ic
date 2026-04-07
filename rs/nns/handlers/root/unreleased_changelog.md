# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* create_canister_and_install_code method. This is only callable by the Governance
  canister though, so this is not really a "new feature" in the sense that others
  can call this directly, but it is a new capability of this canister that will
  nevertheless indirectly be of use to others (outside of NNS). That will happen
  via an upcoming new proposal type (with the same name).

## Changed

## Deprecated

## Removed

## Fixed

## Security
