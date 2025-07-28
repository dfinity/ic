# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

* Minor improvement on voting power spike detection mechanism - the mechanism is kept in place even
  when the voting power snapshot is not full.

## Changed

* `AddOrRemoveNodeProvider` and `update_node_provider` now require 32-byte account-identifiers, which are equivalent
  to the 28-byte identifiers except with the checksum. This is a breaking change for the API.
* `NodeProvider.reward_account` always returns the 32-byte account identifier, even if the
  node provider was created with a 28-byte identifier. This is to ensure consistency in the API and to make it easier
  to use the reward account in other contexts, such as looking up the account in the ledger. All clients needed to
  support the 32-byte address already, so this is not a breaking change for the API.

## Deprecated

## Removed

## Fixed

## Security
