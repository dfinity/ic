# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

### New `RegisterExtension` proposal type

A new proposal type, `RegisterExtension`, is added for registering SNS extensions.
Extensions are a new class of SNS canisters that (unlike SNS-controlled dapp canisters)
can operate on behalf of the DAO, e.g., by managing a portion of the treasury funds.

Note that while `RegisterExtension` proposals are already recognized, they are not enabled yet.

### New `RegisterExtension` proposal type

A new proposal type, `RegisterExtension`, is added for registering SNS extensions. 
Extensions are a new class of SNS canisters that (unlike SNS-controlled dapp canisters)
can operate on behalf of the DAO, e.g., by managing a portion of the treasury funds.

## Changed

## Deprecated

## Removed

## Fixed

Fixed a bug in the decoder of Candid `Nat` values as `u64`.

## Security
