# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

### New `get_metrics` function for SNS Governance

A new function, `get_metrics`, has been added to the SNS Governance canister. This allows front-end clients and SNS aggregators to query for activity metrics of an SNS over a specified time period. Currently, the metrics include the number of most-recent proposals and the timestamp of the latest SNS ledger transaction.

### New `RegisterExtension` proposal type

A new proposal type, `RegisterExtension`, is added for registering SNS extensions. 
Extensions are a new class of SNS canisters that (unlike SNS-controlled dapp canisters)
can operate on behalf of the DAO, e.g., by managing a portion of the treasury funds.

## Changed

## Deprecated

## Removed

## Fixed

## Security
