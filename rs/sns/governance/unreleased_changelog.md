# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

### Set the principal of the index canister when installing the ledger ([ICRC-106](https://github.com/dfinity/ICRC-1/pull/196/files/7f9b4739d9b3ec2cf549bf468e3a1731c31eecbf))

When installing the ledger canister for a new SNS, the index canister's principal is now set in the ledger.
This allows a ledger client to query the ledger using the `icrc106_get_index_principal` endpoint to figure out where the
ledger index canister is running.

### New Feature: `get_metrics` Function for SNS Governance 

A new function, `get_metrics`, has been added to the SNS Governance system. This allows front-end clients and SNS aggregators to query and retrieve activity metrics of an SNS over a specified time period.
This feature can be integrated into dashboard to help users gauge the recent activity and activeness level of a given SNS; supporting decision-making for users based on SNS activity patterns.
## Changed

## Deprecated

## Removed

## Fixed

## Security
