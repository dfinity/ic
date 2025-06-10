# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

### New Feature: `get_metrics` Function for SNS Governance 

A new function, `get_metrics`, has been added to the SNS Governance canister. This allows front-end clients and SNS aggregators to query for activity metrics of an SNS over a specified time period. Currently, the metrics include the number of most-recent proposals and the timestamp of the latest SNS ledger transaction.
This feature can be integrated into dashboard to help users gauge the recent activity and activeness level of a given SNS; supporting decision-making for users based on SNS activity patterns.

## Changed

## Deprecated

## Removed

## Fixed

## Security
