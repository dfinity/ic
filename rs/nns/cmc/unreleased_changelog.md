# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.

# Next Upgrade Proposal

## Added

## Changed

## Deprecated

## Removed

- Removed `transaction_notification` and `transaction_notification_pb` endpoints as they
  no longer be called. The ICP ledger removed the notify flow, and these methods were not
  callable by callers other than the ICP ledger.

## Fixed

## Security
