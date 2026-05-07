# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Daily timer task that fetches ICP/XDR rates from the Exchange Rate Canister, maintains a 365-day price history in Governance state, and computes Mission 70 maturity modulation locally. The computed value is not yet consumed by spawning or disbursement; that switchover will happen in a follow-up PR.

* `get_maturity_modulation` query endpoint that returns the current Mission 70 maturity modulation value, including `current_value_permyriad` and `updated_at_timestamp_seconds`.

## Changed

## Deprecated

## Removed

## Fixed

## Security
