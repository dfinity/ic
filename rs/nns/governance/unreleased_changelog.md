# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added two Prometheus gauges to the `/metrics` endpoint to expose maturity modulation
  freshness:
  - `governance_maturity_modulation_updated_at_timestamp_seconds` — the day for which the
    cached maturity modulation was last computed, multiplied by 86400.
  - `governance_icp_xdr_price_history_missing_days_in_window` — the number of days in
    `[today-364, today]` with no entry in `icp_price_history.icp_xdr_rates`.

  Both gauges are skipped entirely until the underlying state is populated, so a
  freshly-installed canister does not trip alerts before the initial backfill completes.

## Changed

## Deprecated

## Removed

## Fixed

## Security
