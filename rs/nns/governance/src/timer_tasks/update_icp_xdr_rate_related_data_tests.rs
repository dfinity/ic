use super::*;

use crate::test_utils::{MockEnvironment, MockRandomness, StubCMC, StubIcpLedger};
use ic_nervous_system_clients::exchange_rate_canister_client::{
    GetExchangeRateError, ICP_SYMBOL, MINIMUM_CXDR_SOURCES, MINIMUM_ICP_SOURCES,
};
use ic_nns_governance_api as api;
use ic_xrc_types::{Asset, AssetClass, ExchangeRate, ExchangeRateMetadata};
use std::sync::Arc;

const CXDR_SYMBOL: &str = "CXDR";

/// XRC rate decimals. With decimals=9, `exchange_rate_to_permyriad` divides by 10^5.
const XRC_DECIMALS: u32 = 9;

/// One permyriad equals this many nanos (XRC rate units at 9 decimal places): 10^(9-4).
/// Multiply permyriad by NANOS_PER_PERMYRIAD to get nanos; divide nanos by NANOS_PER_PERMYRIAD
/// to get permyriad.
const NANOS_PER_PERMYRIAD: u64 = 100_000; // 10^(9-4)

fn make_valid_exchange_rate(timestamp_seconds: u64, xdr_permyriad_per_icp: u64) -> ExchangeRate {
    ExchangeRate {
        base_asset: Asset {
            symbol: ICP_SYMBOL.to_string(),
            class: AssetClass::Cryptocurrency,
        },
        quote_asset: Asset {
            symbol: CXDR_SYMBOL.to_string(),
            class: AssetClass::FiatCurrency,
        },
        timestamp: timestamp_seconds,
        rate: xdr_permyriad_per_icp * NANOS_PER_PERMYRIAD,
        metadata: ExchangeRateMetadata {
            decimals: XRC_DECIMALS,
            base_asset_num_queried_sources: 7,
            base_asset_num_received_rates: MINIMUM_ICP_SOURCES,
            quote_asset_num_queried_sources: 7,
            quote_asset_num_received_rates: MINIMUM_CXDR_SOURCES,
            standard_deviation: 0,
            forex_timestamp: Some(0),
        },
    }
}

// --- Mock XRC client via mockall ---

mockall::mock! {
    pub XrcClient {}

    #[async_trait]
    impl ExchangeRateCanisterClient for XrcClient {
        async fn get_icp_to_xdr_exchange_rate(
            &self,
            timestamp: Option<u64>,
        ) -> Result<ExchangeRate, GetExchangeRateError>;
    }
}

// --- Test governance setup ---

fn new_governance(now_seconds: u64) -> Governance {
    Governance::new(
        api::Governance::default(),
        Arc::new(MockEnvironment::new(vec![], now_seconds)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    )
}

// --- Unit tests for helper functions ---

#[test]
fn test_update_rates_buffer_dedup_same_day() {
    let mut history = IcpPriceHistory {
        icp_xdr_rates: vec![SampledPrice {
            timestamp_seconds: 100 * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 50_000,
        }],
    };
    update_rates_buffer(
        &mut history,
        SampledPrice {
            timestamp_seconds: 100 * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 55_000,
        },
    );
    assert_eq!(
        history,
        IcpPriceHistory {
            icp_xdr_rates: vec![SampledPrice {
                timestamp_seconds: 100 * ONE_DAY_SECONDS,
                xdr_permyriad_per_icp: 55_000,
            }],
        }
    );
}

#[test]
fn test_update_rates_buffer_adds_new_day() {
    let mut history = IcpPriceHistory {
        icp_xdr_rates: vec![SampledPrice {
            timestamp_seconds: 100 * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 50_000,
        }],
    };
    update_rates_buffer(
        &mut history,
        SampledPrice {
            timestamp_seconds: 101 * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 52_000,
        },
    );
    assert_eq!(
        history,
        IcpPriceHistory {
            icp_xdr_rates: vec![
                SampledPrice {
                    timestamp_seconds: 100 * ONE_DAY_SECONDS,
                    xdr_permyriad_per_icp: 50_000,
                },
                SampledPrice {
                    timestamp_seconds: 101 * ONE_DAY_SECONDS,
                    xdr_permyriad_per_icp: 52_000,
                },
            ],
        }
    );
}

#[test]
fn test_update_rates_buffer_sorted() {
    let mut history = IcpPriceHistory {
        icp_xdr_rates: vec![
            SampledPrice {
                timestamp_seconds: 100 * ONE_DAY_SECONDS,
                xdr_permyriad_per_icp: 50_000,
            },
            SampledPrice {
                timestamp_seconds: 102 * ONE_DAY_SECONDS,
                xdr_permyriad_per_icp: 51_000,
            },
        ],
    };
    update_rates_buffer(
        &mut history,
        SampledPrice {
            timestamp_seconds: 101 * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 52_000,
        },
    );
    assert_eq!(
        history,
        IcpPriceHistory {
            icp_xdr_rates: vec![
                SampledPrice {
                    timestamp_seconds: 100 * ONE_DAY_SECONDS,
                    xdr_permyriad_per_icp: 50_000,
                },
                SampledPrice {
                    timestamp_seconds: 101 * ONE_DAY_SECONDS,
                    xdr_permyriad_per_icp: 52_000,
                },
                SampledPrice {
                    timestamp_seconds: 102 * ONE_DAY_SECONDS,
                    xdr_permyriad_per_icp: 51_000,
                },
            ],
        }
    );
}

#[test]
fn test_update_rates_buffer_caps_at_max() {
    let rates: Vec<SampledPrice> = (0..MAX_RATES_BUFFER_SIZE as u64)
        .map(|d| SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 50_000,
        })
        .collect();
    let mut history = IcpPriceHistory {
        icp_xdr_rates: rates,
    };
    update_rates_buffer(
        &mut history,
        SampledPrice {
            timestamp_seconds: MAX_RATES_BUFFER_SIZE as u64 * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 55_000,
        },
    );
    assert_eq!(history.icp_xdr_rates.len(), MAX_RATES_BUFFER_SIZE);
    assert_eq!(history.icp_xdr_rates[0].timestamp_seconds, ONE_DAY_SECONDS);
    assert_eq!(
        history.icp_xdr_rates[MAX_RATES_BUFFER_SIZE - 1].timestamp_seconds,
        MAX_RATES_BUFFER_SIZE as u64 * ONE_DAY_SECONDS
    );
}

#[test]
fn test_compute_maturity_modulation_no_data_with_previous() {
    let result = compute_maturity_modulation_permyriad(&[], 100, Some((50, 99)));
    assert_eq!(
        result,
        Err("insufficient recent price data despite full history".to_string())
    );
}

#[test]
fn test_compute_maturity_modulation_no_data_no_previous() {
    let result = compute_maturity_modulation_permyriad(&[], 100, None);
    assert_eq!(
        result,
        Err("insufficient recent price data despite full history".to_string())
    );
}

#[test]
fn test_compute_maturity_modulation_zero_reference_price_returns_error() {
    // 365 days of zero rates: 7-day and 365-day averages are both zero, hitting the
    // reference-price-zero branch.
    let rates: Vec<SampledPrice> = (1..=365)
        .map(|d| SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 0,
        })
        .collect();
    let result = compute_maturity_modulation_permyriad(&rates, 365, Some((10, 364)));
    assert_eq!(result, Err("reference price averaged to zero".to_string()));
}

#[test]
fn test_compute_maturity_modulation_stable_price() {
    // In this scenario, the price is perfectly stable (not realistic). In that case, maturity
    // modulation "wants" to be 0. But, since the previous maturity modulation was 42 basis points
    // (probably impossible based on perfectly stable price), the "speed limit" kicks in. With a
    // maximum change of 30 basis points per day, the closest we can get to 0 is 12 basis points.
    let rates: Vec<SampledPrice> = (1..=365)
        .map(|d| SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 50_000,
        })
        .collect();
    let result = compute_maturity_modulation_permyriad(&rates, 365, Some((42, 364)));
    assert_eq!(result, Ok(12));
}

#[test]
fn test_compute_maturity_modulation_price_increase() {
    // ICP was at 5 XDR for the past year, except for the past 7 days it was at 6 XDR.
    // This results in a price jump of slightly less 1 XDR, a nearly 20% jump.
    // (Precisely, 7-day average: 60_000; 365-day average = (358*50_000 + 7*60_000) / 365 = 50_192...
    // That is massive; and thus, limits start kicking in. In particular, the "speed limit"
    // (30 basis points per day) kicks in.
    let mut rates: Vec<SampledPrice> = (1..=358)
        .map(|d| SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 50_000,
        })
        .collect();
    for d in 359..=365 {
        rates.push(SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 60_000,
        });
    }
    let result = compute_maturity_modulation_permyriad(&rates, 365, Some((0, 364)));
    assert_eq!(result, Ok(MATURITY_MODULATION_DAILY_SPEED_LIMIT_PERMYRIAD));
}

#[test]
fn test_compute_maturity_modulation_price_decrease() {
    // ICP was at 5 XDR for the past year, except for the past 7 days it dropped to 4 XDR.
    // 7-day average: 40_000; 365-day average = (358*50_000 + 7*40_000) / 365 = 49_808.
    // target = 2_500 * (40_000 - 49_808) / 49_808 ≈ -492 permyriad (negative = price dropped).
    // Starting from 0, speed limit is 30 permyriad/day → result = -30.
    let mut rates: Vec<SampledPrice> = (1..=358)
        .map(|d| SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 50_000,
        })
        .collect();
    for d in 359..=365 {
        rates.push(SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 40_000,
        });
    }
    let result = compute_maturity_modulation_permyriad(&rates, 365, Some((0, 364)));
    assert_eq!(result, Ok(-MATURITY_MODULATION_DAILY_SPEED_LIMIT_PERMYRIAD));
}

#[test]
fn test_compute_maturity_modulation_first_calculation_skips_speed_limit() {
    // Same prices as test_compute_maturity_modulation_price_decrease (target ≈ -492 permyriad),
    // but with no previous value: the speed limit must not apply, so the result should reflect
    // the full target (subject to global bounds).
    let mut rates: Vec<SampledPrice> = (1..=358)
        .map(|d| SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 50_000,
        })
        .collect();
    for d in 359..=365 {
        rates.push(SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 40_000,
        });
    }
    let result = compute_maturity_modulation_permyriad(&rates, 365, None)
        .expect("complete history should yield Ok");
    // Target is well within global bounds, so we should see roughly -492.
    assert!(
        (-500..=-450).contains(&result),
        "expected target near -492, got {result}"
    );
}

#[test]
fn test_compute_maturity_modulation_respects_global_bounds() {
    // 358 days at 10_000, then 7 days at 30_000 (3× recent spike).
    // 7-day average: 30_000.
    // 365-day average: (358*10_000 + 7*30_000) / 365 = 10_383.
    // target = 2_500 * (30_000 - 10_383) / 10_383 ≈ 4_720 permyriad >> MAX (200).
    // First calculation: speed limit is skipped, so global clamping takes over directly.
    // Expected: result == MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70.
    let mut rates: Vec<SampledPrice> = (1..=358)
        .map(|d| SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 10_000,
        })
        .collect();
    for d in 359..=365 {
        rates.push(SampledPrice {
            timestamp_seconds: d * ONE_DAY_SECONDS,
            xdr_permyriad_per_icp: 30_000,
        });
    }
    let result = compute_maturity_modulation_permyriad(&rates, 365, None);
    assert_eq!(result, Ok(MATURITY_MODULATION_MAX_PERMYRIAD_MISSION_70));
}

#[test]
fn test_duration_until_next_midnight_utc() {
    assert_eq!(
        duration_until_next_midnight_utc(1_774_828_800),
        Duration::from_secs(ONE_DAY_SECONDS)
    );
    assert_eq!(
        duration_until_next_midnight_utc(1_774_828_800 + ONE_DAY_SECONDS),
        Duration::from_secs(ONE_DAY_SECONDS)
    );
    assert_eq!(
        duration_until_next_midnight_utc(1_774_828_800 + ONE_DAY_SECONDS / 2),
        Duration::from_secs(ONE_DAY_SECONDS / 2)
    );
    assert_eq!(
        duration_until_next_midnight_utc(1_774_828_800 + ONE_DAY_SECONDS + 1),
        Duration::from_secs(ONE_DAY_SECONDS - 1)
    );
}

// --- Tests against execute() ---

#[tokio::test]
async fn test_execute_stores_rate_and_computes_modulation() {
    let current_day = 20_500_u64;
    let xdr_permyriad = 50_000_u64;
    let oldest_needed = current_day - MAX_RATES_BUFFER_SIZE as u64 + 1;

    thread_local! {
        static GOV: RefCell<Governance> = RefCell::new(new_governance(20_500 * ONE_DAY_SECONDS + 3600));
    }

    let mut mock_client = MockXrcClient::new();
    mock_client
        .expect_get_icp_to_xdr_exchange_rate()
        .return_once(move |ts| Ok(make_valid_exchange_rate(ts.unwrap(), xdr_permyriad)));

    let task = UpdateIcpXdrRateRelatedData::new(&GOV, Arc::new(mock_client));
    let (delay, _task) = task.execute().await;

    GOV.with_borrow(|gov| {
        assert_eq!(
            *gov.heap_data.icp_price_history.as_ref().unwrap(),
            IcpPriceHistory {
                icp_xdr_rates: vec![SampledPrice {
                    timestamp_seconds: oldest_needed * ONE_DAY_SECONDS,
                    xdr_permyriad_per_icp: xdr_permyriad,
                }],
            }
        );
        // The 365-day window is not yet full, so maturity modulation is not computed.
        assert_eq!(gov.heap_data.maturity_modulation, None);
    });

    // With almost no history, the next delay should be short (backfill interval) so that
    // history can quickly be fully populated.
    assert_eq!(delay, Duration::from_secs(BACKFILL_INTERVAL_SECONDS));
}

#[tokio::test]
async fn test_execute_xrc_failure_leaves_state_unchanged() {
    let current_day = 20_500_u64;

    thread_local! {
        static GOV: RefCell<Governance> = RefCell::new(new_governance(20_500 * ONE_DAY_SECONDS));
    }

    // Pre-populate state so we can verify it is not clobbered on failure.
    GOV.with_borrow_mut(|gov| {
        gov.heap_data.icp_price_history = Some(IcpPriceHistory {
            icp_xdr_rates: vec![SampledPrice {
                timestamp_seconds: (current_day - 1) * ONE_DAY_SECONDS,
                xdr_permyriad_per_icp: 50_000,
            }],
        });
        gov.heap_data.maturity_modulation = Some(MaturityModulation {
            current_value_permyriad: Some(42),
            updated_at_days_since_epoch: Some(current_day - 1),
        });
    });

    let mut mock_client = MockXrcClient::new();
    mock_client
        .expect_get_icp_to_xdr_exchange_rate()
        .return_once(|_| {
            Err(GetExchangeRateError::Call {
                code: 1,
                message: "canister unreachable".to_string(),
            })
        });

    let task = UpdateIcpXdrRateRelatedData::new(&GOV, Arc::new(mock_client));
    let (delay, _task) = task.execute().await;

    // State must be unchanged.
    GOV.with_borrow(|gov| {
        assert_eq!(
            *gov.heap_data.icp_price_history.as_ref().unwrap(),
            IcpPriceHistory {
                icp_xdr_rates: vec![SampledPrice {
                    timestamp_seconds: (current_day - 1) * ONE_DAY_SECONDS,
                    xdr_permyriad_per_icp: 50_000,
                }],
            }
        );
        assert_eq!(
            *gov.heap_data.maturity_modulation.as_ref().unwrap(),
            MaturityModulation {
                current_value_permyriad: Some(42),
                updated_at_days_since_epoch: Some(current_day - 1),
            }
        );
    });
    // On failure the task should retry soon, not wait until the next day.
    assert_eq!(delay, Duration::from_secs(ERROR_RETRY_INTERVAL_SECONDS));
}

#[tokio::test]
async fn test_execute_zero_rate_is_ignored() {
    let current_day = 20_500_u64;

    thread_local! {
        static GOV: RefCell<Governance> = RefCell::new(new_governance(20_500 * ONE_DAY_SECONDS));
    }

    // Pre-populate state so we can verify it is not clobbered on zero-rate.
    GOV.with_borrow_mut(|gov| {
        gov.heap_data.icp_price_history = Some(IcpPriceHistory {
            icp_xdr_rates: vec![SampledPrice {
                timestamp_seconds: (current_day - 1) * ONE_DAY_SECONDS,
                xdr_permyriad_per_icp: 50_000,
            }],
        });
        gov.heap_data.maturity_modulation = Some(MaturityModulation {
            current_value_permyriad: Some(42),
            updated_at_days_since_epoch: Some(current_day - 1),
        });
    });

    let mut mock_client = MockXrcClient::new();
    mock_client
        .expect_get_icp_to_xdr_exchange_rate()
        .return_once(|_| Ok(make_valid_exchange_rate(20_500 * ONE_DAY_SECONDS, 0)));

    let task = UpdateIcpXdrRateRelatedData::new(&GOV, Arc::new(mock_client));
    let (delay, _task) = task.execute().await;

    // State must be unchanged.
    GOV.with_borrow(|gov| {
        assert_eq!(
            *gov.heap_data.icp_price_history.as_ref().unwrap(),
            IcpPriceHistory {
                icp_xdr_rates: vec![SampledPrice {
                    timestamp_seconds: (current_day - 1) * ONE_DAY_SECONDS,
                    xdr_permyriad_per_icp: 50_000,
                }],
            }
        );
        assert_eq!(
            *gov.heap_data.maturity_modulation.as_ref().unwrap(),
            MaturityModulation {
                current_value_permyriad: Some(42),
                updated_at_days_since_epoch: Some(current_day - 1),
            }
        );
    });
    // A zero rate is treated the same as an error.
    assert_eq!(delay, Duration::from_secs(ERROR_RETRY_INTERVAL_SECONDS));
}

#[tokio::test]
async fn test_execute_skips_when_already_updated_today() {
    // Simulate an early timer fire: maturity modulation has already been computed for current_day,
    // but the timer fires again before midnight has rolled over. The task should skip all work and
    // reschedule until the next midnight.
    let current_day = 20_500_u64;
    let now = current_day * ONE_DAY_SECONDS + 86_399; // 23:59:59 UTC

    thread_local! {
        static GOV: RefCell<Governance> = RefCell::new(new_governance(20_500 * ONE_DAY_SECONDS + 86_399));
    }

    GOV.with_borrow_mut(|gov| {
        gov.heap_data.icp_price_history = Some(IcpPriceHistory {
            icp_xdr_rates: vec![SampledPrice {
                timestamp_seconds: (current_day - 1) * ONE_DAY_SECONDS,
                xdr_permyriad_per_icp: 50_000,
            }],
        });
        gov.heap_data.maturity_modulation = Some(MaturityModulation {
            current_value_permyriad: Some(42),
            updated_at_days_since_epoch: Some(current_day),
        });
    });

    // No XRC call expected.
    let mock_client = MockXrcClient::new();
    let task = UpdateIcpXdrRateRelatedData::new(&GOV, Arc::new(mock_client));
    let (delay, _task) = task.execute().await;

    assert_eq!(delay, duration_until_next_midnight_utc(now));
    // State must be unchanged.
    GOV.with_borrow(|gov| {
        assert_eq!(
            *gov.heap_data.maturity_modulation.as_ref().unwrap(),
            MaturityModulation {
                current_value_permyriad: Some(42),
                updated_at_days_since_epoch: Some(current_day),
            }
        );
    });
}

#[tokio::test]
async fn test_execute_backfill_then_daily() {
    // Pre-populate 363 days of history, leaving 2 gaps: current_day-1 and current_day.
    // The last week (days current_day-6 through current_day-2) uses a higher price (55_000)
    // so that the computed maturity modulation is non-zero.
    let current_day = 20_500_u64;
    let now = current_day * ONE_DAY_SECONDS;

    thread_local! {
        static GOV: RefCell<Governance> = RefCell::new(new_governance(20_500 * ONE_DAY_SECONDS));
    }

    let oldest_needed = current_day - (MAX_RATES_BUFFER_SIZE as u64 - 1);
    GOV.with_borrow_mut(|gov| {
        // Fill days oldest_needed through current_day-2 (363 days total).
        let rates: Vec<SampledPrice> = (oldest_needed..current_day - 1)
            .map(|d| {
                let price = if d >= current_day - 6 { 55_000 } else { 50_000 };
                SampledPrice {
                    timestamp_seconds: d * ONE_DAY_SECONDS,
                    xdr_permyriad_per_icp: price,
                }
            })
            .collect();
        gov.heap_data.icp_price_history = Some(IcpPriceHistory {
            icp_xdr_rates: rates,
        });
        gov.heap_data.maturity_modulation = Some(MaturityModulation {
            current_value_permyriad: Some(100),
            updated_at_days_since_epoch: Some(current_day - 2),
        });
    });

    // First execute(): fetches current_day-1 (the oldest missing day). History still incomplete
    // (missing current_day), so the delay should be BACKFILL_INTERVAL_SECONDS.
    let mut mock_client_1 = MockXrcClient::new();
    mock_client_1
        .expect_get_icp_to_xdr_exchange_rate()
        .times(1)
        .return_once(move |_| {
            Ok(make_valid_exchange_rate(
                (current_day - 1) * ONE_DAY_SECONDS,
                55_000,
            ))
        });
    let task = UpdateIcpXdrRateRelatedData::new(&GOV, Arc::new(mock_client_1));
    let (delay_1, _task) = task.execute().await;
    assert_eq!(delay_1, Duration::from_secs(BACKFILL_INTERVAL_SECONDS));

    // Second execute(): fetches current_day, completing the 365-day history. The delay is still
    // BACKFILL_INTERVAL_SECONDS — the modulation update happens on the next iteration via the
    // "history complete on entry" branch.
    let mut mock_client_2 = MockXrcClient::new();
    mock_client_2
        .expect_get_icp_to_xdr_exchange_rate()
        .times(1)
        .return_once(move |_| Ok(make_valid_exchange_rate(now, 55_000)));
    let task = UpdateIcpXdrRateRelatedData::new(&GOV, Arc::new(mock_client_2));
    let (delay_2, _task) = task.execute().await;
    assert_eq!(delay_2, Duration::from_secs(BACKFILL_INTERVAL_SECONDS));

    // Third execute(): history is already complete on entry, so modulation is computed and the
    // delay is until next midnight. No XRC call expected.
    let mock_client_3 = MockXrcClient::new();
    let task = UpdateIcpXdrRateRelatedData::new(&GOV, Arc::new(mock_client_3));
    let (delay_3, _task) = task.execute().await;
    assert_eq!(delay_3, duration_until_next_midnight_utc(now));

    GOV.with_borrow(|gov| {
        let mm = gov.heap_data.maturity_modulation.as_ref().unwrap();
        assert!(mm.current_value_permyriad.is_some());
        assert_eq!(mm.updated_at_days_since_epoch, Some(current_day));
    });
}

#[tokio::test]
async fn test_execute_repeated_calls_accumulate_rates() {
    let base_day = 20_500_u64;

    thread_local! {
        static GOV: RefCell<Governance> = RefCell::new(new_governance(20_500 * ONE_DAY_SECONDS));
    }

    let oldest_needed = base_day - MAX_RATES_BUFFER_SIZE as u64 + 1;

    // First call: backfill fetches the oldest missing day.
    let mut mock_client = MockXrcClient::new();
    mock_client
        .expect_get_icp_to_xdr_exchange_rate()
        .return_once(move |ts| Ok(make_valid_exchange_rate(ts.unwrap(), 50_000)));
    let task = UpdateIcpXdrRateRelatedData::new(&GOV, Arc::new(mock_client));
    task.execute().await;

    GOV.with_borrow(|gov| {
        assert_eq!(
            *gov.heap_data.icp_price_history.as_ref().unwrap(),
            IcpPriceHistory {
                icp_xdr_rates: vec![SampledPrice {
                    timestamp_seconds: oldest_needed * ONE_DAY_SECONDS,
                    xdr_permyriad_per_icp: 50_000,
                }],
            }
        );
    });

    // Second call: backfill fetches the next oldest missing day at a different price.
    let mut mock_client = MockXrcClient::new();
    mock_client
        .expect_get_icp_to_xdr_exchange_rate()
        .return_once(move |ts| Ok(make_valid_exchange_rate(ts.unwrap(), 60_000)));
    let task = UpdateIcpXdrRateRelatedData::new(&GOV, Arc::new(mock_client));
    task.execute().await;

    GOV.with_borrow(|gov| {
        // Both rates should be in the history, sorted by day.
        assert_eq!(
            *gov.heap_data.icp_price_history.as_ref().unwrap(),
            IcpPriceHistory {
                icp_xdr_rates: vec![
                    SampledPrice {
                        timestamp_seconds: oldest_needed * ONE_DAY_SECONDS,
                        xdr_permyriad_per_icp: 50_000,
                    },
                    SampledPrice {
                        timestamp_seconds: (oldest_needed + 1) * ONE_DAY_SECONDS,
                        xdr_permyriad_per_icp: 60_000,
                    },
                ],
            }
        );
        // The 365-day window is not yet full, so maturity modulation is not computed.
        assert_eq!(gov.heap_data.maturity_modulation, None);
    });
}
