use crate::balance_scan::ScanErrors;
use crate::balance_scan::batcher::Delegation;
use crate::deposit_address::DepositAddress;
use crate::state::sweep_observations::SweepObservations;
use crate::timed_sized_map::Timestamp;
use ic_ethereum_types::Address;
use std::collections::BTreeMap;
use std::time::Duration;

const DELEGATE: Address = Address::new([0x5e; 20]);
const ANOTHER_DELEGATE: Address = Address::new([0x99; 20]);

#[test]
fn should_report_no_balance_scan_age_before_the_first_pass() {
    let observations = SweepObservations::default();

    assert_eq!(observations.last_balance_scan_age(ts(1_000)), None);
    assert_eq!(observations.balance_scan_call_errors(), 0);
    assert_eq!(observations.balance_scan_decode_errors(), 0);
}

#[test]
fn should_report_the_age_of_the_last_completed_pass() {
    let mut observations = SweepObservations::default();

    observations.record_completed_balance_scan(ts(1_000));

    assert_eq!(
        observations.last_balance_scan_age(ts(4_000)),
        Some(Duration::from_nanos(3_000))
    );

    observations.record_completed_balance_scan(ts(4_000));

    assert_eq!(
        observations.last_balance_scan_age(ts(4_000)),
        Some(Duration::ZERO)
    );
}

#[test]
fn should_report_a_zero_age_for_a_pass_stamped_in_the_future() {
    let mut observations = SweepObservations::default();

    observations.record_completed_balance_scan(ts(4_000));

    assert_eq!(
        observations.last_balance_scan_age(ts(1_000)),
        Some(Duration::ZERO)
    );
}

#[test]
fn should_accumulate_balance_scan_errors_across_passes() {
    let mut observations = SweepObservations::default();

    observations.record_balance_scan_errors(&errors(2, 1));
    observations.record_balance_scan_errors(&errors(0, 3));

    assert_eq!(observations.balance_scan_call_errors(), 4);
    assert_eq!(observations.balance_scan_decode_errors(), 2);
    assert_eq!(
        observations.last_balance_scan_age(ts(1_000)),
        None,
        "counting a pass' failures must not make the scan look fresh"
    );
}

#[test]
fn should_count_each_address_delegated_elsewhere_once_per_read() {
    let mut observations = SweepObservations::default();
    assert_eq!(observations.untracked_delegations(), 0);

    observations.record_delegation_read(
        &BTreeMap::from([
            (address(0), Delegation::NotDelegated),
            (address(1), Delegation::Delegated(DELEGATE)),
            (address(2), Delegation::Delegated(ANOTHER_DELEGATE)),
            (address(3), Delegation::Delegated(Address::new([0x77; 20]))),
            (address(4), Delegation::Other),
        ]),
        DELEGATE,
    );

    assert_eq!(observations.untracked_delegations(), 2);

    observations.record_delegation_read(
        &BTreeMap::from([(address(2), Delegation::Delegated(ANOTHER_DELEGATE))]),
        DELEGATE,
    );

    assert_eq!(observations.untracked_delegations(), 3);
}

#[test]
fn should_count_nothing_for_a_read_that_came_back_empty() {
    let mut observations = SweepObservations::default();

    observations.record_delegation_read(&BTreeMap::new(), DELEGATE);

    assert_eq!(observations.untracked_delegations(), 0);
}

#[test]
fn should_saturate_rather_than_overflow_the_counters() {
    let mut observations = SweepObservations::default();

    observations.record_balance_scan_errors(&errors(u64::MAX, u64::MAX));
    observations.record_balance_scan_errors(&errors(1, 1));

    assert_eq!(observations.balance_scan_call_errors(), u64::MAX);
    assert_eq!(observations.balance_scan_decode_errors(), u64::MAX);
}

fn ts(nanos: u64) -> Timestamp {
    Timestamp::from_nanos(nanos)
}

fn errors(decode: u64, call: u64) -> ScanErrors {
    ScanErrors { decode, call }
}

fn address(byte: u8) -> DepositAddress {
    DepositAddress::new(Address::new([byte; 20]))
}
