use super::{
    AutomaticDeposits, DEPOSIT_ADDRESS_SCAN_WINDOW, DepositRequest, MAX_ACTIVE_DEPOSIT_ADDRESSES,
};
use crate::endpoints::DepositErc20Error;
use crate::state::event::DepositAddressRegistration;
use crate::timed_sized_map::{Entry, Timestamp};
use candid::Principal;
use ic_ethereum_types::Address;
use ic_sha3::Keccak256;
use icrc_ledger_types::icrc1::account::Account;

#[test]
fn should_arm_deposit_address_for_the_scan_window() {
    let mut deposits = AutomaticDeposits::default();
    let now = ts(1_000);

    let result = deposits.watch_address_for_account(now, account(0), deposit_address(&account(0)));

    let expected = Entry {
        value: DepositRequest::from(deposit_address(&account(0))),
        expires_at: ts(1_000 + window_nanos()),
    };
    assert_eq!(result, Ok(expected.clone()));
    assert_eq!(deposits.get_entry(now, &account(0)), Some(&expected));
    assert_eq!(deposits.watchlist_iter().count(), 1);
}

#[test]
fn should_return_stored_entry_without_rearming_on_reregistration() {
    let mut deposits = AutomaticDeposits::default();
    let first = deposits
        .watch_address_for_account(ts(0), account(0), deposit_address(&account(0)))
        .unwrap();

    let second =
        deposits.watch_address_for_account(ts(1_000), account(0), deposit_address(&account(0)));

    assert_eq!(second, Ok(first));
    assert_eq!(deposits.watchlist_iter().count(), 1);
}

#[test]
fn should_treat_missing_and_all_zero_subaccount_as_the_same_account() {
    let mut deposits = AutomaticDeposits::default();
    let no_subaccount = Account {
        owner: owner(),
        subaccount: None,
    };
    let all_zero_subaccount = Account {
        owner: owner(),
        subaccount: Some([0_u8; 32]),
    };

    let armed = deposits
        .watch_address_for_account(ts(0), no_subaccount, deposit_address(&no_subaccount))
        .unwrap();
    let rearmed = deposits.watch_address_for_account(
        ts(1_000),
        all_zero_subaccount,
        deposit_address(&all_zero_subaccount),
    );

    assert_eq!(rearmed, Ok(armed.clone()));
    assert_eq!(
        deposits.get_entry(ts(0), &all_zero_subaccount),
        Some(&armed)
    );
    assert_eq!(deposits.get_entry(ts(0), &no_subaccount), Some(&armed));
    assert_eq!(deposits.watchlist_iter().count(), 1);
}

#[test]
fn should_reject_new_address_when_watchlist_is_full() {
    let mut deposits = AutomaticDeposits::default();
    let capacity = MAX_ACTIVE_DEPOSIT_ADDRESSES.get();
    for i in 0..capacity {
        let account = account(i as u64);
        deposits
            .watch_address_for_account(ts(0), account, deposit_address(&account))
            .unwrap();
    }

    let account = account(capacity as u64);
    let rejected = deposits.watch_address_for_account(ts(0), account, deposit_address(&account));

    assert_eq!(rejected, Err(DepositErc20Error::TooManyActiveAddresses));
    assert_eq!(deposits.watchlist_iter().count(), capacity);
}

#[test]
fn should_snapshot_entries_sorted_by_descending_expiry() {
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_address_for_account(ts(0), account(0), deposit_address(&account(0)))
        .unwrap();
    deposits
        .watch_address_for_account(ts(10), account(1), deposit_address(&account(1)))
        .unwrap();
    deposits
        .watch_address_for_account(ts(5), account(2), deposit_address(&account(2)))
        .unwrap();

    let snapshot = deposits.watchlist_snapshot();

    assert_eq!(
        snapshot,
        vec![
            registration(account(1), ts(10 + window_nanos())),
            registration(account(2), ts(5 + window_nanos())),
            registration(account(0), ts(window_nanos())),
        ]
    );
}

#[test]
fn should_restore_live_entries_from_snapshot() {
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_address_for_account(ts(0), account(0), deposit_address(&account(0)))
        .unwrap();
    deposits
        .watch_address_for_account(ts(5), account(1), deposit_address(&account(1)))
        .unwrap();
    let snapshot = deposits.watchlist_snapshot();

    let mut restored = AutomaticDeposits::default();
    restored.rebuild_watchlist(ts(10), &snapshot);

    assert_eq!(restored.watchlist_snapshot(), snapshot);
}

#[test]
fn should_drop_expired_entries_on_rebuild() {
    let snapshot = vec![
        registration(account(0), ts(100)),
        registration(account(1), ts(50)),
    ];
    let mut deposits = AutomaticDeposits::default();

    deposits.rebuild_watchlist(ts(60), &snapshot);

    assert_eq!(
        deposits.get_entry(ts(60), &account(0)),
        Some(&Entry {
            value: DepositRequest::from(deposit_address(&account(0))),
            expires_at: ts(100),
        })
    );
    assert_eq!(deposits.get_entry(ts(60), &account(1)), None);
    assert_eq!(deposits.watchlist_iter().count(), 1);
}

#[test]
fn should_clamp_entry_validity_to_current_window_on_rebuild() {
    let far_future = ts(10 + 2 * window_nanos());
    let snapshot = vec![registration(account(0), far_future)];
    let mut deposits = AutomaticDeposits::default();

    deposits.rebuild_watchlist(ts(10), &snapshot);

    assert_eq!(
        deposits.get_entry(ts(10), &account(0)),
        Some(&Entry {
            value: DepositRequest::from(deposit_address(&account(0))),
            expires_at: ts(10 + window_nanos()),
        })
    );
}

#[test]
fn should_replace_existing_entries_on_rebuild() {
    let mut deposits = AutomaticDeposits::default();
    deposits
        .watch_address_for_account(ts(0), account(0), deposit_address(&account(0)))
        .unwrap();

    let snapshot = vec![registration(account(1), ts(100))];
    deposits.rebuild_watchlist(ts(10), &snapshot);

    assert_eq!(deposits.get_entry(ts(10), &account(0)), None);
    assert!(deposits.get_entry(ts(10), &account(1)).is_some());
    assert_eq!(deposits.watchlist_iter().count(), 1);
}

fn ts(nanos: u64) -> Timestamp {
    Timestamp::from_nanos(nanos)
}

fn window_nanos() -> u64 {
    DEPOSIT_ADDRESS_SCAN_WINDOW.as_nanos() as u64
}

fn account(index: u64) -> Account {
    let mut subaccount = [0_u8; 32];
    subaccount[..8].copy_from_slice(&index.to_be_bytes());
    Account {
        owner: owner(),
        subaccount: Some(subaccount),
    }
}

fn owner() -> Principal {
    Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap()
}

/// The deposit address is a deterministic function of the account, so a given
/// account always maps to the same address (mirroring the production key
/// derivation).
fn deposit_address(account: &Account) -> Address {
    let mut preimage = account.owner.as_slice().to_vec();
    preimage.extend_from_slice(account.effective_subaccount());
    let hash = Keccak256::hash(&preimage);
    let mut bytes = [0_u8; 20];
    bytes.copy_from_slice(&hash[12..32]);
    Address::new(bytes)
}

fn registration(account: Account, expires_at: Timestamp) -> DepositAddressRegistration {
    DepositAddressRegistration {
        owner: account.owner,
        subaccount: account.subaccount,
        address: deposit_address(&account),
        expires_at_nanos: expires_at,
    }
}
