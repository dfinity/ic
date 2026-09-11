use super::{AuthorizationStore, Delegation};
use crate::numeric::TransactionNonce;
use crate::state::transactions::SweepId;
use crate::test_fixtures::{account, transaction_signature};
use crate::tx::AuthorizationRequest;
use ic_ethereum_types::Address;

const DELEGATE: Address = Address::new([0xde; 20]);
const ANOTHER_DELEGATE: Address = Address::new([0x1e; 20]);
const CHAIN_ID: u64 = 11_155_111;

#[test]
fn should_hold_no_delegation_before_a_tuple_applies() {
    let mut store = AuthorizationStore::default();
    let request = authorization_request(DELEGATE, 0);

    store.record_signed(request.clone(), transaction_signature());

    assert!(store.signature(&request).is_some());
    assert_eq!(store.delegation(&account()), None);
    assert_eq!(applied_by(&store), None);
    assert_eq!(store.stored_len(), 1);
    assert_eq!(store.applied_len(), 0);
}

#[test]
fn should_apply_a_tuple_at_the_account_nonce() {
    let mut store = AuthorizationStore::default();
    let request = authorization_request(DELEGATE, 0);
    store.record_signed(request.clone(), transaction_signature());

    store.record_applied(request, SweepId(0));

    assert_eq!(
        store.delegation(&account()),
        Some(Delegation {
            delegate: DELEGATE,
            nonce: TransactionNonce::ZERO,
        })
    );
    assert_eq!(applied_by(&store), Some(SweepId(0)));
    assert_eq!(store.applied_len(), 1);
}

#[test]
fn should_keep_serving_the_signature_of_an_applied_tuple() {
    let mut store = AuthorizationStore::default();
    let request = authorization_request(DELEGATE, 0);
    store.record_signed(request.clone(), transaction_signature());

    store.record_applied(request.clone(), SweepId(0));

    assert_eq!(store.signature(&request), Some(&transaction_signature()));
}

#[test]
fn should_skip_a_tuple_whose_nonce_the_account_has_spent() {
    let mut store = AuthorizationStore::default();
    let request = authorization_request(DELEGATE, 0);
    store.record_signed(request.clone(), transaction_signature());
    store.record_applied(request.clone(), SweepId(0));

    store.record_applied(request, SweepId(1));

    assert_eq!(applied_by(&store), Some(SweepId(0)));
}

#[test]
fn should_skip_a_tuple_signed_for_a_nonce_the_account_has_not_reached() {
    let mut store = AuthorizationStore::default();
    let ahead = authorization_request(DELEGATE, 1);
    store.record_signed(ahead.clone(), transaction_signature());

    store.record_applied(ahead.clone(), SweepId(0));

    assert_eq!(store.delegation(&account()), None);
    assert!(store.signature(&ahead).is_some());
}

#[test]
fn should_drop_the_rival_tuple_the_applied_nonce_invalidated() {
    let mut store = AuthorizationStore::default();
    let incumbent = authorization_request(DELEGATE, 0);
    let rival = authorization_request(ANOTHER_DELEGATE, 0);
    store.record_signed(incumbent.clone(), transaction_signature());
    store.record_signed(rival.clone(), transaction_signature());

    store.record_applied(incumbent.clone(), SweepId(0));

    assert!(store.signature(&rival).is_none());
    assert!(store.signature(&incumbent).is_some());
    assert_eq!(store.stored_len(), 1);
    assert_eq!(
        store.delegation(&account()),
        Some(Delegation {
            delegate: DELEGATE,
            nonce: TransactionNonce::ZERO,
        })
    );
}

#[test]
fn should_keep_a_tuple_ahead_of_the_applied_nonce() {
    let mut store = AuthorizationStore::default();
    let current = authorization_request(DELEGATE, 0);
    let ahead = authorization_request(ANOTHER_DELEGATE, 1);
    store.record_signed(current.clone(), transaction_signature());
    store.record_signed(ahead.clone(), transaction_signature());

    store.record_applied(current, SweepId(0));

    assert!(store.signature(&ahead).is_some());
}

#[test]
fn should_report_the_delegate_of_the_highest_applied_nonce() {
    let mut store = AuthorizationStore::default();
    let first = authorization_request(DELEGATE, 0);
    let rotated = authorization_request(ANOTHER_DELEGATE, 1);
    store.record_signed(first.clone(), transaction_signature());
    store.record_applied(first, SweepId(0));
    store.record_signed(rotated.clone(), transaction_signature());

    store.record_applied(rotated, SweepId(1));

    assert_eq!(
        store.delegation(&account()),
        Some(Delegation {
            delegate: ANOTHER_DELEGATE,
            nonce: TransactionNonce::ONE,
        })
    );
    assert_eq!(applied_by(&store), Some(SweepId(1)));
    assert_eq!(store.applied_len(), 1);
}

#[test]
fn equality_should_notice_which_sweep_applied_a_tuple() {
    let request = authorization_request(DELEGATE, 0);
    let mut left = AuthorizationStore::default();
    left.record_signed(request.clone(), transaction_signature());
    let mut right = left.clone();

    left.record_applied(request.clone(), SweepId(0));
    right.record_applied(request, SweepId(1));

    assert_ne!(left, right);
}

#[test]
#[should_panic(expected = "BUG: a sweep carried an authorization the minter never signed")]
fn should_refuse_to_apply_a_tuple_that_was_never_signed() {
    let mut store = AuthorizationStore::default();

    store.record_applied(authorization_request(DELEGATE, 0), SweepId(0));
}

fn authorization_request(delegate: Address, nonce: u128) -> AuthorizationRequest {
    AuthorizationRequest::new(account(), CHAIN_ID, delegate, TransactionNonce::new(nonce))
}

fn applied_by(store: &AuthorizationStore) -> Option<SweepId> {
    store
        .accounts
        .get(&account())?
        .delegation
        .as_ref()
        .map(|applied| applied.applied_by)
}
