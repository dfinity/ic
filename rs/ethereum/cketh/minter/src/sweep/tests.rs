use crate::attestation::AttestationRequest;
use crate::deposit_address::{DepositAddressSchema, deposit_derivation_path};
use crate::management::{CallError, Reason};
use crate::numeric::{BlockNumber, TransactionNonce, Wei, WeiPerGas};
use crate::state::audit::{EventType, apply_state_transition};
use crate::state::eth_logs_scraping::LogScrapings;
use crate::state::event::AutomaticDeposit;
use crate::state::transactions::{SweepId, SweepRequest};
use crate::state::{State, mutate_state, read_state};
use crate::storage::with_event_iter;
use crate::sweep::create_pending_sweeper_requests;
use crate::test_fixtures::mock::MockCanisterRuntime;
use crate::test_fixtures::{
    account, another_account, automatic_deposit, deposit_address, init_state, initial_state,
    prepay_sweep_gas, state_with_deposit_helper, usdc, usdt,
};
use crate::tx::{Authorization, AuthorizationRequest, GasFeeEstimate, TransactionSignature};
use ethnum::u256;
use ic_cdk_management_canister::EcdsaPublicKeyResult;
use ic_ethereum_types::Address;
use ic_secp256k1::{DerivationIndex, DerivationPath, PrivateKey};
use icrc_ledger_types::icrc1::account::Account;

const NOW: u64 = 1_620_328_630_000_000_000;
const GAS_FEE_ESTIMATE_AGE_NANOS: u64 = 1_000_000_000;
const DEPOSIT_HELPER: Address = Address::new([0xde; 20]);
const SWEEPER_CONTRACT: Address = Address::new([0x5e; 20]);
const ANOTHER_SWEEPER_CONTRACT: Address = Address::new([0x99; 20]);
const CHAIN_CODE: [u8; 32] = [0_u8; 32];

#[tokio::test]
async fn should_be_no_op_when_no_sweeper_contract() {
    let mut state = initial_state();
    state.sweeper_contract_address = None;
    init_state(state);
    let before = read_state(State::clone);

    create_pending_sweeper_requests(&mock()).await;

    assert_eq!(read_state(State::clone), before);
}

#[tokio::test]
async fn should_be_no_op_when_no_deposit_helper_contract() {
    let mut state = state_ready_to_sign(&[(account(), usdc())]);
    state.log_scrapings = LogScrapings::new(BlockNumber::ONE);
    init_state(state);
    let before = read_state(State::clone);
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);

    create_pending_sweeper_requests(&runtime).await;

    assert_eq!(read_state(State::clone), before);
}

#[tokio::test]
async fn should_not_price_an_empty_sweep_queue() {
    let mut state = state_with_deposit_helper(DEPOSIT_HELPER);
    state.sweeper_contract_address = Some(SWEEPER_CONTRACT);
    init_state(state);
    let before = read_state(State::clone);

    create_pending_sweeper_requests(&mock()).await;

    assert_eq!(read_state(State::clone), before);
}

#[tokio::test]
async fn should_sign_one_attestation_for_every_token_of_an_account() {
    init_state(state_ready_to_sign(&[
        (account(), usdc()),
        (account(), usdt()),
    ]));
    let request = attestation_request(account());
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_signing(&mut runtime);

    create_pending_sweeper_requests(&runtime).await;

    assert_eq!(
        recorded_events()
            .into_iter()
            .filter(|event| matches!(event, EventType::AttestedDepositAddress { .. }))
            .collect::<Vec<_>>(),
        vec![EventType::AttestedDepositAddress {
            request: request.clone(),
            signature: expected_signature(&request),
        }]
    );
    assert_eq!(
        read_state(|s| s.automatic_deposits.attestation(&request).cloned()),
        Some(expected_signature(&request))
    );
}

#[tokio::test]
async fn should_sign_and_record_one_authorization_for_every_account() {
    init_state(state_ready_to_sign(&[
        (account(), usdc()),
        (account(), usdt()),
    ]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_authorization_signing(&mut runtime, SWEEPER_CONTRACT, 1);
    expect_signing(&mut runtime);

    create_pending_sweeper_requests(&runtime).await;

    assert_eq!(
        recorded_events()
            .into_iter()
            .filter(|event| matches!(event, EventType::AuthorizedDepositAddress { .. }))
            .count(),
        1
    );
    assert!(stored_authorization(SWEEPER_CONTRACT).is_some());
}

#[tokio::test]
async fn should_reuse_the_recorded_authorization_on_a_later_sweep() {
    init_state(state_ready_to_sign(&[(account(), usdc())]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_authorization_signing(&mut runtime, SWEEPER_CONTRACT, 1);
    expect_signing(&mut runtime);

    create_pending_sweeper_requests(&runtime).await;
    create_pending_sweeper_requests(&runtime).await;

    assert_eq!(
        recorded_events()
            .into_iter()
            .filter(|event| matches!(event, EventType::AuthorizedDepositAddress { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn should_sign_a_fresh_authorization_when_the_sweeper_contract_changes() {
    init_state(state_ready_to_sign(&[(account(), usdc())]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_authorization_signing(&mut runtime, SWEEPER_CONTRACT, 1);
    expect_authorization_signing(&mut runtime, ANOTHER_SWEEPER_CONTRACT, 1);
    expect_signing(&mut runtime);

    create_pending_sweeper_requests(&runtime).await;
    let first = stored_authorization(SWEEPER_CONTRACT);
    assert!(first.is_some());

    mutate_state(|s| s.sweeper_contract_address = Some(ANOTHER_SWEEPER_CONTRACT));
    // The first sweep took the account's USDC, so give the second pass its USDT to batch. Same
    // account, hence the same authorization but for the delegate, which is what must miss.
    queue_deposit(&account(), &usdt());

    create_pending_sweeper_requests(&runtime).await;
    let second = stored_authorization(ANOTHER_SWEEPER_CONTRACT);
    assert!(second.is_some());
    assert_ne!(first, second);
    assert_eq!(stored_authorization(SWEEPER_CONTRACT), first);
}

#[tokio::test]
async fn should_enqueue_one_sweep_per_token() {
    init_state(state_ready_to_sign(&[
        (account(), usdc()),
        (another_account(), usdc()),
        (account(), usdt()),
    ]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_signing(&mut runtime);

    create_pending_sweeper_requests(&runtime).await;

    let enqueued = pending_sweeps();
    assert_eq!(
        enqueued.iter().map(|r| r.token).collect::<Vec<_>>(),
        vec![usdc(), usdt()]
    );
    assert_eq!(
        enqueued.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![SweepId(0), SweepId(1)]
    );

    let usdc_sweep = &enqueued[0];
    assert_eq!(
        usdc_sweep
            .items
            .iter()
            .map(|i| i.item.account)
            .collect::<Vec<_>>(),
        vec![account(), another_account()]
    );
    assert_eq!(usdc_sweep.destination, SWEEPER_CONTRACT);
    assert_eq!(usdc_sweep.created_at, NOW);
    assert!(usdc_sweep.max_transaction_fee > Wei::ZERO);
}

#[tokio::test]
async fn should_carry_the_signed_attestation_and_authorization_of_every_swept_account() {
    init_state(state_ready_to_sign(&[(account(), usdc())]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_signing(&mut runtime);

    create_pending_sweeper_requests(&runtime).await;

    let enqueued = pending_sweeps();
    let [sweep] = enqueued.as_slice() else {
        panic!("BUG: expected exactly one sweep, got {enqueued:?}");
    };
    let [item] = sweep.items.as_slice() else {
        panic!("BUG: expected exactly one item, got {:?}", sweep.items);
    };
    assert_eq!(item.item.deposit, deposit_address(&account()));
    assert_eq!(
        item.item.attestation,
        expected_signature(&attestation_request(account()))
    );
    assert_eq!(
        item.authorization,
        read_state(|s| s
            .automatic_deposits
            .authorization(&authorization_request(SWEEPER_CONTRACT))
            .map(
                |signature| authorization_request(SWEEPER_CONTRACT).signed_with(signature.clone())
            ))
    );
}

#[tokio::test]
async fn should_not_accept_a_sweep_the_sweeper_gas_cannot_pay_for() {
    init_state(state_ready_to_sign_with_unfunded_sweeper(&[(
        account(),
        usdc(),
    )]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_signing(&mut runtime);

    create_pending_sweeper_requests(&runtime).await;

    assert_eq!(
        pending_sweeps(),
        vec![],
        "a sweep whose fee the sweeper's gas cannot cover must not be accepted"
    );
    assert_eq!(
        read_state(|s| s.automatic_deposits.sweep_len()),
        1,
        "the deposit stays queued until a funding delivers the gas"
    );
}

#[tokio::test]
async fn should_not_offer_an_enqueued_deposit_to_a_second_sweep() {
    init_state(state_ready_to_sign(&[(account(), usdc())]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_signing(&mut runtime);

    create_pending_sweeper_requests(&runtime).await;
    assert_eq!(pending_sweeps().len(), 1);

    create_pending_sweeper_requests(&runtime).await;

    assert_eq!(pending_sweeps().len(), 1);
}

#[tokio::test]
async fn should_leave_out_a_deposit_whose_attestation_could_not_be_signed() {
    init_state(state_ready_to_sign(&[
        (account(), usdc()),
        (another_account(), usdc()),
    ]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    let unsignable = attestation_request(another_account()).digest().0;
    runtime
        .expect_sign_with_ecdsa()
        .withf(move |_, _, message_hash| *message_hash == unsignable)
        .returning(|_, _, _| Err(CallError::new("sign_with_ecdsa", Reason::OutOfCycles)));
    expect_signing(&mut runtime);

    create_pending_sweeper_requests(&runtime).await;

    let enqueued = pending_sweeps();
    let [sweep] = enqueued.as_slice() else {
        panic!("BUG: expected exactly one sweep, got {enqueued:?}");
    };
    assert_eq!(
        sweep
            .items
            .iter()
            .map(|item| item.item.account)
            .collect::<Vec<_>>(),
        vec![account()],
        "the account whose attestation failed must not be swept"
    );

    // It stays queued, so a later tick can try it again.
    assert_eq!(read_state(|s| s.automatic_deposits.sweep_len()), 2);
}

fn pending_sweeps() -> Vec<SweepRequest> {
    read_state(|s| s.automatic_deposits.sweep_requests_batch(usize::MAX))
}

/// Expects `times` signatures over the authorization tuple every deposit address delegates with:
/// the minter's chain, `delegate`, and nonce 0, signed along the deposit address' own derivation
/// path.
fn expect_authorization_signing(
    runtime: &mut MockCanisterRuntime,
    delegate: Address,
    times: usize,
) {
    let digest = authorization_digest(delegate);
    let path = derivation_path_bytes();
    runtime
        .expect_sign_with_ecdsa()
        .withf(move |_, derivation_path, message_hash| {
            *message_hash == digest && *derivation_path == path
        })
        .times(times)
        .returning(sign_digest_with_derived_key);
}

/// Signs whatever it is handed with the key the given path derives, the way the subnet would.
fn expect_signing(runtime: &mut MockCanisterRuntime) {
    runtime
        .expect_ecdsa_public_key()
        .return_once(move |_, _| Ok(master_public_key()));
    runtime
        .expect_sign_with_ecdsa()
        .returning(sign_digest_with_derived_key);
}

fn sign_digest_with_derived_key(
    _key_name: String,
    derivation_path: Vec<Vec<u8>>,
    message_hash: [u8; 32],
) -> Result<[u8; 64], CallError> {
    let path = DerivationPath::new(derivation_path.into_iter().map(DerivationIndex).collect());
    Ok(master_private_key()
        .derive_subkey_with_chain_code(&path, &CHAIN_CODE)
        .0
        .sign_digest_with_ecdsa(&message_hash))
}

/// Spelled out rather than taken from `delegation_authorization`, so that changing the tuple the
/// minter signs — its delegate, or the nonce 0 that makes a stale authorization skip harmlessly
/// rather than sink the sweep — fails here.
fn stored_authorization(delegate: Address) -> Option<TransactionSignature> {
    read_state(|s| {
        s.automatic_deposits
            .authorization(&authorization_request(delegate))
            .cloned()
    })
}

fn authorization_request(delegate: Address) -> AuthorizationRequest {
    AuthorizationRequest::new(
        account(),
        initial_state().ethereum_network.chain_id(),
        delegate,
        TransactionNonce::ZERO,
    )
}

fn authorization_digest(delegate: Address) -> [u8; 32] {
    Authorization {
        chain_id: initial_state().ethereum_network.chain_id(),
        delegate,
        nonce: TransactionNonce::ZERO,
    }
    .hash()
    .0
}

fn derivation_path_bytes() -> Vec<Vec<u8>> {
    deposit_derivation_path(DepositAddressSchema::CkErc20, &account())
        .into_iter()
        .map(|index| index.into_vec())
        .collect()
}

fn state_ready_to_sign(deposits: &[(Account, Address)]) -> State {
    let mut state = state_ready_to_sign_with_unfunded_sweeper(deposits);
    prepay_sweep_gas(&mut state);
    state
}

fn state_ready_to_sign_with_unfunded_sweeper(deposits: &[(Account, Address)]) -> State {
    let mut state = state_with_deposit_helper(DEPOSIT_HELPER);
    state.sweeper_contract_address = Some(SWEEPER_CONTRACT);
    state.last_transaction_price_estimate = Some((
        NOW - GAS_FEE_ESTIMATE_AGE_NANOS,
        GasFeeEstimate {
            base_fee_per_gas: WeiPerGas::ONE,
            max_priority_fee_per_gas: WeiPerGas::ONE,
        },
    ));
    for (account, token) in deposits {
        apply_state_transition(&mut state, &deposit_received(account, token));
    }
    assert_eq!(state.automatic_deposits.sweep_len(), deposits.len());
    state
}

fn queue_deposit(account: &Account, token: &Address) {
    mutate_state(|s| apply_state_transition(s, &deposit_received(account, token)));
}

fn deposit_received(account: &Account, token: &Address) -> EventType {
    EventType::AutomaticDepositReceived(AutomaticDeposit {
        owner: account.owner,
        subaccount: account.subaccount,
        address: deposit_address(account),
        erc20_contract_address: *token,
        ..automatic_deposit()
    })
}

fn attestation_request(account: Account) -> AttestationRequest {
    AttestationRequest::new(
        initial_state().ethereum_network.chain_id(),
        DEPOSIT_HELPER,
        account,
    )
}

fn derivation_path(request: &AttestationRequest) -> DerivationPath {
    DerivationPath::new(
        request
            .derivation_path()
            .iter()
            .map(|index| DerivationIndex(index.to_vec()))
            .collect(),
    )
}

fn master_private_key() -> PrivateKey {
    PrivateKey::deserialize_sec1(&[0x46_u8; 32]).unwrap()
}

fn master_public_key() -> EcdsaPublicKeyResult {
    EcdsaPublicKeyResult {
        public_key: master_private_key().public_key().serialize_sec1(true),
        chain_code: CHAIN_CODE.to_vec(),
    }
}

fn sign_with_derived_key(request: &AttestationRequest) -> [u8; 64] {
    master_private_key()
        .derive_subkey_with_chain_code(&derivation_path(request), &CHAIN_CODE)
        .0
        .sign_digest_with_ecdsa(&request.digest().0)
}

fn expected_signature(request: &AttestationRequest) -> TransactionSignature {
    let signature = sign_with_derived_key(request);
    let recovery_id = master_private_key()
        .public_key()
        .derive_subkey_with_chain_code(&derivation_path(request), &CHAIN_CODE)
        .0
        .try_recovery_from_digest(&request.digest().0, &signature)
        .unwrap();
    let (r_bytes, s_bytes) = signature.split_at(32);
    TransactionSignature {
        signature_y_parity: recovery_id.is_y_odd(),
        r: u256::from_be_bytes(r_bytes.try_into().unwrap()),
        s: u256::from_be_bytes(s_bytes.try_into().unwrap()),
    }
}

fn recorded_events() -> Vec<EventType> {
    with_event_iter(|events| events.map(|event| event.payload).collect())
}

fn mock() -> MockCanisterRuntime {
    MockCanisterRuntime::new()
}
