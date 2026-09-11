use crate::asset::Asset;
use crate::attestation::AttestationRequest;
use crate::balance_scan::batcher::Delegation;
use crate::deposit_address::{AddressSchema, DepositAddress};
use crate::eth_rpc::Hash;
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::management::{CallError, Reason};
use crate::numeric::{BlockNumber, GasAmount, TransactionNonce, Wei, WeiPerGas};
use crate::state::audit::{EventType, apply_state_transition, process_event};
use crate::state::eth_logs_scraping::LogScrapings;
use crate::state::event::AutomaticDeposit;
use crate::state::transactions::{PipelineRequest, SweepId, SweepRequest};
use crate::state::{State, mutate_state, read_state};
use crate::storage::with_event_iter;
use crate::sweep::{create_pending_sweeper_requests, enqueue_pending_sweeps};
use crate::test_fixtures::mock::MockCanisterRuntime;
use crate::test_fixtures::{
    LATEST_BLOCK, account, another_account, automatic_deposit, delegation_response,
    deposit_address, init_state, initial_state, prepay_sweep_gas, state_with_deposit_helper,
    stub_rpc_client, transaction_signature, usdc, usdt,
};
use crate::tx::{
    Authorization, AuthorizationRequest, GasFeeEstimate, SignableTransaction, Signed,
    TransactionSignature,
};
use ethnum::u256;
use evm_rpc_types::{Hex, MultiRpcResult};
use ic_canister_runtime::IcError;
use ic_cdk_management_canister::EcdsaPublicKeyResult;
use ic_ethereum_types::Address;
use ic_secp256k1::{DerivationIndex, DerivationPath, PrivateKey};
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeMap;

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

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;

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

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;

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

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;

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

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;
    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;

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

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;
    let first = stored_authorization(SWEEPER_CONTRACT);
    assert!(first.is_some());

    mutate_state(|s| s.sweeper_contract_address = Some(ANOTHER_SWEEPER_CONTRACT));
    // The first sweep took the account's USDC, so give the second pass its USDT to batch. Same
    // account, hence the same authorization but for the delegate, which is what must miss.
    queue_deposit(&account(), &usdt());

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;
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

    enqueue(
        &runtime,
        &[
            (account(), Delegation::NotDelegated),
            (another_account(), Delegation::NotDelegated),
        ],
    )
    .await;

    let enqueued = pending_sweeps();
    assert_eq!(
        enqueued.iter().map(|r| r.asset).collect::<Vec<_>>(),
        vec![Asset::Erc20(usdc()), Asset::Erc20(usdt())]
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

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;

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
        read_state(|s| {
            let request = authorization_request(SWEEPER_CONTRACT, TransactionNonce::ZERO);
            s.automatic_deposits
                .authorization(&request)
                .map(|signature| request.signed_with(signature.clone()))
        })
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

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;

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

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;
    assert_eq!(pending_sweeps().len(), 1);

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;

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

    enqueue(
        &runtime,
        &[
            (account(), Delegation::NotDelegated),
            (another_account(), Delegation::NotDelegated),
        ],
    )
    .await;

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

#[tokio::test]
async fn should_sweep_a_delegated_address_without_an_authorization() {
    init_state(state_ready_to_sign(&[(account(), usdc())]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_signing(&mut runtime);

    enqueue(
        &runtime,
        &[(account(), Delegation::Delegated(SWEEPER_CONTRACT))],
    )
    .await;

    let enqueued = pending_sweeps();
    let [sweep] = enqueued.as_slice() else {
        panic!("BUG: expected exactly one sweep, got {enqueued:?}");
    };
    let [item] = sweep.items.as_slice() else {
        panic!("BUG: expected exactly one item, got {:?}", sweep.items);
    };
    assert_eq!(
        item.authorization, None,
        "an address already delegated to the sweeper contract must be swept carrying no tuple"
    );
    assert_eq!(
        recorded_events()
            .into_iter()
            .filter(|event| matches!(event, EventType::AuthorizedDepositAddress { .. }))
            .count(),
        0,
        "signing a tuple the sweep does not carry would pay for a threshold signature for nothing"
    );
    assert_eq!(
        sweep.gas_limit(),
        GasAmount::new(185_000),
        "the sweep must not budget the gas of a tuple it does not carry"
    );
}

#[tokio::test]
async fn should_leave_out_an_address_holding_other_code() {
    init_state(state_ready_to_sign(&[
        (account(), usdc()),
        (another_account(), usdc()),
    ]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_signing(&mut runtime);

    enqueue(
        &runtime,
        &[
            (account(), Delegation::Other),
            (another_account(), Delegation::NotDelegated),
        ],
    )
    .await;

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
        vec![another_account()],
        "an address holding contract code cannot be delegated, so it must not be swept"
    );
    assert_eq!(read_state(|s| s.automatic_deposits.sweep_len()), 2);
}

#[tokio::test]
async fn should_skip_the_tick_when_the_delegation_read_fails() {
    let truncated_blob = Ok(MultiRpcResult::Consistent(Ok(Hex::from(vec![0_u8; 5]))));
    for response in [Err(IcError::CallPerformFailed), truncated_blob] {
        init_state(state_ready_to_sign(&[(account(), usdc())]));
        let before = read_state(State::clone);
        let mut runtime = mock();
        runtime.expect_time().return_const(NOW);

        enqueue_pending_sweeps(&runtime, &stub_rpc_client(vec![response])).await;

        assert_eq!(
            read_state(State::clone),
            before,
            "a tick that cannot read the delegations must leave the queue untouched"
        );
        assert_eq!(recorded_events(), vec![]);
    }
}

#[tokio::test]
async fn should_read_delegations_once_for_every_asset_of_a_tick() {
    init_state(state_ready_to_sign(&[
        (account(), usdc()),
        (account(), usdt()),
        (another_account(), usdc()),
        (another_account(), usdt()),
    ]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_signing(&mut runtime);

    enqueue(
        &runtime,
        &[
            (account(), Delegation::NotDelegated),
            (another_account(), Delegation::NotDelegated),
        ],
    )
    .await;

    assert_eq!(
        pending_sweeps().len(),
        2,
        "the one stubbed answer must serve both assets: a second read has nothing to answer it"
    );
}

#[tokio::test]
async fn should_skip_the_tick_when_the_sweeper_contract_changed_since_the_read() {
    init_state(state_ready_to_sign(&[(account(), usdc())]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    runtime
        .expect_ecdsa_public_key()
        .returning(|_, _| Ok(master_public_key()));
    runtime
        .expect_sign_with_ecdsa()
        .returning(|key_name, derivation_path, message_hash| {
            mutate_state(|s| s.sweeper_contract_address = Some(ANOTHER_SWEEPER_CONTRACT));
            sign_digest_with_derived_key(key_name, derivation_path, message_hash)
        });

    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;

    assert_eq!(
        pending_sweeps(),
        vec![],
        "a tuple naming a contract the sweep no longer calls must not be sent"
    );
    assert_eq!(
        read_state(|s| s.automatic_deposits.sweep_len()),
        1,
        "the deposit stays queued for a tick reading against the new contract"
    );
}

#[tokio::test]
async fn should_skip_the_tick_when_the_sweeper_contract_changed_since_a_tuple_less_read() {
    init_state(state_ready_to_sign(&[(account(), usdc())]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    runtime
        .expect_ecdsa_public_key()
        .returning(|_, _| Ok(master_public_key()));
    runtime
        .expect_sign_with_ecdsa()
        .returning(|key_name, derivation_path, message_hash| {
            mutate_state(|s| s.sweeper_contract_address = Some(ANOTHER_SWEEPER_CONTRACT));
            sign_digest_with_derived_key(key_name, derivation_path, message_hash)
        });

    enqueue(
        &runtime,
        &[(account(), Delegation::Delegated(SWEEPER_CONTRACT))],
    )
    .await;

    assert_eq!(
        pending_sweeps(),
        vec![],
        "an address read as delegated to the contract the sweep no longer calls must not be swept without a tuple"
    );
    assert_eq!(
        read_state(|s| s.automatic_deposits.sweep_len()),
        1,
        "the deposit stays queued for a tick reading against the new contract"
    );
}

#[tokio::test]
async fn should_sign_a_rotation_authorization_at_the_tracked_nonce() {
    init_state(state_ready_to_sign(&[(account(), usdc())]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_signing(&mut runtime);
    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;
    finalize_sweep_through_the_event_log(&one_pending_sweep(), &runtime);
    queue_deposit(&account(), &usdc());

    enqueue(
        &runtime,
        &[(account(), Delegation::Delegated(ANOTHER_SWEEPER_CONTRACT))],
    )
    .await;

    let rotation = authorization_request(SWEEPER_CONTRACT, TransactionNonce::ONE);
    assert_eq!(
        recorded_events()
            .into_iter()
            .filter(|event| matches!(event, EventType::AuthorizedDepositAddress { request, .. } if *request == rotation))
            .count(),
        1,
        "rotating an address onto the configured contract must sign a tuple for the nonce the \
         address has reached"
    );
    let sweep = one_pending_sweep();
    let [item] = sweep.items.as_slice() else {
        panic!("BUG: expected exactly one item, got {:?}", sweep.items);
    };
    assert_eq!(
        item.authorization,
        read_state(|s| s
            .automatic_deposits
            .authorization(&rotation)
            .map(|signature| rotation.signed_with(signature.clone()))),
        "the sweep must carry the rotation, which is what makes it a type-0x04 transaction"
    );
}

#[tokio::test]
async fn should_rebuild_the_delegation_nonce_from_the_event_log() {
    init_state(state_ready_to_sign(&[(account(), usdc())]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_signing(&mut runtime);
    enqueue(&runtime, &[(account(), Delegation::NotDelegated)]).await;

    finalize_sweep_through_the_event_log(&one_pending_sweep(), &runtime);

    let live = read_state(|s| s.automatic_deposits.clone());
    assert_eq!(
        live.delegation_nonce(&deposit_address(&account())),
        TransactionNonce::ONE
    );
    let mut replayed = state_ready_to_sign(&[(account(), usdc())]);
    for event in recorded_events() {
        apply_state_transition(&mut replayed, &event);
    }
    assert_eq!(
        replayed.automatic_deposits.is_equivalent_to(&live),
        Ok(()),
        "the nonce a sweep spent must be rebuilt by replaying the log, without an event of its own"
    );
}

/// Drives `request` through create, sign, fee bump and a successful receipt, recording every event
/// the production path records so that the log can be replayed.
///
/// The transaction is created below the fee the request was priced at, leaving the headroom the
/// bump needs, and the receipt finalizes the transaction actually sent rather than its replacement.
fn finalize_sweep_through_the_event_log(request: &SweepRequest, runtime: &MockCanisterRuntime) {
    let free_gas = GasFeeEstimate {
        base_fee_per_gas: WeiPerGas::ZERO,
        max_priority_fee_per_gas: WeiPerGas::ZERO,
    };
    let create = |estimate, nonce| {
        request
            .create_transaction(
                nonce,
                estimate,
                request.gas_limit(),
                initial_state().ethereum_network,
            )
            .expect("BUG: the sweep must be priced for the estimate it is created with")
    };
    let transaction = mutate_state(|s| {
        let nonce = s.automatic_deposits.next_sweeper_transaction_nonce();
        let transaction = create(free_gas, nonce);
        process_event(
            s,
            EventType::CreatedSweeperTransaction {
                sweep_id: request.id,
                transaction: transaction.clone(),
            },
            runtime,
        );
        transaction
    });
    let signed = Signed::from((transaction.clone(), transaction_signature()));
    let receipt = TransactionReceipt {
        block_hash: Hash([0x11; 32]),
        block_number: BlockNumber::new(4_190_269),
        effective_gas_price: signed.transaction().max_fee_per_gas(),
        gas_used: signed.transaction().gas_limit(),
        status: TransactionStatus::Success,
        transaction_hash: signed.hash(),
    };
    let bumped = create(priced_gas_fee_estimate(), transaction.nonce());
    mutate_state(|s| {
        for event in [
            EventType::SignedSweeperTransaction {
                sweep_id: request.id,
                transaction: signed,
            },
            EventType::ReplacedSweeperTransaction {
                sweep_id: request.id,
                transaction: bumped,
            },
            EventType::FinalizedSweeperTransaction {
                sweep_id: request.id,
                transaction_receipt: receipt,
            },
        ] {
            process_event(s, event, runtime);
        }
    });
}

/// The estimate every sweep here is priced with, and so the highest one a transaction of it can be
/// created at.
fn priced_gas_fee_estimate() -> GasFeeEstimate {
    GasFeeEstimate {
        base_fee_per_gas: WeiPerGas::ONE,
        max_priority_fee_per_gas: WeiPerGas::ONE,
    }
}

fn one_pending_sweep() -> SweepRequest {
    let enqueued = pending_sweeps();
    let [request] = enqueued.as_slice() else {
        panic!("BUG: expected exactly one sweep, got {enqueued:?}");
    };
    request.clone()
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
            .authorization(&authorization_request(delegate, TransactionNonce::ZERO))
            .cloned()
    })
}

fn authorization_request(delegate: Address, nonce: TransactionNonce) -> AuthorizationRequest {
    AuthorizationRequest::new(
        account(),
        initial_state().ethereum_network.chain_id(),
        delegate,
        nonce,
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
    AddressSchema::Deposit(account())
        .derivation_path()
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
    state.latest_block_height = Some(LATEST_BLOCK);
    state.last_transaction_price_estimate =
        Some((NOW - GAS_FEE_ESTIMATE_AGE_NANOS, priced_gas_fee_estimate()));
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
        asset: Asset::Erc20(*token),
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

/// Runs one enqueue tick against a client answering its single delegation read with `delegations`.
async fn enqueue(runtime: &MockCanisterRuntime, delegations: &[(Account, Delegation)]) {
    enqueue_pending_sweeps(
        runtime,
        &stub_rpc_client(vec![delegation_read(delegations)]),
    )
    .await;
}

/// The answer to a delegation read of these accounts' addresses, ordered as the read lists them.
fn delegation_read(delegations: &[(Account, Delegation)]) -> Result<MultiRpcResult<Hex>, IcError> {
    let by_address: BTreeMap<DepositAddress, Delegation> = delegations
        .iter()
        .map(|(account, delegation)| (deposit_address(account), *delegation))
        .collect();
    delegation_response(&by_address.into_values().collect::<Vec<_>>())
}
