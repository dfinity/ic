use crate::attestation::AttestationRequest;
use crate::numeric::{BlockNumber, WeiPerGas};
use crate::state::audit::{EventType, apply_state_transition};
use crate::state::eth_logs_scraping::LogScrapings;
use crate::state::event::AutomaticDeposit;
use crate::state::{State, read_state};
use crate::storage::with_event_iter;
use crate::sweep::create_pending_sweeper_requests;
use crate::test_fixtures::mock::MockCanisterRuntime;
use crate::test_fixtures::{
    account, automatic_deposit, deposit_address, init_state, initial_state,
    state_with_deposit_helper, usdc, usdt,
};
use crate::tx::{GasFeeEstimate, TransactionSignature};
use ethnum::u256;
use ic_cdk_management_canister::EcdsaPublicKeyResult;
use ic_ethereum_types::Address;
use ic_secp256k1::{DerivationIndex, DerivationPath, PrivateKey};
use icrc_ledger_types::icrc1::account::Account;

const NOW: u64 = 1_620_328_630_000_000_000;
const GAS_FEE_ESTIMATE_AGE_NANOS: u64 = 1_000_000_000;
const DEPOSIT_HELPER: Address = Address::new([0xde; 20]);
const SWEEPER_CONTRACT: Address = Address::new([0x5e; 20]);
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
    // Everything the earlier guards want, so that the run reaches the deposit helper: without a
    // sweeper contract and a queued deposit it would return before ever reading the helper.
    let mut state = state_ready_to_sign(&[(account(), usdc())]);
    state.log_scrapings = LogScrapings::new(BlockNumber::ONE);
    init_state(state);
    let before = read_state(State::clone);
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);

    // No signing expectation: getting past the helper would be an unexpected call and fail here.
    create_pending_sweeper_requests(&runtime).await;

    assert_eq!(read_state(State::clone), before);
}

#[tokio::test]
async fn should_not_price_an_empty_sweep_queue() {
    let mut state = state_with_deposit_helper(DEPOSIT_HELPER);
    state.sweeper_contract_address = Some(SWEEPER_CONTRACT);
    init_state(state);
    let before = read_state(State::clone);

    // No `expect_time`: refreshing the gas fee estimate reads the clock, so pricing a queue with
    // nothing to sweep would be an unexpected call and fail here.
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
    let signature = sign_with_derived_key(&request);
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    runtime
        .expect_ecdsa_public_key()
        .times(1)
        .return_once(move |_, _| Ok(master_public_key()));
    runtime
        .expect_sign_with_ecdsa()
        .times(1)
        .return_once(move |_, _, _| Ok(signature));

    create_pending_sweeper_requests(&runtime).await;

    assert_eq!(
        recorded_events(),
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

fn state_ready_to_sign(deposits: &[(Account, Address)]) -> State {
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
        apply_state_transition(
            &mut state,
            &EventType::AutomaticDepositReceived(AutomaticDeposit {
                owner: account.owner,
                subaccount: account.subaccount,
                address: deposit_address(account),
                erc20_contract_address: *token,
                ..automatic_deposit()
            }),
        );
    }
    assert_eq!(state.automatic_deposits.sweep_len(), deposits.len());
    state
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
