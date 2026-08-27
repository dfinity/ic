use crate::attestation::AttestationRequest;
use crate::deposit_address::{DepositAddressSchema, deposit_derivation_path};
use crate::management::CallError;
use crate::numeric::{BlockNumber, TransactionNonce, WeiPerGas};
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
use crate::tx::{Authorization, GasFeeEstimate, TransactionSignature};
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

#[tokio::test]
async fn should_sign_one_authorization_for_every_deposit_of_an_account() {
    init_state(state_ready_to_sign(&[
        (account(), usdc()),
        (account(), usdt()),
    ]));
    let mut runtime = mock();
    runtime.expect_time().return_const(NOW);
    expect_authorization_signing(&mut runtime, 2);
    expect_signing(&mut runtime);

    create_pending_sweeper_requests(&runtime).await;
}

/// Expects `times` signatures over the authorization tuple every deposit address delegates with:
/// the minter's chain, the configured sweeper contract, and nonce 0, signed along the deposit
/// address' own derivation path.
fn expect_authorization_signing(runtime: &mut MockCanisterRuntime, times: usize) {
    let digest = authorization_digest();
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
fn authorization_digest() -> [u8; 32] {
    Authorization {
        chain_id: initial_state().ethereum_network.chain_id(),
        delegate: SWEEPER_CONTRACT,
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
