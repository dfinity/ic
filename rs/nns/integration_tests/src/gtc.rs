use candid::{Decode, Encode};
use ic_base_types::PrincipalId;
use ic_canister_client_sender::Sender;
use ic_ledger_core::tokens::CheckedAdd;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_KEYPAIR,
    TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID};
use ic_nns_governance_api::{GovernanceError, Neuron, NeuronInfo};
use ic_nns_gtc::{
    pb::v1::AccountState,
    test_constants::{
        TEST_IDENTITY_1, TEST_IDENTITY_2, TEST_IDENTITY_3, TEST_IDENTITY_4, TestIdentity,
    },
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        get_neuron_ids, ledger_account_balance, nns_governance_get_full_neuron,
        nns_governance_get_neuron_info, setup_nns_canisters, state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::StateMachine;
use ic_types::ingress::WasmResult;
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, DEFAULT_TRANSFER_FEE, Subaccount, Tokens,
};
use std::{collections::HashSet, convert::TryFrom, sync::Arc, time::SystemTime};

/// Seed Round (SR) neurons are released over 48 months in the following tests
pub const SR_MONTHS_TO_RELEASE: u8 = 48;

/// Early Contributor Token holder (ECT) neurons are released over 12 months in
/// the following tests
pub const ECT_MONTHS_TO_RELEASE: u8 = 12;

const TEST_SR_ACCOUNTS: &[(&str, u32); 2] = &[
    (TEST_IDENTITY_1.gtc_address, 1200),
    (TEST_IDENTITY_3.gtc_address, 14500),
];

const TEST_ECT_ACCOUNTS: &[(&str, u32); 2] = &[
    (TEST_IDENTITY_2.gtc_address, 8544),
    (TEST_IDENTITY_4.gtc_address, 3789),
];

/// Test the GTC's `claim_neurons` method (and associated methods
/// `account_has_claimed_neurons` and `permanently_lock_account`)
#[test]
pub fn test_claim_neurons() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let mut nns_init_payload_builder = NnsInitPayloadsBuilder::new();
    add_test_gtc_neurons(&mut nns_init_payload_builder);

    let donate_account_recipient_neuron_id =
        get_donate_account_recipient_neuron_id(&nns_init_payload_builder);

    nns_init_payload_builder
        .genesis_token
        .donate_account_recipient_neuron_id = Some(donate_account_recipient_neuron_id);

    let forward_all_unclaimed_accounts_recipient_neuron_id =
        get_forward_whitelisted_unclaimed_accounts_recipient_neuron_id(&nns_init_payload_builder);

    nns_init_payload_builder
        .genesis_token
        .forward_whitelisted_unclaimed_accounts_recipient_neuron_id =
        Some(forward_all_unclaimed_accounts_recipient_neuron_id);

    let nns_init_payload = nns_init_payload_builder.build();

    let identity_1_neuron_ids = nns_init_payload
        .genesis_token
        .accounts
        .get(TEST_IDENTITY_1.gtc_address)
        .unwrap()
        .neuron_ids
        .clone();
    assert_eq!(identity_1_neuron_ids.len(), SR_MONTHS_TO_RELEASE as usize);

    let identity_2_neuron_ids = nns_init_payload
        .genesis_token
        .accounts
        .get(TEST_IDENTITY_2.gtc_address)
        .unwrap()
        .neuron_ids
        .clone();
    assert_eq!(identity_2_neuron_ids.len(), ECT_MONTHS_TO_RELEASE as usize);

    setup_nns_canisters(&state_machine, nns_init_payload);
    state_machine.set_time(SystemTime::now());

    assert_neurons_can_only_be_claimed_by_account_owner(&state_machine);
    assert_neurons_can_only_be_donated_by_account_owner(&state_machine);

    assert_neurons_can_be_donated(
        &state_machine,
        donate_account_recipient_neuron_id,
        &TEST_NEURON_1_OWNER_KEYPAIR,
        &TEST_IDENTITY_3,
    );

    // Assert that a Seed Round (SR) investor can claim their tokens
    assert_neurons_can_be_claimed(&state_machine, identity_1_neuron_ids, &TEST_IDENTITY_1);

    // Try to forward the whitelisted account. Note that this should only forward
    // the whitelisted account so a non-whitelisted account should still be
    // able to claim afterwards.
    assert_unclaimed_neurons_can_be_forwarded(
        &state_machine,
        forward_all_unclaimed_accounts_recipient_neuron_id,
        &TEST_NEURON_2_OWNER_KEYPAIR,
    );

    // Assert that an Early Contributor Token holder (ECT) investor can claim their
    // tokens
    assert_neurons_can_be_claimed(&state_machine, identity_2_neuron_ids, &TEST_IDENTITY_2);
}

/// At Genesis, calls to `claim_neurons` and `forward_all_unclaimed_accounts`
/// should fail, as they both depend on a certain amount of time passing before
/// they are able to be called.
#[test]
pub fn test_gtc_at_genesis() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let mut nns_init_payload_builder = NnsInitPayloadsBuilder::new();
    add_test_gtc_neurons(&mut nns_init_payload_builder);

    // Set the Genesis Moratorium to start now
    nns_init_payload_builder
        .genesis_token
        .genesis_timestamp_seconds = SystemTime::now().elapsed().unwrap().as_secs();

    let nns_init_payload = nns_init_payload_builder.build();

    setup_nns_canisters(&state_machine, nns_init_payload);

    let sign_cmd = move |msg: &[u8]| Ok(TEST_IDENTITY_1.sign(msg));
    let sender = Sender::ExternalHsm {
        pub_key: TEST_IDENTITY_1.public_key().serialize_der(),
        sign: Arc::new(sign_cmd),
    };

    // Assert `claim_neurons` fails during the moratorium
    let claim_neurons_response: Result<Vec<NeuronId>, String> =
        claim_neurons(&state_machine, sender.get_principal_id(), &TEST_IDENTITY_1);
    assert!(claim_neurons_response.is_err());

    // Assert that `TEST_IDENTITY_1` did not claim their neurons
    let account_has_claimed_neurons_response: Result<AccountState, String> =
        get_gtc_account(&state_machine, &TEST_IDENTITY_1);
    assert!(!account_has_claimed_neurons_response.unwrap().has_claimed);

    // Assert that `forward_all_unclaimed_accounts` fails
    let forward_all_unclaimed_accounts_response: Result<(), String> =
        forward_whitelisted_unclaimed_accounts(&state_machine, &sender);
    assert!(forward_all_unclaimed_accounts_response.is_err());
}

/// Assert that users can't claim other users' neurons
///
/// Identity 3 tries to claim Identity 1's neurons, but fails to do so
fn assert_neurons_can_only_be_claimed_by_account_owner(state_machine: &StateMachine) {
    // Assert that one user can't claim another user's neurons
    let claim_neurons_response = claim_neurons(
        state_machine,
        TEST_IDENTITY_3.principal_id(),
        &TEST_IDENTITY_1,
    );

    assert!(claim_neurons_response.is_err());
}

/// Assert that users can't donate other users' neurons
///
/// Identity 3 tries to donate Identity 1's neurons, but fails to do so
fn assert_neurons_can_only_be_donated_by_account_owner(state_machine: &StateMachine) {
    // Assert that one user can't donate another user's neurons
    let donate_account_response = donate_accounts(
        state_machine,
        TEST_IDENTITY_3.principal_id(),
        &TEST_IDENTITY_1,
    );
    assert!(donate_account_response.is_err());
}

/// Assert that any user can forward an unclaimed GTC account.
///
/// This assumes the window after Genesis, during which the forwarding of
/// unclaimed accounts is forbidden, has expired.
fn assert_unclaimed_neurons_can_be_forwarded(
    state_machine: &StateMachine,
    custodian_neuron_id: NeuronId,
    custodian_key_pair: &ic_canister_client_sender::Ed25519KeyPair,
) {
    let sign_cmd = move |msg: &[u8]| Ok(TEST_IDENTITY_1.sign(msg));
    let sender = Sender::ExternalHsm {
        pub_key: TEST_IDENTITY_1.public_key().serialize_der(),
        sign: Arc::new(sign_cmd),
    };

    let custodian_principal_id = Sender::from_keypair(custodian_key_pair).get_principal_id();

    // Assert that `TEST_IDENTITY_4` has not yet claimed or donated their neurons
    let get_account_response: Result<AccountState, String> =
        get_gtc_account(state_machine, &TEST_IDENTITY_4);
    let account_before_forward = get_account_response.unwrap();
    assert!(!account_before_forward.has_claimed);
    assert!(!account_before_forward.has_donated);
    assert!(!account_before_forward.has_forwarded);

    // Calculate how much ICP is expected to be forwarded to the custodian
    // neuron.
    let expected_custodian_account_balance_increase: Tokens = Tokens::from_e8s(
        Tokens::from_tokens(account_before_forward.icpts as u64)
            .unwrap()
            .get_e8s()
            - (DEFAULT_TRANSFER_FEE.get_e8s() * account_before_forward.neuron_ids.len() as u64),
    );

    // Get the custodian neuron and its ledger account, so that we can later
    // assert that the account value has increased (as the result of
    // forwarding).
    let custodian_neuron = nns_governance_get_full_neuron(
        state_machine,
        custodian_principal_id,
        custodian_neuron_id.id,
    )
    .unwrap();
    let custodian_subaccount = Subaccount::try_from(&custodian_neuron.account[..]).unwrap();
    let custodian_account =
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(custodian_subaccount));

    let custodian_account_balance = ledger_account_balance(
        state_machine,
        LEDGER_CANISTER_ID,
        &BinaryAccountBalanceArgs {
            account: custodian_account.to_address(),
        },
    );
    let expected_custodian_account_balance_after_forward = custodian_account_balance
        .checked_add(&expected_custodian_account_balance_increase)
        .unwrap();

    // Have `TEST_IDENTITY_1` forward `TEST_IDENTITY_2`'s and `TEST_IDENTITY_4`'s
    // neurons
    let forward_whitelisted_unclaimed_accounts_response: Result<(), String> =
        forward_whitelisted_unclaimed_accounts(state_machine, &sender);
    assert!(forward_whitelisted_unclaimed_accounts_response.is_ok());

    // Assert that the forward updated the account state as expected
    let get_account_response: Result<AccountState, String> =
        get_gtc_account(state_machine, &TEST_IDENTITY_4);
    let account_after_forward = get_account_response.unwrap();
    assert!(!account_after_forward.has_claimed);
    assert!(!account_after_forward.has_donated);
    assert!(account_after_forward.has_forwarded);
    assert_eq!(account_after_forward.authenticated_principal_id, None);
    assert_eq!(
        account_after_forward.successfully_transferred_neurons.len(),
        account_before_forward.neuron_ids.len(),
    );

    // But has not forwarded not whitelisted accounts.

    // Assert that the custodian neuron's ledger account has received the
    // forwarded funds
    let actual_custodian_account_balance_after_forward = ledger_account_balance(
        state_machine,
        LEDGER_CANISTER_ID,
        &BinaryAccountBalanceArgs {
            account: custodian_account.to_address(),
        },
    );

    assert_eq!(
        expected_custodian_account_balance_after_forward,
        actual_custodian_account_balance_after_forward
    );

    // Assert that the custodian neuron's stake matches its ledger account
    // balance
    let custodian_neuron = nns_governance_get_full_neuron(
        state_machine,
        custodian_principal_id,
        custodian_neuron_id.id,
    )
    .unwrap();
    let custodian_neuron_stake = Tokens::from_e8s(custodian_neuron.cached_neuron_stake_e8s);

    assert_eq!(
        custodian_neuron_stake,
        actual_custodian_account_balance_after_forward
    );
}

/// Assert that GTC neurons can be donated by the owner of the GTC account
fn assert_neurons_can_be_donated(
    state_machine: &StateMachine,
    custodian_neuron_id: NeuronId,
    custodian_key_pair: &ic_canister_client_sender::Ed25519KeyPair,
    test_identity: &'static TestIdentity,
) {
    let sign_cmd = move |msg: &[u8]| Ok(test_identity.sign(msg));
    let sender = Sender::ExternalHsm {
        pub_key: test_identity.public_key().serialize_der(),
        sign: Arc::new(sign_cmd),
    };

    let custodian_principal_id = Sender::from_keypair(custodian_key_pair).get_principal_id();

    // Assert that `test_identity` has not yet claimed or donated their neurons
    let get_account_response: Result<AccountState, String> =
        get_gtc_account(state_machine, test_identity);
    let account_before_donation = get_account_response.unwrap();
    assert!(!account_before_donation.has_claimed);
    assert!(!account_before_donation.has_donated);
    assert!(!account_before_donation.has_forwarded);

    // Calculate how much ICP is expected to be donated to the custodian
    // neuron.
    let expected_custodian_account_balance_increase: Tokens = Tokens::from_e8s(
        Tokens::from_tokens(account_before_donation.icpts as u64)
            .unwrap()
            .get_e8s()
            - (DEFAULT_TRANSFER_FEE.get_e8s() * account_before_donation.neuron_ids.len() as u64),
    );

    // Get the custodian neuron and its ledger account, so that we can later
    // assert that the account value has increased (as the result of a
    // donation).
    let custodian_neuron = nns_governance_get_full_neuron(
        state_machine,
        custodian_principal_id,
        custodian_neuron_id.id,
    )
    .unwrap();
    let custodian_subaccount = Subaccount::try_from(&custodian_neuron.account[..]).unwrap();
    let custodian_account =
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(custodian_subaccount));
    let custodian_account_balance = ledger_account_balance(
        state_machine,
        LEDGER_CANISTER_ID,
        &BinaryAccountBalanceArgs {
            account: custodian_account.to_address(),
        },
    );

    let expected_custodian_account_balance_after_donation = custodian_account_balance
        .checked_add(&expected_custodian_account_balance_increase)
        .unwrap();

    // Have `test_identity` donate their neurons
    let donate_account_response: Result<(), String> =
        donate_accounts(state_machine, sender.get_principal_id(), test_identity);
    assert!(donate_account_response.is_ok());

    // Assert that `test_identity` has donated their neurons
    let get_account_response: Result<AccountState, String> =
        get_gtc_account(state_machine, test_identity);
    let account_after_donation = get_account_response.unwrap();
    assert!(account_after_donation.has_donated);
    assert_eq!(
        account_after_donation.authenticated_principal_id,
        Some(test_identity.principal_id())
    );
    assert_eq!(
        account_after_donation
            .successfully_transferred_neurons
            .len(),
        account_before_donation.neuron_ids.len(),
    );

    // Assert that donated neurons can't be claimed
    let claim_neurons_response: Result<Vec<NeuronId>, String> =
        claim_neurons(state_machine, sender.get_principal_id(), test_identity);
    assert!(claim_neurons_response.is_err());

    // Assert calling donate a second time fails
    let donate_account_response: Result<(), String> =
        donate_accounts(state_machine, sender.get_principal_id(), test_identity);
    assert!(donate_account_response.is_err());

    // Assert that the custodian neuron's ledger account has received the
    // donated funds
    let actual_custodian_account_balance_after_donation = ledger_account_balance(
        state_machine,
        LEDGER_CANISTER_ID,
        &BinaryAccountBalanceArgs {
            account: custodian_account.to_address(),
        },
    );

    assert_eq!(
        expected_custodian_account_balance_after_donation,
        actual_custodian_account_balance_after_donation
    );

    // Assert that the custodian neuron's stake matches its ledger account
    // balance
    let custodian_neuron = nns_governance_get_full_neuron(
        state_machine,
        custodian_principal_id,
        custodian_neuron_id.id,
    )
    .unwrap();

    let custodian_neuron_stake = Tokens::from_e8s(custodian_neuron.cached_neuron_stake_e8s);

    assert_eq!(
        custodian_neuron_stake,
        actual_custodian_account_balance_after_donation
    );
}

/// Test that the given `test_identity` can claim their neurons, expected to
/// be `expected_neuron_ids`.
fn assert_neurons_can_be_claimed(
    state_machine: &StateMachine,
    expected_neuron_ids: Vec<NeuronId>,
    test_identity: &'static TestIdentity,
) {
    let sign_cmd = move |msg: &[u8]| Ok(test_identity.sign(msg));
    let sender = Sender::ExternalHsm {
        pub_key: test_identity.public_key().serialize_der(),
        sign: Arc::new(sign_cmd),
    };
    // Assert that `test_identity` has not yet claimed their neurons
    let get_account_response: Result<AccountState, String> =
        get_gtc_account(state_machine, test_identity);
    assert!(!get_account_response.unwrap().has_claimed);

    // Assert that `test_identity` does not control any neurons in the Governance
    // canister
    let get_neuron_ids_response: Vec<u64> =
        get_neuron_ids(state_machine, sender.get_principal_id());
    assert!(get_neuron_ids_response.is_empty());

    // Given a sample neuron ID from `expected_neuron_ids`, assert that we can
    // can get this neuron's info via the `get_neuron_info` Governance method,
    // but `get_full_neuron` returns an error (as `test_identity` does not
    // control the neuron yet)
    let sample_neuron_id = expected_neuron_ids.last().unwrap().id;
    let get_neuron_info_response: Result<NeuronInfo, GovernanceError> =
        nns_governance_get_neuron_info(state_machine, sender.get_principal_id(), sample_neuron_id);
    assert!(get_neuron_info_response.is_ok());

    let get_full_neuron_response =
        nns_governance_get_full_neuron(state_machine, sender.get_principal_id(), sample_neuron_id);
    assert!(get_full_neuron_response.is_err());

    // Call the GTC to claim neurons for `test_identity`
    let gtc_response: Result<Vec<NeuronId>, String> =
        claim_neurons(state_machine, sender.get_principal_id(), test_identity);
    let returned_neuron_ids = gtc_response.unwrap();

    let get_neuron_ids_response: Vec<u64> =
        get_neuron_ids(state_machine, sender.get_principal_id());
    let controlled_neuron_ids: Vec<NeuronId> = get_neuron_ids_response
        .into_iter()
        .map(|id| NeuronId { id })
        .collect();

    // Assert that the neuron IDs:
    //   * returned by the GTC's `claim_neurons` method
    //   * returned by the Governance's `get_neuron_ids` method
    //   * given by `expected_neuron_ids`
    // all contain the exact same set of neuron IDs
    let returned_neuron_ids_set: HashSet<NeuronId> = returned_neuron_ids.iter().cloned().collect();
    let expected_neuron_ids_set: HashSet<NeuronId> = expected_neuron_ids.iter().cloned().collect();
    let controlled_neuron_ids_set: HashSet<NeuronId> =
        controlled_neuron_ids.iter().cloned().collect();
    assert_eq!(returned_neuron_ids_set, expected_neuron_ids_set);
    assert_eq!(controlled_neuron_ids_set, expected_neuron_ids_set);

    // Assert that `test_identity` has now claimed their neurons
    let get_account_response: Result<AccountState, String> =
        get_gtc_account(state_machine, test_identity);
    assert!(get_account_response.unwrap().has_claimed);

    // Assert that calling `get_full_neuron` with `sample_neuron_id` now
    // returns successfully, as `test_identity` now controls this neuron
    let governance_response: Result<Neuron, GovernanceError> =
        nns_governance_get_full_neuron(state_machine, sender.get_principal_id(), sample_neuron_id);
    let neuron = governance_response.unwrap();
    assert_eq!(neuron.controller, Some(test_identity.principal_id()));

    // Assert that calling `claim_neurons` a second time returns the same set
    // of neuron IDs
    let gtc_response_2: Result<Vec<NeuronId>, String> =
        claim_neurons(state_machine, sender.get_principal_id(), test_identity);

    let returned_neuron_ids_2 = gtc_response_2.unwrap();
    let returned_neuron_ids_2_set: HashSet<NeuronId> =
        returned_neuron_ids_2.iter().cloned().collect();
    assert_eq!(returned_neuron_ids_2_set, expected_neuron_ids_set);

    // Assert that `test_identity`'s principal has been set in their GTC account
    let get_account_response: Result<AccountState, String> =
        get_gtc_account(state_machine, test_identity);
    assert_eq!(
        get_account_response.unwrap().authenticated_principal_id,
        Some(test_identity.principal_id())
    );

    // Assert that a claimed neuron is pre-aged
    let get_neuron_info_response: Result<NeuronInfo, GovernanceError> =
        nns_governance_get_neuron_info(state_machine, sender.get_principal_id(), sample_neuron_id);
    let neuron_info = get_neuron_info_response.unwrap();
    assert!(neuron_info.age_seconds >= 86400 * 18 * 30);
}

pub fn add_test_gtc_neurons(payload_builder: &mut NnsInitPayloadsBuilder) {
    payload_builder.genesis_token.genesis_timestamp_seconds = 1;
    payload_builder.genesis_token.sr_months_to_release = Some(SR_MONTHS_TO_RELEASE);
    payload_builder.genesis_token.ect_months_to_release = Some(ECT_MONTHS_TO_RELEASE);

    payload_builder
        .genesis_token
        .add_sr_neurons(TEST_SR_ACCOUNTS);
    payload_builder
        .genesis_token
        .add_ect_neurons(TEST_ECT_ACCOUNTS);
    payload_builder
        .governance
        .add_gtc_neurons(payload_builder.genesis_token.get_gtc_neurons());
    payload_builder
        .genesis_token
        .add_forward_whitelist(&[TEST_IDENTITY_4.gtc_address]);
    payload_builder.governance.with_test_neurons();
}

/// Return the neuron ID of the neuron that the GTC method `donate_account`
/// should donate to.
fn get_donate_account_recipient_neuron_id(payload_builder: &NnsInitPayloadsBuilder) -> NeuronId {
    let id = *payload_builder
        .governance
        .proto
        .neurons
        .iter()
        .find(|(_, neuron)| neuron.controller == Some(*TEST_NEURON_1_OWNER_PRINCIPAL))
        .unwrap()
        .0;

    NeuronId { id }
}

/// Return the neuron ID of the neuron that the GTC method
/// `forward_whitelisted_unclaimed_accounts` should donate to.
fn get_forward_whitelisted_unclaimed_accounts_recipient_neuron_id(
    payload_builder: &NnsInitPayloadsBuilder,
) -> NeuronId {
    let id = *payload_builder
        .governance
        .proto
        .neurons
        .iter()
        .find(|(_, neuron)| neuron.controller == Some(*TEST_NEURON_2_OWNER_PRINCIPAL))
        .unwrap()
        .0;

    NeuronId { id }
}

fn get_gtc_account(
    state_machine: &StateMachine,
    test_identity: &TestIdentity,
) -> Result<AccountState, String> {
    let result = state_machine
        .execute_ingress(
            GENESIS_TOKEN_CANISTER_ID,
            "get_account",
            Encode!(&test_identity.gtc_address.to_string()).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_account failed: {s:#?}"),
    };

    Decode!(&result, Result<AccountState, String>).unwrap()
}

fn forward_whitelisted_unclaimed_accounts(
    state_machine: &StateMachine,
    sender: &Sender,
) -> Result<(), String> {
    let result = state_machine
        .execute_ingress_as(
            sender.get_principal_id(),
            GENESIS_TOKEN_CANISTER_ID,
            "forward_whitelisted_unclaimed_accounts",
            Encode!(&()).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => {
            panic!("Call to forward_whitelisted_unclaimed_accounts failed: {s:#?}")
        }
    };

    Decode!(&result, Result<(), String>).unwrap()
}

fn donate_accounts(
    state_machine: &StateMachine,
    sender: PrincipalId,
    test_identity: &TestIdentity,
) -> Result<(), String> {
    let result = state_machine
        .execute_ingress_as(
            sender,
            GENESIS_TOKEN_CANISTER_ID,
            "donate_account",
            Encode!(&test_identity.public_key_hex.to_string()).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to donate_account failed: {s:#?}"),
    };

    Decode!(&result,Result<(), String>).unwrap()
}

fn claim_neurons(
    state_machine: &StateMachine,
    sender: PrincipalId,
    test_identity: &TestIdentity,
) -> Result<Vec<NeuronId>, String> {
    let result = state_machine
        .execute_ingress_as(
            sender,
            GENESIS_TOKEN_CANISTER_ID,
            "claim_neurons",
            Encode!(&test_identity.public_key_hex.to_string()).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to claim_neurons failed: {s:#?}"),
    };

    Decode!(&result, Result<Vec<NeuronId>, String>).unwrap()
}
