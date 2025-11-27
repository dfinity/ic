//! Unit tests for disburse_neuron functionality and related fee calculations.

use super::test_helpers::{
    A_MOTION_PROPOSAL, A_NEURON, A_NEURON_PRINCIPAL_ID, basic_governance_proto,
};
use super::*;
use crate::{
    governance::AccountProto,
    pb::v1::{
        NeuronId, ProposalData, ProposalId, Subaccount, governance_error::ErrorType, manage_neuron,
        neuron::DissolveState,
    },
    types::test_helpers::NativeEnvironment,
};
use async_trait::async_trait;
use candid::Nat;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_common::{
    E8, NervousSystemError, ledger::compute_neuron_staking_subaccount_bytes,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use std::sync::{Arc, Mutex};

// Struct representing a transfer call with named fields matching transfer_funds parameters
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TransferCall {
    pub amount_e8s: u64,
    pub fee_e8s: u64,
    pub from_subaccount: Option<[u8; 32]>,
    pub to: Account,
    pub memo: u64,
}

impl TransferCall {
    /// Returns true if this is a burn call (fee is 0, indicating a burn operation)
    pub fn is_burn(&self) -> bool {
        self.fee_e8s == 0
    }

    /// Returns true if this is a regular transfer call (fee > 0)
    pub fn is_transfer(&self) -> bool {
        self.fee_e8s > 0
    }

    /// Asserts that this call has the expected amount and fee
    pub fn assert_amount_and_fee(&self, expected_amount: u64, expected_fee: u64) {
        assert_eq!(self.amount_e8s, expected_amount);
        assert_eq!(self.fee_e8s, expected_fee);
    }
}

// Mock ledger for testing that implements transfer_funds without panicking
#[derive(Clone)]
pub(crate) struct MockLedger {
    pub transfer_calls: Arc<Mutex<Vec<TransferCall>>>,
}

impl MockLedger {
    pub fn new() -> Self {
        Self {
            transfer_calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_transfer_calls(&self) -> Vec<TransferCall> {
        self.transfer_calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl ICRC1Ledger for MockLedger {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<[u8; 32]>,
        to: Account,
        memo: u64,
    ) -> Result<u64, NervousSystemError> {
        // Record the call for test verification
        self.transfer_calls.lock().unwrap().push(TransferCall {
            amount_e8s,
            fee_e8s,
            from_subaccount,
            to,
            memo,
        });
        // Return a mock block index for successful transfer
        Ok(1)
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        Ok(Tokens::from_e8s(1_000_000 * E8))
    }

    async fn account_balance(&self, _account: Account) -> Result<Tokens, NervousSystemError> {
        Ok(Tokens::from_e8s(E8))
    }

    fn canister_id(&self) -> CanisterId {
        CanisterId::from(42)
    }

    async fn icrc2_approve(
        &self,
        _spender: Account,
        _amount: u64,
        _expires_at: Option<u64>,
        _fee: u64,
        _from_subaccount: Option<icrc_ledger_types::icrc1::account::Subaccount>,
        _expected_allowance: Option<u64>,
    ) -> Result<Nat, NervousSystemError> {
        Err(NervousSystemError {
            error_message: "Not Implemented".to_string(),
        })
    }

    async fn icrc3_get_blocks(
        &self,
        _args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError> {
        Ok(GetBlocksResult {
            blocks: vec![],
            log_length: Nat::from(0u64),
            archived_blocks: vec![],
        })
    }
}

fn governance_with_ledger_tracking(governance_proto: GovernanceProto) -> (Governance, MockLedger) {
    let test_governance_canister_id = CanisterId::from_u64(501);

    // Create the SNS ledger that we want to track calls to
    // (disburse_neuron uses self.ledger which is the SNS ledger)
    let sns_ledger = MockLedger::new();

    let governance = Governance::new(
        governance_proto
            .try_into()
            .expect("Failed validating governance proto"),
        Box::new(NativeEnvironment::new(Some(test_governance_canister_id))),
        Box::new(sns_ledger.clone()), // SNS ledger - clone shares the same Arc<Mutex<Vec<...>>>
        Box::new(MockLedger::new()),  // ICP ledger - separate instance
        Box::new(FakeCmc::new()),
    )
    .enable_test_features();

    // Return the original SNS ledger instance - it shares the transfer_calls
    // with the cloned instance inside governance due to Arc<Mutex<_>>
    (governance, sns_ledger)
}

fn test_neuron_id(controller: PrincipalId) -> NeuronId {
    NeuronId::from(compute_neuron_staking_subaccount_bytes(controller, 0))
}

// =============================================================================
// Tests for maximum_burnable_fees_per_neuron
// =============================================================================

fn setup_burnable_fee_test() -> (Governance, NeuronId) {
    let governance_proto = basic_governance_proto();
    let (mut governance, _ledger) = governance_with_ledger_tracking(governance_proto);

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8;
    neuron.neuron_fees_e8s = 1000;

    // Insert the neuron into governance
    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    (governance, neuron_id)
}

fn proposal_data_with_reject_cost(
    id: u64,
    proposer: NeuronId,
    reject_cost_e8s: u64,
    decided_timestamp_seconds: u64,
) -> ProposalData {
    ProposalData {
        id: Some(ProposalId { id }),
        proposer: Some(proposer),
        reject_cost_e8s,
        decided_timestamp_seconds,
        ..Default::default()
    }
}

#[test]
fn test_maximum_burnable_fees_per_neuron_no_open_proposals() {
    // Test that when a neuron has no open proposals, all fees can be burned
    let (governance, neuron_id) = setup_burnable_fee_test();

    let neuron = governance.get_neuron_result(&neuron_id).unwrap();
    // With no open proposals, all fees should be burnable
    let max_burnable = governance.maximum_burnable_fees_for_neuron(neuron).unwrap();
    assert_eq!(max_burnable, 1000);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_with_open_proposals() {
    // Test that fees tied up in open proposals are not burnable
    let (mut governance, neuron_id) = setup_burnable_fee_test();

    // Create an open proposal with reject cost of 300
    let proposal_data = proposal_data_with_reject_cost(1, neuron_id.clone(), 300, 0);

    governance.proto.proposals.insert(1, proposal_data);

    // Only 1000 - 300 = 700 should be burnable
    let neuron = governance.get_neuron_result(&neuron_id).unwrap();
    let max_burnable = governance.maximum_burnable_fees_for_neuron(neuron).unwrap();
    assert_eq!(max_burnable, 700);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_multiple_open_proposals() {
    // Test that multiple open proposals accumulate their reject costs
    let (mut governance, neuron_id) = setup_burnable_fee_test();

    // Create first open proposal with reject cost of 200
    let proposal_data_1 = proposal_data_with_reject_cost(1, neuron_id.clone(), 200, 0);

    // Create second open proposal with reject cost of 300
    let proposal_data_2 = proposal_data_with_reject_cost(2, neuron_id.clone(), 300, 0);

    governance.proto.proposals.insert(1, proposal_data_1);
    governance.proto.proposals.insert(2, proposal_data_2);

    // Only 1000 - 200 - 300 = 500 should be burnable
    let neuron = governance.get_neuron_result(&neuron_id).unwrap();
    let max_burnable = governance.maximum_burnable_fees_for_neuron(neuron).unwrap();
    assert_eq!(max_burnable, 500);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_closed_proposals_ignored() {
    // Test that closed proposals don't affect burnable fees
    let (mut governance, neuron_id) = setup_burnable_fee_test();

    // Create a closed (decided) proposal with reject cost of 300
    let proposal_data =
        proposal_data_with_reject_cost(1, neuron_id.clone(), 300, governance.env.now());

    governance.proto.proposals.insert(1, proposal_data);

    // All fees should be burnable since the proposal is closed
    let neuron = governance.get_neuron_result(&neuron_id).unwrap();
    let max_burnable = governance.maximum_burnable_fees_for_neuron(neuron).unwrap();
    assert_eq!(max_burnable, 1000);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_different_proposer_ignored() {
    // Test that open proposals from other neurons don't affect this neuron's burnable fees
    let (mut governance, neuron_id) = setup_burnable_fee_test();
    let other_neuron_id = test_neuron_id(PrincipalId::new_user_test_id(999));

    // Create an open proposal from a different neuron
    let proposal_data = ProposalData {
        proposal: Some(A_MOTION_PROPOSAL.clone()),
        ..proposal_data_with_reject_cost(1, other_neuron_id, 300, 0) // Different proposer
    };

    governance.proto.proposals.insert(1, proposal_data);

    // All fees should be burnable since this neuron didn't propose the open proposal
    let neuron = governance.get_neuron_result(&neuron_id).unwrap();
    let max_burnable = governance.maximum_burnable_fees_for_neuron(neuron).unwrap();
    assert_eq!(max_burnable, 1000);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_fees_exceed_reject_costs() {
    // Test that when open proposal reject costs exceed available fees, we don't underflow
    let governance_proto = basic_governance_proto();
    let (mut governance, _ledger) = governance_with_ledger_tracking(governance_proto);

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.neuron_fees_e8s = 100; // Low fees

    // Insert the neuron into governance
    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    // Create an open proposal with high reject cost
    let proposal_data = proposal_data_with_reject_cost(1, neuron_id.clone(), 500, 0); // Higher than available fees

    governance.proto.proposals.insert(1, proposal_data);

    // Should return 0, not underflow
    let neuron = governance.get_neuron_result(&neuron_id).unwrap();
    let max_burnable = governance.maximum_burnable_fees_for_neuron(neuron).unwrap();
    assert_eq!(max_burnable, 0);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_no_neuron_id() {
    // Test error handling when neuron has no ID
    let governance_proto = basic_governance_proto();
    let (governance, _ledger) = governance_with_ledger_tracking(governance_proto);

    let mut neuron = A_NEURON.clone();
    neuron.id = None; // No ID
    neuron.neuron_fees_e8s = 1000;

    // Should return an error
    let result = governance.maximum_burnable_fees_for_neuron(&neuron);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().error_type, ErrorType::NotFound as i32);
}

// =============================================================================
// Tests for disburse_neuron edge cases
// =============================================================================

fn setup_disburse_neuron_test(
    dissolve_state: DissolveState,
    neuron_fees_e8s: u64,
) -> (Governance, NeuronId, MockLedger) {
    let governance_proto = basic_governance_proto();
    let (mut governance, ledger) = governance_with_ledger_tracking(governance_proto);

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = 5 * E8; // 5 tokens
    neuron.neuron_fees_e8s = neuron_fees_e8s;
    neuron.dissolve_state = Some(dissolve_state);
    // Insert the neuron into governance
    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    (governance, neuron_id, ledger)
}

#[test]
fn test_disburse_neuron_with_dissolve_delay_fails() {
    // Test that disburse_neuron fails when neuron has a dissolve delay (locked)
    let (mut governance, neuron_id, ledger) =
        setup_disburse_neuron_test(DissolveState::DissolveDelaySeconds(1000), 1000);

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: None,
    };

    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert!(ledger.get_transfer_calls().is_empty());

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::PreconditionFailed as i32);
    assert!(error.error_message.contains("NOT dissolved"));
}

#[test]
fn test_disburse_neuron_dissolving_fails() {
    // Test that disburse_neuron fails when neuron is dissolving but not yet dissolved
    let (mut governance, neuron_id, ledger) =
        setup_disburse_neuron_test(DissolveState::DissolveDelaySeconds(1000), 1000);

    // Now update the neuron to be dissolving (future timestamp means still dissolving)
    let future_timestamp = governance.env.now() + 3600; // 1 hour from now
    governance
        .proto
        .neurons
        .get_mut(&neuron_id.to_string())
        .unwrap()
        .dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(
        future_timestamp,
    ));

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: None,
    };

    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert!(ledger.get_transfer_calls().is_empty());

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::PreconditionFailed as i32);
    assert!(error.error_message.contains("NOT dissolved"));
}

#[test]
fn test_disburse_neuron_unauthorized_caller_fails() {
    // Test that disburse_neuron fails when caller is not authorized
    let (mut governance, neuron_id, ledger) =
        setup_disburse_neuron_test(DissolveState::WhenDissolvedTimestampSeconds(0), 1000);

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: None,
    };

    // Use unauthorized caller
    let unauthorized_caller = PrincipalId::new_user_test_id(999);
    let result = governance
        .disburse_neuron(&neuron_id, &unauthorized_caller, &disburse)
        .now_or_never()
        .unwrap();

    assert!(ledger.get_transfer_calls().is_empty());

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::NotAuthorized as i32);
}

#[test]
fn test_disburse_neuron_nonexistent_neuron_fails() {
    // Test that disburse_neuron fails when neuron doesn't exist
    let governance_proto = basic_governance_proto();
    let (mut governance, _ledger) = governance_with_ledger_tracking(governance_proto);

    let nonexistent_neuron_id = test_neuron_id(PrincipalId::new_user_test_id(999));

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: None,
    };

    let result = governance
        .disburse_neuron(&nonexistent_neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::NotFound as i32);
}

#[test]
fn test_disburse_neuron_invalid_subaccount_fails() {
    // Test that disburse_neuron fails when to_account has invalid subaccount
    let (mut governance, neuron_id, ledger) =
        setup_disburse_neuron_test(DissolveState::WhenDissolvedTimestampSeconds(0), 1000);

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: Some(AccountProto {
            owner: Some(*A_NEURON_PRINCIPAL_ID),
            subaccount: Some(Subaccount {
                subaccount: vec![1, 2, 3], // Invalid subaccount (too short)
            }),
        }),
    };

    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert!(ledger.get_transfer_calls().is_empty());

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::InvalidCommand as i32);
    assert!(error.error_message.contains("subaccount is invalid"));
}

#[test]
fn test_disburse_neuron_with_open_proposals_burns_limited_fees() {
    // Test that disburse_neuron only burns the safe amount when there are open proposals
    let (mut governance, neuron_id, ledger) =
        setup_disburse_neuron_test(DissolveState::WhenDissolvedTimestampSeconds(0), 100_000);

    // Create an open proposal with reject cost of 30,000 e8s
    let proposal_data = proposal_data_with_reject_cost(1, neuron_id.clone(), 30_000, 0);

    governance.proto.proposals.insert(1, proposal_data);

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: None,
    };

    // This should succeed and burn 70,000 e8s (100,000 - 30,000)
    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert_eq!(result, Ok(1)); // Mock ledger returns block height 1

    // Verify that the ledger burn was called
    let transfer_calls = ledger.get_transfer_calls();
    assert_eq!(transfer_calls.len(), 2); // One burn, one transfer

    // Check burn call (first transfer)
    let burn_call = &transfer_calls[0];
    assert!(burn_call.is_burn());
    burn_call.assert_amount_and_fee(70_000, 0); // amount burned (100,000 - 30,000)

    // Check disburse call (second transfer)
    let disburse_call = &transfer_calls[1];
    assert!(disburse_call.is_transfer());
    // Disburse: (500M stake - 100K fees) - 10K tx_fee = 499,890,000
    disburse_call.assert_amount_and_fee(499_890_000, 10_000);

    // Check that the neuron fees were reduced by the burnable amount
    let updated_neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .unwrap();
    // Should have 30,000 fees remaining (the amount tied to the open proposal)
    assert_eq!(updated_neuron.neuron_fees_e8s, 30_000);

    // Check cached_neuron_stake_e8s: 500M - 70K burned - 499.89M disbursed - 10K tx_fee = 30K
    assert_eq!(updated_neuron.cached_neuron_stake_e8s, 30_000);
}

#[test]
fn test_disburse_neuron_small_fees_not_burned() {
    // Test that disburse_neuron doesn't burn fees that are too small and preserves accounting
    let (mut governance, neuron_id, ledger) =
        setup_disburse_neuron_test(DissolveState::WhenDissolvedTimestampSeconds(0), 1000);

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: None,
    };

    // This should succeed but not burn any fees
    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert_eq!(result, Ok(1)); // Mock ledger returns block height 1

    // Verify that only one transfer was made (no burn), just the disburse transfer
    let transfer_calls = ledger.get_transfer_calls();
    assert_eq!(transfer_calls.len(), 1); // Only one transfer (disburse), no burn

    // Check disburse call
    let disburse_call = &transfer_calls[0];
    assert!(disburse_call.is_transfer());
    // Disburse: (500M stake - 1K fees) - 10K tx_fee = 499,989,000
    disburse_call.assert_amount_and_fee(499_989_000, 10_000);

    // Check that the neuron fees were NOT reduced (preserved for future)
    let updated_neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .unwrap();
    // Fees should remain unchanged since they were too small to burn
    assert_eq!(updated_neuron.neuron_fees_e8s, 1_000);

    // Check cached_neuron_stake_e8s: 500M - 499.989M disbursed - 10K tx_fee = 1K (equals fees)
    assert_eq!(updated_neuron.cached_neuron_stake_e8s, 1_000);
}

#[test]
fn test_disburse_neuron_zero_burnable_fees_with_high_reject_costs() {
    // Test that disburse_neuron handles case where reject costs exceed total fees
    let (mut governance, neuron_id, ledger) =
        setup_disburse_neuron_test(DissolveState::WhenDissolvedTimestampSeconds(0), 100);

    // Create an open proposal with reject cost higher than available fees
    let proposal_data = proposal_data_with_reject_cost(1, neuron_id.clone(), 500, 0); // More than the 100 available fees

    governance.proto.proposals.insert(1, proposal_data);

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: None,
    };

    // This should succeed, but burn 0 fees (since max_burnable would be 0)
    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert_eq!(result, Ok(1)); // Mock ledger returns block height 1

    // Verify that only one transfer was made (no burn), just the disburse transfer
    let transfer_calls = ledger.get_transfer_calls();
    assert_eq!(transfer_calls.len(), 1); // Only one transfer (disburse), no burn

    // Check disburse call
    let disburse_call = &transfer_calls[0];
    assert!(disburse_call.is_transfer());
    // Disburse: (500M stake - 100 fees) - 10K tx_fee = 499,989,900
    disburse_call.assert_amount_and_fee(499_989_900, 10_000);

    // Check that no fees were burned (all fees remain to potentially cover the reject cost)
    let updated_neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .unwrap();
    assert_eq!(updated_neuron.neuron_fees_e8s, 100); // No change

    // Check cached_neuron_stake_e8s: 500M - 499.9899M disbursed - 10K tx_fee = 100 (equals fees)
    assert_eq!(updated_neuron.cached_neuron_stake_e8s, 100);
}

#[test]
fn test_disburse_neuron_partial_amount_with_non_burnable_fees() {
    // Test partial disbursal when neuron has fees tied up in open proposals
    let (mut governance, neuron_id, ledger) =
        setup_disburse_neuron_test(DissolveState::WhenDissolvedTimestampSeconds(0), 50_000);

    // Create an open proposal with reject cost of 20,000 e8s
    let proposal_data = proposal_data_with_reject_cost(1, neuron_id.clone(), 20_000, 0);

    governance.proto.proposals.insert(1, proposal_data);

    // Request partial disbursal of 2 tokens (2 * E8 = 200,000,000 e8s)
    let disburse = manage_neuron::Disburse {
        amount: Some(manage_neuron::disburse::Amount {
            e8s: 2 * E8, // 2 tokens
        }),
        to_account: None,
    };

    // This should succeed: burn 30,000 e8s (50,000 - 20,000), disburse 2 tokens - fees - transaction_fee
    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert_eq!(result, Ok(1)); // Mock ledger returns block height 1

    // Verify that the ledger burn and disburse were called
    let transfer_calls = ledger.get_transfer_calls();
    assert_eq!(transfer_calls.len(), 2); // One burn, one disburse

    // Check burn call (first transfer)
    let burn_call = &transfer_calls[0];
    assert!(burn_call.is_burn());
    burn_call.assert_amount_and_fee(30_000, 0); // amount burned (50,000 - 20,000)

    // Check disburse call (second transfer)
    let disburse_call = &transfer_calls[1];
    assert!(disburse_call.is_transfer());
    // Partial disburse: 2 tokens requested - 10K tx_fee = 199,990,000 e8s
    disburse_call.assert_amount_and_fee(199_990_000, 10_000);

    // Check final neuron state
    let updated_neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .unwrap();

    // Should have 20,000 fees remaining (tied to open proposal)
    assert_eq!(updated_neuron.neuron_fees_e8s, 20_000);

    // Check cached_neuron_stake_e8s: 500M - 30K burned - 199_990_000 disbursed - 10_000 tx_fee = 299,970,000
    assert_eq!(updated_neuron.cached_neuron_stake_e8s, 299_970_000);

    // Remaining stake: 299.97M cached - 20K fees = 299.95M
    assert_eq!(updated_neuron.stake_e8s(), 299_950_000);
}

#[test]
fn test_disburse_neuron_caps_to_maximum_available_stake() {
    // Test that disburse_neuron disburses maximum possible when requested amount exceeds available
    let (mut governance, neuron_id, ledger) =
        setup_disburse_neuron_test(DissolveState::WhenDissolvedTimestampSeconds(0), 50_000);

    // Create an open proposal with reject cost of 30,000 e8s (makes 30K non-burnable)
    let proposal_data = proposal_data_with_reject_cost(1, neuron_id.clone(), 30_000, 0);

    governance.proto.proposals.insert(1, proposal_data);

    // Available for disbursal: stake_e8s = cached_stake - fees = 500M - 50K = 499.95M
    // Max disburse considering tx fee: 499.95M - 10K = 499.94M
    // Try to disburse 500M (more than available, should disburse max possible)
    let disburse = manage_neuron::Disburse {
        amount: Some(manage_neuron::disburse::Amount {
            e8s: 500 * E8, // 500M e8s (more than available, should get capped)
        }),
        to_account: None,
    };

    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    // Should succeed and disburse the maximum possible amount
    assert_eq!(result, Ok(1)); // Mock ledger returns block height 1

    // Verify that the ledger calls were made correctly
    let transfer_calls = ledger.get_transfer_calls();
    assert_eq!(transfer_calls.len(), 2); // One burn, one disburse

    // Check burn call (first transfer)
    let burn_call = &transfer_calls[0];
    assert!(burn_call.is_burn());
    burn_call.assert_amount_and_fee(20_000, 0); // amount burned (50K - 30K non-burnable)

    // Check disburse call (second transfer)
    let disburse_call = &transfer_calls[1];
    assert!(disburse_call.is_transfer());
    // Max disburse: 499.95M available - 10K tx_fee = 499,940,000
    disburse_call.assert_amount_and_fee(499_940_000, 10_000);

    // Check final neuron state after max disbursal
    let updated_neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .unwrap();

    // Should have 30K fees remaining (tied to open proposal)
    assert_eq!(updated_neuron.neuron_fees_e8s, 30_000);

    // Check cached_neuron_stake_e8s: 500M - 20K burned - 499.94M disbursed - 10K tx_fee = 30K
    assert_eq!(updated_neuron.cached_neuron_stake_e8s, 30_000);

    // Remaining stake: 30K cached - 30K fees = 0 (neuron fully disbursed)
    assert_eq!(updated_neuron.stake_e8s(), 0);
}
