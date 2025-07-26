//! Unit tests for disburse_neuron functionality and related fee calculations.

use super::test_helpers::{
    basic_governance_proto, A_MOTION_PROPOSAL, A_NEURON, A_NEURON_PRINCIPAL_ID,
};
use super::*;
use crate::{
    governance::AccountProto,
    pb::v1::{
        governance_error::ErrorType, manage_neuron, neuron::DissolveState, NeuronId, ProposalData,
        ProposalId, Subaccount, Tally, WaitForQuietState,
    },
    types::test_helpers::NativeEnvironment,
};
use async_trait::async_trait;
use candid::Nat;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_common::{
    ledger::compute_neuron_staking_subaccount_bytes, NervousSystemError, E8,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use std::sync::{Arc, Mutex};

// Mock ledger for testing that implements transfer_funds without panicking
#[derive(Clone)]
pub(crate) struct MockLedger {
    pub transfer_calls: Arc<Mutex<Vec<(u64, u64, Option<[u8; 32]>, Account, u64)>>>,
}

impl MockLedger {
    pub fn new() -> Self {
        Self {
            transfer_calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    pub fn get_transfer_calls(&self) -> Vec<(u64, u64, Option<[u8; 32]>, Account, u64)> {
        self.transfer_calls.lock().unwrap().clone()
    }
    
    pub fn clear_transfer_calls(&self) {
        self.transfer_calls.lock().unwrap().clear();
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
        self.transfer_calls.lock().unwrap().push((amount_e8s, fee_e8s, from_subaccount, to, memo));
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

fn default_governance_with_proto(governance_proto: GovernanceProto) -> Governance {
    let test_governance_canister_id = CanisterId::from_u64(501);
    Governance::new(
        governance_proto
            .try_into()
            .expect("Failed validating governance proto"),
        Box::new(NativeEnvironment::new(Some(test_governance_canister_id))),
        Box::new(MockLedger::new()), // Use MockLedger for SNS ledger
        Box::new(MockLedger::new()), // Use MockLedger for ICP ledger
        Box::new(FakeCmc::new()),
    )
    .enable_test_features()
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
// Test Arc sharing works in MockLedger
// =============================================================================

#[test]
fn test_mock_ledger_sharing_works() {
    // Verify that MockLedger cloning actually shares the transfer_calls data
    let ledger1 = MockLedger::new();
    let ledger2 = ledger1.clone();
    
    // Simulate a call on the cloned ledger
    ledger2.transfer_calls.lock().unwrap().push((100, 0, None, Account {
        owner: ic_base_types::PrincipalId::new_user_test_id(1).0,
        subaccount: None,
    }, 0));
    
    // Verify the original ledger sees the call
    let calls = ledger1.get_transfer_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, 100); // amount
}

// =============================================================================
// Tests for maximum_burnable_fees_per_neuron
// =============================================================================

#[test]
fn test_maximum_burnable_fees_per_neuron_no_open_proposals() {
    // Test that when a neuron has no open proposals, all fees can be burned
    let mut governance = default_governance_with_proto(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.neuron_fees_e8s = 1000;

    // Insert the neuron into governance
    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    // With no open proposals, all fees should be burnable
    let max_burnable = governance
        .maximum_burnable_fees_for_neuron(&neuron)
        .unwrap();
    assert_eq!(max_burnable, 1000);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_with_open_proposals() {
    // Test that fees tied up in open proposals are not burnable
    let mut governance = default_governance_with_proto(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.neuron_fees_e8s = 1000;

    // Insert the neuron into governance
    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    // Create an open proposal with reject cost of 300
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 300,
        decided_timestamp_seconds: 0, // 0 means open
        ..Default::default()
    };

    governance.proto.proposals.insert(1, proposal_data);

    // Only 1000 - 300 = 700 should be burnable
    let max_burnable = governance
        .maximum_burnable_fees_for_neuron(&neuron)
        .unwrap();
    assert_eq!(max_burnable, 700);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_multiple_open_proposals() {
    // Test that multiple open proposals accumulate their reject costs
    let mut governance = default_governance_with_proto(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.neuron_fees_e8s = 1000;

    // Insert the neuron into governance
    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    // Create first open proposal with reject cost of 200
    let proposal_data_1 = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 200,
        decided_timestamp_seconds: 0, // 0 means open
        ..Default::default()
    };

    // Create second open proposal with reject cost of 300
    let proposal_data_2 = ProposalData {
        id: Some(ProposalId { id: 2 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 300,
        decided_timestamp_seconds: 0, // 0 means open
        ..Default::default()
    };

    governance.proto.proposals.insert(1, proposal_data_1);
    governance.proto.proposals.insert(2, proposal_data_2);

    // Only 1000 - 200 - 300 = 500 should be burnable
    let max_burnable = governance
        .maximum_burnable_fees_for_neuron(&neuron)
        .unwrap();
    assert_eq!(max_burnable, 500);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_closed_proposals_ignored() {
    // Test that closed proposals don't affect burnable fees
    let mut governance = default_governance_with_proto(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.neuron_fees_e8s = 1000;

    // Insert the neuron into governance
    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    // Create a closed (decided) proposal with reject cost of 300
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 300,
        decided_timestamp_seconds: governance.env.now(), // Non-zero means decided
        ..Default::default()
    };

    governance.proto.proposals.insert(1, proposal_data);

    // All fees should be burnable since the proposal is closed
    let max_burnable = governance
        .maximum_burnable_fees_for_neuron(&neuron)
        .unwrap();
    assert_eq!(max_burnable, 1000);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_different_proposer_ignored() {
    // Test that open proposals from other neurons don't affect this neuron's burnable fees
    let mut governance = default_governance_with_proto(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let other_neuron_id = test_neuron_id(PrincipalId::new_user_test_id(999));

    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.neuron_fees_e8s = 1000;

    // Insert the neuron into governance
    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    // Create an open proposal from a different neuron
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(other_neuron_id), // Different proposer
        reject_cost_e8s: 300,
        proposal: Some(A_MOTION_PROPOSAL.clone()),
        decided_timestamp_seconds: 0, // 0 means open
        ..Default::default()
    };

    governance.proto.proposals.insert(1, proposal_data);

    // All fees should be burnable since this neuron didn't propose the open proposal
    let max_burnable = governance
        .maximum_burnable_fees_for_neuron(&neuron)
        .unwrap();
    assert_eq!(max_burnable, 1000);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_fees_exceed_reject_costs() {
    // Test that when open proposal reject costs exceed available fees, we don't underflow
    let mut governance = default_governance_with_proto(basic_governance_proto());

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
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 500,         // Higher than available fees
        decided_timestamp_seconds: 0, // 0 means open
        ..Default::default()
    };

    governance.proto.proposals.insert(1, proposal_data);

    // Should return 0, not underflow
    let max_burnable = governance
        .maximum_burnable_fees_for_neuron(&neuron)
        .unwrap();
    assert_eq!(max_burnable, 0);
}

#[test]
fn test_maximum_burnable_fees_per_neuron_no_neuron_id() {
    // Test error handling when neuron has no ID
    let governance = default_governance_with_proto(basic_governance_proto());

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

#[test]
fn test_disburse_neuron_with_dissolve_delay_fails() {
    // Test that disburse_neuron fails when neuron has a dissolve delay (locked)
    let mut governance = default_governance_with_proto(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8; // 1 token
    neuron.neuron_fees_e8s = 1000;

    // Keep neuron locked with dissolve delay
    neuron.dissolve_state = Some(DissolveState::DissolveDelaySeconds(1000));

    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: None,
    };

    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::PreconditionFailed as i32);
    assert!(error.error_message.contains("NOT dissolved"));
}

#[test]
fn test_disburse_neuron_dissolving_fails() {
    // Test that disburse_neuron fails when neuron is dissolving but not yet dissolved
    let mut governance = default_governance_with_proto(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8; // 1 token
    neuron.neuron_fees_e8s = 1000;

    // Set neuron to dissolving state (future timestamp means still dissolving)
    let future_timestamp = governance.env.now() + 3600; // 1 hour from now
    neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(
        future_timestamp,
    ));

    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: None,
    };

    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::PreconditionFailed as i32);
    assert!(error.error_message.contains("NOT dissolved"));
}

#[test]
fn test_disburse_neuron_unauthorized_caller_fails() {
    // Test that disburse_neuron fails when caller is not authorized
    let mut governance = default_governance_with_proto(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8;
    neuron.neuron_fees_e8s = 1000;

    // Make neuron dissolved
    neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0));

    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

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

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::NotAuthorized as i32);
}

#[test]
fn test_disburse_neuron_nonexistent_neuron_fails() {
    // Test that disburse_neuron fails when neuron doesn't exist
    let mut governance = default_governance_with_proto(basic_governance_proto());

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
    let mut governance = default_governance_with_proto(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8;
    neuron.neuron_fees_e8s = 1000;

    // Make neuron dissolved
    neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0));

    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

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

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::InvalidCommand as i32);
    assert!(error.error_message.contains("subaccount is invalid"));
}

#[test]
fn test_disburse_neuron_with_open_proposals_burns_limited_fees() {
    // Test that disburse_neuron only burns the safe amount when there are open proposals
    let (mut governance, ledger) = governance_with_ledger_tracking(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8; // 1 token
    neuron.neuron_fees_e8s = 100_000; // 100,000 e8s in fees (large enough to burn)

    // Make neuron dissolved
    neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0));

    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    // Create an open proposal with reject cost of 30,000 e8s
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 30_000,
        proposal: Some(A_MOTION_PROPOSAL.clone()),
        proposal_creation_timestamp_seconds: governance.env.now(),
        ballots: Default::default(),
        latest_tally: Some(Tally::default()),
        decided_timestamp_seconds: 0, // 0 means open
        executed_timestamp_seconds: 0,
        failed_timestamp_seconds: 0,
        failure_reason: None,
        reward_event_round: 0,
        wait_for_quiet_state: Some(WaitForQuietState {
            current_deadline_timestamp_seconds: governance.env.now() + 1000,
        }),
        initial_voting_period_seconds: 1000,
        action: 1, // Motion proposal
        reward_event_end_timestamp_seconds: None,
        topic: Some(1), // Topic for Motion
        minimum_yes_proportion_of_total: None,
        minimum_yes_proportion_of_exercised: None,
        ..Default::default()
    };

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

    assert!(result.is_ok());

    // Verify that the ledger burn was called
    let transfer_calls = ledger.get_transfer_calls();
    assert_eq!(transfer_calls.len(), 2); // One burn, one transfer
    let burn_call = &transfer_calls[0];
    assert_eq!(burn_call.0, 70_000); // amount burned
    assert_eq!(burn_call.1, 0); // fee for burn

    // Check that the neuron fees were reduced by the burnable amount
    let updated_neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .unwrap();
    // Should have 30,000 fees remaining (the amount tied to the open proposal)
    assert_eq!(updated_neuron.neuron_fees_e8s, 30_000);
}

#[test]
fn test_disburse_neuron_small_fees_not_burned() {
    // Test that disburse_neuron doesn't burn fees that are too small and preserves accounting
    let (mut governance, ledger) = governance_with_ledger_tracking(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8; // 1 token
    neuron.neuron_fees_e8s = 1000; // Small fees (less than transaction fee)

    // Make neuron dissolved
    neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0));

    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    let disburse = manage_neuron::Disburse {
        amount: None,
        to_account: None,
    };

    // This should succeed but not burn any fees
    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();

    assert!(result.is_ok());

    // Verify that only one transfer was made (no burn), just the disburse transfer
    let transfer_calls = ledger.get_transfer_calls();
    assert_eq!(transfer_calls.len(), 1); // Only one transfer (disburse), no burn

    // Check that the neuron fees were NOT reduced (preserved for future)
    let updated_neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .unwrap();
    // Fees should remain unchanged since they were too small to burn
    assert_eq!(updated_neuron.neuron_fees_e8s, 1000);
}

#[test]
fn test_disburse_neuron_zero_burnable_fees_with_high_reject_costs() {
    // Test that disburse_neuron handles case where reject costs exceed total fees
    let (mut governance, ledger) = governance_with_ledger_tracking(basic_governance_proto());

    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8; // 1 token
    neuron.neuron_fees_e8s = 100; // Only 100 e8s in fees

    // Make neuron dissolved
    neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0));

    governance
        .proto
        .neurons
        .insert(neuron_id.to_string(), neuron.clone());

    // Create an open proposal with reject cost higher than available fees
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 500, // More than the 100 available fees
        proposal: Some(A_MOTION_PROPOSAL.clone()),
        proposal_creation_timestamp_seconds: governance.env.now(),
        ballots: Default::default(),
        latest_tally: Some(Tally::default()),
        decided_timestamp_seconds: 0, // 0 means open
        executed_timestamp_seconds: 0,
        failed_timestamp_seconds: 0,
        failure_reason: None,
        reward_event_round: 0,
        wait_for_quiet_state: Some(WaitForQuietState {
            current_deadline_timestamp_seconds: governance.env.now() + 1000,
        }),
        initial_voting_period_seconds: 1000,
        action: 1, // Motion proposal
        reward_event_end_timestamp_seconds: None,
        topic: Some(1), // Topic for Motion
        minimum_yes_proportion_of_total: None,
        minimum_yes_proportion_of_exercised: None,
        ..Default::default()
    };

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

    assert!(result.is_ok());

    // Verify that only one transfer was made (no burn), just the disburse transfer
    let transfer_calls = ledger.get_transfer_calls();
    assert_eq!(transfer_calls.len(), 1); // Only one transfer (disburse), no burn

    // Check that no fees were burned (all fees remain to potentially cover the reject cost)
    let updated_neuron = governance
        .proto
        .neurons
        .get(&neuron_id.to_string())
        .unwrap();
    assert_eq!(updated_neuron.neuron_fees_e8s, 100); // No change
}
