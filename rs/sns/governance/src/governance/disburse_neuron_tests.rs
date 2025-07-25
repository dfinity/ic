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
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_nervous_system_canisters::cmc::FakeCmc;
use ic_nervous_system_common::{
    ledger::compute_neuron_staking_subaccount_bytes, 
    NervousSystemError, 
    E8
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use candid::Nat;

// Mock ledger for testing that implements transfer_funds without panicking
pub(crate) struct MockLedger {}

#[async_trait]
impl ICRC1Ledger for MockLedger {
    async fn transfer_funds(
        &self,
        _amount_e8s: u64,
        _fee_e8s: u64,
        _from_subaccount: Option<[u8; 32]>,
        _to: Account,
        _memo: u64,
    ) -> Result<u64, NervousSystemError> {
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
    Governance::new(
        governance_proto
            .try_into()
            .expect("Failed validating governance proto"),
        Box::<NativeEnvironment>::default(),
        Box::new(MockLedger {}), // Use MockLedger for SNS ledger
        Box::new(MockLedger {}), // Use MockLedger for ICP ledger
        Box::new(FakeCmc::new()),
    )
    .enable_test_features()
}

fn test_neuron_id(controller: PrincipalId) -> NeuronId {
    NeuronId::from(compute_neuron_staking_subaccount_bytes(controller, 0))
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
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
    // With no open proposals, all fees should be burnable
    let max_burnable = governance.maximum_burnable_fees_for_neuron(&neuron).unwrap();
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
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
    // Create an open proposal with reject cost of 300
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 300,
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
    
    // Only 1000 - 300 = 700 should be burnable
    let max_burnable = governance.maximum_burnable_fees_for_neuron(&neuron).unwrap();
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
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
    // Create first open proposal with reject cost of 200
    let proposal_data_1 = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 200,
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
    
    // Create second open proposal with reject cost of 300
    let proposal_data_2 = ProposalData {
        id: Some(ProposalId { id: 2 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 300,
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
    
    governance.proto.proposals.insert(1, proposal_data_1);
    governance.proto.proposals.insert(2, proposal_data_2);
    
    // Only 1000 - 200 - 300 = 500 should be burnable
    let max_burnable = governance.maximum_burnable_fees_for_neuron(&neuron).unwrap();
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
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
    // Create a closed (decided) proposal with reject cost of 300
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 300,
        proposal: Some(A_MOTION_PROPOSAL.clone()),
        proposal_creation_timestamp_seconds: governance.env.now(),
        ballots: Default::default(),
        latest_tally: Some(Tally::default()),
        decided_timestamp_seconds: governance.env.now(), // Non-zero means decided
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
    
    // All fees should be burnable since the proposal is closed
    let max_burnable = governance.maximum_burnable_fees_for_neuron(&neuron).unwrap();
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
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
    // Create an open proposal from a different neuron
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(other_neuron_id), // Different proposer
        reject_cost_e8s: 300,
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
    
    // All fees should be burnable since this neuron didn't propose the open proposal
    let max_burnable = governance.maximum_burnable_fees_for_neuron(&neuron).unwrap();
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
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
    // Create an open proposal with high reject cost
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 500, // Higher than available fees
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
    
    // Should return 0, not underflow
    let max_burnable = governance.maximum_burnable_fees_for_neuron(&neuron).unwrap();
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
fn test_disburse_neuron_not_dissolved_fails() {
    // Test that disburse_neuron fails when neuron is not dissolved
    let mut governance = default_governance_with_proto(basic_governance_proto());
    
    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8; // 1 token
    neuron.neuron_fees_e8s = 1000;
    
    // Keep neuron in dissolving state, not dissolved
    neuron.dissolve_state = Some(DissolveState::DissolveDelaySeconds(1000));
    
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
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
    
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
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
    
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
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
    let mut governance = default_governance_with_proto(basic_governance_proto());
    
    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8; // 1 token
    neuron.neuron_fees_e8s = 1000; // 1000 e8s in fees
    
    // Make neuron dissolved
    neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0));
    
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
    // Create an open proposal with reject cost of 300
    let proposal_data = ProposalData {
        id: Some(ProposalId { id: 1 }),
        proposer: Some(neuron_id.clone()),
        reject_cost_e8s: 300,
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
    
    // This should succeed, but only burn 700 e8s (1000 - 300)
    let result = governance
        .disburse_neuron(&neuron_id, &A_NEURON_PRINCIPAL_ID, &disburse)
        .now_or_never()
        .unwrap();
    
    assert!(result.is_ok());
    
    // Check that the neuron fees were reduced by the burnable amount
    let updated_neuron = governance.proto.neurons.get(&neuron_id.to_string()).unwrap();
    // Should have 300 fees remaining (the amount tied to the open proposal)
    assert_eq!(updated_neuron.neuron_fees_e8s, 300);
}

#[test]
fn test_disburse_neuron_zero_burnable_fees_with_high_reject_costs() {
    // Test that disburse_neuron handles case where reject costs exceed total fees
    let mut governance = default_governance_with_proto(basic_governance_proto());
    
    let neuron_id = test_neuron_id(*A_NEURON_PRINCIPAL_ID);
    let mut neuron = A_NEURON.clone();
    neuron.id = Some(neuron_id.clone());
    neuron.cached_neuron_stake_e8s = E8; // 1 token
    neuron.neuron_fees_e8s = 100; // Only 100 e8s in fees
    
    // Make neuron dissolved
    neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0));
    
    governance.proto.neurons.insert(neuron_id.to_string(), neuron.clone());
    
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
    
    // Check that no fees were burned (all fees remain to potentially cover the reject cost)
    let updated_neuron = governance.proto.neurons.get(&neuron_id.to_string()).unwrap();
    assert_eq!(updated_neuron.neuron_fees_e8s, 100); // No change
} 