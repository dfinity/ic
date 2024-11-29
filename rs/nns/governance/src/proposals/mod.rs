use crate::{
    governance::LOG_PREFIX,
    pb::v1::{governance_error::ErrorType, GovernanceError, ProposalData, Topic, Vote},
};
use ic_base_types::CanisterId;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{
    BITCOIN_MAINNET_CANISTER_ID, BITCOIN_TESTNET_CANISTER_ID, CYCLES_LEDGER_CANISTER_ID,
    CYCLES_LEDGER_INDEX_CANISTER_ID, CYCLES_MINTING_CANISTER_ID, EXCHANGE_RATE_CANISTER_ID,
    GENESIS_TOKEN_CANISTER_ID, GOVERNANCE_CANISTER_ID, ICP_LEDGER_ARCHIVE_1_CANISTER_ID,
    ICP_LEDGER_ARCHIVE_2_CANISTER_ID, ICP_LEDGER_ARCHIVE_CANISTER_ID, LEDGER_CANISTER_ID,
    LEDGER_INDEX_CANISTER_ID, LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID,
    SNS_AGGREGATOR_CANISTER_ID, SNS_WASM_CANISTER_ID, SUBNET_RENTAL_CANISTER_ID,
};
use std::collections::HashMap;

pub mod call_canister;
pub mod create_service_nervous_system;
pub mod install_code;
pub mod stop_or_start_canister;
pub mod update_canister_settings;

const PROTOCOL_CANISTER_IDS: [&CanisterId; 17] = [
    &REGISTRY_CANISTER_ID,
    &GOVERNANCE_CANISTER_ID,
    &LEDGER_CANISTER_ID,
    &ROOT_CANISTER_ID,
    &CYCLES_MINTING_CANISTER_ID,
    &LIFELINE_CANISTER_ID,
    &GENESIS_TOKEN_CANISTER_ID,
    &ICP_LEDGER_ARCHIVE_CANISTER_ID,
    &LEDGER_INDEX_CANISTER_ID,
    &ICP_LEDGER_ARCHIVE_1_CANISTER_ID,
    &SUBNET_RENTAL_CANISTER_ID,
    &ICP_LEDGER_ARCHIVE_2_CANISTER_ID,
    &EXCHANGE_RATE_CANISTER_ID,
    &BITCOIN_MAINNET_CANISTER_ID,
    &BITCOIN_TESTNET_CANISTER_ID,
    &CYCLES_LEDGER_CANISTER_ID,
    &CYCLES_LEDGER_INDEX_CANISTER_ID,
];

const SNS_RELATED_CANISTER_IDS: [&CanisterId; 2] =
    [&SNS_WASM_CANISTER_ID, &SNS_AGGREGATOR_CANISTER_ID];

pub(crate) fn topic_to_manage_canister(canister_id: &CanisterId) -> Topic {
    if PROTOCOL_CANISTER_IDS.contains(&canister_id) {
        Topic::ProtocolCanisterManagement
    } else if SNS_RELATED_CANISTER_IDS.contains(&canister_id) {
        Topic::ServiceNervousSystemManagement
    } else {
        Topic::NetworkCanisterManagement
    }
}

pub(crate) fn invalid_proposal_error(reason: &str) -> GovernanceError {
    GovernanceError::new_with_message(
        ErrorType::InvalidProposal,
        format!("Proposal invalid because of {}", reason),
    )
}

/// Weighted voting power is just voting power * the proposal's (topic's) weight.
///
/// For example, suppose this returns ({42 => 3.14}, 99.9). This means that
/// neuron 42 should get 3.14/99.9 of today's reward purse.
///
/// Non-essential fact: Typically, result.1 is strictly greater than the sum of
/// the values in result.0. The main reason they are usually not equal is that
/// some neurons didn't vote. Another reason is that some neurons did not
/// "refresh" their voting power recently enough. Probably the former has more
/// of an impact on the sum of values in result.1.
pub fn sum_weighted_voting_power<'a>(
    proposals: impl Iterator<Item = &'a ProposalData>,
) -> (
    HashMap<
        NeuronId,
        f64, // exercised
    >,
    f64, // total
) {
    // Results.
    let mut neuron_id_to_exercised_weighted_voting_power: HashMap<NeuronId, f64> = HashMap::new();
    let mut total_weighted_voting_power = 0.0;

    for proposal in proposals {
        let reward_weight = proposal.topic().reward_weight();

        // This is used in lieu of total_potential_voting_power. That is, this
        // gets used if proposal does not have total_potential_voting_power.
        // This fall back will only be used during a short transition period
        // when there is a backlog of "old" proposals that were created without
        // total_potential_voting_power, but all new proposals have it. In the
        // case of such legacy proposals, their total potential voting power
        // would have been equal to this anyway, so this is a sound substitute
        // for total_potential_voting_power.
        let mut total_ballots_voting_power = 0;

        for (neuron_id, ballot) in &proposal.ballots {
            total_ballots_voting_power += ballot.voting_power;

            // Don't reward neurons that did not actually vote. (Whereas, ALL
            // eligible neurons get an "empty" ballot when the proposal is first
            // created. An "empty" ballot is one where the vote field is set to
            // Unspecified.)
            let vote = Vote::try_from(ballot.vote).unwrap_or_else(|err| {
                println!(
                    "{}ERROR: Unrecognized Vote {} in ballot by neuron {} \
                     on proposal {:?}: {:?}",
                    LOG_PREFIX, ballot.vote, neuron_id, proposal.id, err,
                );
                Vote::Unspecified
            });
            if !vote.eligible_for_rewards() {
                continue;
            }

            // Increment neuron.
            *neuron_id_to_exercised_weighted_voting_power
                .entry(NeuronId { id: *neuron_id })
                .or_insert(0.0) += (ballot.voting_power as f64) * reward_weight;
        }

        // Increment global total.
        total_weighted_voting_power += reward_weight
            * proposal
                .total_potential_voting_power
                .unwrap_or(total_ballots_voting_power) as f64;
    }

    (
        neuron_id_to_exercised_weighted_voting_power,
        total_weighted_voting_power,
    )
}
