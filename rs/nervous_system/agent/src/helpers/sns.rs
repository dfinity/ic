use ic_base_types::PrincipalId;
use std::time::Duration;
use thiserror::Error;

use crate::nns::ledger::icrc1_transfer;
use crate::sns::governance::{GovernanceCanister, ProposalSubmissionError, SubmittedProposal};
use crate::sns::swap::SwapCanister;
use crate::{CallCanisters, CallCanistersWithStoppedCanisterError, ProgressNetwork};
use candid::Nat;
use ic_sns_governance_api::pb::v1::{
    ListNeurons, NeuronId, Proposal, ProposalData, ProposalId, get_proposal_response,
};
use ic_sns_swap::{
    pb::v1::{BuyerState, Lifecycle, RefreshBuyerTokensResponse},
    swap::principal_to_subaccount,
};
use icp_ledger::Tokens;
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};

#[derive(Debug, Error, PartialEq)]
pub enum SnsProposalError {
    #[error("Error submitting proposal: {0}")]
    ProposalSubmissionError(ProposalSubmissionError),
    // TODO @rvem: shoule we use more meaningful constructors rather than wrapping 'String' below?
    #[error("Error handling proposal {0:?}: {1}")]
    ProposalError(ProposalId, String),
}

pub async fn propose<C: CallCanisters + ProgressNetwork>(
    agent: &C,
    neuron_id: NeuronId,
    sns_governance_canister: GovernanceCanister,
    proposal: Proposal,
) -> Result<ProposalId, SnsProposalError> {
    let response = sns_governance_canister
        .submit_proposal(agent, neuron_id, proposal)
        .await
        .unwrap();
    let SubmittedProposal { proposal_id } =
        SubmittedProposal::try_from(response).map_err(SnsProposalError::ProposalSubmissionError)?;

    Ok(proposal_id)
}

pub async fn propose_and_wait<C: CallCanistersWithStoppedCanisterError + ProgressNetwork>(
    agent: &C,
    neuron_id: NeuronId,
    sns_governance_canister: GovernanceCanister,
    proposal: Proposal,
) -> Result<ProposalData, SnsProposalError> {
    let proposal_id = propose(agent, neuron_id, sns_governance_canister, proposal).await?;

    wait_for_proposal_execution(agent, sns_governance_canister, proposal_id).await
}

pub async fn wait_for_proposal_execution<
    C: CallCanistersWithStoppedCanisterError + ProgressNetwork,
>(
    agent: &C,
    sns_governance_canister: GovernanceCanister,
    proposal_id: ProposalId,
) -> Result<ProposalData, SnsProposalError> {
    // We create some blocks until the proposal has finished executing (`agent.progress(...)`).
    let mut last_proposal_data = None;

    for _attempt_count in 1..=50 {
        agent.progress(Duration::from_secs(1)).await;
        let proposal_result = sns_governance_canister
            .get_proposal(agent, proposal_id)
            .await;

        let proposal = match proposal_result {
            Ok(proposal) => proposal,
            Err(user_error) => {
                // Upgrading SNS Governance results in the proposal info temporarily not
                // being available due to the canister being stopped. This requires
                // more attempts to get the proposal info to find out if the proposal
                // actually got executed.
                if agent.is_canister_stopped_error(&user_error) {
                    continue;
                } else {
                    return Err(SnsProposalError::ProposalError(
                        proposal_id,
                        format!("Error getting proposal: {user_error:#?}"),
                    ));
                }
            }
        };

        let proposal = proposal.result.ok_or(SnsProposalError::ProposalError(
            proposal_id,
            "GetProposalResponse.result must be set.".to_string(),
        ))?;
        let proposal_data = match proposal {
            get_proposal_response::Result::Error(err) => {
                return Err(SnsProposalError::ProposalError(
                    proposal_id,
                    format!("Proposal data cannot be found: {err:?}"),
                ));
            }
            get_proposal_response::Result::Proposal(proposal_data) => proposal_data,
        };
        if proposal_data.executed_timestamp_seconds > 0 {
            return Ok(proposal_data);
        }
        proposal_data.failure_reason.clone().map_or(Ok(()), |e| {
            Err(SnsProposalError::ProposalSubmissionError(
                ProposalSubmissionError::GovernanceError(e),
            ))
        })?;
        last_proposal_data = Some(proposal_data);
    }
    Err(SnsProposalError::ProposalError(
        proposal_id,
        format!(
            "Looks like the SNS proposal is never going to be decided: {last_proposal_data:#?}"
        ),
    ))
}

pub async fn get_principal_neurons<C: CallCanisters>(
    agent: &C,
    governance_canister: GovernanceCanister,
    principal: PrincipalId,
) -> Result<Vec<NeuronId>, C::Error> {
    let response = governance_canister
        .list_neurons(
            agent,
            ListNeurons {
                // should be enough for now, we may consider pagination later
                limit: 100,
                of_principal: Some(principal),
                start_page_at: None,
            },
        )
        .await?;
    Ok(response
        .neurons
        .into_iter()
        .map(|n| n.id.expect("NeuronId must be set."))
        .collect())
}

pub async fn get_caller_neuron<C: CallCanisters>(
    agent: &C,
    governance_canister: GovernanceCanister,
) -> Result<Option<NeuronId>, C::Error> {
    get_principal_neurons(agent, governance_canister, agent.caller().unwrap().into())
        .await
        .map(|v| v.first().cloned())
}

pub async fn await_swap_lifecycle<C: CallCanisters + ProgressNetwork>(
    agent: &C,
    sns_swap_canister: SwapCanister,
    expected_lifecycle: Lifecycle,
    swap_immediately_open: bool,
) -> Result<(), String> {
    // The swap opens in up to 48 hours after the proposal for creating this SNS was executed
    // if non-test version of NNS Governance canister is used.
    if !swap_immediately_open {
        agent.progress(Duration::from_secs(48 * 60 * 60)).await;
    }
    let mut last_lifecycle = None;
    for _attempt_count in 1..=200 {
        agent.progress(Duration::from_secs(1)).await;
        let response = sns_swap_canister.get_lifecycle(agent).await.unwrap();
        let lifecycle = Lifecycle::try_from(response.lifecycle.unwrap()).unwrap();
        if lifecycle == expected_lifecycle {
            return Ok(());
        }
        last_lifecycle = Some(lifecycle);
    }
    Err(format!(
        "Looks like the SNS lifecycle {expected_lifecycle:?} is never going to be reached: {last_lifecycle:?}",
    ))
}

pub async fn participate_in_swap<C: CallCanisters>(
    agent: &C,
    sns_swap_canister: SwapCanister,
    amount_icp_excluding_fees: Tokens,
    confirmation_text: Option<String>,
) -> Result<(), String> {
    let direct_participant = agent.caller().unwrap().into();
    let direct_participant_swap_subaccount = Some(principal_to_subaccount(&direct_participant));

    let direct_participant_swap_account = Account {
        owner: sns_swap_canister.canister_id.0,
        subaccount: direct_participant_swap_subaccount,
    };

    let participation_amount = amount_icp_excluding_fees.get_e8s();
    let _ = icrc1_transfer(
        agent,
        TransferArg {
            from_subaccount: None,
            to: direct_participant_swap_account,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(participation_amount),
        },
    )
    .await
    .unwrap();

    let response = sns_swap_canister
        .refresh_buyer_tokens(agent, direct_participant, confirmation_text)
        .await
        .map_err(|err| err.to_string())?;

    assert_eq!(
        response,
        RefreshBuyerTokensResponse {
            icp_ledger_account_balance_e8s: amount_icp_excluding_fees.get_e8s(),
            icp_accepted_participation_e8s: amount_icp_excluding_fees.get_e8s(),
        }
    );

    let response = sns_swap_canister
        .get_buyer_state(agent, direct_participant)
        .await
        .map_err(|_| "Swap.get_buyer_state response should be Ok.")?;
    let (icp, has_created_neuron_recipes) = match response.buyer_state {
        Some(BuyerState {
            icp,
            has_created_neuron_recipes,
        }) => (
            icp.ok_or("buyer_state.icp must be specified.")?,
            has_created_neuron_recipes
                .ok_or("buyer_state.has_created_neuron_recipes must be specified.")?,
        ),
        None => {
            return Err("buyer_state must be specified.".to_string());
        }
    };
    if has_created_neuron_recipes {
        return Err(
            "Neuron recipes are expected to be created only after the swap is adopted".to_string(),
        );
    };
    assert_eq!(icp.amount_e8s, amount_icp_excluding_fees.get_e8s());
    Ok(())
}
