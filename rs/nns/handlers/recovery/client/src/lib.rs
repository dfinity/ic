use async_trait::async_trait;

use ic_nns_handler_recovery_interface::recovery::{RecoveryPayload, RecoveryProposal};
use ic_nns_handler_recovery_interface::{
    simple_node_operator_record::SimpleNodeOperatorRecord, Ballot,
};
use ic_nns_handler_recovery_interface::{RecoveryError, Result};

pub mod builder;
pub mod implementation;
#[cfg(test)]
mod tests;

#[async_trait]
pub trait RecoveryCanister {
    async fn get_node_operators_in_nns(&self) -> Result<Vec<SimpleNodeOperatorRecord>>;

    async fn get_pending_recovery_proposals(&self) -> Result<Vec<RecoveryProposal>>;

    async fn vote_on_latest_proposal(&self, ballot: Ballot) -> Result<()>;

    async fn submit_new_recovery_proposal(&self, new_proposal: RecoveryPayload) -> Result<()>;

    async fn fetch_latest_proposal(&self) -> Result<RecoveryProposal> {
        let proposal_chain = self.get_pending_recovery_proposals().await?;

        proposal_chain
            .last()
            .cloned()
            .ok_or(RecoveryError::NoProposals(
                "There are no proposals to be voted in.".to_string(),
            ))
    }

    async fn fetch_latest_adopted_proposal(&self) -> Result<RecoveryProposal> {
        let proposal_chain = self.get_pending_recovery_proposals().await?;

        proposal_chain
            .iter()
            .rev()
            .find(|proposal| proposal.is_byzantine_majority_yes())
            .cloned()
            .ok_or(RecoveryError::NoProposals(
                "No voted in proposals present at the moment".to_string(),
            ))
    }

    async fn latest_adopted_state(&self) -> RecoveryPayload {
        self.fetch_latest_adopted_proposal()
            .await
            .map(|proposal| proposal.payload)
            // If there isn't any voted in proposals look
            // at NNS as unhalted.
            .unwrap_or(RecoveryPayload::Unhalt)
    }
}
