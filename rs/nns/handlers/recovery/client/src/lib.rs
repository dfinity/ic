use async_trait::async_trait;

use ic_nns_handler_recovery_interface::recovery::{NewRecoveryProposal, RecoveryProposal};
use ic_nns_handler_recovery_interface::Result;
use ic_nns_handler_recovery_interface::{simple_node_record::SimpleNodeRecord, Ballot};

pub mod implementation;

#[async_trait]
pub trait RecoveryCanister {
    async fn get_node_operators_in_nns(&self) -> Result<Vec<SimpleNodeRecord>>;

    async fn get_pending_recovery_proposals(&self) -> Result<Vec<RecoveryProposal>>;

    async fn vote_on_latest_proposal(&self, ballot: Ballot) -> Result<()>;

    async fn submit_new_recovery_proposal(&self, new_proposal: NewRecoveryProposal) -> Result<()>;
}
