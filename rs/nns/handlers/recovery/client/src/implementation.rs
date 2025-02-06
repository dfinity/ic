use async_trait::async_trait;
use candid::{CandidType, Principal};
use ed25519_dalek::SigningKey;
use ic_agent::Agent;
use ic_nns_handler_recovery_interface::{
    recovery::{NewRecoveryProposal, RecoveryProposal, VoteOnRecoveryProposal},
    security_metadata::SecurityMetadata,
    simple_node_operator_record::SimpleNodeOperatorRecord,
    Ballot, RecoveryError, Result, VerifyIntegirty,
};

use crate::RecoveryCanister;

pub struct RecoveryCanisterImpl {
    canister_id: Principal,
    ic_agent: Agent,
    signing_key: SigningKey,
}

impl RecoveryCanisterImpl {
    pub fn new(ic_agent: Agent, canister_id: Principal, signing_key: SigningKey) -> Self {
        Self {
            ic_agent,
            canister_id,
            signing_key,
        }
    }

    async fn query<T, P>(&self, method: &str, args: P) -> Result<T>
    where
        T: CandidType + for<'a> candid::Deserialize<'a>,
        P: Into<Vec<u8>>,
    {
        self.ic_agent
            .query(&self.canister_id, method)
            .with_arg(args)
            .call()
            .await
            .map(|response| candid::decode_one(&response))
            .map_err(|e| RecoveryError::AgentError(e.to_string()))?
            .map_err(|e| e.into())
    }

    async fn update<T, P>(&self, method: &str, args: P) -> Result<T>
    where
        T: CandidType + for<'a> candid::Deserialize<'a>,
        P: Into<Vec<u8>>,
    {
        self.ic_agent
            .update(&self.canister_id, method)
            .with_arg(args)
            .call_and_wait()
            .await
            .map(|response| candid::decode_one(&response))
            .map_err(|e| RecoveryError::AgentError(e.to_string()))?
            .map_err(|e| e.into())
    }

    fn ensure_not_anonymous(&self) -> Result<()> {
        let principal = self
            .ic_agent
            .get_principal()
            .map_err(|e| RecoveryError::AgentError(e))?;

        match Principal::anonymous().eq(&principal) {
            false => Ok(()),
            true => Err(RecoveryError::InvalidIdentity(
                "Anonymous sender can't proceed with the request action".to_string(),
            )),
        }
    }
}

#[async_trait]
impl RecoveryCanister for RecoveryCanisterImpl {
    async fn get_node_operators_in_nns(&self) -> Result<Vec<SimpleNodeOperatorRecord>> {
        self.query("get_current_nns_node_operators", candid::encode_one(())?)
            .await
    }

    async fn get_pending_recovery_proposals(&self) -> Result<Vec<RecoveryProposal>> {
        let response: Vec<RecoveryProposal> = self
            .query("get_pending_recovery_proposals", candid::encode_one(())?)
            .await?;
        response.iter().verify()?;

        Ok(response)
    }

    async fn vote_on_latest_proposal(&self, ballot: Ballot) -> Result<()> {
        self.ensure_not_anonymous()?;
        let last_proposal = self.fetch_latest_proposal().await?;

        let mut signing_key = self.signing_key.clone();

        self.update(
            "vote_on_proposal",
            candid::encode_one(VoteOnRecoveryProposal {
                security_metadata: SecurityMetadata {
                    signature: last_proposal.sign(&mut signing_key)?,
                    payload: last_proposal.signature_payload()?,
                    pub_key: signing_key.verifying_key().to_bytes(),
                },
                ballot,
            })?,
        )
        .await
    }

    async fn submit_new_recovery_proposal(&self, new_proposal: NewRecoveryProposal) -> Result<()> {
        self.ensure_not_anonymous()?;

        self.update(
            "submit_new_recovery_proposal",
            candid::encode_one(new_proposal)?,
        )
        .await
    }
}
