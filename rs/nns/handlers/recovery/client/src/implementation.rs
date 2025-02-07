use std::{sync::Arc, time::SystemTime};

use async_trait::async_trait;
use candid::{CandidType, Principal};
use ic_agent::Agent;
use ic_nns_handler_recovery_interface::{
    recovery::{NewRecoveryProposal, RecoveryPayload, RecoveryProposal, VoteOnRecoveryProposal},
    security_metadata::SecurityMetadata,
    signing::Signer,
    simple_node_operator_record::SimpleNodeOperatorRecord,
    Ballot, RecoveryError, Result, VerifyIntegirty,
};

use crate::RecoveryCanister;

pub struct RecoveryCanisterImpl {
    canister_id: Principal,
    ic_agent: Agent,
    signer: Arc<dyn Signer>,
}

impl RecoveryCanisterImpl {
    pub fn new(ic_agent: Agent, canister_id: Principal, signer: Arc<dyn Signer>) -> Self {
        Self {
            ic_agent,
            canister_id,
            signer,
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
            .map(|response| candid::decode_one::<std::result::Result<T, String>>(&response))
            .map_err(|e| RecoveryError::AgentError(e.to_string()))?
            .map_err(|e| RecoveryError::CandidError(e.to_string()))?
            .map_err(|e| RecoveryError::CanisterError(e.to_string()))
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
        response.iter().verify_integrity()?;

        Ok(response)
    }

    async fn vote_on_latest_proposal(&self, ballot: Ballot) -> Result<()> {
        self.ensure_not_anonymous()?;
        let last_proposal = self.fetch_latest_proposal().await?;
        let payload = last_proposal.signature_payload()?;
        let signature = self.signer.sign_payload(&payload)?;

        self.update(
            "vote_on_proposal",
            candid::encode_one(VoteOnRecoveryProposal {
                security_metadata: SecurityMetadata {
                    signature,
                    payload,
                    pub_key_der: self.signer.to_public_key_der()?,
                },
                ballot,
            })?,
        )
        .await
    }

    async fn submit_new_recovery_proposal(&self, new_proposal: RecoveryPayload) -> Result<()> {
        self.ensure_not_anonymous()?;
        let epoch = SystemTime::UNIX_EPOCH.elapsed().unwrap();
        let seconds_payload = epoch.as_secs().to_le_bytes().to_vec();
        let signature = self.signer.sign_payload(&seconds_payload)?;

        self.update(
            "submit_new_recovery_proposal",
            candid::encode_one(NewRecoveryProposal {
                payload: new_proposal,
                security_metadata: SecurityMetadata {
                    signature,
                    payload: seconds_payload,
                    pub_key_der: self.signer.to_public_key_der()?,
                },
            })?,
        )
        .await
    }
}
