//! Function to submit a proposal for an external update from Rust code.

use crate::pb::v1::proposal;
use crate::pb::v1::{ExecuteNnsFunction, NnsFunction, Proposal};
use candid::{CandidType, Encode};
use dfn_core::api::{call, caller};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

/// Wraps the given proposal_payload into a proposal; sends it to the proposal
/// canister; returns the proposal id.
pub async fn submit_proposal<T: CandidType>(
    proposer: &NeuronId,
    nns_function: NnsFunction,
    proposal_payload: &T,
    log_prefix: &str,
) -> Result<ProposalId, String> {
    let proposal = Proposal {
        summary: "<proposal created from initialization>".to_string(),
        url: "".to_string(),
        action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: nns_function as i32,
            payload: Encode!(proposal_payload).expect("Error encoding proposal payload"),
        })),
    };

    let result: Result<ProposalId, (Option<i32>, String)> = call(
        GOVERNANCE_CANISTER_ID,
        "submit_proposal",
        dfn_candid::candid,
        (proposer, proposal, caller()),
    )
    .await;

    match result {
        Ok(proposal_id) => {
            println!(
                "{}Proposal submitted. ProposalId: {}.",
                log_prefix, proposal_id,
            );
            Ok(proposal_id)
        }
        Err((code, error)) => {
            println!(
                "{}Error calling proposals canister. Code: {:?}. Error: {:?}",
                log_prefix, code, error
            );
            Err(error)
        }
    }
}
