//! # Architecture
//!
//! +----------------+------------------+---------------------+
//! |    Scheduler   |    Hypervisor    |  Canister Sandbox   |
//! +----------------+------------------+---------------------+
//! |                   Message Routing                       |
//! +---------------------------------------------------------+
//! |                    PocketIC API                         |
//! +---------------------------------------------------------+
//! | PocketIC REST Interface |   | drun              | etc.. |
//! |         +---------------+   +---------------+   |       |
//! |         | Internet Computer HTTTP Interface |   |       |
//!
//!
//! The PocketIC is a self-contained, light-weight, versatile, efficient platform to test canister
//! smart contracts and systems that interact with the IC. It mocks the network and consensus
//! layer of the IC.
//!
//! A PocketIC is a deterministic state machine that emulates an instance of the Internet Computer.
//! Currently, a PocketIC instance consists of at most one (system) subnet. In the future,
//! multi-subnet support will be added.
//!
//! The states of a PocketIC instance form a directed graph, where nodes are states and edges are
//! computations. A computation is an operation on a given state (the source of the edge) resulting
//! in a target state and possibly some outcome. An operation is a function that takes a state and
//! possibly some input value and produces a new state.
//!
//! For example, adjusting the network time is an operation that takes a state, and the new time
//! and produces a new state. Setting the network time has no outcome, or side-effect.
//!
//! Note that the source and target state might be equivalent. This is the case for Internet
//! Computer queries, e.g.
//!
//! The start state is a dedicated state that always exists independent of which computations have
//! been carried out. A state which has no outcoming computations is called a leaf.

pub mod pocket_ic;
pub mod state_api;

use crate::state_api::state::OpOut;
use ::pocket_ic::common::rest::{BinaryBlob, BlobId};
use axum::async_trait;
use pocket_ic::PocketIc;
use serde::Deserialize;

pub const RUN_AS_BITCOIN_ADAPTER_FLAG: &str = "--run-as-bitcoin-adapter";

/// Represents an identifiable operation on PocketIC.
pub trait Operation {
    /// Executes an operation.
    fn compute(&self, pocket_ic: &mut PocketIc) -> OpOut;

    /// True iff this operation should be retried if the instance is busy.
    /// This must be the case if the caller cannot handle the error condition
    /// of a busy instance.
    fn retry_if_busy(&self) -> bool {
        false
    }

    /// Returns the unique identifier of this operation.
    fn id(&self) -> OpId;
}

/// Uniquely identifies an operation.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize)]
pub struct OpId(pub String);

// Index into a vector of PocketIc instances
pub type InstanceId = usize;

#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn store(&self, blob: BinaryBlob) -> BlobId;
    async fn fetch(&self, blob_id: BlobId) -> Option<BinaryBlob>;
}

// ================================================================================================================= //
// Helpers

pub fn copy_dir(
    src: impl AsRef<std::path::Path>,
    dst: impl AsRef<std::path::Path>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pocket_ic::{CanisterCall, ExecuteIngressMessage, PocketIc};
    use crate::state_api::state::*;
    use ::pocket_ic::WasmResult;
    use candid::{decode_args, encode_args};
    use ic_cdk::api::management_canister::main::CreateCanisterArgument;
    use ic_cdk::api::management_canister::provisional::CanisterIdRecord;
    use ic_types::{CanisterId, PrincipalId};
    use std::time::Duration;
    use tokio::runtime::Runtime;

    #[test]
    fn test_pocket_ic() {
        let rt = Runtime::new().unwrap();
        let pocket_ic = PocketIc::default();
        let api_state = PocketIcApiStateBuilder::new()
            .add_initial_instance(pocket_ic)
            .build();
        let instance_id = 0;
        let msg1 = ExecuteIngressMessage(CanisterCall {
            sender: PrincipalId::default(),
            canister_id: CanisterId::ic_00(),
            method: "provisional_create_canister_with_cycles".to_string(),
            payload: encode_args((CreateCanisterArgument { settings: None },)).unwrap(),
            effective_principal: pocket_ic::EffectivePrincipal::None,
        });

        let timeout = Some(Duration::from_secs(30));
        let res = rt
            .block_on(api_state.update_with_timeout(msg1.into(), instance_id, timeout))
            .unwrap();

        match res {
            UpdateReply::Output(OpOut::CanisterResult(Ok(WasmResult::Reply(bytes)))) => {
                let (CanisterIdRecord { canister_id },) = decode_args(&bytes).unwrap();
                assert!(!canister_id.to_text().is_empty());
            }
            UpdateReply::Output(OpOut::CanisterResult(Ok(WasmResult::Reject(x)))) => {
                panic!("unexpected reject: {:?}", x);
            }
            e => {
                panic!("unexpected result: {:?}", e);
            }
        }
    }
}
