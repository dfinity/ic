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

mod beta_features;

pub mod external_canister_types;
pub mod pocket_ic;
pub mod state_api;

use crate::state_api::state::OpOut;
use ::pocket_ic::common::rest::{BinaryBlob, BlobId, RawSubnetBlockmaker};
use async_trait::async_trait;
use candid::Principal;
use ic_types::{NodeId, PrincipalId, SubnetId};
use pocket_ic::PocketIc;
use serde::Deserialize;
use std::fmt::Display;

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

impl Display for OpId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Index into a vector of PocketIc instances
pub type InstanceId = usize;

#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn store(&self, blob: BinaryBlob) -> BlobId;
    async fn fetch(&self, blob_id: BlobId) -> Option<BinaryBlob>;
}

// ================================================================================================================= //
// Helpers

#[derive(Clone, Debug)]
pub struct SubnetBlockmaker {
    pub subnet: SubnetId,
    pub blockmaker: NodeId,
    pub failed_blockmakers: Vec<NodeId>,
}

impl From<RawSubnetBlockmaker> for SubnetBlockmaker {
    fn from(raw: RawSubnetBlockmaker) -> Self {
        let subnet = SubnetId::from(PrincipalId::from(Principal::from(raw.subnet)));
        let blockmaker = NodeId::from(PrincipalId::from(Principal::from(raw.blockmaker)));
        let failed_blockmakers: Vec<NodeId> = raw
            .failed_blockmakers
            .into_iter()
            .map(|node_id| NodeId::from(PrincipalId::from(Principal::from(node_id))))
            .collect();

        SubnetBlockmaker {
            subnet,
            blockmaker,
            failed_blockmakers,
        }
    }
}
