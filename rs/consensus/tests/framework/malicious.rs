//! Implementation of malicious behaviors in consensus.

use ic_artifact_pool::consensus_pool::ConsensusPoolImpl;
use ic_consensus::consensus::ConsensusImpl;
use ic_interfaces::{
    artifact_pool::ChangeSetProducer,
    consensus_pool::{ChangeAction::*, ChangeSet, ConsensusPool},
};
use ic_protobuf::types::v1 as pb;
use ic_types::consensus::{ConsensusMessageHashable, NotarizationShare};

/// Simulate a malicious notary that always produces a bad NotarizationShare
/// by mutating the signature.
pub struct InvalidNotaryShareSignature {
    consensus: ConsensusImpl,
}

impl<T: ConsensusPool> ChangeSetProducer<T> for InvalidNotaryShareSignature {
    type ChangeSet = ChangeSet;
    fn on_state_change(&self, pool: &T) -> ChangeSet {
        let mut change_set = self.consensus.on_state_change(pool);
        for action in change_set.iter_mut() {
            if let AddToValidated(msg) = action {
                if let Some(share) = NotarizationShare::assert(msg)
                    .and_then(|share| pb::NotarizationShare::try_from(share).ok())
                    .map(|mut share| {
                        let len = share.signature.len();
                        share.signature[len / 2] = share.signature[len / 2].wrapping_add(1);
                        share
                    })
                    .and_then(|share| NotarizationShare::try_from(share).ok())
                {
                    std::mem::swap(action, &mut AddToValidated(share.into_message()));
                }
            }
        }
        change_set
    }
}

impl InvalidNotaryShareSignature {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        consensus: ConsensusImpl,
    ) -> Box<
        dyn ChangeSetProducer<
            ConsensusPoolImpl,
            ChangeSet = Vec<ic_interfaces::consensus_pool::ChangeAction>,
        >,
    > {
        Box::new(Self { consensus })
    }
}
