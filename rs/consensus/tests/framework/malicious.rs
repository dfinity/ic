//! Implementation of malicious behaviors in consensus.

use super::ConsensusModifier;
use ic_consensus::consensus::ConsensusImpl;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::{
    artifact_pool::ChangeSetProducer,
    consensus_pool::{ChangeAction::*, ChangeSet, ConsensusPool},
};
use ic_protobuf::types::v1 as pb;
use ic_types::consensus::{ConsensusMessageHashable, NotarizationShare};
use ic_types::malicious_flags::MaliciousFlags;

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

pub fn invalid_notary_share_signature() -> ConsensusModifier {
    Box::new(|consensus: ConsensusImpl| Box::new(InvalidNotaryShareSignature { consensus }))
}

/// Simulate a non-responding notary that does not sign on notary shares.
pub struct AbsentNotaryShare {
    consensus: ConsensusImpl,
}

impl<T: ConsensusPool> ChangeSetProducer<T> for AbsentNotaryShare {
    type ChangeSet = ChangeSet;
    fn on_state_change(&self, pool: &T) -> ChangeSet {
        self.consensus
            .on_state_change(pool)
            .into_iter()
            .filter(|action| {
                if let AddToValidated(msg) = action {
                    NotarizationShare::assert(msg).is_none()
                } else {
                    true
                }
            })
            .collect::<Vec<_>>()
    }
}

pub fn absent_notary_share() -> ConsensusModifier {
    Box::new(|consensus: ConsensusImpl| Box::new(AbsentNotaryShare { consensus }))
}

/// Simulate a malicious behavior via MaliciousFlags.
pub struct WithMaliciousFlags {
    consensus: ConsensusImpl,
    malicious_flags: MaliciousFlags,
}

impl<T: ConsensusPool> ChangeSetProducer<T> for WithMaliciousFlags {
    type ChangeSet = ChangeSet;
    fn on_state_change(&self, pool: &T) -> ChangeSet {
        let changeset = self.consensus.on_state_change(pool);
        let pool_reader = PoolReader::new(pool);
        if self.malicious_flags.is_consensus_malicious() {
            ic_consensus::consensus::malicious_consensus::maliciously_alter_changeset(
                &pool_reader,
                changeset,
                &self.malicious_flags,
                &self.consensus.block_maker,
                &self.consensus.finalizer,
                &self.consensus.notary,
                &self.consensus.log,
            )
        } else {
            changeset
        }
    }
}

pub fn with_malicious_flags(malicious_flags: MaliciousFlags) -> super::ConsensusModifier {
    Box::new(move |consensus: ConsensusImpl| {
        Box::new(WithMaliciousFlags {
            consensus,
            malicious_flags: malicious_flags.clone(),
        })
    })
}
