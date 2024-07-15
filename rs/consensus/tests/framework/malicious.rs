//! Implementation of malicious behaviors in consensus.

use super::ComponentModifier;
use ic_consensus::consensus::ConsensusImpl;
use ic_consensus::ecdsa::{malicious_pre_signer, EcdsaImpl};
use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::{
    consensus_pool::{ChangeAction::*, ChangeSet, ConsensusPool, ValidatedConsensusArtifact},
    ecdsa::{IDkgChangeSet, IDkgPool},
    p2p::consensus::ChangeSetProducer,
};
use ic_protobuf::types::v1 as pb;
use ic_types::consensus::{ConsensusMessageHashable, NotarizationShare};
use ic_types::malicious_flags::MaliciousFlags;
use ic_types::time::current_time;
use std::cell::RefCell;

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
                let timestamp = msg.timestamp;
                if let Some(share) = NotarizationShare::assert(&msg.msg)
                    .map(|share| {
                        let mut share = pb::NotarizationShare::from(share);
                        let len = share.signature.len();
                        share.signature[len / 2] = share.signature[len / 2].wrapping_add(1);
                        share
                    })
                    .and_then(|share| NotarizationShare::try_from(share).ok())
                {
                    std::mem::swap(
                        action,
                        &mut AddToValidated(ValidatedConsensusArtifact {
                            msg: share.into_message(),
                            timestamp,
                        }),
                    );
                }
            }
        }
        change_set
    }
}

pub fn invalid_notary_share_signature() -> ComponentModifier {
    ComponentModifier {
        consensus: Box::new(|consensus: ConsensusImpl| {
            Box::new(InvalidNotaryShareSignature { consensus })
        }),
        ..Default::default()
    }
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
                    NotarizationShare::assert(&msg.msg).is_none()
                } else {
                    true
                }
            })
            .collect::<Vec<_>>()
    }
}

pub fn absent_notary_share() -> ComponentModifier {
    ComponentModifier {
        consensus: Box::new(|consensus: ConsensusImpl| Box::new(AbsentNotaryShare { consensus })),
        ..Default::default()
    }
}

/// Simulate a malicious consensus behavior via MaliciousFlags.
pub struct ConsensusWithMaliciousFlags {
    consensus: ConsensusImpl,
    malicious_flags: MaliciousFlags,
}

impl<T: ConsensusPool> ChangeSetProducer<T> for ConsensusWithMaliciousFlags {
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
                current_time(),
            )
        } else {
            changeset
        }
    }
}

/// Simulate a malicious ecdsa behavior via MaliciousFlags.
pub struct EcdsaWithMaliciousFlags {
    ecdsa: RefCell<EcdsaImpl>,
    malicious_flags: MaliciousFlags,
}

impl<T: IDkgPool> ChangeSetProducer<T> for EcdsaWithMaliciousFlags {
    type ChangeSet = IDkgChangeSet;
    fn on_state_change(&self, pool: &T) -> IDkgChangeSet {
        let changeset = EcdsaImpl::on_state_change(&self.ecdsa.borrow(), pool);
        if self.malicious_flags.is_ecdsa_malicious() {
            malicious_pre_signer::maliciously_alter_changeset(
                changeset,
                &self.ecdsa.borrow().pre_signer,
                &self.malicious_flags,
            )
        } else {
            changeset
        }
    }
}

pub fn with_malicious_flags(malicious_flags: MaliciousFlags) -> ComponentModifier {
    let mut modifier = ComponentModifier::default();
    let malicious_flags_clone = malicious_flags.clone();
    if malicious_flags_clone.is_consensus_malicious() {
        modifier.consensus = Box::new(move |consensus: ConsensusImpl| {
            Box::new(ConsensusWithMaliciousFlags {
                consensus,
                malicious_flags: malicious_flags_clone.clone(),
            })
        })
    };
    if malicious_flags.is_ecdsa_malicious() {
        modifier.ecdsa = Box::new(move |ecdsa: EcdsaImpl| {
            Box::new(EcdsaWithMaliciousFlags {
                ecdsa: RefCell::new(ecdsa),
                malicious_flags: malicious_flags.clone(),
            })
        })
    };
    modifier
}
