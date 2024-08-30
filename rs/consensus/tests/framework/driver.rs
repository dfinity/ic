pub use super::types::*;
use ic_artifact_pool::{
    certification_pool::CertificationPoolImpl, consensus_pool::ConsensusPoolImpl,
    dkg_pool::DkgPoolImpl, idkg_pool::IDkgPoolImpl,
};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus::consensus::ConsensusGossipImpl;
use ic_interfaces::{
    certification,
    consensus_pool::{ChangeAction, ChangeSet as ConsensusChangeSet},
    dkg::ChangeAction as DkgChangeAction,
    idkg::{IDkgChangeAction, IDkgChangeSet},
    p2p::consensus::{ChangeSetProducer, MutablePool},
};
use ic_logger::{debug, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_test_artifact_pool::ingress_pool::TestIngressPool;
use ic_types::{consensus::ConsensusMessage, NodeId};
use std::cell::RefCell;
use std::sync::{Arc, RwLock};

/// A helper that drives consensus using a separate consensus artifact pool.
impl<'a> ConsensusDriver<'a> {
    /// Create a new ConsensusDriver with the given node id and consensus
    /// component.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: NodeId,
        pool_config: ArtifactPoolConfig,
        consensus: Box<dyn ChangeSetProducer<ConsensusPoolImpl, ChangeSet = ConsensusChangeSet>>,
        consensus_gossip: ConsensusGossipImpl,
        dkg: ic_consensus::dkg::DkgImpl,
        idkg: Box<dyn ChangeSetProducer<IDkgPoolImpl, ChangeSet = IDkgChangeSet>>,
        certifier: Box<
            dyn ChangeSetProducer<CertificationPoolImpl, ChangeSet = certification::ChangeSet> + 'a,
        >,
        consensus_pool: Arc<RwLock<ConsensusPoolImpl>>,
        dkg_pool: Arc<RwLock<DkgPoolImpl>>,
        idkg_pool: Arc<RwLock<IDkgPoolImpl>>,
        logger: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> ConsensusDriver<'a> {
        let ingress_pool = RefCell::new(TestIngressPool::new(node_id, pool_config.clone()));
        let certification_pool = Arc::new(RwLock::new(CertificationPoolImpl::new(
            node_id,
            pool_config,
            logger.clone(),
            metrics_registry,
        )));
        let consensus_priority =
            BouncerState::new(&consensus_gossip, &*consensus_pool.read().unwrap());
        ConsensusDriver {
            consensus,
            consensus_gossip,
            dkg,
            idkg,
            certifier,
            logger,
            consensus_pool,
            certification_pool,
            ingress_pool,
            dkg_pool,
            idkg_pool,
            consensus_priority,
        }
    }

    /// Run a single step of consensus, dkg, certification, and idkg by repeatedly
    /// calling on_state_change and apply the changes until no more changes
    /// occur.
    ///
    /// Return a list of output messages produced in the process.
    pub fn step(&self) -> Vec<InputMessage> {
        let mut to_deliver = Vec::new();
        loop {
            let changeset = self
                .consensus
                .on_state_change(&*self.consensus_pool.read().unwrap());
            if changeset.is_empty() {
                break;
            }

            for change_action in &changeset {
                match change_action {
                    // MoveToValidated are what we have received and verified.
                    // But we don't deliver them to peers.
                    ChangeAction::MoveToValidated(to_move) => {
                        debug_print_msg(&self.logger, "Receive", to_move);
                    }
                    // AddToValidated are what we have produced.
                    // We will deliver them to peers.
                    ChangeAction::AddToValidated(to_add) => {
                        debug_print_msg(&self.logger, "Deliver", &to_add.msg);
                        to_deliver.push(InputMessage::Consensus(to_add.msg.clone()));
                    }
                    _ => (),
                }
            }
            self.consensus_pool
                .write()
                .unwrap()
                .apply_changes(changeset);
        }
        loop {
            let changeset = self.dkg.on_state_change(&*self.dkg_pool.read().unwrap());
            if changeset.is_empty() {
                break;
            }
            {
                for change_action in &changeset {
                    if let DkgChangeAction::AddToValidated(to_add) = change_action {
                        debug!(self.logger, "Deliver {:?}", to_add);
                        to_deliver.push(InputMessage::Dkg(Box::new(to_add.clone())));
                    }
                }
                let dkg_pool = &mut self.dkg_pool.write().unwrap();
                dkg_pool.apply_changes(changeset);
            }
        }
        loop {
            let changeset = self
                .certifier
                .on_state_change(&*self.certification_pool.read().unwrap());
            if changeset.is_empty() {
                break;
            }
            {
                for change_action in &changeset {
                    if let certification::ChangeAction::AddToValidated(msg) = change_action {
                        debug!(self.logger, "Certification Message Deliver {:?}", msg);
                        to_deliver.push(InputMessage::Certification(msg.clone()));
                    }
                    if let certification::ChangeAction::MoveToValidated(msg) = change_action {
                        debug!(self.logger, "Certification Message Validated {:?}", msg);
                    }
                }
                let mut certification_pool = self.certification_pool.write().unwrap();
                certification_pool.apply_changes(changeset);
            }
        }
        loop {
            let changeset = self.idkg.on_state_change(&*self.idkg_pool.read().unwrap());
            if changeset.is_empty() {
                break;
            }
            {
                for change_action in &changeset {
                    match change_action {
                        IDkgChangeAction::AddToValidated(msg) => {
                            debug!(self.logger, "IDKG Message Deliver {:?}", msg);
                            to_deliver.push(InputMessage::IDkg(msg.clone()));
                        }
                        IDkgChangeAction::MoveToValidated(msg) => {
                            debug!(self.logger, "IDKG Message Validated {:?}", msg);
                        }
                        _ => {}
                    }
                }
                let mut idkg_pool = self.idkg_pool.write().unwrap();
                idkg_pool.apply_changes(changeset);
            }
        }
        to_deliver
    }
}

fn debug_print_msg(logger: &ReplicaLogger, prefix: &str, msg: &ConsensusMessage) {
    match msg {
        ConsensusMessage::BlockProposal(x) => debug!(
            logger,
            "{} {:?}, blockhash = {:?}",
            prefix,
            msg,
            x.content.get_hash()
        ),
        _ => debug!(logger, "{} {:?}", prefix, msg),
    }
}
