// The state manager executor provides non blocking access to the state manager.
// Calls to state_manager can vary in cpu intensity and to not block the async runtime
// state_manager interaction is off loaded to a dedicated thread.
use crate::HttpError;
use hyper::StatusCode;
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_interfaces_state_manager::{Labeled, StateReader};
use ic_replicated_state::ReplicatedState;
use ic_types::consensus::certification::Certification;
use std::sync::{Arc, Mutex};
use threadpool::ThreadPool;
use tokio::sync::oneshot;

// Number of threads used for the state reader executor.
const STATE_READER_EXECUTOR_THREADS: usize = 1;

#[derive(Clone)]
pub(crate) struct StateReaderExecutor {
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    threadpool: Arc<Mutex<ThreadPool>>,
}

impl StateReaderExecutor {
    pub fn new(state_reader: Arc<dyn StateReader<State = ReplicatedState>>) -> Self {
        StateReaderExecutor {
            state_reader,
            threadpool: Arc::new(Mutex::new(ThreadPool::new(STATE_READER_EXECUTOR_THREADS))),
        }
    }

    pub async fn get_latest_state(&self) -> Result<Labeled<Arc<ReplicatedState>>, HttpError> {
        let (tx, rx) = oneshot::channel();
        let state = self.state_reader.clone();
        self.threadpool.lock().unwrap().execute(move || {
            let _ = tx.send(state.get_latest_state());
        });

        rx.await.map_err(|e| HttpError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("Internal Error: {}.", e),
        })
    }

    pub async fn read_certified_state(
        &self,
        labeled_tree: &LabeledTree<()>,
    ) -> Result<Option<(Arc<ReplicatedState>, MixedHashTree, Certification)>, HttpError> {
        let (tx, rx) = oneshot::channel();
        let sr = self.state_reader.clone();
        let lt = labeled_tree.clone();
        self.threadpool.lock().unwrap().execute(move || {
            let _ = tx.send(sr.read_certified_state(&lt));
        });

        rx.await.map_err(|e| HttpError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("Internal Error: {}.", e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto_tree_hash::{flatmap, Label, LabeledTree};
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{BitcoinState, CanisterQueues, ReplicatedState, SystemMetadata};
    use ic_test_utilities::{
        mock_time, state::ReplicatedStateBuilder, state_manager::MockStateManager,
        types::ids::subnet_test_id,
    };
    use ic_types::{
        consensus::certification::{Certification, CertificationContent},
        crypto::{
            threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, Signed,
        },
        signature::ThresholdSignature,
        CryptoHashOfPartialState, Height,
    };
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn async_get_latest_state() {
        let subnet_id = subnet_test_id(1);
        let mut mock_state_manager = MockStateManager::new();
        mock_state_manager
            .expect_get_latest_state()
            .returning(move || {
                let mut metadata = SystemMetadata::new(subnet_id, SubnetType::Application);
                metadata.batch_time = mock_time();
                Labeled::new(
                    Height::from(1),
                    Arc::new(ReplicatedState::new_from_checkpoint(
                        BTreeMap::new(),
                        metadata,
                        CanisterQueues::default(),
                        Vec::new(),
                        BitcoinState::default(),
                        std::path::PathBuf::new(),
                    )),
                )
            });

        let state_manager = Arc::new(mock_state_manager);
        let sre = StateReaderExecutor::new(state_manager.clone());
        assert_eq!(
            sre.get_latest_state().await.unwrap(),
            state_manager.get_latest_state()
        );
    }

    #[tokio::test]
    async fn async_read_certified_state_none() {
        let mut mock_state_manager = MockStateManager::new();
        mock_state_manager
            .expect_read_certified_state()
            .returning(move |_labeled_tree| None);

        let state_manger = Arc::new(mock_state_manager);
        let sre = StateReaderExecutor::new(state_manger.clone());
        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {
            Label::from("time") => LabeledTree::Leaf(())
        });

        assert_eq!(
            sre.read_certified_state(&path).await.unwrap(),
            state_manger.read_certified_state(&path)
        );
    }

    #[tokio::test]
    async fn async_read_certified_state_some() {
        let mut mock_state_manager = MockStateManager::new();
        mock_state_manager
            .expect_read_certified_state()
            .returning(move |_labeled_tree| {
                let rs: Arc<ReplicatedState> = Arc::new(ReplicatedStateBuilder::new().build());
                let mht = MixedHashTree::Leaf(Vec::new());
                let cert = Certification {
                    height: Height::from(123),
                    signed: Signed {
                        signature: ThresholdSignature {
                            signer: NiDkgId {
                                start_block_height: Height::from(0),
                                dealer_subnet: subnet_test_id(0),
                                dkg_tag: NiDkgTag::HighThreshold,
                                target_subnet: NiDkgTargetSubnet::Local,
                            },
                            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
                        },
                        content: CertificationContent::new(CryptoHashOfPartialState::from(
                            CryptoHash(vec![]),
                        )),
                    },
                };
                Some((rs, mht, cert))
            });

        let path: LabeledTree<()> = LabeledTree::SubTree(flatmap! {
            Label::from("time") => LabeledTree::Leaf(())
        });
        let state_manger = Arc::new(mock_state_manager);
        let sre = StateReaderExecutor::new(state_manger.clone());
        assert_eq!(
            sre.read_certified_state(&path).await.unwrap(),
            state_manger.read_certified_state(&path)
        );
    }
}
