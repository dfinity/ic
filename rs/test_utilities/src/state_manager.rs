use crate::types::ids::subnet_test_id;
use ic_crypto_sha::Sha256;
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_interfaces::certified_stream_store::{
    CertifiedStreamStore, DecodeStreamError, EncodeStreamError,
};
use ic_interfaces_state_manager::{
    CertificationMask, CertificationScope, Labeled, PermanentStateHashError::*, StateHashError,
    StateManager, StateManagerError, StateManagerResult, StateReader, TransientStateHashError::*,
    CERT_ANY, CERT_CERTIFIED, CERT_UNCERTIFIED,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::crypto::CryptoHash;
use ic_types::{
    consensus::certification::Certification,
    crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
    crypto::CryptoHashOf,
    xnet::{CertifiedStreamSlice, StreamIndex, StreamSlice},
    CryptoHashOfPartialState, CryptoHashOfState, Height, RegistryVersion, SubnetId,
};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use ic_types::messages::RequestOrResponse;
use ic_types::xnet::{StreamHeader, StreamIndexedQueue};
use mockall::*;
use serde::{Deserialize, Serialize};

mock! {
    pub StateManager {}

    trait StateReader {
        type State = ReplicatedState;

        fn get_state_at(&self, height: Height) -> StateManagerResult<Labeled<Arc<ReplicatedState>>>;

        fn get_latest_state(&self) -> Labeled<Arc<ReplicatedState>>;

        fn latest_state_height(&self) -> Height;

        fn latest_certified_height(&self) -> Height;

        fn read_certified_state(
            &self,
            _paths: &LabeledTree<()>
        ) -> Option<(Arc<ReplicatedState>, MixedHashTree, Certification)>;
    }

    trait StateManager: StateReader {
        fn take_tip(&self) -> (Height, ReplicatedState);

        fn take_tip_at(&self, h: Height) -> StateManagerResult<ReplicatedState>;

        fn get_state_hash_at(&self, height: Height) -> Result<CryptoHashOfState, StateHashError>;

        fn fetch_state(&self, height: Height, root_hash: CryptoHashOfState, cup_interval_length: Height);

        fn list_state_hashes_to_certify(&self) -> Vec<(Height, CryptoHashOfPartialState)>;

        fn deliver_state_certification(&self, certification: Certification);

        fn list_state_heights(
            &self,
            cert_mask: CertificationMask,
        ) -> Vec<Height>;

        fn remove_states_below(&self, height: Height);

        fn commit_and_certify(
            &self,
            state: ReplicatedState,
            height: Height,
            scope: CertificationScope,
        );

        fn report_diverged_state(&self, height: Height);
    }
}

#[derive(Clone)]
struct Snapshot {
    state: Arc<ReplicatedState>,
    height: Height,
    root_hash: CryptoHashOfState,
    partial_hash: CryptoHashOfPartialState,
    certification: Option<Certification>,
}

impl Snapshot {
    fn make_labeled_state(&self) -> Labeled<Arc<ReplicatedState>> {
        Labeled::new(self.height, self.state.clone())
    }

    fn certification_mask(&self) -> CertificationMask {
        match self.certification {
            Some(_) => CERT_CERTIFIED,
            None => CERT_UNCERTIFIED,
        }
    }
}

/// A fake implementation of the `StateManager` interface.
///
/// It only keeps states in memory, has no persistence and can't do state
/// sync.
#[derive(Clone)]
pub struct FakeStateManager {
    states: Arc<RwLock<Vec<Snapshot>>>,
    tip: Arc<RwLock<Option<(Height, ReplicatedState)>>>,
    _tempdir: Arc<tempfile::TempDir>,
}

impl Default for FakeStateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeStateManager {
    pub fn new() -> Self {
        let height = Height::new(0);
        let fake_hash = CryptoHash(Sha256::hash(&height.get().to_le_bytes()).to_vec());
        let partial_hash = CryptoHashOf::from(fake_hash);
        let fake_hash = CryptoHash(Sha256::hash(&height.get().to_le_bytes()).to_vec());
        let snapshot = Snapshot {
            height,
            state: initial_state().take(),
            partial_hash,
            root_hash: CryptoHashOf::from(fake_hash),
            certification: None,
        };
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        Self {
            states: Arc::new(RwLock::new(vec![snapshot])),
            tip: Arc::new(RwLock::new(Some((
                height,
                ReplicatedState::new_rooted_at(
                    subnet_test_id(1),
                    SubnetType::Application,
                    tmpdir.path().into(),
                ),
            )))),
            _tempdir: Arc::new(tmpdir),
        }
    }
}

fn initial_state() -> Labeled<Arc<ReplicatedState>> {
    Labeled::new(
        Height::new(0),
        Arc::new(ReplicatedState::new_rooted_at(
            subnet_test_id(1),
            SubnetType::Application,
            "Initial".into(),
        )),
    )
}

impl StateManager for FakeStateManager {
    fn take_tip(&self) -> (Height, Self::State) {
        self.tip
            .write()
            .unwrap()
            .take()
            .expect("TIP is not owned by this StateManager")
    }

    fn take_tip_at(&self, h: Height) -> StateManagerResult<Self::State> {
        let mut guard = self.tip.write().unwrap();
        let (height, tip) = guard.take().expect("TIP is not owned by this StateManager");

        if height < h {
            *guard = Some((height, tip));
            return Err(StateManagerError::StateNotCommittedYet(h));
        }

        if h < height {
            *guard = Some((height, tip));
            return Err(StateManagerError::StateRemoved(h));
        }

        Ok(tip)
    }

    fn get_state_hash_at(&self, height: Height) -> Result<CryptoHashOfState, StateHashError> {
        if self.latest_state_height() < height {
            return Err(StateHashError::Transient(StateNotCommittedYet(height)));
        }

        let states = self.states.read().unwrap();

        states
            .iter()
            .find_map(|snap| {
                if snap.height == height {
                    Some(snap.root_hash.clone())
                } else {
                    None
                }
            })
            .ok_or(StateHashError::Permanent(StateRemoved(height)))
    }

    fn fetch_state(
        &self,
        height: Height,
        root_hash: CryptoHashOfState,
        _cup_interval_length: Height,
    ) {
        if let Ok(hash) = self.get_state_hash_at(height) {
            assert_eq!(hash, root_hash);
        }
        let mut states = self.states.write().unwrap();
        let last_snapshot = states
            .last()
            .cloned()
            .expect("fake state manager must always have at least 1 state");

        // _The_ fastest state sync on earth
        states.push(Snapshot {
            state: last_snapshot.state,
            height,
            partial_hash: CryptoHashOfPartialState::from(root_hash.get_ref().clone()),
            root_hash,
            certification: None,
        });
    }

    fn list_state_hashes_to_certify(&self) -> Vec<(Height, CryptoHashOfPartialState)> {
        self.states
            .read()
            .unwrap()
            .iter()
            .filter(|s| s.height > Height::from(0) && s.certification.is_none())
            .map(|s| (s.height, s.partial_hash.clone()))
            .collect()
    }

    fn deliver_state_certification(&self, certification: Certification) {
        let mut snapshots = self.states.write().unwrap();
        if let Some(snapshot) = snapshots
            .iter_mut()
            .find(|s| s.height == certification.height && s.certification.is_none())
        {
            snapshot.certification = Some(certification);
        }
    }

    fn list_state_heights(&self, cert_mask: CertificationMask) -> Vec<Height> {
        self.states
            .read()
            .unwrap()
            .iter()
            .filter_map(|snapshot| {
                if cert_mask.is_set(snapshot.certification_mask()) {
                    Some(snapshot.height)
                } else {
                    None
                }
            })
            .collect()
    }

    fn remove_states_below(&self, height: Height) {
        self.states
            .write()
            .unwrap()
            .retain(|snap| snap.height == Height::new(0) || snap.height >= height)
    }

    fn commit_and_certify(
        &self,
        state: ReplicatedState,
        height: Height,
        _scope: CertificationScope,
    ) {
        let fake_hash = CryptoHash(Sha256::hash(&height.get().to_le_bytes()).to_vec());
        self.states.write().unwrap().push(Snapshot {
            state: Arc::new(state.clone()),
            height,
            root_hash: CryptoHashOf::from(fake_hash.clone()),
            partial_hash: CryptoHashOf::from(fake_hash),
            certification: None,
        });

        let mut tip = self.tip.write().unwrap();
        // If following assert trips, it means take_tip is not matched with
        // its corresponding commit_and_certify. Every take_tip
        // should have a matching commit_and_certify.(#4618)
        assert!(
            tip.is_none(),
            "Attempt to submit a state not borrowed from this StateManager Height {}",
            height
        );
        *tip = Some((height, state));
    }

    fn report_diverged_state(&self, height: Height) {
        panic!("Diverged at height {}", height)
    }
}

impl StateReader for FakeStateManager {
    type State = ReplicatedState;

    fn latest_state_height(&self) -> Height {
        *StateManager::list_state_heights(self, CERT_ANY)
            .last()
            .unwrap()
    }

    // No certification support in FakeStateManager
    fn latest_certified_height(&self) -> Height {
        self.states
            .read()
            .unwrap()
            .iter()
            .filter(|s| s.height > Height::from(0) && s.certification.is_some())
            .map(|s| s.height)
            .last()
            .unwrap_or_else(|| Height::from(0))
    }

    fn get_latest_state(&self) -> Labeled<Arc<Self::State>> {
        self.states
            .read()
            .unwrap()
            .last()
            .map(|snap| snap.make_labeled_state())
            .unwrap_or_else(initial_state)
    }

    fn get_state_at(&self, height: Height) -> StateManagerResult<Labeled<Arc<Self::State>>> {
        if height == Height::new(0) {
            return Ok(initial_state());
        }

        if self.latest_state_height() < height {
            return Err(StateManagerError::StateNotCommittedYet(height));
        }

        self.states
            .read()
            .unwrap()
            .iter()
            .find_map(|snap| {
                if snap.height == height {
                    Some(snap.make_labeled_state())
                } else {
                    None
                }
            })
            .ok_or(StateManagerError::StateRemoved(height))
    }

    fn read_certified_state(
        &self,
        _paths: &LabeledTree<()>,
    ) -> Option<(Arc<Self::State>, MixedHashTree, Certification)> {
        None
    }
}

// Local helper to enable serialization and deserialization of
// ic_types::xnet::StreamIndexedQueue for testing
#[derive(Serialize, Deserialize)]
struct SerializableStreamIndexedQueue {
    begin: StreamIndex,
    queue: VecDeque<RequestOrResponse>,
}

impl From<&StreamIndexedQueue<RequestOrResponse>> for SerializableStreamIndexedQueue {
    fn from(q: &StreamIndexedQueue<RequestOrResponse>) -> Self {
        SerializableStreamIndexedQueue {
            begin: q.begin(),
            queue: q.iter().map(|(_, msg)| msg.clone()).collect(),
        }
    }
}

impl From<SerializableStreamIndexedQueue> for StreamIndexedQueue<RequestOrResponse> {
    fn from(q: SerializableStreamIndexedQueue) -> StreamIndexedQueue<RequestOrResponse> {
        let mut queue = StreamIndexedQueue::with_begin(q.begin);
        q.queue.iter().for_each(|entry| queue.push(entry.clone()));
        queue
    }
}

// Local helper to enable serialization and deserialization of
// ic_types::xnet::StreamSlice for testing
#[derive(Serialize, Deserialize)]
struct SerializableStreamSlice {
    header: StreamHeader,
    messages: Option<SerializableStreamIndexedQueue>,
}

impl From<StreamSlice> for SerializableStreamSlice {
    fn from(slice: StreamSlice) -> Self {
        SerializableStreamSlice {
            header: slice.header().clone(),
            messages: slice.messages().map(|messages| messages.into()),
        }
    }
}

impl From<SerializableStreamSlice> for StreamSlice {
    fn from(slice: SerializableStreamSlice) -> StreamSlice {
        StreamSlice::new(
            slice.header,
            slice
                .messages
                .map(|messages| messages.into())
                .unwrap_or_default(),
        )
    }
}

impl CertifiedStreamStore for FakeStateManager {
    /// Behaves similarly to `StateManager::encode_certified_stream_slice()`,
    /// except the slice is encoded directly as CBOR, with no witness or
    /// certification.
    ///
    /// `byte_limit` is ignored except if it is `Some(0)`, in which case the
    /// result contains a slice with exactly one message if `msg_limit > 0` and
    /// a message is available.
    fn encode_certified_stream_slice(
        &self,
        remote_subnet: SubnetId,
        _witness_begin: Option<StreamIndex>,
        msg_begin: Option<StreamIndex>,
        mut msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> Result<CertifiedStreamSlice, EncodeStreamError> {
        use ic_types::{
            consensus::certification::CertificationContent,
            crypto::{CombinedThresholdSig, CombinedThresholdSigOf, Signed},
            signature::ThresholdSignature,
        };

        let state = self.get_latest_state();
        let stream = state
            .get_ref()
            .get_stream(&remote_subnet)
            .ok_or(EncodeStreamError::NoStreamForSubnet(remote_subnet))?;

        let begin_index = msg_begin.unwrap_or_else(|| stream.messages_begin());
        if begin_index < stream.messages_begin() || stream.messages_end() < begin_index {
            return Err(EncodeStreamError::InvalidSliceBegin {
                slice_begin: begin_index,
                stream_begin: stream.messages_begin(),
                stream_end: stream.messages_end(),
            });
        }

        if byte_limit.unwrap_or(1) == 0 && msg_limit.unwrap_or(1) != 0 {
            // If `byte_limit == 0 && msg_limit > 0`, return exactly 1 message.
            msg_limit = Some(1);
        }
        let slice: SerializableStreamSlice = stream.slice(begin_index, msg_limit).into();

        Ok(CertifiedStreamSlice {
            payload: serde_cbor::to_vec(&slice).expect("failed to serialize stream slice"),
            merkle_proof: vec![],
            certification: Certification {
                height: state.height(),
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
                    content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(
                        vec![],
                    ))),
                },
            },
        })
    }

    fn decode_certified_stream_slice(
        &self,
        _remote_subnet: SubnetId,
        _registry_version: RegistryVersion,
        certified_slice: &CertifiedStreamSlice,
    ) -> Result<StreamSlice, DecodeStreamError> {
        self.decode_valid_certified_stream_slice(certified_slice)
    }

    fn decode_valid_certified_stream_slice(
        &self,
        certified_slice: &CertifiedStreamSlice,
    ) -> Result<StreamSlice, DecodeStreamError> {
        serde_cbor::from_slice(&certified_slice.payload[..])
            .map_err(|err| DecodeStreamError::SerializationError(err.to_string()))
            .map(|slice: SerializableStreamSlice| slice.into())
    }

    fn subnets_with_certified_streams(&self) -> Vec<SubnetId> {
        self.get_latest_state()
            .get_ref()
            .subnets_with_available_streams()
    }
}

/// This wrapper is needed, so that we can share the same mocked StateManager
/// across multiple components. Also, since we first instantiate the components
/// and _then_ add the expectations to it (which requires the mock to be
/// mutable), we need to use a lock.
#[derive(Default)]
pub struct RefMockStateManager {
    pub mock: RwLock<MockStateManager>,
}

impl RefMockStateManager {
    pub fn get_mut(&self) -> std::sync::RwLockWriteGuard<'_, MockStateManager> {
        self.mock.write().unwrap()
    }
}

impl StateManager for RefMockStateManager {
    fn take_tip(&self) -> (Height, Self::State) {
        self.mock.read().unwrap().take_tip()
    }

    fn take_tip_at(&self, h: Height) -> StateManagerResult<Self::State> {
        self.mock.read().unwrap().take_tip_at(h)
    }

    fn get_state_hash_at(&self, height: Height) -> Result<CryptoHashOfState, StateHashError> {
        self.mock.read().unwrap().get_state_hash_at(height)
    }

    fn fetch_state(
        &self,
        height: Height,
        root_hash: CryptoHashOfState,
        cup_interval_length: Height,
    ) {
        self.mock
            .read()
            .unwrap()
            .fetch_state(height, root_hash, cup_interval_length)
    }

    fn list_state_hashes_to_certify(&self) -> Vec<(Height, CryptoHashOfPartialState)> {
        self.mock.read().unwrap().list_state_hashes_to_certify()
    }

    fn deliver_state_certification(&self, certification: Certification) {
        self.mock
            .read()
            .unwrap()
            .deliver_state_certification(certification)
    }

    fn list_state_heights(&self, cert_mask: CertificationMask) -> Vec<Height> {
        self.mock.read().unwrap().list_state_heights(cert_mask)
    }

    fn remove_states_below(&self, height: Height) {
        self.mock.read().unwrap().remove_states_below(height)
    }

    fn commit_and_certify(
        &self,
        state: ReplicatedState,
        height: Height,
        scope: CertificationScope,
    ) {
        self.mock
            .read()
            .unwrap()
            .commit_and_certify(state, height, scope)
    }

    fn report_diverged_state(&self, height: Height) {
        self.mock.read().unwrap().report_diverged_state(height)
    }
}

impl StateReader for RefMockStateManager {
    type State = ReplicatedState;

    fn latest_state_height(&self) -> Height {
        self.mock.read().unwrap().latest_state_height()
    }

    fn latest_certified_height(&self) -> Height {
        self.mock.read().unwrap().latest_certified_height()
    }

    fn get_latest_state(&self) -> Labeled<Arc<Self::State>> {
        self.mock.read().unwrap().get_latest_state()
    }

    fn get_state_at(&self, height: Height) -> StateManagerResult<Labeled<Arc<Self::State>>> {
        self.mock.read().unwrap().get_state_at(height)
    }

    fn read_certified_state(
        &self,
        paths: &LabeledTree<()>,
    ) -> Option<(Arc<Self::State>, MixedHashTree, Certification)> {
        self.mock.read().unwrap().read_certified_state(paths)
    }
}
