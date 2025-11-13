use ic_crypto_sha2::Sha256;
use ic_crypto_tree_hash::{LabeledTree, MatchPatternPath, MixedHashTree};
use ic_interfaces_certified_stream_store::{
    CertifiedStreamStore, DecodeStreamError, EncodeStreamError,
};
use ic_interfaces_state_manager::{
    CertificationScope, CertifiedStateSnapshot, Labeled, PermanentStateHashError::*,
    StateHashError, StateManager, StateReader, TransientStateHashError::*,
};
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    ReplicatedState,
    page_map::{PageAllocatorFileDescriptor, TestPageAllocatorFileDescriptorImpl},
};
use ic_test_utilities_types::ids::subnet_test_id;
use ic_types::{
    CryptoHashOfPartialState, CryptoHashOfState, Height, RegistryVersion, SubnetId,
    batch::BatchSummary,
    consensus::certification::Certification,
    crypto::{
        CryptoHash, CryptoHashOf,
        threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
    },
    messages::{Refund, Request, Response, StreamMessage},
    state_manager::{StateManagerError, StateManagerResult},
    xnet::{
        CertifiedStreamSlice, RejectReason, RejectSignal, StreamFlags, StreamHeader, StreamIndex,
        StreamIndexedQueue, StreamSlice,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Barrier, RwLock};

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
}

/// A fake implementation of the `StateManager` interface.
///
/// It only keeps states in memory, has no persistence and can't do state
/// sync.
#[derive(Clone)]
pub struct FakeStateManager {
    states: Arc<RwLock<Vec<Snapshot>>>,
    tip: Arc<RwLock<Option<(Height, ReplicatedState)>>>,
    tempdir: Arc<tempfile::TempDir>,
    /// Size 1 by default (no op).
    pub encode_certified_stream_slice_barrier: Arc<RwLock<Barrier>>,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
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
                ReplicatedState::new(subnet_test_id(169), SubnetType::Application),
            )))),
            tempdir: Arc::new(tmpdir),
            encode_certified_stream_slice_barrier: Arc::new(RwLock::new(Barrier::new(1))),
            fd_factory: Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
        }
    }

    pub fn tmp(&self) -> &Path {
        self.tempdir.path()
    }

    pub fn get_fd_factory(&self) -> Arc<dyn PageAllocatorFileDescriptor> {
        Arc::clone(&self.fd_factory)
    }
}

const INITIAL_STATE_HEIGHT: Height = Height::new(0);
fn initial_state() -> Labeled<Arc<ReplicatedState>> {
    Labeled::new(
        INITIAL_STATE_HEIGHT,
        Arc::new(ReplicatedState::new(
            subnet_test_id(1),
            SubnetType::Application,
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

    fn remove_states_below(&self, height: Height) {
        self.states
            .write()
            .unwrap()
            .retain(|snap| snap.height == Height::new(0) || snap.height >= height)
    }

    fn remove_inmemory_states_below(
        &self,
        _height: Height,
        _extra_heights_to_keep: &BTreeSet<Height>,
    ) {
        // All heights are checkpoints
    }

    fn commit_and_certify(
        &self,
        state: ReplicatedState,
        height: Height,
        _scope: CertificationScope,
        _batch_summary: Option<BatchSummary>,
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
            "Attempt to submit a state not borrowed from this StateManager Height {height}"
        );
        *tip = Some((height, state));
    }

    fn report_diverged_checkpoint(&self, height: Height) {
        panic!("Diverged at height {height}")
    }
}

impl StateReader for FakeStateManager {
    type State = ReplicatedState;

    fn latest_state_height(&self) -> Height {
        self.states
            .read()
            .unwrap()
            .last()
            .map_or(INITIAL_STATE_HEIGHT, |snap| snap.height)
    }

    // No certification support in FakeStateManager
    fn latest_certified_height(&self) -> Height {
        self.states
            .read()
            .unwrap()
            .iter()
            .filter(|s| s.height > Height::from(0) && s.certification.is_some())
            .map(|s| s.height)
            .next_back()
            .unwrap_or_else(|| Height::from(0))
    }

    fn get_latest_state(&self) -> Labeled<Arc<Self::State>> {
        self.states
            .read()
            .unwrap()
            .last()
            .map_or_else(initial_state, |snap| snap.make_labeled_state())
    }

    // No certification support in FakeStateManager
    fn get_latest_certified_state(&self) -> Option<Labeled<Arc<Self::State>>> {
        None
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

    fn read_certified_state_with_exclusion(
        &self,
        _paths: &LabeledTree<()>,
        _exclusion: Option<&MatchPatternPath>,
    ) -> Option<(Arc<Self::State>, MixedHashTree, Certification)> {
        None
    }

    fn get_certified_state_snapshot(
        &self,
    ) -> Option<Box<dyn CertifiedStateSnapshot<State = Self::State> + 'static>> {
        None
    }
}

/// Local helper to enable serialization and deserialization of
/// [`StreamMessage`] for testing.
#[derive(Deserialize, Serialize)]
enum SerializableStreamMessage {
    Request(Request),
    Response(Response),
    Refund(Refund),
}

impl From<&StreamMessage> for SerializableStreamMessage {
    fn from(msg: &StreamMessage) -> Self {
        match msg {
            StreamMessage::Request(req) => SerializableStreamMessage::Request((**req).clone()),
            StreamMessage::Response(rep) => SerializableStreamMessage::Response((**rep).clone()),
            StreamMessage::Refund(refund) => SerializableStreamMessage::Refund(**refund),
        }
    }
}

impl From<SerializableStreamMessage> for StreamMessage {
    fn from(msg: SerializableStreamMessage) -> StreamMessage {
        match msg {
            SerializableStreamMessage::Request(req) => StreamMessage::Request(Arc::new(req)),
            SerializableStreamMessage::Response(rep) => StreamMessage::Response(Arc::new(rep)),
            SerializableStreamMessage::Refund(refund) => StreamMessage::Refund(Arc::new(refund)),
        }
    }
}

/// Local helper to enable serialization and deserialization of
/// ['StreamHeader'] for testing.
#[derive(Deserialize, Serialize)]
struct SerializableStreamHeader {
    begin: StreamIndex,
    end: StreamIndex,
    signals_end: StreamIndex,
    reject_signals: VecDeque<SerializableRejectSignal>,
    flags: SerializableStreamFlags,
}

impl From<&StreamHeader> for SerializableStreamHeader {
    fn from(header: &StreamHeader) -> Self {
        Self {
            begin: header.begin(),
            end: header.end(),
            signals_end: header.signals_end(),
            reject_signals: header.reject_signals().iter().map(From::from).collect(),
            flags: header.flags().into(),
        }
    }
}

impl From<SerializableStreamHeader> for StreamHeader {
    fn from(header: SerializableStreamHeader) -> StreamHeader {
        StreamHeader::new(
            header.begin,
            header.end,
            header.signals_end,
            header.reject_signals.into_iter().map(From::from).collect(),
            header.flags.into(),
        )
    }
}

/// Local helper to enable serialization and deserialization of
/// ['RejectReason'] for testing.
#[derive(Deserialize, Serialize)]
pub enum SerializableRejectReason {
    CanisterMigrating = 1,
    CanisterNotFound = 2,
    CanisterStopped = 3,
    CanisterStopping = 4,
    QueueFull = 5,
    OutOfMemory = 6,
    Unknown = 7,
}

impl From<&RejectReason> for SerializableRejectReason {
    fn from(reason: &RejectReason) -> Self {
        match reason {
            RejectReason::CanisterMigrating => Self::CanisterMigrating,
            RejectReason::CanisterNotFound => Self::CanisterNotFound,
            RejectReason::CanisterStopped => Self::CanisterStopped,
            RejectReason::CanisterStopping => Self::CanisterStopping,
            RejectReason::QueueFull => Self::QueueFull,
            RejectReason::OutOfMemory => Self::OutOfMemory,
            RejectReason::Unknown => Self::Unknown,
        }
    }
}

impl From<SerializableRejectReason> for RejectReason {
    fn from(reason: SerializableRejectReason) -> RejectReason {
        match reason {
            SerializableRejectReason::CanisterMigrating => RejectReason::CanisterMigrating,
            SerializableRejectReason::CanisterNotFound => RejectReason::CanisterNotFound,
            SerializableRejectReason::CanisterStopped => RejectReason::CanisterStopped,
            SerializableRejectReason::CanisterStopping => RejectReason::CanisterStopping,
            SerializableRejectReason::QueueFull => RejectReason::QueueFull,
            SerializableRejectReason::OutOfMemory => RejectReason::OutOfMemory,
            SerializableRejectReason::Unknown => RejectReason::Unknown,
        }
    }
}

/// Local helper to enable serialization and deserialization of
/// ['RejectSignal'] for testing.
#[derive(Deserialize, Serialize)]
pub struct SerializableRejectSignal {
    pub reason: SerializableRejectReason,
    pub index: StreamIndex,
}

impl From<&RejectSignal> for SerializableRejectSignal {
    fn from(signal: &RejectSignal) -> Self {
        Self {
            reason: (&signal.reason).into(),
            index: signal.index,
        }
    }
}

impl From<SerializableRejectSignal> for RejectSignal {
    fn from(signal: SerializableRejectSignal) -> RejectSignal {
        RejectSignal {
            reason: signal.reason.into(),
            index: signal.index,
        }
    }
}

/// Local helper to enable serialization and deserialization of
/// ['StreamFlags'] for testing.
#[derive(Deserialize, Serialize)]
pub struct SerializableStreamFlags {
    pub deprecated_responses_only: bool,
}

impl From<&StreamFlags> for SerializableStreamFlags {
    fn from(flags: &StreamFlags) -> Self {
        Self {
            deprecated_responses_only: flags.deprecated_responses_only,
        }
    }
}

impl From<SerializableStreamFlags> for StreamFlags {
    fn from(flags: SerializableStreamFlags) -> StreamFlags {
        StreamFlags {
            deprecated_responses_only: flags.deprecated_responses_only,
        }
    }
}

/// Local helper to enable serialization and deserialization of
/// [`StreamIndexedQueue`] for testing.
#[derive(Deserialize, Serialize)]
struct SerializableStreamIndexedQueue {
    begin: StreamIndex,
    queue: VecDeque<SerializableStreamMessage>,
}

impl From<&StreamIndexedQueue<StreamMessage>> for SerializableStreamIndexedQueue {
    fn from(q: &StreamIndexedQueue<StreamMessage>) -> Self {
        SerializableStreamIndexedQueue {
            begin: q.begin(),
            queue: q.iter().map(|(_, msg)| msg.into()).collect(),
        }
    }
}

impl From<SerializableStreamIndexedQueue> for StreamIndexedQueue<StreamMessage> {
    fn from(q: SerializableStreamIndexedQueue) -> StreamIndexedQueue<StreamMessage> {
        let mut queue = StreamIndexedQueue::with_begin(q.begin);
        q.queue
            .into_iter()
            .for_each(|entry| queue.push(entry.into()));
        queue
    }
}

/// Local helper to enable serialization and deserialization of
/// [`StreamSlice`] for testing.
#[derive(Deserialize, Serialize)]
struct SerializableStreamSlice {
    header: SerializableStreamHeader,
    messages: Option<SerializableStreamIndexedQueue>,
}

impl From<StreamSlice> for SerializableStreamSlice {
    fn from(slice: StreamSlice) -> Self {
        SerializableStreamSlice {
            header: slice.header().into(),
            messages: slice.messages().map(|messages| messages.into()),
        }
    }
}

impl From<SerializableStreamSlice> for StreamSlice {
    fn from(slice: SerializableStreamSlice) -> StreamSlice {
        StreamSlice::new(
            slice.header.into(),
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
        self.encode_certified_stream_slice_barrier
            .read()
            .unwrap()
            .wait();

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

        Ok(encode_certified_stream_slice(
            stream.slice(begin_index, msg_limit),
            state.height(),
        ))
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

/// Encode a `StreamSlice` directly as CBOR, with no witness or certification;
/// compatible with `FakeStateManager`.
///
/// This is useful for generating a `CertifiedStreamSlice` where
/// `slice.header().begin() != `slice.messages().begin()` for use in tests.
pub fn encode_certified_stream_slice(
    slice: StreamSlice,
    state_height: Height,
) -> CertifiedStreamSlice {
    use ic_types::{
        consensus::certification::CertificationContent,
        crypto::{CombinedThresholdSig, CombinedThresholdSigOf, Signed},
        signature::ThresholdSignature,
    };

    let slice: SerializableStreamSlice = slice.into();

    CertifiedStreamSlice {
        payload: serde_cbor::to_vec(&slice).expect("failed to serialize stream slice"),
        merkle_proof: vec![],
        certification: Certification {
            height: state_height,
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

    fn remove_states_below(&self, height: Height) {
        self.mock.read().unwrap().remove_states_below(height)
    }

    fn remove_inmemory_states_below(
        &self,
        height: Height,
        extra_heights_to_keep: &BTreeSet<Height>,
    ) {
        self.mock
            .read()
            .unwrap()
            .remove_inmemory_states_below(height, extra_heights_to_keep)
    }

    fn commit_and_certify(
        &self,
        state: ReplicatedState,
        height: Height,
        scope: CertificationScope,
        batch_summary: Option<BatchSummary>,
    ) {
        self.mock
            .read()
            .unwrap()
            .commit_and_certify(state, height, scope, batch_summary)
    }

    fn report_diverged_checkpoint(&self, height: Height) {
        self.mock.read().unwrap().report_diverged_checkpoint(height)
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

    fn get_latest_certified_state(&self) -> Option<Labeled<Arc<Self::State>>> {
        self.mock.read().unwrap().get_latest_certified_state()
    }

    fn get_state_at(&self, height: Height) -> StateManagerResult<Labeled<Arc<Self::State>>> {
        self.mock.read().unwrap().get_state_at(height)
    }

    fn read_certified_state_with_exclusion(
        &self,
        paths: &LabeledTree<()>,
        exclusion: Option<&MatchPatternPath>,
    ) -> Option<(Arc<Self::State>, MixedHashTree, Certification)> {
        self.mock
            .read()
            .unwrap()
            .read_certified_state_with_exclusion(paths, exclusion)
    }

    fn get_certified_state_snapshot(
        &self,
    ) -> Option<Box<dyn CertifiedStateSnapshot<State = Self::State> + 'static>> {
        self.mock.read().unwrap().get_certified_state_snapshot()
    }
}
