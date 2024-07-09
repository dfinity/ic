use std::{
    collections::{hash_map::DefaultHasher, BTreeMap, HashSet},
    hash::{Hash, Hasher},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Duration,
};

use ic_interfaces::p2p::state_sync::{
    AddChunkError, Chunk, ChunkId, Chunkable, StateSyncArtifactId, StateSyncClient,
};
use ic_logger::ReplicaLogger;
use ic_memory_transport::TransportRouter;
use ic_metrics::MetricsRegistry;
use ic_p2p_test_utils::mocks::{MockChunkable, MockStateSync};
use ic_quic_transport::Shutdown;
use ic_state_manager::state_sync::types::StateSyncMessage;
use ic_types::{crypto::CryptoHash, Height, NodeId, PrincipalId};
use tokio::runtime::Handle;

const META_MANIFEST_ID: u32 = u32::MAX - 1;

// We define manifest chunks as chunks with id > u32::MAX >> 2.
fn is_manifest_chunk(chunk_id: ChunkId) -> bool {
    chunk_id.get() > (u32::MAX >> 2)
}

#[derive(Debug, Clone, Default)]
struct StateInner {
    height: Height,
    /// Chunks part of this state. The actual chunks always consist of zeros for this
    /// mock and we only store the size.
    chunks: BTreeMap<ChunkId, usize>,
}

#[derive(Debug, Clone)]
pub struct State(Arc<Mutex<StateInner>>);

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.artifact_id() == other.artifact_id()
    }
}

impl Eq for State {}

impl State {
    /// Create a new state with a small initial state.
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(StateInner {
            height: Height::from(1),
            chunks: BTreeMap::from([(ChunkId::from(1), 100)]),
        })))
    }

    /// Add many chunks all with the same size
    pub fn add_new_chunks(&self, num: u32, size: usize) {
        let mut state = self.0.lock().unwrap();
        let last = state.chunks.last_entry().unwrap().key().get() + 1;
        for c in last..(last + num) {
            state.chunks.insert(ChunkId::from(c), size);
        }

        state.height = state.height.increment();
    }

    /// Add new chunk to state.
    /// Panics if chunk already part of state.
    pub fn add_chunk(&self, chunk_id: ChunkId, size: usize) {
        let mut state = self.0.lock().unwrap();
        if state.chunks.insert(chunk_id, size).is_some() {
            panic!("Inserting chunk that is already present.");
        }
    }

    pub fn height(&self) -> Height {
        let state = self.0.lock().unwrap();
        state.height
    }

    pub fn set_height(&self, h: Height) {
        let mut state = self.0.lock().unwrap();
        state.height = h;
    }

    pub fn chunk(&self, chunk_id: ChunkId) -> Option<Vec<u8>> {
        let state = self.0.lock().unwrap();
        state
            .chunks
            .get(&chunk_id)
            .map(|chunk_size| vec![0; *chunk_size])
    }

    /// Calculates the artifact Id of the current state by hashing the ChunkId map.
    pub fn artifact_id(&self) -> StateSyncArtifactId {
        let state = self.0.lock().unwrap();
        let mut hasher = DefaultHasher::new();
        state.height.hash(&mut hasher);
        state.chunks.hash(&mut hasher);
        StateSyncArtifactId {
            height: state.height,
            hash: CryptoHash(hasher.finish().to_be_bytes().to_vec()),
        }
    }

    pub fn num_chunks(&self) -> usize {
        self.0.lock().unwrap().chunks.len()
    }

    /// Returns vector of chunks that are not in this state but in the other.
    pub fn chunk_diff(&self, other: &State) -> Vec<ChunkId> {
        let this_state = self.0.lock().unwrap();
        let other_state = other.0.lock().unwrap();
        other_state
            .chunks
            .iter()
            .filter_map(|(k, _)| {
                if !this_state.chunks.contains_key(k) {
                    Some(k)
                } else {
                    None
                }
            })
            .cloned()
            .collect()
    }
}

/// Fake state sync object that mocks the state sync part of the state manager.
///
/// There are two possible modes that it can be in:
///     1. It uses a global state. The global state represents the state on which
///        there exists consensus. Nodes can be simulated as healthy by setting the
///        the uses_global flag. This means they act as if they have the global state
///        and are able to serve the global state to peers.
///     2. The node uses a local state. This simulates a node that does not know about
///        the global state and it will try to sync to the global state if it learns about it.
///        If it successfully synced it will start acting as a healthy node with the global state.
#[derive(Clone)]
pub struct FakeStateSync {
    local_state: State,
    global_state: State,
    uses_global: Arc<AtomicBool>,
    disconnected: Arc<AtomicBool>,
}

impl FakeStateSync {
    pub fn is_equal(&self, other: &Self) -> bool {
        match (self.uses_global(), other.uses_global()) {
            (true, true) => true,
            (true, false) => self.global_state == other.local_state,
            (false, true) => self.local_state == other.global_state,
            (false, false) => self.local_state == other.local_state,
        }
    }

    pub fn disconnected(&self) -> bool {
        self.disconnected.load(Ordering::SeqCst)
    }

    pub fn uses_global(&self) -> bool {
        self.uses_global.load(Ordering::SeqCst)
    }

    pub fn current_height(&self) -> Height {
        if self.uses_global() {
            self.global_state.height()
        } else {
            self.local_state.height()
        }
    }
}

impl StateSyncClient for FakeStateSync {
    type Message = StateSyncMessage;

    fn available_states(&self) -> Vec<StateSyncArtifactId> {
        if self.disconnected.load(Ordering::SeqCst) {
            return vec![];
        }
        if self.uses_global() {
            vec![self.global_state.artifact_id()]
        } else {
            vec![self.local_state.artifact_id()]
        }
    }

    fn maybe_start_state_sync(
        &self,
        id: &StateSyncArtifactId,
    ) -> Option<Box<dyn Chunkable<StateSyncMessage> + Send>> {
        if !self.uses_global() && id.height > self.current_height() && !self.disconnected() {
            return Some(Box::new(FakeChunkable::new(
                self.local_state.clone(),
                self.global_state.clone(),
            )));
        }
        None
    }

    fn cancel_if_running(&self, id: &StateSyncArtifactId) -> bool {
        if !self.uses_global() {
            self.global_state.height() > id.height + Height::from(1)
        } else {
            false
        }
    }

    fn chunk(&self, id: &StateSyncArtifactId, chunk_id: ChunkId) -> Option<Chunk> {
        if self.disconnected.load(Ordering::SeqCst) || id != &self.global_state.artifact_id() {
            return None;
        }

        if is_manifest_chunk(chunk_id) {
            return Some(vec![0; 100].into());
        }

        self.global_state.chunk(chunk_id).map(Chunk::from)
    }
}

pub struct FakeChunkable {
    local_state: State,
    syncing_state: StateSyncArtifactId,
    // [meta-manifest, manifests, chunks]
    chunk_sets: [HashSet<ChunkId>; 3],
    is_completed: bool,
}

impl FakeChunkable {
    pub fn new(local_state: State, global_state: State) -> Self {
        let global_state_chunks = global_state.num_chunks() as f32;
        // State sync chunks are requested in order. First meta-manifest, second
        // manifests and last data chunks. The manifests and data chunks build a tree
        // and this is what we simulate here.
        let num_manifests = global_state_chunks.log2() as u32;
        let chunk_sets = [
            HashSet::from_iter(vec![ChunkId::from(META_MANIFEST_ID)]),
            HashSet::from_iter((2..num_manifests).map(|i| ChunkId::from(u32::MAX - i))),
            HashSet::from_iter(local_state.chunk_diff(&global_state)),
        ];
        Self {
            local_state,
            syncing_state: global_state.artifact_id(),
            chunk_sets,
            is_completed: false,
        }
    }
}

impl Chunkable<StateSyncMessage> for FakeChunkable {
    /// Returns iterator for chunks to download.
    /// Tries to first download metamanifest, then manifest and then chunks. Does not advance if previous didn't complete.
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>> {
        let mut to_download = Vec::new();
        for set in self.chunk_sets.iter() {
            for chunk in set.iter() {
                to_download.push(*chunk);
            }
            if !to_download.is_empty() {
                break;
            }
        }
        Box::new(to_download.into_iter().map(ChunkId::from))
    }

    fn add_chunk(&mut self, chunk_id: ChunkId, chunk: Chunk) -> Result<(), AddChunkError> {
        for set in self.chunk_sets.iter_mut() {
            if set.is_empty() {
                continue;
            }
            if set.remove(&chunk_id) {
                break;
            } else {
                panic!("Downloaded chunk {} twice", chunk_id)
            }
        }

        // Add chunk to state if not part of manifest
        if !is_manifest_chunk(chunk_id) {
            self.local_state.add_chunk(chunk_id, chunk.as_bytes().len())
        }

        let elems = self.chunk_sets.iter().map(|set| set.len()).sum::<usize>();
        if elems == 0 {
            self.local_state.set_height(self.syncing_state.height);
            self.is_completed = true;
        }

        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct SharableMockChunkable {
    mock: Arc<Mutex<MockChunkable<StateSyncMessage>>>,
    chunks_to_download_calls: Arc<AtomicUsize>,
    add_chunks_calls: Arc<AtomicUsize>,
}

impl SharableMockChunkable {
    pub fn new() -> Self {
        Self {
            mock: Arc::new(Mutex::new(MockChunkable::default())),
            ..Default::default()
        }
    }
    pub fn get_mut(&self) -> MutexGuard<'_, MockChunkable<StateSyncMessage>> {
        self.mock.lock().unwrap()
    }
    pub fn add_chunks_calls(&self) -> usize {
        self.add_chunks_calls.load(Ordering::SeqCst)
    }
    pub fn clear(&self) {
        self.chunks_to_download_calls.store(0, Ordering::SeqCst);
        self.add_chunks_calls.store(0, Ordering::SeqCst);
    }
}

impl Chunkable<StateSyncMessage> for SharableMockChunkable {
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>> {
        self.chunks_to_download_calls.fetch_add(1, Ordering::SeqCst);
        self.mock.lock().unwrap().chunks_to_download()
    }
    fn add_chunk(&mut self, chunk_id: ChunkId, chunk: Chunk) -> Result<(), AddChunkError> {
        self.add_chunks_calls.fetch_add(1, Ordering::SeqCst);
        self.mock.lock().unwrap().add_chunk(chunk_id, chunk)
    }
}

#[derive(Clone, Default)]
pub struct SharableMockStateSync {
    mock: Arc<Mutex<MockStateSync<StateSyncMessage>>>,
    available_states_calls: Arc<AtomicUsize>,
    maybe_start_state_sync_calls: Arc<AtomicUsize>,
    cancel_if_running_calls: Arc<AtomicUsize>,
    chunk_calls: Arc<AtomicUsize>,
}

impl SharableMockStateSync {
    pub fn new() -> Self {
        Self {
            mock: Arc::new(Mutex::new(MockStateSync::default())),
            ..Default::default()
        }
    }
    pub fn get_mut(&self) -> MutexGuard<'_, MockStateSync<StateSyncMessage>> {
        self.mock.lock().unwrap()
    }
    pub fn maybe_start_state_sync_calls(&self) -> usize {
        self.maybe_start_state_sync_calls.load(Ordering::SeqCst)
    }
    pub fn clear(&self) {
        self.available_states_calls.store(0, Ordering::SeqCst);
        self.maybe_start_state_sync_calls.store(0, Ordering::SeqCst);
        self.cancel_if_running_calls.store(0, Ordering::SeqCst);
        self.chunk_calls.store(0, Ordering::SeqCst);
    }
}

impl StateSyncClient for SharableMockStateSync {
    type Message = StateSyncMessage;

    fn available_states(&self) -> Vec<StateSyncArtifactId> {
        self.available_states_calls.fetch_add(1, Ordering::SeqCst);
        self.mock.lock().unwrap().available_states()
    }
    fn maybe_start_state_sync(
        &self,
        id: &StateSyncArtifactId,
    ) -> Option<Box<dyn Chunkable<StateSyncMessage> + Send>> {
        self.maybe_start_state_sync_calls
            .fetch_add(1, Ordering::SeqCst);
        self.mock.lock().unwrap().maybe_start_state_sync(id)
    }
    fn cancel_if_running(&self, id: &StateSyncArtifactId) -> bool {
        self.cancel_if_running_calls.fetch_add(1, Ordering::SeqCst);
        self.mock.lock().unwrap().cancel_if_running(id)
    }
    fn chunk(&self, id: &StateSyncArtifactId, chunk_id: ChunkId) -> Option<Chunk> {
        self.chunk_calls.fetch_add(1, Ordering::SeqCst);
        self.mock.lock().unwrap().chunk(id, chunk_id)
    }
}

/// Returns tuple of link latency and capacity in bytes for the described link
pub fn latency_50ms_throughput_300mbits() -> (Duration, usize) {
    (Duration::from_millis(50), 1_875_000)
}

/// Returns tuple of link latency and capacity in bytes for the described link
pub fn latency_30ms_throughput_1000mbits() -> (Duration, usize) {
    (Duration::from_millis(30), 3_750_000)
}

pub fn create_node(
    node_num: u64,
    log: ReplicaLogger,
    transport_router: &mut TransportRouter,
    rt: &Handle,
    uses_global: bool,
    global_state: State,
    link: (Duration, usize),
) -> (Arc<FakeStateSync>, Shutdown) {
    let local_state = State::new();
    let state_sync = Arc::new(FakeStateSync {
        local_state,
        global_state,
        uses_global: Arc::new(AtomicBool::new(uses_global)),
        disconnected: Arc::new(AtomicBool::new(false)),
    });

    let (router, rx) = ic_state_sync_manager::build_axum_router(
        state_sync.clone(),
        log.clone(),
        &MetricsRegistry::default(),
    );
    let transport = transport_router.add_peer(
        NodeId::from(PrincipalId::new_node_test_id(node_num)),
        router,
        link.0,
        link.1,
    );
    let shutdown = ic_state_sync_manager::start_state_sync_manager(
        &log,
        &MetricsRegistry::default(),
        rt,
        Arc::new(transport),
        state_sync.clone(),
        rx,
    );

    (state_sync, shutdown)
}
