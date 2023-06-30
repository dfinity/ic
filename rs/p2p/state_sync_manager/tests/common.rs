use std::{
    collections::{hash_map::DefaultHasher, BTreeMap, HashSet},
    hash::{Hash, Hasher},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use ic_interfaces::state_sync_client::StateSyncClient;
use ic_logger::ReplicaLogger;
use ic_memory_transport::TransportRouter;
use ic_metrics::MetricsRegistry;
use ic_types::{
    artifact::{Artifact, StateSyncArtifactId, StateSyncMessage},
    chunkable::{ArtifactChunk, ArtifactChunkData, ArtifactErrorCode, ChunkId, Chunkable},
    crypto::CryptoHash,
    state_sync::{Manifest, MetaManifest, StateSyncVersion},
    CryptoHashOfState, Height, NodeId, PrincipalId,
};
use tokio::{runtime::Handle, task::JoinHandle};

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

    pub fn chunk(&self, chunk_id: ChunkId) -> Option<Vec<u8>> {
        let state = self.0.lock().unwrap();
        state
            .chunks
            .get(&chunk_id)
            .map(|chunk_size| vec![0; *chunk_size])
    }

    /// Calulcates the artifact Id of the current state by hasing the ChunkId map.
    pub fn artifact_id(&self) -> StateSyncArtifactId {
        let state = self.0.lock().unwrap();
        let mut hasher = DefaultHasher::new();
        state.height.hash(&mut hasher);
        state.chunks.hash(&mut hasher);
        StateSyncArtifactId {
            height: state.height,
            hash: CryptoHashOfState::from(CryptoHash(hasher.finish().to_be_bytes().to_vec())),
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
    pub fn set_use_global(&self, global: bool) {
        self.uses_global.store(global, Ordering::SeqCst);
    }

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
    fn latest_state(&self) -> Option<StateSyncArtifactId> {
        if self.disconnected.load(Ordering::SeqCst) {
            return None;
        }
        if self.uses_global() {
            Some(self.global_state.artifact_id())
        } else {
            Some(self.local_state.artifact_id())
        }
    }

    fn start_state_sync(
        &self,
        id: &StateSyncArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>> {
        if !self.uses_global() && id.height > self.current_height() && !self.disconnected() {
            return Some(Box::new(FakeChunkable::new(
                self.local_state.clone(),
                self.global_state.clone(),
            )));
        }
        None
    }

    fn should_cancel(&self, id: &StateSyncArtifactId) -> bool {
        if !self.uses_global() {
            self.global_state.height() > id.height + Height::from(1)
        } else {
            false
        }
    }

    fn chunk(&self, id: &StateSyncArtifactId, chunk_id: ChunkId) -> Option<ArtifactChunk> {
        if self.disconnected.load(Ordering::SeqCst) || id != &self.global_state.artifact_id() {
            return None;
        }

        if is_manifest_chunk(chunk_id) {
            return Some(ArtifactChunk {
                chunk_id,
                witness: vec![],
                artifact_chunk_data: ArtifactChunkData::SemiStructuredChunkData(vec![0; 100]),
            });
        }

        self.global_state
            .chunk(chunk_id)
            .map(|chunk| ArtifactChunk {
                chunk_id,
                witness: vec![],
                artifact_chunk_data: ArtifactChunkData::SemiStructuredChunkData(chunk),
            })
    }

    fn deliver_state_sync(&self, _msg: StateSyncMessage, _peer_id: NodeId) {
        if !self.uses_global() {
            self.set_use_global(true);
        } else {
            panic!("Node that follows global state should not start state sync");
        }
    }
}

pub struct FakeChunkable {
    local_state: State,
    syncing_state: StateSyncArtifactId,
    // [meta-manifest, manifests, chunks]
    chunk_sets: [HashSet<ChunkId>; 3],
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
        }
    }
}

impl Chunkable for FakeChunkable {
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

    fn add_chunk(&mut self, artifact_chunk: ArtifactChunk) -> Result<Artifact, ArtifactErrorCode> {
        for set in self.chunk_sets.iter_mut() {
            if set.is_empty() {
                continue;
            }
            if set.remove(&artifact_chunk.chunk_id) {
                break;
            } else {
                panic!("Downloaded chunk {} twice", artifact_chunk.chunk_id)
            }
        }

        // Add chunk to state if not part of manifest
        if !is_manifest_chunk(artifact_chunk.chunk_id) {
            if let ArtifactChunkData::SemiStructuredChunkData(data) =
                artifact_chunk.artifact_chunk_data
            {
                self.local_state
                    .add_chunk(artifact_chunk.chunk_id, data.len())
            } else {
                panic!("Bug: Wrong artifact data type.")
            }
        }

        let elems = self.chunk_sets.iter().map(|set| set.len()).sum::<usize>();
        if elems == 0 {
            Ok(state_sync_artifact(self.syncing_state.clone()))
        } else {
            Err(ArtifactErrorCode::ChunksMoreNeeded)
        }
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

fn state_sync_artifact(id: StateSyncArtifactId) -> Artifact {
    let manifest = Manifest::new(StateSyncVersion::V0, vec![], vec![]);
    let meta_manifest = MetaManifest {
        version: StateSyncVersion::V0,
        sub_manifest_hashes: vec![],
    };

    Artifact::StateSync(StateSyncMessage {
        height: id.height,
        root_hash: id.hash,
        checkpoint_root: PathBuf::new(),
        manifest,
        meta_manifest: Arc::new(meta_manifest),
        state_sync_file_group: Default::default(),
    })
}

pub fn create_node(
    node_num: u64,
    log: ReplicaLogger,
    transport_router: &mut TransportRouter,
    rt: &Handle,
    uses_global: bool,
    global_state: State,
    link: (Duration, usize),
) -> (Arc<FakeStateSync>, JoinHandle<()>) {
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
    let jh = ic_state_sync_manager::start_state_sync_manager(
        log,
        &MetricsRegistry::default(),
        rt,
        Arc::new(transport),
        state_sync.clone(),
        rx,
    );

    (state_sync, jh)
}
