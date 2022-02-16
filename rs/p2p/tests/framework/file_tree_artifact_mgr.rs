//! Test file tree sync artifact manager.
//!
//! Use this artifact pool *ONLY* for representing and testing pools backed by a
//! filesystem tree like layout.

use ic_interfaces::artifact_manager::{
    ArtifactAcceptance, ArtifactClient, ArtifactProcessor, ProcessingResult,
};
use ic_interfaces::artifact_pool::{ArtifactPoolError, UnvalidatedArtifact};
use ic_interfaces::time_source::TimeSource;
use ic_replica_setup_ic_network::{
    TestArtifact, TestArtifactAttribute, TestArtifactId, TestArtifactMessage,
};
use ic_types::artifact::{Advert, AdvertClass, AdvertSendRequest, ArtifactId, Priority};
use ic_types::chunkable::Chunkable;
use ic_types::crypto::CryptoHash;
use ic_types::filetree_sync::{
    FileTreeSyncArtifact, FileTreeSyncChunksTracker, UnderConstructionState,
};
use ic_types::NodeId;
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Mutex;

const NODE_PREFIX: &str = "NODE";
const POOL: &str = "POOL";
const STATE_SYNC_ARTIFACT_PREFIX: &str = "statesync_";
const CHUNK_PREFIX: &str = "Chunk";
const MAX_CHUNKS: u32 = 5;

type FileTreeSyncInMemoryPool = HashMap<TestArtifactId, FileTreeSyncArtifact>;

pub struct ArtifactChunkingTestImpl {
    node_pool_dir: PathBuf, // Path to on disk pool
    node_id: NodeId,
    file_tree_sync_unvalidated_pool: Mutex<FileTreeSyncInMemoryPool>, /* In memory representaion
                                                                       * on on-disk
                                                                       * pool */
    file_tree_sync_validated_pool: Mutex<FileTreeSyncInMemoryPool>,
}

impl ArtifactProcessor<TestArtifact> for ArtifactChunkingTestImpl {
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        _artifacts: Vec<UnvalidatedArtifact<FileTreeSyncArtifact>>,
    ) -> (Vec<AdvertSendRequest<TestArtifact>>, ProcessingResult) {
        let mut unvalidated_pool = self.file_tree_sync_unvalidated_pool.lock().unwrap();
        let mut validated_pool = self.file_tree_sync_validated_pool.lock().unwrap();
        let adverts = unvalidated_pool
            .iter()
            .map(|(artifact_id, artifact)| AdvertSendRequest {
                advert: Advert {
                    attribute: artifact.id.to_string(),
                    size: 0,
                    id: artifact.id.clone(),
                    integrity_hash: CryptoHash(artifact_id.clone().into_bytes()),
                },
                advert_class: AdvertClass::Critical,
            })
            .collect::<Vec<_>>();
        let changed = if !adverts.is_empty() {
            ProcessingResult::StateChanged
        } else {
            ProcessingResult::StateUnchanged
        };
        validated_pool.extend(unvalidated_pool.drain());
        (adverts, changed)
    }
}

impl ArtifactClient<TestArtifact> for ArtifactChunkingTestImpl {
    fn check_artifact_acceptance(
        &self,
        artifact: TestArtifactMessage,
        peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<FileTreeSyncArtifact>, ArtifactPoolError> {
        println!(
            "Node-{} Receive complete for artifact {:?} from last node {}",
            self.node_id.get(),
            artifact,
            peer_id
        );
        Ok(ArtifactAcceptance::Processed)
    }

    fn has_artifact(&self, message_id: &TestArtifactId) -> bool {
        let pool = self.file_tree_sync_validated_pool.lock().unwrap();
        pool.contains_key(message_id)
    }

    fn get_validated_by_identifier(
        &self,
        message_id: &TestArtifactId,
    ) -> Option<TestArtifactMessage> {
        let pool = self.file_tree_sync_validated_pool.lock().unwrap();
        pool.get(message_id).cloned()
    }

    fn get_priority_function(
        &self,
    ) -> Option<
        Box<dyn Fn(&TestArtifactId, &TestArtifactAttribute) -> Priority + Send + Sync + 'static>,
    > {
        None
    }

    fn get_chunk_tracker(&self, id: &TestArtifactId) -> Box<dyn Chunkable + Send + Sync> {
        let mut absolute_path = self.node_pool_dir.clone();
        absolute_path.push(id);
        Box::new(FileTreeSyncChunksTracker {
            received_chunks: 0,
            state: UnderConstructionState::WaitForManifest,
            absolute_path,
        })
    }
}

// Conflates 2 entities with different functionalities (for test):
//    An artifact manager
//         AND
//    A POOL (Client).
impl ArtifactChunkingTestImpl {
    #![allow(dead_code)]
    pub fn new(mut root_dir: PathBuf, node_id: NodeId) -> Self {
        let mut mem_pool: FileTreeSyncInMemoryPool = HashMap::new();

        // Setup on disk disk POOL
        let on_disk_pool_path =
            ArtifactChunkingTestImpl::set_up_on_disk_state(&mut root_dir, node_id, &mut mem_pool)
                .unwrap_or_else(|_| panic!("Failed to setup node pool"));

        ArtifactChunkingTestImpl {
            node_pool_dir: on_disk_pool_path,
            node_id,
            file_tree_sync_unvalidated_pool: Mutex::new(mem_pool),
            file_tree_sync_validated_pool: Mutex::new(HashMap::new()),
        }
    }

    //
    // set_up_on_disk_state
    //
    //      Setups a node's on disk file tree  with one artifact makde up of
    // MAX_CHUNKS      Then builds and in returns a mem-pool corresponding to
    // this on-disk pool
    //
    // Pool on disk layout
    //  Implements as simple on disk presentation of state
    //                Workdir
    //                  ── NODE_1
    //                     └── POOL
    //                         └── statesync_1
    //                             ├── Chunk0
    //                             |   .....
    //                             ├── ChunkMAX
    fn set_up_on_disk_state(
        workdir: &mut PathBuf,
        node_id: NodeId,
        mem_pool: &mut FileTreeSyncInMemoryPool,
    ) -> Result<PathBuf, Box<dyn Error>> {
        workdir.push(format!("{}{}", NODE_PREFIX, node_id));
        workdir.push(POOL);
        workdir.push(format!("{}{}", STATE_SYNC_ARTIFACT_PREFIX, node_id));
        std::fs::create_dir_all(&workdir)?;
        for i in 0..MAX_CHUNKS {
            workdir.push(format!("{}{}", CHUNK_PREFIX, i));
            std::fs::File::create(&workdir)?;
            workdir.pop();
        }

        // Setup mem-pool
        let id = ArtifactChunkingTestImpl::get_node_artifact_id_string(node_id);
        mem_pool.insert(
            id.clone(),
            FileTreeSyncArtifact {
                absolute_path: workdir.clone(),
                id,
            },
        );

        workdir.pop();
        Ok(workdir.to_path_buf())
    }

    // fn get node's artifact id
    fn get_node_artifact_id(id: String) -> ArtifactId {
        ArtifactId::FileTreeSync(id)
    }

    fn get_node_artifact_id_string(node_id: NodeId) -> String {
        format!("{}{}", STATE_SYNC_ARTIFACT_PREFIX, node_id)
    }
}
