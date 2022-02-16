//! File tree sync artifact.

use crate::{
    artifact::Artifact,
    chunkable::{
        ArtifactChunk, ArtifactChunkData, ArtifactErrorCode, ChunkId, Chunkable, ChunkableArtifact,
    },
    crypto::CryptoHash,
};
use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const CHUNKID_MANIFEST_CHUNK: u32 = u32::max_value();

/// Unique identifier to describe a FSTreeSyncObject
pub type FileTreeSyncId = String;

//////////////////////////////////////////////////////////////////
// Sender side chunking logic is abstracted by implementing the //
// ChunkableArtifact trait on the complete artifact             //
//////////////////////////////////////////////////////////////////

/// Artifact to be be delivered to the artifact pool when
/// file tree sync is complete
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct FileTreeSyncArtifact {
    pub absolute_path: PathBuf,
    pub id: FileTreeSyncId,
}

impl ChunkableArtifact for FileTreeSyncArtifact {
    fn get_chunk(self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk> {
        let paths = std::fs::read_dir(self.absolute_path).ok()?;
        let count = paths.count() as u32;

        // Return manifest for artifact. Returns a count of files
        // under the artifact directory
        if chunk_id.get() == CHUNKID_MANIFEST_CHUNK {
            return Some(ArtifactChunk {
                chunk_id,
                witness: Default::default(),
                artifact_chunk_data: ArtifactChunkData::SemiStructuredChunkData(
                    serialize(&count).expect("Binary serialization failed"),
                ),
            });
        }

        if chunk_id.get() >= count {
            println!(
                "Arifact has only {} chunks requested {}",
                count,
                chunk_id.get(),
            );
            return None;
        }

        Some(ArtifactChunk {
            chunk_id,
            witness: Default::default(),
            artifact_chunk_data: ArtifactChunkData::SemiStructuredChunkData(
                serialize(&chunk_id).expect("Binary serialization failed"),
            ),
        })
    }
}

impl From<FileTreeSyncArtifact> for Box<dyn ChunkableArtifact> {
    fn from(msg: FileTreeSyncArtifact) -> Box<dyn ChunkableArtifact> {
        Box::new(msg)
    }
}

/////////////////////////////////////////////////////////////////////////
// Receive side chunking logic is by implemented by the Chunkable      //
// trait over the download tracker object. The download tracker is     //
// also referred to as the under construction object                   //
/////////////////////////////////////////////////////////////////////////
///
/// Represents the state under construction for a file tree sync artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnderConstructionState {
    WaitForManifest,
    SyncFromDir(u32),
}

/// File tree sync tracker.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileTreeSyncChunksTracker {
    pub state: UnderConstructionState,
    pub received_chunks: u32,

    // Tracker looks at this fs path  syncs it to a remote fs path.
    pub absolute_path: PathBuf,
}

impl Default for FileTreeSyncChunksTracker {
    fn default() -> Self {
        FileTreeSyncChunksTracker {
            state: UnderConstructionState::WaitForManifest,
            received_chunks: 0,
            absolute_path: Default::default(),
        }
    }
}

const CHUNK_PREFIX: &str = "Chunk";

impl Chunkable for FileTreeSyncChunksTracker {
    fn get_artifact_hash(&self) -> CryptoHash {
        // The hash should be the merkle root. Pending implementation
        unimplemented!();
    }

    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>> {
        let v = match self.state {
            UnderConstructionState::WaitForManifest => {
                println!("Requesting chunk manifest for {:?}", self);
                vec![ChunkId::from(CHUNKID_MANIFEST_CHUNK)]
            }
            UnderConstructionState::SyncFromDir(remote_chunks_count) => {
                println!(
                    "Requesting chunk count {} for {:?}",
                    remote_chunks_count, self
                );
                (0..remote_chunks_count).map(ChunkId::from).collect()
            }
        };
        Box::new(v.into_iter())
    }

    fn get_artifact_identifier(&self) -> CryptoHash {
        unimplemented!();
    }

    fn add_chunk(&mut self, artifact_chunk: ArtifactChunk) -> Result<Artifact, ArtifactErrorCode> {
        // Both manifest and chunk payload are u32
        let count_or_chunk_id = if let ArtifactChunkData::SemiStructuredChunkData(chunkdata) =
            artifact_chunk.artifact_chunk_data
        {
            deserialize(&chunkdata).expect("Failed to deserialize chunk data")
        } else {
            println!("File tree sync FSM error 1");
            return Err(ArtifactErrorCode::ChunkVerificationFailed);
        };

        // FSM state for waiting on manifest
        if artifact_chunk.chunk_id.get() == CHUNKID_MANIFEST_CHUNK {
            std::fs::create_dir_all(self.absolute_path.clone())
                .map_err(|_| ArtifactErrorCode::ChunksMoreNeeded)?;
            let count = count_or_chunk_id;
            self.state = UnderConstructionState::SyncFromDir(count);
            return Err(ArtifactErrorCode::ChunksMoreNeeded);
        }

        // FSM state for syncing objects
        let chunk_id = count_or_chunk_id;
        let expected_count = if let UnderConstructionState::SyncFromDir(count) = self.state {
            count
        } else {
            println!("File tree sync FSM error 2");
            return Err(ArtifactErrorCode::ChunkVerificationFailed);
        };

        if chunk_id > expected_count {
            return Err(ArtifactErrorCode::ChunkVerificationFailed);
        }

        println!("Received Chunk {}", artifact_chunk.chunk_id);
        let mut chunk_path_buf = self.absolute_path.clone();
        chunk_path_buf.push(format!("{}{}", CHUNK_PREFIX, artifact_chunk.chunk_id));
        std::fs::File::create(chunk_path_buf.as_path())
            .map_err(|_| ArtifactErrorCode::ChunksMoreNeeded)?;

        self.received_chunks += 1;
        if self.received_chunks < expected_count {
            return Err(ArtifactErrorCode::ChunksMoreNeeded);
        }

        // FSM End state
        Ok(Artifact::FileTreeSync(FileTreeSyncArtifact {
            id: Default::default(),
            absolute_path: self.absolute_path.clone(),
        }))
    }

    fn is_complete(&self) -> bool {
        false
    }

    fn get_chunk_size(&self, _chunk_id: ChunkId) -> usize {
        0
    }
}
