//! File tree sync artifact.
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

impl From<FileTreeSyncArtifact> for pb::FileTreeSyncArtifact {
    fn from(value: FileTreeSyncArtifact) -> Self {
        #[cfg(not(target_family = "unix"))]
        {
            _ = value;
            panic!("This method may only be used on unix.");
        }
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::ffi::OsStringExt;
            Self {
                absolute_path: value.absolute_path.into_os_string().into_vec(),
                id: value.id,
            }
        }
    }
}

impl From<pb::FileTreeSyncArtifact> for FileTreeSyncArtifact {
    fn from(value: pb::FileTreeSyncArtifact) -> Self {
        #[cfg(not(target_family = "unix"))]
        {
            _ = value;
            panic!("This method may only be used on unix.");
        }
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::ffi::OsStringExt;
            Self {
                absolute_path: std::ffi::OsString::from_vec(value.absolute_path).into(),
                id: value.id,
            }
        }
    }
}
