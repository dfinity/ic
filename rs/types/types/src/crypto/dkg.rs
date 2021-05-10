//! Defines interactive distributed key generation (DKG) types.
use crate::{IDkgId, NodeId};
use serde::{Deserialize, Serialize};

mod config;
mod encryption_public_key;
pub use config::{Config, Dealers, DkgConfig, DkgConfigData, Receivers};
pub use encryption_public_key::EncryptionPublicKey;

/// A dealing for interactive DKG.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dealing(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// An interactive DKG transcript.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Transcript {
    pub dkg_id: IDkgId,
    pub committee: Vec<Option<NodeId>>,
    pub transcript_bytes: TranscriptBytes,
}

/// An interactive DKG transcript as bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TranscriptBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// The dealer's response in the interactive DKG protocol. See
/// `DkgAlgorithm::create_response`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Response(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// An encryption public key together with its proof of posession.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EncryptionPublicKeyWithPop {
    pub key: EncryptionPublicKey,
    pub proof_of_possession: EncryptionPublicKeyPop,
}

impl Default for EncryptionPublicKeyWithPop {
    // TODO (CRP-328)
    fn default() -> Self {
        EncryptionPublicKeyWithPop {
            key: Default::default(),
            proof_of_possession: EncryptionPublicKeyPop(Default::default()),
        }
    }
}

/// The encryption public key proof of posession.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EncryptionPublicKeyPop(#[serde(with = "serde_bytes")] pub Vec<u8>);
