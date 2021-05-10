//! The artifact pool public interface.
use derive_more::From;
use ic_types::{replica_version::ReplicaVersion, NodeId, Time};
use serde::{Deserialize, Serialize};

#[derive(Debug, From)]
pub enum ArtifactPoolError {
    /// Error if not enough quota for a peer in the unvalidated pool for an
    /// artifact.
    InsufficientQuotaError,
    /// Message has expired.
    MessageExpired,
    /// Message expiry is too far in the future.
    MessageExpiryTooLong,
    /// Error when artifact version is not accepted.
    ArtifactReplicaVersionError(ReplicaVersionMismatch),
    /// Error when artifact acceptance goes wrong.
    ArtifactRejected(Box<dyn std::error::Error>),
}

/// Describe expected version and artifact version when there is a mismatch.
#[derive(Debug)]
pub struct ReplicaVersionMismatch {
    pub expected: ReplicaVersion,
    pub artifact: ReplicaVersion,
}

/// A trait similar to Into, but without its restrictions.
pub trait IntoInner<T>: AsRef<T> {
    fn into_inner(self) -> T;
}

/// Validated artifact
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedArtifact<T> {
    pub msg: T,
    pub timestamp: Time,
}

impl<T> ValidatedArtifact<T> {
    pub fn map<U, F>(self, f: F) -> ValidatedArtifact<U>
    where
        F: FnOnce(T) -> U,
    {
        ValidatedArtifact {
            msg: f(self.msg),
            timestamp: self.timestamp,
        }
    }
}

impl<T> AsRef<T> for ValidatedArtifact<T> {
    fn as_ref(&self) -> &T {
        &self.msg
    }
}

impl<T> IntoInner<T> for ValidatedArtifact<T> {
    fn into_inner(self) -> T {
        self.msg
    }
}

/// Unvalidated artifact
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnvalidatedArtifact<T> {
    pub message: T,
    pub peer_id: NodeId,
    pub timestamp: Time,
}

impl<T> AsRef<T> for UnvalidatedArtifact<T> {
    fn as_ref(&self) -> &T {
        &self.message
    }
}

impl<T> IntoInner<T> for UnvalidatedArtifact<T> {
    fn into_inner(self) -> T {
        self.message
    }
}

/// A trait to get timestamp.
pub trait HasTimestamp {
    fn timestamp(&self) -> Time;
}

impl<T> HasTimestamp for ValidatedArtifact<T> {
    fn timestamp(&self) -> Time {
        self.timestamp
    }
}

impl<T> HasTimestamp for UnvalidatedArtifact<T> {
    fn timestamp(&self) -> Time {
        self.timestamp
    }
}
