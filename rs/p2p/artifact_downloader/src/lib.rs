mod fetch_artifact;
mod fetch_stripped_artifact;

pub use fetch_artifact::FetchArtifact;
pub use fetch_stripped_artifact::{FetchStrippedConsensusArtifact, MIN_STRIPPED_CONTENT_BYTES};
