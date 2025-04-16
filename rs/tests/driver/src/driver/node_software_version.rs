//! Each subnet of a running IC specifies a replica version that the nodes on
//! that subnet are supposed to be running. This module contains utility
//! functions and structures used to specify replica versions in tests.
use ic_types::ReplicaVersion;
use serde::Deserialize;
use std::hash::Hash;
use url::Url;

#[derive(Clone, Hash, Debug, Deserialize)]
pub struct NodeSoftwareVersion {
    pub replica_version: ReplicaVersion,
    pub replica_url: Url,
    pub replica_hash: String,
    pub orchestrator_url: Url,
    pub orchestrator_hash: String,
}
