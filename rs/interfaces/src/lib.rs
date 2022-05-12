//! The public interfaces of the various components of the replica.
//!
//! Having the public interfaces defined separately from their components
//! helps reduce unnecessary dependencies between them.
pub mod artifact_manager;
pub mod artifact_pool;
pub mod canister_http;
pub mod certification;
pub mod certified_stream_store;
pub mod consensus;
pub mod consensus_pool;
pub mod crypto;
pub mod dkg;
pub mod ecdsa;
pub mod execution_environment;
pub mod gossip_pool;
pub mod ingress_manager;
pub mod ingress_pool;
pub mod messages;
pub mod messaging;
pub mod registry;
pub mod replica_config;
pub mod self_validating_payload;
pub mod time_source;
pub mod validation;

// Note [Associated Types in Interfaces]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Several traits in this package use associated types to avoid direct
// dependency on ReplicatedState.  This results in cleaner dependency graph and
// speeds up incremental compilation when replicated_state changes.
