//! The public interfaces of the various components of the replica.
//!
//! Having the public interfaces defined separately from their components
//! helps reduce unnecessary dependencies between them.
pub mod batch_payload;
pub mod canister_http;
pub mod certification;
pub mod consensus;
pub mod consensus_pool;
pub mod crypto;
pub mod dkg;
pub mod execution_environment;
pub mod idkg;
pub mod ingress_manager;
pub mod ingress_pool;
pub mod messaging;
pub mod p2p;
pub mod query_stats;
pub mod self_validating_payload;
pub mod time_source;
pub mod validation;

// Note [Associated Types in Interfaces]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Several traits in this package use associated types to avoid direct
// dependency on ReplicatedState.  This results in cleaner dependency graph and
// speeds up incremental compilation when replicated_state changes.
