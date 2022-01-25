//! The orchestrator is a component of the Internet Computer that
//! manages the replica.
//!
//! Among other things, it continuously determines the correct Replica
//! binary to run for this node at any point in time, runs this
//! binary, and monitors this process (e.g.  restarting it if it exits
//! unexpectedly)
//!
//! # Upgrades
//!
//! The orchestrator also triggers upgrades of the replica
//! process. For that, it periodically performs the following operations:
//!
//! 1. Ask the registry for the current peers in the subnetwork it is suposed to
//! run it.
//!
//! 2. From each peer, fetch the latest catch-up package via a separate CUP
//! endpoint.
//!
//! 3. Verify each of those CUPs (by means of the subnet signature) and select
//! the most recent one (based on the block height).
//!
//! 4. Check the registry version referenced in that CUP and the replica version
//! associated with that registry version.
//!
//! 5. If the version is different from what we are currently running, apply
//! upgrade and restart replica with that CUP.
//!
//! # Registry
//!
//! The orchestrator also fetches configuration updates from the
//! registry and writes them to disk for other components of the
//! system to read.

pub mod args;
mod catch_up_package_provider;
mod crypto_helper;
mod error;
mod firewall;
mod metrics;
pub mod orchestrator;
mod registration;
mod registry_helper;
mod release_package;
mod release_package_provider;
mod replica_process;
mod ssh_access_manager;
mod utils;
