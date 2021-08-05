#[rustfmt::skip]
mod unformatted {
//! <h1>Overview</h1>
//!
//! The *Artifact Manager* stores artifacts in the artifact pool. These
//! artifacts are used by the node it is running on and other nodes in the same
//! subnet. The *Artifact Manager* interacts with *Gossip* and its application
//! components:
//!
//!   * *Consensus*
//!   * *Distributed Key Generation*
//!   * *Certification*
//!   * *Ingress Manager*
//!   * *State Sync*
//!
//! It acts as a dispatcher for *Gossip* and ensures that the artifacts are
//! processed by the correct application components. It (de)multiplexes
//! artifacts to and from the different application components on behalf of
//! *Gossip* and bundles filters and priority functions.
//!
//! In order to let the *Consensus* components be stateless, the artifact
//! manager notifies the application components of artifacts received from
//! peers. The application components can then check if they are valid and
//! change their artifact pools (with a write lock to prevent conflicts and to
//! allow concurrent reads to the artifact pools).
//!
//! <h1>Properties</h1>
//!
//!   * All artifacts in the validated part of the artifact pool have been
//!     checked to be valid by the corresponding application component.
//!   * When new artifacts have been added to the artifact pool or when
//!     triggered by *Gossip*, the *Artifact Manager* asks the application
//!     components to check if they want to add new artifacts or move artifacts
//!     from the unvalidated part to the validated part of the pool.
//!   * When artifacts are added to the validated part of the artifact pool, the
//!     *Artifact Manager* notifies *Gossip* of adverts to send to peers.
//!     checked to be valid by the corresponding application component
//!   * When new artifacts have been added to the artifact pool or when
//!     triggered by Gossip the Artifact Manager asks the application components
//!     to check if they want to add new artifacts or move artifacts from the
//!     unvalidated part to the validated part of the pool
//!   * When artifacts are added to the validated part of the artifact pool, the
//!     Artifact Manager notifies Gossip of adverts to send to peers.
//!
//! <h1>High Level View</h1>
//!
//!
//!#                                                                 --------------------------
//!#                                                                 | ArtifactManagerBackend |
//!#                                                           |->   |     (Consensus)        |
//!#                                                           |     -------------------------
//!#                                                           |     --------------------------
//!#                                                           |     | ArtifactManagerBackend |
//!#                                                           |->   |       (Dkg)            |
//!#                                                           |     -------------------------
//!#     --------------          ------------------------      |     --------------------------
//!#     |   P2P      | <------> |  ArtifactManagerImpl |  ----|->   | ArtifactManagerBackend |
//!#     --------------          ------------------------      |     |     (Certification)    |
//!#                                                           |     --------------------------
//!#                                                           |     --------------------------
//!#                                                           |     | ArtifactManagerBackend |
//!#                                                           |->   |     (Ingress)          |
//!#                                                           |     -------------------------
//!#                                                           |     --------------------------
//!#                                                           |     | ArtifactManagerBackend |
//!#                                                           |->   |     (State Sync)       |
//!#                                                                 -------------------------
//!
//!  The main components are:
//!   * Front end
//!     manager::ArtifactManagerImpl implements the ArtifactManager trait and talks
//!     to P2P. It maintains the map of backends, one for each client: consensus, DKG,
//!     certification, ingress, state sync. It is just a light weight layer that routes the
//!     requests to the appropriate backend
//!
//!   * Back ends
//!     clients::ArtifactManagerBackend is a per-client wrapper that has two parts:
//!     1. Sync: Requests that can be served in the caller's context are processed by the
//!        sync part (e.g) has_artifact(), get_validated_by_identifier() that only need to
//!        look up the artifact pool
//!
//!        clients::ConsensusClient, etc implement the per-client sync part
//!
//!     2. Async: Processes the received artifacts via on_artifact(). The new artifacts are
//!        queued to a background worker thread. The thread runs a loop that calls into the
//!        per-client ArtifactProcessor implementation with the newly received artifacts
//!
//!        a. processors::ArtifactProcessorManager manages the life cycle of these back ground
//!           threads, and queues the requests to the background thread via a crossbeam channel
//!        b. processors::ConsensusProcessor, etc implement the per-client ArtifactProcessor
//!           logic called by the threads. These roughly perform the sequence: add the new
//!           artifacts to the unvalidated pool, call the client.on_state_change(), apply the
//!           returned changes(mutations) to the artifact pools
//!
}

pub mod artifact;
pub mod clients;
pub mod manager;
pub mod processors;
