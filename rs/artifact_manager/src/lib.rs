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

pub mod actors;
pub mod artifact;
pub mod clients;
pub mod manager;
