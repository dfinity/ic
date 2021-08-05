//! The artifact manager implementation.
//!
//! The artifact manager component manages all the artifact pools (*Consensus*
//! pool, ingress pool, state sync pool, DKG pool, and certification pool).
//!
//! It provides an interface to *Gossip* enabling it to interact with all the
//! pools without knowing artifact-related details.
use crate::clients::{ArtifactManagerBackend, ArtifactManagerBackendImpl};
use crate::processors::ArtifactProcessorManager;
use ic_interfaces::{
    artifact_manager::{ArtifactClient, ArtifactManager, OnArtifactError},
    time_source::TimeSource,
};
use ic_types::{
    artifact,
    artifact::{Advert, ArtifactKind, ArtifactPriorityFn, ArtifactTag},
    chunkable::{Chunkable, ChunkableArtifact},
    p2p, NodeId,
};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;

/// The artifact manager maintains a list of artifact clients, and is generic in
/// the client type. It mostly just forwards function calls to each client
/// depending on the artifact type.
///
/// For each client, there is both a processor component and an artifact client
/// component. The steps to create a client is:
///
/// 1. Create both the processor and artifact client components.
/// 2. The processor is run in a tokio blocking thread.
/// 3. The artifact client and the processor are then added to an artifact
///    manager through an artifact manager maker.
///
/// After all clients are added to the `ArtifactManagerMaker`, an
/// `ArtifactManager` is created.
#[allow(clippy::type_complexity)]
pub struct ArtifactManagerImpl {
    /// The time source.
    time_source: Arc<dyn TimeSource>,
    /// The clients for each artifact tag.
    clients: HashMap<ArtifactTag, Box<dyn ArtifactManagerBackend>>,
}

impl ArtifactManagerImpl {
    /// The constructor creates an `ArtifactManagerImpl` instance.
    pub fn new(time_source: Arc<dyn TimeSource>) -> Self {
        Self {
            time_source,
            clients: HashMap::new(),
        }
    }
}

impl ArtifactManager for ArtifactManagerImpl {
    /// When a new artifact is received by *Gossip*, it is forwarded to
    /// the artifact manager via an `on_artifact` call, which then forwards it
    /// to be processed by the corresponding artifact client based on the
    /// artifact type.
    ///
    ///The method returns an `OnArtifactError::NotProcessed` if no clients
    /// were able to process it or an `OnArtifactError::ArtifactPoolError`
    /// if any other error has occurred.
    fn on_artifact(
        &self,
        msg: artifact::Artifact,
        advert: p2p::GossipAdvert,
        peer_id: &NodeId,
    ) -> Result<(), OnArtifactError<artifact::Artifact>> {
        let tag: ArtifactTag = (&msg).into();
        if let Some(client) = self.clients.get(&tag) {
            return client.on_artifact(self.time_source.as_ref(), msg, advert, *peer_id);
        }
        Err(OnArtifactError::NotProcessed(Box::new(msg)))
    }

    /// The method checks if any of the artifact clients already have the
    /// artifact with the given ID in the pool.
    fn has_artifact(&self, message_id: &artifact::ArtifactId) -> bool {
        let tag: ArtifactTag = message_id.into();

        match self.clients.get(&tag) {
            Some(client) => client.has_artifact(message_id).unwrap_or(false),
            None => false,
        }
    }

    /// The method returns a validated artifact with the given identifier if
    /// available.
    fn get_validated_by_identifier(
        &self,
        message_id: &artifact::ArtifactId,
    ) -> Option<Box<dyn ChunkableArtifact + '_>> {
        // TODO: P2P-513
        let tag: ArtifactTag = message_id.into();

        match self.clients.get(&tag) {
            Some(client) => client
                .get_validated_by_identifier(message_id)
                .unwrap_or(None),
            None => None,
        }
    }

    /// The method returns a collection of all filters from all clients.
    ///
    /// See `ArtifactClient::get_filter` for more details.
    fn get_filter(&self) -> artifact::ArtifactFilter {
        let mut filter = Default::default();
        self.clients
            .values()
            .for_each(|client| client.get_filter(&mut filter));
        filter
    }

    /// The method returns adverts of all validated artifacts by the filter from
    /// all clients.
    ///
    /// See `ArtifactClient::get_all_validated_by_filter` for more details.
    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert> {
        let mut adverts: Box<dyn Iterator<Item = p2p::GossipAdvert>> =
            Box::new(std::iter::empty::<p2p::GossipAdvert>());
        for client in self.clients.values() {
            adverts =
                Box::new(adverts.chain(client.get_all_validated_by_filter(filter).into_iter()))
        }
        adverts.collect()
    }

    /// The method returns the remaining quota the given peer is allowed to
    /// consume for a specific client that is identified by the given
    /// artifact tag.
    ///
    /// See `ArtifactClient::get_remaining_quota` for more details.
    fn get_remaining_quota(&self, tag: artifact::ArtifactTag, peer_id: NodeId) -> Option<usize> {
        self.clients
            .get(&tag)
            .and_then(|client| client.get_remaining_quota(tag, peer_id))
    }

    /// The method returns the priority function for a specific client that is
    /// identified by the given artifact tag.
    ///
    /// See `ArtifactClient::get_priority_function` for more details.
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> Option<ArtifactPriorityFn> {
        self.clients
            .get(&tag)
            .and_then(|client| client.get_priority_function(tag))
    }

    /// The method returns the chunk tracker for an advert with the given ID.
    ///
    /// See `ArtifactClient::get_chunk_tracker` for more details
    fn get_chunk_tracker(
        &self,
        artifact_id: &artifact::ArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>> {
        let tag: ArtifactTag = artifact_id.into();

        self.clients
            .get(&tag)
            .and_then(|client| client.get_chunk_tracker(&artifact_id))
    }
}

/// The `ArtifactManagerMaker` is a helper to create an `ArtifactManager` after
/// adding each client. It is separated from the `ArtifactManager` interface to
/// ensure that all clients are added only once, and that the `ArtifactManager`
/// can not be modified after creation.
#[allow(clippy::type_complexity)]
pub struct ArtifactManagerMaker {
    time_source: Arc<dyn TimeSource>,
    clients: HashMap<ArtifactTag, Box<dyn ArtifactManagerBackend>>,
}

impl ArtifactManagerMaker {
    /// The constructor creates an `ArtifactManagerMaker` instance.
    pub fn new(time_source: Arc<dyn TimeSource>) -> Self {
        Self {
            time_source,
            clients: HashMap::new(),
        }
    }
    /// The method adds a new `ArtifactClient` (that is already wrapped in
    /// `Arc`) to be managed.
    pub fn add_arc_client<Artifact: ArtifactKind + 'static>(
        &mut self,
        client: Arc<dyn ArtifactClient<Artifact>>,
        processor: ArtifactProcessorManager<Artifact>,
    ) where
        Artifact::SerializeAs: TryFrom<artifact::Artifact, Error = artifact::Artifact>,
        Artifact::Message: ChunkableArtifact + Send,
        Advert<Artifact>:
            Into<p2p::GossipAdvert> + TryFrom<p2p::GossipAdvert, Error = p2p::GossipAdvert> + Eq,
        for<'b> &'b Artifact::Id:
            TryFrom<&'b artifact::ArtifactId, Error = &'b artifact::ArtifactId>,
        artifact::ArtifactFilter: AsMut<Artifact::Filter> + AsRef<Artifact::Filter>,
        for<'b> &'b Artifact::Attribute:
            TryFrom<&'b artifact::ArtifactAttribute, Error = &'b artifact::ArtifactAttribute>,
        Artifact::Attribute: 'static,
    {
        let tag = Artifact::TAG;
        self.clients.insert(
            tag,
            Box::new(ArtifactManagerBackendImpl { client, processor }),
        );
    }

    /// The method adds a new `ArtifactClient` to be managed.
    pub fn add_client<Artifact: ArtifactKind + 'static, Client: 'static>(
        &mut self,
        client: Client,
        processor: ArtifactProcessorManager<Artifact>,
    ) where
        Client: ArtifactClient<Artifact>,
        Artifact::SerializeAs: TryFrom<artifact::Artifact, Error = artifact::Artifact>,
        Artifact::Message: ChunkableArtifact + Send,
        Advert<Artifact>:
            Into<p2p::GossipAdvert> + TryFrom<p2p::GossipAdvert, Error = p2p::GossipAdvert> + Eq,
        for<'b> &'b Artifact::Id:
            TryFrom<&'b artifact::ArtifactId, Error = &'b artifact::ArtifactId>,
        artifact::ArtifactFilter: AsMut<Artifact::Filter> + AsRef<Artifact::Filter>,
        for<'b> &'b Artifact::Attribute:
            TryFrom<&'b artifact::ArtifactAttribute, Error = &'b artifact::ArtifactAttribute>,
        Artifact::Attribute: 'static,
    {
        let tag = Artifact::TAG;
        self.clients.insert(
            tag,
            Box::new(ArtifactManagerBackendImpl {
                client: Arc::new(client) as Arc<_>,
                processor,
            }),
        );
    }

    /// The method finishes the collection of `ArtifactClient` components and
    /// creates an `ArtifactManager` component that manages all clients.
    pub fn finish(self) -> Arc<dyn ArtifactManager> {
        Arc::new(ArtifactManagerImpl {
            time_source: self.time_source,
            clients: self.clients,
        })
    }
}
