//! The artifact manager implementation.
//!
//! The artifact manager component manages all the artifact pools (*Consensus*
//! pool, ingress pool, state sync pool, DKG pool, and certification pool).
//!
//! It provides an interface to *Gossip* enabling it to interact with all the
//! pools without knowing artifact-related details.
use crate::actors::ClientActor;
use ic_interfaces::{
    artifact_manager::{
        AdvertMismatchError, ArtifactAcceptance, ArtifactClient, ArtifactManager, OnArtifactError,
    },
    artifact_pool::UnvalidatedArtifact,
    time_source::TimeSource,
};
use ic_types::{
    artifact,
    artifact::{Advert, ArtifactKind, ArtifactPriorityFn, ArtifactTag},
    chunkable::{Chunkable, ChunkableArtifact},
    p2p, NodeId,
};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

/// In order to let the artifact manager manage artifact clients, which can be
/// parameterized by different artifact types, it has to use trait objects.
///Consequently, there has to be a translation between various artifact
/// sub-types to the top-level enum types. The trait `SomeArtifactClient`
/// achieves both goals by acting as a middleman.
///
/// The trick of this translation is to erase the type parameter from all
/// interface functions. As a result, member functions of this trait mostly
/// resemble those of `ArtifactClient`, but use top-level artifact types. The
/// translation is mostly handled via `From/Into`, `TryFrom/Into`, `AsMut` and
/// `AsRef` traits that are automatically derived between artifact subtypes and
/// the top-level types.
trait SomeArtifactClient: Send + Sync {
    /// The method is called when an artifact is received.
    fn on_artifact(
        &self,
        time_source: &dyn TimeSource,
        msg: artifact::Artifact,
        advert: p2p::GossipAdvert,
        peer_id: NodeId,
    ) -> Result<(), OnArtifactError<artifact::Artifact>>;

    /// The method indicates whether an artifact exists.
    fn has_artifact(&self, msg_id: &artifact::ArtifactId) -> Result<bool, ()>;

    /// The method returns a validated artifact with the given ID, or an error.
    fn get_validated_by_identifier(
        &self,
        msg_id: &artifact::ArtifactId,
    ) -> Result<Option<Box<dyn ChunkableArtifact>>, ()>;

    /// THe method adds the client's filter to the given artifact filter.
    fn get_filter(&self, filter: &mut artifact::ArtifactFilter);

    /// The method returns all validated artifacts that match the given filter.
    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert>;

    /// The method returns the remaining quota for a given peer and artifact
    /// tag.
    fn get_remaining_quota(&self, tag: artifact::ArtifactTag, peer_id: NodeId) -> Option<usize>;

    /// The method returns a priority function for a given artifact tag.
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> Option<ArtifactPriorityFn>;

    /// The method returns a chunk tracker for a given artifact ID.
    fn get_chunk_tracker(
        &self,
        id: &artifact::ArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>>;
}

/// Implementation struct for `SomeArtifactClient`.
struct SomeArtifactClientImpl<Artifact: ArtifactKind + 'static> {
    /// Reference to the artifact client.
    client: Arc<dyn ArtifactClient<Artifact>>,
    /// The client actor.
    actor: ClientActor<Artifact>,
}

/// Trait implementation for `SomeArtifactClient`.
impl<Artifact: ArtifactKind> SomeArtifactClient for SomeArtifactClientImpl<Artifact>
where
    Artifact::SerializeAs: TryFrom<artifact::Artifact, Error = artifact::Artifact>,
    Artifact::Message: ChunkableArtifact + Send + 'static,
    Advert<Artifact>:
        Into<p2p::GossipAdvert> + TryFrom<p2p::GossipAdvert, Error = p2p::GossipAdvert> + Eq,
    for<'a> &'a Artifact::Id: TryFrom<&'a artifact::ArtifactId, Error = &'a artifact::ArtifactId>,
    artifact::ArtifactFilter: AsMut<Artifact::Filter> + AsRef<Artifact::Filter>,
    for<'a> &'a Artifact::Attribute:
        TryFrom<&'a artifact::ArtifactAttribute, Error = &'a artifact::ArtifactAttribute>,
    Artifact::Attribute: 'static,
    Artifact::Id: 'static,
{
    /// The method is called when the given artifact is received.
    fn on_artifact(
        &self,
        time_source: &dyn TimeSource,
        artifact: artifact::Artifact,
        advert: p2p::GossipAdvert,
        peer_id: NodeId,
    ) -> Result<(), OnArtifactError<artifact::Artifact>> {
        match (artifact.try_into(), advert.try_into()) {
            (Ok(msg), Ok(advert)) => {
                let result = self
                    .client
                    .as_ref()
                    .check_artifact_acceptance(msg, &peer_id)?;
                match result {
                    ArtifactAcceptance::Processed => (),
                    ArtifactAcceptance::AcceptedForProcessing(message) => {
                        Artifact::check_advert(&message, &advert).map_err(|expected| {
                            AdvertMismatchError {
                                received: advert.into(),
                                expected: expected.into(),
                            }
                        })?;
                        // this sends to an unbounded channel, which is what we want here
                        self.actor.on_artifact(UnvalidatedArtifact {
                            message,
                            peer_id,
                            timestamp: time_source.get_relative_time(),
                        })
                    }
                };
                Ok(())
            }
            (Err(artifact), _) => Err(OnArtifactError::NotProcessed(Box::new(artifact))),
            (_, Err(advert)) => Err(OnArtifactError::MessageConversionfailed(advert)),
        }
    }

    /// The method checks if the artifact with the given ID is available.
    fn has_artifact(&self, msg_id: &artifact::ArtifactId) -> Result<bool, ()> {
        match msg_id.try_into() {
            Ok(id) => Ok(self.client.as_ref().has_artifact(id)),
            Err(_) => Err(()),
        }
    }

    /// The method returns the validated artifact for the given ID.
    fn get_validated_by_identifier(
        &self,
        msg_id: &artifact::ArtifactId,
    ) -> Result<Option<Box<dyn ChunkableArtifact>>, ()> {
        match msg_id.try_into() {
            Ok(id) => Ok(self
                .client
                .as_ref()
                .get_validated_by_identifier(id)
                .map(|x| Box::new(x) as Box<dyn ChunkableArtifact>)),
            Err(_) => Err(()),
        }
    }

    /// The method gets the client's filter and adds it to the artifact filter.
    fn get_filter(&self, filter: &mut artifact::ArtifactFilter) {
        *filter.as_mut() = self.client.as_ref().get_filter()
    }

    /// The method returns all validated adverts.
    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert> {
        self.client
            .as_ref()
            .get_all_validated_by_filter(filter.as_ref())
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<_>>()
    }

    /// The method returns the remaining quota for the peer with the given ID.s
    fn get_remaining_quota(&self, tag: artifact::ArtifactTag, peer_id: NodeId) -> Option<usize> {
        if tag == Artifact::TAG {
            Some(self.client.as_ref().get_remaining_quota(peer_id))
        } else {
            None
        }
    }

    /// The method returns the priority function.
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> Option<ArtifactPriorityFn> {
        if tag == Artifact::TAG {
            let func = self.client.as_ref().get_priority_function()?;
            Some(Box::new(
                move |id: &'_ artifact::ArtifactId, attribute: &'_ artifact::ArtifactAttribute| {
                    match (id.try_into(), attribute.try_into()) {
                        (Ok(idd), Ok(attr)) => func(idd, attr),
                        _ => panic!("Priority function called on wrong id or attribute!"),
                    }
                },
            ))
        } else {
            None
        }
    }

    /// The method returns the artifact chunk tracker.
    fn get_chunk_tracker(
        &self,
        artifact_id: &artifact::ArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>> {
        match artifact_id.try_into() {
            Ok(artifact_id) => Some(self.client.as_ref().get_chunk_tracker(artifact_id)),
            Err(_) => None,
        }
    }
}

/// The artifact manager maintains a list of artifact clients, and is generic in
/// the client type. It mostly just forwards function calls to each client
/// depending on the artifact type.
///
/// For each client, there is both an actor component and an artifact client
/// component. The steps to create a client is:
///
/// 1. Create both the actor and artifact client components.
/// 2. The actor is run in an arbiter.
/// 3. The artifact client and actor address are then added to an artifact
/// manager    through an artifact manager maker.
///
/// After all clients are added to the `ArtifactManagerMaker`, an
/// `ArtifactManager` is created.
#[allow(clippy::type_complexity)]
pub struct ArtifactManagerImpl {
    /// The time source.
    time_source: Arc<dyn TimeSource>,
    /// The clients for each artifact tag.
    clients: HashMap<ArtifactTag, Box<dyn SomeArtifactClient>>,
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
    clients: HashMap<ArtifactTag, Box<dyn SomeArtifactClient>>,
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
        actor: ClientActor<Artifact>,
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
        self.clients
            .insert(tag, Box::new(SomeArtifactClientImpl { client, actor }));
    }

    /// The method adds a new `ArtifactClient` to be managed.
    pub fn add_client<Artifact: ArtifactKind + 'static, Client: 'static>(
        &mut self,
        client: Client,
        actor: ClientActor<Artifact>,
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
            Box::new(SomeArtifactClientImpl {
                client: Arc::new(client) as Arc<_>,
                actor,
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
