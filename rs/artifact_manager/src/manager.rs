//! The artifact manager implementation.
//!
//! The artifact manager component manages all the artifact pools (*Consensus*
//! pool, ingress pool, state sync pool, DKG pool, and certification pool).
//!
//! It provides an interface to *Gossip* enabling it to interact with all the
//! pools without knowing artifact-related details.
use crate::ArtifactClientHandle;
use ic_interfaces::p2p::artifact_manager::{ArtifactManager, OnArtifactError};
use ic_types::{
    artifact,
    artifact::{
        Advert, ArtifactKind, ArtifactPriorityFn, ArtifactTag, Priority,
        UnvalidatedArtifactMutation,
    },
    chunkable::ChunkableArtifact,
    p2p, NodeId,
};
use std::collections::HashMap;
use std::convert::TryFrom;

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
pub struct ArtifactManagerImpl {
    /// The clients for each artifact tag.
    clients: HashMap<ArtifactTag, Box<dyn ArtifactManagerBackend>>,
    default_priority_fn_factory: Box<dyn Fn() -> ArtifactPriorityFn + Send + Sync>,
}

impl ArtifactManagerImpl {
    pub fn new(
        clients: HashMap<ArtifactTag, Box<dyn ArtifactManagerBackend>>,
        default_priority_fn_factory: Box<dyn Fn() -> ArtifactPriorityFn + Send + Sync>,
    ) -> Self {
        Self {
            clients,
            default_priority_fn_factory,
        }
    }

    pub fn new_with_default_priority_fn(
        clients: HashMap<ArtifactTag, Box<dyn ArtifactManagerBackend>>,
    ) -> Self {
        Self {
            clients,
            ..Default::default()
        }
    }
}

impl Default for ArtifactManagerImpl {
    fn default() -> Self {
        Self {
            clients: HashMap::new(),
            default_priority_fn_factory: Box::new(|| {
                Box::new(
                    move |_id: &'_ artifact::ArtifactId,
                          _attribute: &'_ artifact::ArtifactAttribute| {
                        Priority::Fetch
                    },
                )
            }),
        }
    }
}

impl ArtifactManager for ArtifactManagerImpl {
    /// When a new artifact is received by *Gossip*, it is forwarded to
    /// the artifact manager via an `on_artifact` call, which then forwards it
    /// to be processed by the corresponding artifact client based on the
    /// artifact type.
    ///
    /// The method returns an `OnArtifactError::NotProcessed` if no clients
    /// were able to process it or an `OnArtifactError::ArtifactPoolError`
    /// if any other error has occurred.
    fn on_artifact(
        &self,
        msg: artifact::Artifact,
        peer_id: &NodeId,
    ) -> Result<(), OnArtifactError> {
        let tag: ArtifactTag = (&msg).into();
        if let Some(client) = self.clients.get(&tag) {
            return client.on_artifact(msg, *peer_id);
        }
        Err(OnArtifactError::NotProcessed)
    }

    /// The method checks if any of the artifact clients already have the
    /// artifact with the given ID in the pool.
    fn has_artifact(&self, message_id: &artifact::ArtifactId) -> bool {
        let tag: ArtifactTag = message_id.into();

        match self.clients.get(&tag) {
            Some(client) => client.has_artifact(message_id),
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
            Some(client) => client.get_validated_by_identifier(message_id),
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

    /// The method returns the priority function for a specific client that is
    /// identified by the given artifact tag.
    ///
    /// See `ArtifactClient::get_priority_function` for more details.
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> ArtifactPriorityFn {
        match self.clients.get(&tag) {
            // This happens only in tests and never in production. Ideally we use the type system
            // so we don't need to use a fallback here at all.
            None => (self.default_priority_fn_factory)(),
            Some(client) => client.get_priority_function(tag),
        }
    }
}

/// In order to let the artifact manager manage artifact clients, which can be
/// parameterized by different artifact types, it has to use trait objects.
/// Consequently, there has to be a translation between various artifact
/// sub-types to the top-level enum types. The trait `ArtifactManagerBackend`
/// achieves both goals by acting as a middleman.
///
/// The trick of this translation is to erase the type parameter from all
/// interface functions. As a result, member functions of this trait mostly
/// resemble those of `ArtifactClient`, but use top-level artifact types. The
/// translation is mostly handled via `From/Into`, `TryFrom/Into`, `AsMut` and
/// `AsRef` traits that are automatically derived between artifact subtypes and
/// the top-level types.
pub trait ArtifactManagerBackend: Send + Sync {
    /// The method is called when an artifact is received.
    #[allow(clippy::result_large_err)]
    fn on_artifact(&self, msg: artifact::Artifact, peer_id: NodeId) -> Result<(), OnArtifactError>;

    /// The method indicates whether an artifact exists.
    fn has_artifact(&self, msg_id: &artifact::ArtifactId) -> bool;

    /// The method returns a validated artifact with the given ID, or an error.
    fn get_validated_by_identifier(
        &self,
        msg_id: &artifact::ArtifactId,
    ) -> Option<Box<dyn ChunkableArtifact>>;

    /// The method adds the client's filter to the given artifact filter.
    fn get_filter(&self, filter: &mut artifact::ArtifactFilter);

    /// The method returns all validated artifacts that match the given filter.
    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert>;

    /// The method returns a priority function for a given artifact tag.
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> ArtifactPriorityFn;
}

/// Trait implementation for `ArtifactManagerBackend`.
impl<Artifact: ArtifactKind> ArtifactManagerBackend for ArtifactClientHandle<Artifact>
where
    Artifact::Message: ChunkableArtifact
        + Send
        + 'static
        + TryFrom<artifact::Artifact, Error = artifact::Artifact>,
    Advert<Artifact>: Into<p2p::GossipAdvert>,
    for<'a> &'a Artifact::Id: TryFrom<&'a artifact::ArtifactId, Error = &'a artifact::ArtifactId>,
    artifact::ArtifactFilter: AsMut<Artifact::Filter> + AsRef<Artifact::Filter>,
    for<'a> &'a Artifact::Attribute:
        TryFrom<&'a artifact::ArtifactAttribute, Error = &'a artifact::ArtifactAttribute>,
    Artifact::Attribute: 'static,
    Artifact::Id: 'static + Send,
{
    /// The method is called when the given artifact is received.
    fn on_artifact(
        &self,
        artifact: artifact::Artifact,
        peer_id: NodeId,
    ) -> Result<(), OnArtifactError> {
        match artifact.try_into() {
            Ok(message) => {
                // this sends to an unbounded channel, which is what we want here
                self.sender
                    .send(UnvalidatedArtifactMutation::Insert((message, peer_id)))
                    .unwrap_or_else(|err| panic!("Failed to send request: {:?}", err));
                Ok(())
            }
            Err(_) => Err(OnArtifactError::NotProcessed),
        }
    }

    /// The method checks if the artifact with the given ID is available.
    fn has_artifact(&self, msg_id: &artifact::ArtifactId) -> bool {
        match msg_id.try_into() {
            Ok(id) => self.pool_reader.as_ref().has_artifact(id),
            Err(_) => false,
        }
    }

    /// The method returns the validated artifact for the given ID.
    fn get_validated_by_identifier(
        &self,
        msg_id: &artifact::ArtifactId,
    ) -> Option<Box<dyn ChunkableArtifact>> {
        match msg_id.try_into() {
            Ok(id) => self
                .pool_reader
                .as_ref()
                .get_validated_by_identifier(id)
                .map(|x| Box::new(x) as Box<dyn ChunkableArtifact>),
            Err(_) => None,
        }
    }

    /// The method gets the client's filter and adds it to the artifact filter.
    fn get_filter(&self, filter: &mut artifact::ArtifactFilter) {
        *filter.as_mut() = self.pool_reader.as_ref().get_filter()
    }

    /// The method returns all validated adverts.
    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert> {
        self.pool_reader
            .as_ref()
            .get_all_validated_by_filter(filter.as_ref())
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<_>>()
    }

    /// The method returns the priority function.
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> ArtifactPriorityFn {
        if tag == Artifact::TAG {
            let func = self.pool_reader.as_ref().get_priority_function();
            Box::new(
                move |id: &'_ artifact::ArtifactId, attribute: &'_ artifact::ArtifactAttribute| {
                    match (id.try_into(), attribute.try_into()) {
                        (Ok(idd), Ok(attr)) => func(idd, attr),
                        _ => crate::Priority::Drop,
                    }
                },
            )
        } else {
            Box::new(
                move |_id: &'_ artifact::ArtifactId,
                      _attribute: &'_ artifact::ArtifactAttribute| {
                    Priority::Fetch
                },
            )
        }
    }
}
