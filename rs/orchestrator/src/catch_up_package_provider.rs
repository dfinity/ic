//! The catchup package provider module is responsible for identifying and retrieving the latest CUP
//! for the orchestrator.
//!
//! The latest CUP can come from two places: from the registry or from peers. Every time we manage
//! to detect a new CUP we persist it locally. The CUP carries an important information for the
//! orchestrator: it indicates whether the current node is still a member of the current subnet and
//! if yes, whether this node is running the correct replica version.
//!
//! The registry can contain the newest CUP in two cases: the subnet genesis (in fact, this is the very
//! first CUP of a subnet) and a subnet recovery. In the case of the subnet recovery, the CUP
//! contains a state hash and a height from which the subnet is supposed to restart its
//! computation.
//!
//! In the normal operation mode, the CUP fetched from the peers will be eventually always newer than
//! the one we have persisted locally because CUPs are produced by the subnet on a regular basis.
//! We try to fetch a newer CUP every 10 seconds. The orchestrator always tries to fetch the CUP
//! from its own replica first and if no newer CUP is available, it tries to fetch one from one of the
//! random peers. To avoid bandwidth waste, every request contains the CUP version available locally.
//! The request will only be responded to with a new CUP if a newer one actually exists. Moreover, trying to
//! fetch the CUP from the node's own replica makes the upgrade behaviour of a subnet more efficient. This
//! is because if all replicas are up to date, they will obtain a new CUP at about the same time. Then
//! some nodes will instantly go into the upgrade process and stop serving CUPs to their peers.
//! Hence, fetching the CUP from the node's own replica first allows the orchestrator to get the CUP
//! quicker because its own replica will serve the CUP until it gets shut down before an upgrade.
//!
//! CUPs are persisted in Protobuf format and are expected to be backwards compatible. For example,
//! if a node stays offline for a long period of time and its subnet goes through an upgrade in
//! that time, it is the CUP served by peers that will help such a node to get back on track. It
//! will contain a registry version indicating the correct replica version and a list of peers that
//! can be used to fetch newer CUPs. This way a node does not rely on the P2P protocol to catch up
//! with its subnet and allows us to upgrade the protocol with breaking changes on any protocol layer.

use crate::{
    error::{OrchestratorError, OrchestratorResult},
    registry_helper::RegistryHelper,
    utils::http_endpoint_to_url,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces::crypto::ThresholdSigVerifierByPublicKey;
use ic_logger::{info, warn, ReplicaLogger};
use ic_protobuf::{registry::node::v1::NodeRecord, types::v1 as pb};
use ic_sys::fs::write_protobuf_using_tmp_file;
use ic_types::{
    consensus::{
        catchup::{CatchUpContentProtobufBytes, CatchUpPackage, CatchUpPackageParam},
        HasHeight,
    },
    crypto::*,
    Height, NodeId, RegistryVersion, SubnetId,
};
use prost::Message;
use std::{convert::TryFrom, fs::File, path::PathBuf, sync::Arc};

/// Fetches catch-up packages from peers and local storage.
///
/// CUPs are used to determine which version of the IC peers are running
/// and hence which version of the IC this node should be starting.
#[derive(Clone)]
pub(crate) struct CatchUpPackageProvider {
    registry: Arc<RegistryHelper>,
    cup_dir: PathBuf,
    crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
    crypto_tls_config: Arc<dyn TlsConfig + Send + Sync>,
    logger: ReplicaLogger,
    node_id: NodeId,
}

impl CatchUpPackageProvider {
    /// Instantiate a new `CatchUpPackageProvider`
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        cup_dir: PathBuf,
        crypto: Arc<dyn ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + Send + Sync>,
        crypto_tls_config: Arc<dyn TlsConfig + Send + Sync>,
        logger: ReplicaLogger,
        node_id: NodeId,
    ) -> Self {
        Self {
            node_id,
            registry,
            cup_dir,
            crypto,
            crypto_tls_config,
            logger,
        }
    }

    // Randomly selects a peer from the subnet and pulls its CUP. If this CUP is
    // newer than the currently available one and it could be verified, then this
    // CUP is returned. Note that it is acceptable to use a single peer, because
    // CUPs are validated. If all `f` nodes serve unusable CUPs, we have a probability
    // of 2/3 to hit a non-faulty node, so roughly on 4th attempt we should obtain
    // the correct peer CUP.
    async fn get_peer_cup(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
        current_cup: Option<&pb::CatchUpPackage>,
    ) -> Option<pb::CatchUpPackage> {
        use ic_registry_client_helpers::subnet::SubnetTransportRegistry;
        use rand::seq::SliceRandom;

        let mut nodes: Vec<(NodeId, NodeRecord)> = self
            .registry
            .registry_client
            .get_subnet_node_records(subnet_id, registry_version)
            .ok()
            .flatten()
            .unwrap_or_default();
        // Randomize the order of peer_urls
        nodes.shuffle(&mut rand::thread_rng());
        let current_node = nodes
            .as_slice()
            .iter()
            .find(|t| t.0 == self.node_id)
            .cloned();

        // Try only one peer at-a-time if there is already a local CUP,
        // Otherwise, try not to fall back to the registry CUP.
        let mut peers = match current_cup {
            Some(_) => vec![nodes.pop().or_else(|| {
                warn!(
                    self.logger,
                    "Empty peer list for subnet {} at version {}", subnet_id, registry_version
                );
                None
            })?],
            None => nodes,
        };

        // If we are still a member of the subnet, append our own data so that we first try to
        // fetch the CUP from our own replica. This improves the upgrade behaviour of a healthy
        // subnet, as we decrease the probability hitting peers who already started the upgrade
        // process and will not serve a CUP until they're online again.
        if let Some(current_node) = current_node {
            peers.push(current_node);
        }

        let param = current_cup
            .map(CatchUpPackageParam::try_from)
            .and_then(Result::ok);

        for (node_id, node_record) in peers.iter() {
            if let Some((proto, cup)) = self
                .fetch_and_verify_catch_up_package(node_id, node_record, param, subnet_id)
                .await
            {
                // Note: None is < Some(_)
                if Some(CatchUpPackageParam::from(&cup)) > param {
                    return Some(proto);
                }
            }
        }
        None
    }

    // Download CUP from the given node.
    //
    // If `param` is given, download only CUPs that are newer than the
    // given CUP. This avoids unnecessary CUP downloads and hence reduces
    // network bandwidth requirements.
    //
    // Also checks the signature of the downloaded catch up package.
    async fn fetch_and_verify_catch_up_package(
        &self,
        node_id: &NodeId,
        node_record: &NodeRecord,
        param: Option<CatchUpPackageParam>,
        subnet_id: SubnetId,
    ) -> Option<(pb::CatchUpPackage, CatchUpPackage)> {
        let http = node_record.clone().http.or_else(|| {
            warn!(
                self.logger,
                "Node record's http endpoint is None: {:?}", node_record
            );
            None
        })?;
        let mut uri = http_endpoint_to_url(&http, &self.logger)?;
        uri.path_segments_mut()
            .ok()?
            .push("_")
            .push("catch_up_package");

        let uri = uri.to_string();

        let protobuf = self
            .fetch_catch_up_package(node_id, uri.clone(), param)
            .await?;
        let cup = CatchUpPackage::try_from(&protobuf)
            .map_err(|e| {
                warn!(
                    self.logger,
                    "Failed to read CUP from peer at url {}: {:?}", uri, e
                )
            })
            .ok()?;

        self.crypto
            .verify_combined_threshold_sig_by_public_key(
                &CombinedThresholdSigOf::new(CombinedThresholdSig(protobuf.signature.clone())),
                &CatchUpContentProtobufBytes::from(&protobuf),
                subnet_id,
                cup.content.block.get_value().context.registry_version,
            )
            .map_err(|e| {
                warn!(
                    self.logger,
                    "Failed to verify CUP signature at: {:?} with: {:?}", uri, e
                )
            })
            .ok()?;

        Some((protobuf, cup))
    }

    // Attempt to fetch a `CatchUpPackage` from the given endpoint.
    //
    // Does not check the signature of the CUP. This has to be done by the
    // caller.
    async fn fetch_catch_up_package(
        &self,
        node_id: &NodeId,
        url: String,
        param: Option<CatchUpPackageParam>,
    ) -> Option<pb::CatchUpPackage> {
        let body = Bytes::from(
            param
                .and_then(|param| serde_cbor::to_vec(&param).ok())
                .unwrap_or_default(),
        );

        let client_config = self
            .crypto_tls_config
            .client_config(*node_id, self.registry.get_latest_version())
            .map_err(|e| warn!(self.logger, "Failed to create tls client config: {:?}", e))
            .ok()?;

        let https = HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .enable_all_versions()
            .build();

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(tokio::time::Duration::from_secs(600))
            .pool_max_idle_per_host(1)
            .build::<_, Full<Bytes>>(https);

        let req = tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            client.request(
                Request::builder()
                    .method(Method::POST)
                    .header(hyper::header::CONTENT_TYPE, "application/cbor")
                    .uri(url)
                    .body(Full::from(body))
                    .map_err(|e| warn!(self.logger, "Failed to create request: {:?}", e))
                    .ok()?,
            ),
        );

        let res = req
            .await
            .map_err(|e| warn!(self.logger, "Querying CUP endpoint timed out: {:?}", e))
            .ok()?
            .map_err(|e| warn!(self.logger, "Failed to query CUP endpoint: {:?}", e))
            .ok()?;

        let bytes = res
            .into_body()
            .collect()
            .await
            .map_err(|e| {
                warn!(
                    self.logger,
                    "Failed to convert the response body to bytes: {:?}", e
                )
            })
            .ok()?
            .to_bytes();

        if bytes.is_empty() {
            None
        } else {
            pb::CatchUpPackage::decode(&bytes[..])
                .map_err(|e| {
                    warn!(
                        self.logger,
                        "Failed to deserialize CUP from protobuf: {:?}", e
                    )
                })
                .ok()
        }
    }

    /// Persist the given CUP to disk.
    ///
    /// This is necessary, as it allows the orchestrator to find a CUP
    /// it previously downloaded again after restart, so that the node
    /// manager never goes back in time.  It will always find a CUP
    /// that is at least as high as the one it has previously
    /// discovered.
    ///
    /// Follows guidelines for DFINITY thread-safe I/O.
    fn persist_cup(&self, cup_proto: &pb::CatchUpPackage) -> OrchestratorResult<PathBuf> {
        let cup_file_path = self.get_cup_path();
        let cup = CatchUpPackage::try_from(cup_proto).map_err(|e| {
            OrchestratorError::IoError(
                "Failed to deserialize CUP! Couldn't persist.".to_string(),
                std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            )
        })?;
        info!(
            self.logger,
            "Persisting CUP (registry version={}, height={}) to file {}",
            cup.content.registry_version(),
            cup.height(),
            &cup_file_path.display(),
        );
        write_protobuf_using_tmp_file(&cup_file_path, cup_proto).map_err(|e| {
            OrchestratorError::IoError(
                format!("Failed to serialize protobuf to disk: {:?}", &cup_file_path),
                e,
            )
        })?;

        Ok(cup_file_path)
    }

    /// The path that should be used to save the CUP for the assigned subnet.
    /// Includes the specific type encoded in the file for future-proofing and
    /// ease of debugging.
    pub(crate) fn get_cup_path(&self) -> PathBuf {
        self.cup_dir.join("cup.types.v1.CatchUpPackage.pb")
    }

    /// Return the most up to date CUP.
    ///
    /// Choose the highest CUP among: those provided by the subnet peers,
    /// the locally persisted CUP (if one exists) and the CUP that is specified
    /// by the registry. If we manage to find a newer CUP we also persist it.
    pub(crate) async fn get_latest_cup(
        &self,
        local_cup: Option<pb::CatchUpPackage>,
        subnet_id: SubnetId,
    ) -> OrchestratorResult<CatchUpPackage> {
        let registry_version = self.registry.get_latest_version();
        let local_cup_height = local_cup
            .as_ref()
            .map(|cup| {
                get_cup_proto_height(cup).ok_or_else(|| {
                    OrchestratorError::deserialize_cup_error(
                        None,
                        "Failed to get CUP proto height.",
                    )
                })
            })
            .transpose()?;

        let subnet_cup = self
            .get_peer_cup(subnet_id, registry_version, local_cup.as_ref())
            .await;

        let registry_cup = self
            .registry
            .get_registry_cup(registry_version, subnet_id)
            .map(pb::CatchUpPackage::from)
            .ok();

        // Select the latest CUP based on the height of the CUP *proto*. This is to avoid falling
        // back to an outdated registry CUP if the local CUP can't be deserialized. If this is the
        // case, we prefer to return an error and wait until a higher recovery CUP exists.
        let latest_cup_proto = vec![local_cup, registry_cup, subnet_cup]
            .into_iter()
            .flatten()
            .max_by_key(get_cup_proto_height)
            .ok_or(OrchestratorError::MakeRegistryCupError(
                subnet_id,
                registry_version,
            ))?;
        let latest_cup = CatchUpPackage::try_from(&latest_cup_proto).map_err(|err| {
            OrchestratorError::deserialize_cup_error(get_cup_proto_height(&latest_cup_proto), err)
        })?;

        let height = Some(latest_cup.height());
        // We recreate the local registry CUP everytime to avoid incompatibility issues. Without
        // this recreation, we might run into the following problem: assume the orchestrator of
        // version A creates a local unsigned CUP from the registry contents, persists it, then
        // detects a new replica version B, upgrades to it and starts the replica on the previously
        // created CUP. Now since such a case might happen on a new subnet creation or during a
        // subnet recover with failover nodes, all nodes before upgrading to B might have been on
        // different versions and hence might have created different CUPs, which are then consumed
        // by the same replica version B, which is not guaranteed to be deterministic.
        //
        // By re-creating the unsigned CUP every time we realize it's the newest one, we instead
        // recreate the CUP on all orchestrators of the version B before starting the replica.
        if height > local_cup_height || height == local_cup_height && !latest_cup.is_signed() {
            self.persist_cup(&latest_cup_proto)?;
        }

        Ok(latest_cup)
    }

    // Returns the locally persisted CUP in deserialized form
    pub(crate) fn get_local_cup(&self) -> Option<CatchUpPackage> {
        match self.get_local_cup_proto() {
            None => None,
            Some(cup_proto) => (&cup_proto)
                .try_into()
                .map_err(|err| warn!(self.logger, "Deserialization of CUP failed: {}", err))
                .ok(),
        }
    }

    /// Returns the locally persisted CUP in protobuf form
    pub(crate) fn get_local_cup_proto(&self) -> Option<pb::CatchUpPackage> {
        let path = self.get_cup_path();
        if !path.exists() {
            return None;
        }
        match File::open(&path) {
            Ok(reader) => pb::CatchUpPackage::read_from_reader(reader)
                .map_err(|e| warn!(self.logger, "Failed to read CUP from file {:?}", e))
                .ok(),
            Err(err) => {
                warn!(self.logger, "Couldn't open file {:?}: {:?}", path, err);
                None
            }
        }
    }

    pub(crate) fn get_checkpoint_heights(&self) -> OrchestratorResult<impl Iterator<Item = u64>> {
        Ok(std::fs::read_dir("/var/lib/ic/data/ic_state/checkpoints")
            .map_err(|err| {
                OrchestratorError::IoError("Couldn't create a checkpoints directory".into(), err)
            })?
            .flatten()
            .flat_map(|entry| {
                let file_name = entry.file_name();
                let file_name = file_name.to_string_lossy();
                u64::from_str_radix(&file_name, 16)
            }))
    }
}

// Returns the height of the CUP without converting the protobuf
fn get_cup_proto_height(cup: &pb::CatchUpPackage) -> Option<Height> {
    pb::CatchUpContent::decode(cup.content.as_slice())
        .ok()
        .and_then(|content| content.block)
        .map(|block| Height::from(block.height))
}
