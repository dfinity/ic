use crate::error::{OrchestratorError, OrchestratorResult};
use crate::registry_helper::RegistryHelper;
use ic_canister_client::Sender;
use ic_canister_client::{Agent, HttpClient};
use ic_crypto::CryptoComponentForNonReplicaProcess;
use ic_logger::{info, warn, ReplicaLogger};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    consensus::catchup::{
        CUPWithOriginalProtobuf, CatchUpContentProtobufBytes, CatchUpPackage, CatchUpPackageParam,
    },
    consensus::HasHeight,
    crypto::*,
    RegistryVersion, SubnetId,
};
use ic_utils::fs::write_protobuf_using_tmp_file;
use std::convert::TryFrom;
use std::sync::Arc;
use std::{fs::File, path::PathBuf};
use url::Url;

/// This wraps the CUP with the context about its origin.
pub enum LatestCup {
    FromRegistry(CUPWithOriginalProtobuf),
    FromPeers(CUPWithOriginalProtobuf),
}

/// Fetches catch-up packages from peers and local storage.
///
/// CUPs are used to determine which version of the IC peers are running
/// and hence which version of the IC this node should be starting.
#[derive(Clone)]
pub(crate) struct CatchUpPackageProvider {
    registry: Arc<RegistryHelper>,
    cup_dir: PathBuf,
    client: HttpClient,
    crypto: Arc<dyn CryptoComponentForNonReplicaProcess + Send + Sync>,
    logger: ReplicaLogger,
}

impl CatchUpPackageProvider {
    /// Instantiate a new `CatchUpPackageProvider`
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        cup_dir: PathBuf,
        crypto: Arc<dyn CryptoComponentForNonReplicaProcess + Send + Sync>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            cup_dir,
            client: HttpClient::new(),
            crypto,
            logger,
        }
    }

    // Randomly selects a peer from the subnet and pulls its CUP. If this CUP is
    // newer than the currently available one and it could be verified, then this
    // CUP is returned. Else, `current_cup` is returned. Note that it is
    // acceptable to use a single peer, because CUPs are validated. If all `f`
    // nodes serve unusable CUPs, we have a probability of 2/3 to hit a
    // non-faulty node, so roughly on 4th attempt we should obtain the correct
    // peer CUP.
    async fn get_peer_cup(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
        current_cup: Option<CUPWithOriginalProtobuf>,
    ) -> Option<CUPWithOriginalProtobuf> {
        use ic_protobuf::registry::node::v1::NodeRecord;
        use ic_registry_client::helper::subnet::SubnetTransportRegistry;
        use ic_types::NodeId;
        use rand::seq::SliceRandom;

        let mut nodes: Vec<(NodeId, NodeRecord)> = self
            .registry
            .registry_client
            .get_subnet_transport_infos(subnet_id, registry_version)
            .ok()
            .flatten()
            .unwrap_or_else(Vec::new);
        // Randomize the order of peer_urls
        nodes.shuffle(&mut rand::thread_rng());

        let peer_url = match &nodes.as_slice() {
            [] => {
                warn!(
                    self.logger,
                    "Empty peer list for subnet {} at version {}", subnet_id, registry_version
                );
                return current_cup;
            }
            [(_, node_record), ..] => {
                let http = node_record.clone().http?;
                let url = format!("http://[{}]:{}", http.ip_addr, http.port);
                Url::parse(&url)
                    .map_err(|err| {
                        warn!(
                            self.logger,
                            "Unable to parse the peer url {}: {:?}", url, err
                        );
                    })
                    .ok()?
            }
        };

        let param = current_cup.as_ref().map(CatchUpPackageParam::from);
        let peer_cup = self
            .fetch_verify_and_deserialize_catch_up_package(peer_url, param, subnet_id)
            .await;
        // Note: None is < Some(_)
        if peer_cup.as_ref().map(CatchUpPackageParam::from) > param {
            return peer_cup;
        }

        current_cup
    }

    // Download CUP from the given URL.
    //
    // If `param` is given, download only CUPs that are newer than the
    // given CUP. This avoids unnecessary CUP downloads and hence reduces
    // network bandwidth requirements.
    //
    // Also checks the signature of the downloaded catch up package.
    async fn fetch_verify_and_deserialize_catch_up_package(
        &self,
        url: Url,
        param: Option<CatchUpPackageParam>,
        subnet_id: SubnetId,
    ) -> Option<CUPWithOriginalProtobuf> {
        let protobuf = self.fetch_catch_up_package(url.clone(), param).await?;
        let cup = CUPWithOriginalProtobuf {
            cup: CatchUpPackage::try_from(&protobuf)
                .map_err(|e| {
                    warn!(
                        self.logger,
                        "Failed to read CUP from peer at url {}: {:?}", url, e
                    )
                })
                .ok()?,
            protobuf,
        };
        self.crypto
            .verify_combined_threshold_sig_by_public_key(
                &CombinedThresholdSigOf::new(CombinedThresholdSig(cup.protobuf.signature.clone())),
                &CatchUpContentProtobufBytes(cup.protobuf.content.clone()),
                subnet_id,
                cup.cup.content.block.get_value().context.registry_version,
            )
            .map_err(|e| {
                warn!(
                    self.logger,
                    "Failed to verify cup signature at: {:?} with: {:?}", url, e
                )
            })
            .ok()?;
        Some(cup)
    }

    // Attempt to fetch a `CatchUpPackage` from the given endpoint.
    //
    // Does not check the signature of the CUP. This has to be done by the
    // caller.
    async fn fetch_catch_up_package(
        &self,
        url: Url,
        param: Option<CatchUpPackageParam>,
    ) -> Option<pb::CatchUpPackage> {
        Agent::new_with_client(self.client.clone(), url, Sender::Anonymous)
            .query_cup_endpoint(param)
            .await
            .map_err(|e| warn!(self.logger, "Failed to query CUP endpoint: {:?}", e))
            .ok()?
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
    pub(crate) fn persist_cup(&self, cup: &CUPWithOriginalProtobuf) -> OrchestratorResult<PathBuf> {
        let cup_file_path = self.get_cup_path();
        info!(
            self.logger,
            "Persisting CUP to file: {:?}, replica version={}, height={}",
            &cup_file_path,
            cup.cup.content.registry_version(),
            cup.cup.height()
        );
        write_protobuf_using_tmp_file(&cup_file_path, &cup.protobuf).map_err(|e| {
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
    pub fn get_cup_path(&self) -> PathBuf {
        self.cup_dir.join("cup.types.v1.CatchUpPackage.pb")
    }

    /// Return the most up to date CUP.
    ///
    /// Choose the highest CUP among: those provided by the subnet peers,
    /// the locally persisted CUP (if one exists) and the CUP that is specified
    /// by the registry. If we manage to find a newer CUP we also persist it.
    pub(crate) async fn get_latest_cup(
        &self,
        local_cup: Option<CUPWithOriginalProtobuf>,
        subnet_id: SubnetId,
    ) -> OrchestratorResult<LatestCup> {
        let registry_version = self.registry.get_latest_version();
        let local_cup_height = local_cup.as_ref().map(|cup| cup.cup.content.height());

        // Returns local_cup in case no more recent CUP is found.
        let subnet_cup = self
            .get_peer_cup(subnet_id, registry_version, local_cup)
            .await;

        let registry_cup = self
            .registry
            .get_registry_cup(registry_version, subnet_id)
            .map(CUPWithOriginalProtobuf::from_cup)
            .map_err(|err| warn!(self.logger, "Failed to retrieve registry CUP {:?}", err))
            .ok();

        let latest_cup = match (registry_cup, subnet_cup) {
            (Some(r_cup), Some(p_cup)) => {
                if r_cup.cup.content.height() > p_cup.cup.content.height() {
                    LatestCup::FromRegistry(r_cup)
                } else {
                    LatestCup::FromPeers(p_cup)
                }
            }
            (Some(r_cup), None) => LatestCup::FromRegistry(r_cup),
            (None, Some(p_cup)) => LatestCup::FromPeers(p_cup),
            _ => {
                return Err(OrchestratorError::UpgradeError(
                    "No latest CUP was found".to_string(),
                ))
            }
        };

        let latest_cup_unwrapped = match &latest_cup {
            LatestCup::FromRegistry(cup) | LatestCup::FromPeers(cup) => cup,
        };
        if Some(latest_cup_unwrapped.cup.content.height()) > local_cup_height {
            match self.persist_cup(latest_cup_unwrapped) {
                Ok(path) => info!(self.logger, "New CUP persisted to {}", path.display()),
                Err(err) => warn!(self.logger, "Failed to persist CUP: {:?}", err),
            }
        }

        Ok(latest_cup)
    }

    /// Returns the locally persisted CUP.
    pub fn get_local_cup(&self) -> Option<CUPWithOriginalProtobuf> {
        let path = self.get_cup_path();
        if !path.exists() {
            return None;
        }
        match File::open(&path) {
            Ok(reader) => pb::CatchUpPackage::read_from_reader(reader)
                .and_then(|protobuf| {
                    Ok(CUPWithOriginalProtobuf {
                        cup: CatchUpPackage::try_from(&protobuf)?,
                        protobuf,
                    })
                })
                .map_err(|e| warn!(self.logger, "Failed to read CUP from file {:?}", e))
                .ok(),
            Err(err) => {
                warn!(self.logger, "Couldn't open file {:?}: {:?}", path, err);
                None
            }
        }
    }
}
