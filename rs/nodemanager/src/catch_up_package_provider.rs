use crate::error::{NodeManagerError, NodeManagerResult};
use crate::registry_helper::RegistryHelper;
use ic_canister_client::Sender;
use ic_canister_client::{Agent, HttpClient};
use ic_crypto::CryptoComponentForNonReplicaProcess;
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    consensus::catchup::{
        CUPWithOriginalProtobuf, CatchUpContentProtobufBytes, CatchUpPackage, CatchUpPackageParam,
    },
    consensus::HasHeight,
    crypto::*,
    RegistryVersion, SubnetId,
};
use std::convert::TryFrom;
use std::{fs::File, path::PathBuf};
use std::{io, sync::Arc};
use url::Url;

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

    /// Return the latest and highest `CatchUpPackage`s provided by all peers in
    /// this node's Subnet. Use the given `cup` as a starting point, and only
    /// fetch `CatchUpPackage` that are newer.
    ///
    /// If no later CUP than the one given as `latest_cup` can be
    /// found, return that.
    async fn get_latest_subnet_cup(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
        mut latest_cup: Option<CUPWithOriginalProtobuf>,
    ) -> Option<CUPWithOriginalProtobuf> {
        use rand::seq::SliceRandom;

        let mut peer_urls = self.registry.get_node_urls(subnet_id, version);
        // Randomize the order of peer_urls
        peer_urls.shuffle(&mut rand::thread_rng());

        for url in peer_urls {
            if let Some(url) = url {
                let param = latest_cup.as_ref().map(CatchUpPackageParam::from);
                let cup = self
                    .fetch_verify_and_deserialize_catch_up_package(url, param, subnet_id)
                    .await;
                // Note: None is < Some(_)
                if cup.as_ref().map(CatchUpPackageParam::from) > param {
                    latest_cup = cup;
                }
            }
        }

        latest_cup
    }

    /// Download CUP from the given URL.
    ///
    /// If `param` is given, download only CUPs that are newer than the
    /// given CUP. This avoids unnecessary CUP downloads and hence reduces
    /// network bandwidth requirements.
    ///
    /// Also checks the signature of the downloaded catch up package.
    async fn fetch_verify_and_deserialize_catch_up_package(
        &self,
        url: Url,
        param: Option<CatchUpPackageParam>,
        subnet_id: SubnetId,
    ) -> Option<CUPWithOriginalProtobuf> {
        self.fetch_catch_up_package(url.clone(), param)
            .await
            .and_then(|protobuf| {
                let cup = CUPWithOriginalProtobuf {
                    cup: CatchUpPackage::try_from(&protobuf)
                        .map_err(|e| {
                            warn!(
                                self.logger,
                                "Failed to read CUP from peer at url {}, {:?}", url, e
                            )
                        })
                        .ok()?,
                    protobuf,
                };
                self.crypto
                    .verify_combined_threshold_sig_by_public_key(
                        &CombinedThresholdSigOf::new(CombinedThresholdSig(
                            cup.protobuf.signature.clone(),
                        )),
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
            })
    }

    /// Attempt to fetch a `CatchUpPackage` from the given endpoint.
    ///
    /// Does not check the signature of the CUP. This has to be done by the
    /// caller.
    async fn fetch_catch_up_package(
        &self,
        url: Url,
        param: Option<CatchUpPackageParam>,
    ) -> Option<pb::CatchUpPackage> {
        let agent = Agent::new_with_client(self.client.clone(), url, Sender::Anonymous);

        agent
            .query_cup_endpoint(param)
            .await
            .map_err(|e| debug!(self.logger, "Failed to query CUP endpoint: {:?}", e))
            .ok()
            .flatten()
    }

    /// Persist the given CUP to disk.
    ///
    /// This is necessary, as it allows the node manager to find a CUP
    /// it previously downloads again after restart, so that the node
    /// manager never goes back in time.  It will always find a CUP
    /// that is at least as high as the one it has previously
    /// discovered.
    pub(crate) fn persist_cup(
        &self,
        cup: &CUPWithOriginalProtobuf,
        subnet_id: SubnetId,
    ) -> NodeManagerResult<PathBuf> {
        let cup_file_path = self.get_upgrade_cup_save_path(subnet_id);
        info!(
            self.logger,
            "Persisting CUP to file: {:?} - replica version {} - height {}",
            &cup_file_path,
            cup.cup.content.registry_version(),
            cup.cup.height()
        );
        cup.protobuf.write_to_file(&cup_file_path).map_err(|e| {
            NodeManagerError::IoError(
                format!("Failed to write protobuf to disk: {:?}", &cup_file_path),
                e,
            )
        })?;
        Ok(cup_file_path)
    }

    /// Return an io::Read for the most appropriate CUP file for the given
    /// subnet ID, or None if no file could be opened.
    pub(crate) fn get_upgrade_cup_reader(&self, subnet_id: SubnetId) -> Option<Box<dyn io::Read>> {
        let path = self.get_upgrade_cup_save_path(subnet_id);

        debug!(
            self.logger,
            "checking for cup in {}",
            path.to_string_lossy()
        );
        if let Ok(reader) = File::open(&path) {
            info!(
                self.logger,
                "loading CUP for {} from path {}",
                subnet_id,
                path.to_string_lossy()
            );
            return Some(Box::new(reader));
        }

        let path = self.cup_dir.join(format!("cup_{}.proto", subnet_id));
        debug!(
            self.logger,
            "checking for cup in {}",
            path.to_string_lossy()
        );
        if let Ok(reader) = File::open(&path) {
            info!(
                self.logger,
                "loading CUP for {} from path {}",
                subnet_id,
                path.to_string_lossy()
            );
            return Some(Box::new(reader));
        }

        None
    }

    /// The path that should be used to save the CUP for the given subnet.
    /// Includes the specific type encoded in the file for future-proofing and
    /// ease of debugging.
    pub(crate) fn get_upgrade_cup_save_path(&self, subnet_id: SubnetId) -> PathBuf {
        self.cup_dir
            .join(format!("cup_{}.types.v1.CatchUpPackage.pb", subnet_id))
    }

    /// Return the most up to date CUP.
    ///
    /// Choose the highest CUP among: those provided by the subnet peers,
    /// the locally persisted CUP (if one exists) and the CUP that is specified
    /// by the registry.
    pub(crate) async fn get_latest_cup(
        &self,
        subnet_id: SubnetId,
    ) -> NodeManagerResult<CUPWithOriginalProtobuf> {
        let registry_version = self.registry.get_latest_version();
        let local_cup = self.get_local_cup(subnet_id);

        // Returns local_cup in case no more recent CUP is found.
        let subnet_cup = self
            .get_latest_subnet_cup(subnet_id, registry_version, local_cup)
            .await;

        let registry_cup = self
            .registry
            .get_registry_cup(registry_version)
            .map(CUPWithOriginalProtobuf::from_cup)
            .map_err(|err| warn!(self.logger, "Failed to retrieve registry CUP {:?}", err))
            .ok();

        vec![registry_cup, subnet_cup]
            .into_iter()
            .flatten()
            .max_by_key(|cup| cup.cup.content.height())
            .ok_or_else(|| NodeManagerError::MakeRegistryCupError(subnet_id, registry_version))
    }

    /// Return the CUP has been persisted for the given subnet, if it exists
    fn get_local_cup(&self, subnet_id: SubnetId) -> Option<CUPWithOriginalProtobuf> {
        match self.get_upgrade_cup_reader(subnet_id) {
            Some(reader) => pb::CatchUpPackage::read_from_reader(reader)
                .and_then(|protobuf| {
                    Ok(CUPWithOriginalProtobuf {
                        cup: CatchUpPackage::try_from(&protobuf)?,
                        protobuf,
                    })
                })
                .map_err(|e| warn!(self.logger, "Failed to read CUP from file {:?}", e))
                .ok(),
            None => {
                warn!(
                    self.logger,
                    "No CUP files found in {}",
                    self.cup_dir.to_string_lossy()
                );
                None
            }
        }
    }
}
