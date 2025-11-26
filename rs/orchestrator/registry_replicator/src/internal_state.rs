use ic_interfaces_registry::{RegistryClient, ZERO_REGISTRY_VERSION};
use ic_logger::{ReplicaLogger, info, warn};
use ic_protobuf::{
    registry::{
        node::v1::ConnectionEndpoint,
        routing_table::v1::RoutingTable as PbRoutingTable,
        subnet::v1::{SubnetListRecord, SubnetRecord, SubnetType},
    },
    types::v1::{PrincipalId as PrincipalIdProto, SubnetId as SubnetIdProto},
};
use ic_registry_client_helpers::{
    crypto::CryptoRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{SubnetRegistry, SubnetTransportRegistry},
};
use ic_registry_keys::{
    CANISTER_RANGES_PREFIX, ROOT_SUBNET_ID_KEY, make_canister_ranges_key,
    make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_local_store::{ChangelogEntry, KeyMutation, LocalStore};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_types::{
    CanisterId, NodeId, RegistryVersion, SubnetId, crypto::threshold_sig::ThresholdSigPublicKey,
};
use prost::Message;
use std::{
    collections::BTreeMap, convert::TryFrom, fmt::Debug, net::IpAddr, str::FromStr, sync::Arc,
    time::Duration,
};
use url::Url;

const MAX_CONSECUTIVE_FAILURES: i64 = 3;

/// The `InternalState` encompasses a locally persisted registry changelog which
/// is kept up to date by repeated calls to [`Self::poll()`]. If this node is
/// part of a subnet that is starting up as the NNS after a switch-over, the
/// next call to [`Self::poll()`] will update the local registry accordingly and
/// exit the process, to allow the node to be restarted as part of the NNS.
///
/// [`Self::poll()`] updates the `InternalState` by:
/// 1. Fetching certified registry changes from the [`RegistryCanister`].
/// 2. Comparing changes to current local state as provided by the
///    [`RegistryClient`].
/// 3. Applying recent changes by writing to (ideally) the client's
///    [`LocalStore`].
pub(crate) struct InternalState {
    logger: ReplicaLogger,
    node_id: Option<NodeId>,
    registry_client: Arc<dyn RegistryClient>,
    local_store: Arc<dyn LocalStore>,
    latest_version: RegistryVersion,
    nns_urls: Vec<Url>,
    nns_pub_key: Option<ThresholdSigPublicKey>,
    registry_canister: Option<Arc<RegistryCanister>>,
    registry_canister_fallback: Option<Arc<RegistryCanister>>,
    poll_delay: Duration,
    failed_poll_count: i64,
}

impl InternalState {
    pub(crate) fn new(
        logger: ReplicaLogger,
        node_id: Option<NodeId>,
        registry_client: Arc<dyn RegistryClient>,
        local_store: Arc<dyn LocalStore>,
        config_nns_urls: Vec<Url>,
        maybe_config_nns_pub_key: Option<ThresholdSigPublicKey>,
        poll_delay: Duration,
    ) -> Self {
        let registry_canister_fallback = if !config_nns_urls.is_empty() {
            Some(Arc::new(RegistryCanister::new_with_query_timeout(
                config_nns_urls,
                poll_delay,
            )))
        } else {
            None
        };
        Self {
            logger,
            node_id,
            registry_client,
            local_store,
            latest_version: ZERO_REGISTRY_VERSION,
            nns_urls: vec![],
            nns_pub_key: maybe_config_nns_pub_key,
            registry_canister: None,
            registry_canister_fallback,
            poll_delay,
            failed_poll_count: 0,
        }
    }

    /// Requests latest version and certified changes from the
    /// [`RegistryCanister`], applies changes to [`LocalStore`] accordingly.
    /// Exits the process if this node appears on a subnet that is started as
    /// the new NNS after a version update.
    pub(crate) async fn poll(&mut self) -> Result<(), String> {
        // Note, this may not actually be the latest version, rather it is the latest
        // version that is locally available
        let latest_version = self.registry_client.get_latest_version();
        if latest_version != self.latest_version {
            // latest version has changed (originally initialized with 0)
            self.latest_version = latest_version;
            self.start_new_nns_subnet(latest_version)
                .expect("Start new NNS failed.");
            // update (initialize) *remote* registry canister client in case NNS has changed (or
            // this is the first call to poll())
            if let Err(e) = self.update_registry_canister(latest_version) {
                warn!(
                    self.logger,
                    "Could not update registry canister with new topology data: {:?}", e
                );
            }
        }

        let Some(nns_pub_key) = self.nns_pub_key else {
            return Err("NNS public key not set in the registry and not configured.".to_string());
        };

        let registry_canister = match (
            self.registry_canister.as_ref(),
            self.registry_canister_fallback.as_ref(),
        ) {
            (_, Some(fallback)) if self.failed_poll_count >= MAX_CONSECUTIVE_FAILURES => {
                // After several failed attempts to poll the NNS, try the config URLs once, which
                // would possibly fix the local store for the next poll.
                info!(
                    self.logger,
                    "Polling NNS failed {} times consecutively, trying config urls once...",
                    self.failed_poll_count
                );
                // Set to -1 so that the counter is set back to 0 both on success and failure of the
                // poll.
                self.failed_poll_count = -1;
                Arc::clone(fallback)
            }
            (None, Some(fallback)) => {
                info!(
                    self.logger,
                    "Remote registry canister not initialized, probably due to missing NNS config data in the registry, trying config urls..."
                );
                Arc::clone(fallback)
            }
            (Some(canister), _) => Arc::clone(canister),
            (None, None) => return Err("No remote registry canister configured.".to_string()),
        };

        match write_certified_changes_to_local_store(
            &registry_canister,
            &nns_pub_key,
            self.local_store.as_ref(),
            latest_version,
        )
        .await
        {
            Ok(last_stored_version) => {
                self.failed_poll_count = 0;
                if last_stored_version != latest_version {
                    info!(
                        self.logger,
                        "Stored registry versions up to: {}", last_stored_version
                    );
                }
                Ok(())
            }
            Err(e) => {
                self.failed_poll_count += 1;
                Err(format!(
                    "Error when trying to fetch updates from NNS: {e:?}",
                ))
            }
        }
    }

    /// Iff at version `latest_version` the node id of this node appears on a
    /// subnet record that has the `start_as_nns` flag set, this function will
    /// adjust the registry such that the aforementioned subnet will become the
    /// new NNS subnet.
    ///
    /// If this node is not partaking in a switch-over, this function
    /// immediately returns Ok(()). If any operation fails, an error is
    /// returned.
    ///
    /// In case of a switch-over, and if there are no failures, this function
    /// exits the process and hence does not return.
    fn start_new_nns_subnet(&mut self, latest_version: RegistryVersion) -> Result<(), String> {
        // We can check if this node has start_as_nns set, only if node_id is set.
        let node_id = match self.node_id {
            Some(id) => id,
            None => return Ok(()),
        };

        fn map_to_str<E: Debug>(msg: &str, v: RegistryVersion, e: E) -> String {
            format!("{msg} at version {v}: {e:?}")
        }

        let (subnet_id, subnet_record) = match self
            .registry_client
            .get_listed_subnet_for_node_id(node_id, latest_version)
        {
            Ok(Some((id, r))) if r.start_as_nns => (id, r),
            Err(e) => {
                return Err(map_to_str(
                    "Error retrieving subnet records",
                    latest_version,
                    e,
                ));
            }
            _ => return Ok(()),
        };
        assert!(subnet_record.start_as_nns);

        // let k be the least version at which this node is part of the newly created
        // subnet
        let mut v = latest_version - RegistryVersion::from(1);
        let k = loop {
            if self
                .registry_client
                .get_subnet_record(subnet_id, v)
                .map_err(|e| map_to_str("Could not retrieve subnet record", v, e))?
                .is_none()
            {
                break v + RegistryVersion::from(1);
            }
            v -= RegistryVersion::from(1);
        };

        // IOErrors are treated as fatal.
        let mut changelog = self
            .local_store
            .get_changelog_since_version(RegistryVersion::from(0))
            .expect("Could not read changelog from disk.");
        changelog.truncate(k.get() as usize);

        apply_switch_over_to_last_changelog_entry_impl(
            self.registry_client.as_ref(),
            changelog.as_mut_slice(),
            subnet_id,
            subnet_record,
        );
        self.local_store
            .clear()
            .expect("Could not clear registry local store");

        for (v, cle) in changelog.into_iter().enumerate() {
            self.local_store
                .store(RegistryVersion::from((v + 1) as u64), cle)
                .expect("Could not store change log entry");
        }

        warn!(
            self.logger,
            "Rebooting node after switch-over to new NNS subnet."
        );
        std::process::exit(1);
    }

    /// Update the [`RegistryCanister`] API wrapper with the newest API Urls
    /// of the NNS nodes found in the registry if they have changed.
    ///
    /// If the necessary configuration is not set in the registry,
    /// `self.registry_canister` is set to None.
    fn update_registry_canister(&mut self, latest_version: RegistryVersion) -> Result<(), String> {
        let cur_nns_id = self.get_root_subnet_id(latest_version)?;

        let pub_key = self.get_nns_pub_key(cur_nns_id, latest_version)?;
        let pub_key_changed = self.nns_pub_key.map(|k| k != pub_key).unwrap_or(true);

        let urls = self.get_node_api_urls(cur_nns_id, latest_version)?;
        let urls_changed = self.nns_urls != urls;

        // has any of the urls or the pub key changed?
        if pub_key_changed || urls_changed {
            self.nns_pub_key = Some(pub_key);
            self.nns_urls.clone_from(&urls);

            // reinitialize client
            self.registry_canister = Some(Arc::new(RegistryCanister::new_with_query_timeout(
                urls,
                self.poll_delay,
            )));
        }
        Ok(())
    }

    fn get_root_subnet_id(&self, version: RegistryVersion) -> Result<SubnetId, String> {
        match self.registry_client.get_root_subnet_id(version) {
            Ok(Some(v)) => Ok(v),
            Ok(_) => Err(format!("No NNS subnet id configured at version {version}")),
            Err(e) => Err(format!(
                "Could not fetch nns subnet id at version {version}: {e:?}"
            )),
        }
    }

    fn get_nns_pub_key(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> Result<ThresholdSigPublicKey, String> {
        match self
            .registry_client
            .get_threshold_signing_public_key_for_subnet(subnet_id, version)
        {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err(format!(
                "Public key for subnet {subnet_id} not set at version {version}"
            )),
            Err(e) => Err(format!(
                "Error when retrieving public key for subnet {subnet_id} at version {version}: {e:?}"
            )),
        }
    }

    fn get_node_api_urls(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> Result<Vec<Url>, String> {
        let t_infos = match self
            .registry_client
            .get_subnet_node_records(subnet_id, version)
        {
            Ok(Some(v)) => v,
            Ok(None) => {
                return Err(format!(
                    "Missing or incomplete transport infos for subnet {subnet_id} at version {version}."
                ));
            }
            Err(e) => {
                return Err(format!(
                    "Error retrieving transport infos for subnet {subnet_id} at version {version}: {e:?}."
                ));
            }
        };

        let mut urls: Vec<Url> = t_infos
            .iter()
            .filter_map(|(_nid, n_record)| {
                n_record
                    .http
                    .as_ref()
                    .and_then(|h| self.http_endpoint_to_url(h))
            })
            .collect();
        urls.sort();
        Ok(urls)
    }

    fn http_endpoint_to_url(&self, http: &ConnectionEndpoint) -> Option<Url> {
        let host_str = match IpAddr::from_str(&http.ip_addr.clone()) {
            Ok(v) => {
                if v.is_ipv6() {
                    format!("[{v}]")
                } else {
                    v.to_string()
                }
            }
            Err(_) => {
                // assume hostname
                http.ip_addr.clone()
            }
        };

        let url = format!("http://{}:{}/", host_str, http.port);
        match Url::parse(&url) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!(self.logger, "Invalid url: {}: {:?}", url, e);
                None
            }
        }
    }
}

/// Poll the registry canister for certified changes since `from_version`, and
/// write them to the local store.
/// Returns the latest registry version written to the local store, or an error if
/// fetching the changes failed.
/// Panics if writing to the local store fails.
pub async fn write_certified_changes_to_local_store(
    registry_canister: &RegistryCanister,
    nns_pub_key: &ThresholdSigPublicKey,
    local_store: &dyn LocalStore,
    from_version: RegistryVersion,
) -> Result<RegistryVersion, String> {
    let (records, _, _) = registry_canister
        .get_certified_changes_since(from_version.get(), nns_pub_key)
        .await
        .map_err(|e| e.to_string())?;

    let mut changelog: BTreeMap<RegistryVersion, ChangelogEntry> = BTreeMap::new();
    for record in records {
        changelog
            .entry(record.version)
            .or_default()
            .push(KeyMutation {
                key: record.key,
                value: record.value,
            });
    }

    let last_version = changelog
        .last_key_value()
        .map(|(last_version, _)| *last_version)
        .unwrap_or(from_version); // If `changelog` is empty, i.e. no new changes.

    for (registry_version, changelog_entry) in changelog {
        local_store
            .store(registry_version, changelog_entry)
            .expect("Writing to the FS failed at version {registry_version}");
    }

    // If the local store did not panic in the loop above, then `last_version` is indeed the last
    // version stored on disk.
    Ok(last_version)
}

/// Standalone function for switch-over logic, for unit testing.
/// Looks up all required registry data using the provided RegistryClient.
pub fn apply_switch_over_to_last_changelog_entry_impl(
    registry_client: &dyn RegistryClient,
    changelog: &mut [ChangelogEntry],
    new_nns_subnet_id: SubnetId,
    mut new_nns_subnet_record: SubnetRecord,
) {
    let registry_version = RegistryVersion::from(changelog.len() as u64);

    let routing_table = registry_client
        .get_routing_table(registry_version)
        .expect("Could not query registry for routing table.")
        .expect("No routing table configured in registry");

    let old_nns_subnet_id = registry_client
        .get_root_subnet_id(registry_version)
        .expect("Could not query registry for nns subnet id")
        .expect("No NNS subnet id configured in the registry");

    let canister_range_keys = registry_client
        .get_key_family(CANISTER_RANGES_PREFIX, registry_version)
        .expect("Could not query registry for canister ranges");

    let last = changelog.last_mut().expect("Changelog cannot be empty");

    // remove all entries that will be adjusted
    let subnet_record_key = make_subnet_record_key(new_nns_subnet_id);
    last.retain(|k| {
        k.key != ROOT_SUBNET_ID_KEY
            && k.key != make_subnet_list_record_key()
            && k.key != subnet_record_key
            // Remove all canister_ranges_* records that are not deletion records, since those
            // won't come up in the canister_range_keys due to being deleted.
            && !(k.key.starts_with(CANISTER_RANGES_PREFIX) && k.value.is_some())
    });

    // remove the start_as_nns flag on the subnet record
    new_nns_subnet_record.start_as_nns = false;
    // force subnet type to be a system subnet
    new_nns_subnet_record.subnet_type = SubnetType::System as i32;
    // adjust subnet record
    let subnet_record_bytes = new_nns_subnet_record.encode_to_vec();
    last.push(KeyMutation {
        key: subnet_record_key,
        value: Some(subnet_record_bytes),
    });

    // set nns subnet id (actually, root subnet id)
    let new_nns_subnet_id_proto = SubnetIdProto {
        principal_id: Some(PrincipalIdProto {
            raw: new_nns_subnet_id.get().into_vec(),
        }),
    };
    let new_nns_subnet_id_bytes = new_nns_subnet_id_proto.encode_to_vec();
    last.push(KeyMutation {
        key: ROOT_SUBNET_ID_KEY.to_string(),
        value: Some(new_nns_subnet_id_bytes),
    });

    // adjust subnet list
    let subnet_list_record = SubnetListRecord {
        subnets: vec![new_nns_subnet_id.get().into_vec()],
    };
    let subnet_list_record_bytes = subnet_list_record.encode_to_vec();
    last.push(KeyMutation {
        key: make_subnet_list_record_key(),
        value: Some(subnet_list_record_bytes),
    });

    // adjust routing table
    let new_routing_table: BTreeMap<CanisterIdRange, SubnetId> = routing_table
        .into_iter()
        .filter_map(|(r, s_id)| {
            if s_id == old_nns_subnet_id {
                Some((r, new_nns_subnet_id))
            } else {
                None
            }
        })
        .collect();

    let new_routing_table = PbRoutingTable::from(
        RoutingTable::try_from(new_routing_table).expect("bug: invalid routing table"),
    );

    // Delete all routing table shards except the shard for canister id 0, and put the new routing table there.
    let mut routing_table_updates: Vec<_> = canister_range_keys
        .into_iter()
        .map(|key| {
            if key == make_canister_ranges_key(CanisterId::from_u64(0)) {
                KeyMutation {
                    key,
                    value: Some(new_routing_table.encode_to_vec()),
                }
            } else {
                KeyMutation { key, value: None }
            }
        })
        .collect();

    last.append(&mut routing_table_updates);
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_certification_test_utils::{CertificateBuilder, CertificateData::*};
    use ic_crypto_tree_hash::Digest;
    use ic_protobuf::registry::crypto::v1::PublicKey as PbPublicKey;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::node::NodeRecord;
    use ic_registry_keys::{
        ROOT_SUBNET_ID_KEY, make_canister_ranges_key, make_crypto_threshold_signing_pubkey_key,
        make_node_record_key, make_subnet_list_record_key, make_subnet_record_key,
    };
    use ic_registry_local_store::{LocalStoreImpl, LocalStoreWriter};
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types::{CanisterId, SubnetId};
    use ic_types_test_utils::ids::{NODE_1, SUBNET_1, SUBNET_2, SUBNET_3};
    use std::collections::BTreeMap;
    use std::convert::TryFrom;
    use std::sync::Arc;
    use tempfile::TempDir;

    const TEST_POLL_DELAY: Duration = Duration::from_secs(1);

    fn create_threshold_sig_public_key(byte: u8) -> ThresholdSigPublicKey {
        let (_, pk, _) = CertificateBuilder::new(CanisterData {
            canister_id: CanisterId::from_u64(0),
            certified_data: Digest([byte; 32]),
        })
        .build();

        pk
    }

    fn create_test_subnet_record(start_as_nns: bool, subnet_type: SubnetType) -> SubnetRecord {
        SubnetRecord {
            membership: vec![],
            max_ingress_bytes_per_message: 2048,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: "test_version".to_string(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            start_as_nns,
            subnet_type: subnet_type as i32,
            is_halted: false,
            halt_at_cup_height: false,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            chain_key_config: None,
            canister_cycles_cost_schedule: 0,
        }
    }

    fn setup_fake_registry_client(
        old_nns_subnet_id: SubnetId,
        shards: BTreeMap<String, BTreeMap<CanisterIdRange, SubnetId>>,
    ) -> FakeRegistryClient {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());

        // Set root subnet ID
        let old_nns_subnet_id_proto = ic_types::subnet_id_into_protobuf(old_nns_subnet_id);

        data_provider
            .add(
                ROOT_SUBNET_ID_KEY,
                RegistryVersion::from(1),
                Some(old_nns_subnet_id_proto),
            )
            .expect("Failed to set root subnet ID");

        // Add canister range keys
        for (key, shard) in shards {
            let pb_routing_table = PbRoutingTable::from(
                RoutingTable::try_from(shard).expect("Invalid routing table shard"),
            );
            data_provider
                .add(
                    &key,
                    RegistryVersion::from(3),
                    Some(pb_routing_table.clone()), // Just use the same data for test
                )
                .expect("Failed to set canister range");
        }

        let client = FakeRegistryClient::new(data_provider);
        client.update_to_latest_version();

        client
    }

    #[tokio::test]
    async fn test_uses_fallback_after_consecutive_failures() {
        with_test_replica_logger(|logger| async {
            let tempdir = TempDir::new().unwrap();
            let local_store = Arc::new(LocalStoreImpl::new(tempdir.path()));
            let registry_client = Arc::new(FakeRegistryClient::new(local_store.clone()));

            let config_nns_urls = vec![Url::parse("http://fallback:1234").unwrap()];
            let config_nns_pub_key = create_threshold_sig_public_key(0);

            // Initialize root subnet, public key and node record in the registry
            // The node endpoint is invalid on purpose to trigger failures.
            // The expected behavior is to try the fallback URLs after MAX_CONSECUTIVE_FAILURES.
            let http_endpoint = ConnectionEndpoint {
                ip_addr: "2001:db8::1".to_string(),
                port: 8080,
            };
            local_store
                .store(
                    RegistryVersion::from(1),
                    vec![KeyMutation {
                        key: ROOT_SUBNET_ID_KEY.to_string(),
                        value: Some(ic_types::subnet_id_into_protobuf(SUBNET_1).encode_to_vec()),
                    }],
                )
                .expect("Failed to set root subnet ID");
            local_store
                .store(
                    RegistryVersion::from(2),
                    vec![KeyMutation {
                        key: make_crypto_threshold_signing_pubkey_key(SUBNET_1),
                        value: Some(
                            PbPublicKey::from(create_threshold_sig_public_key(1)).encode_to_vec(),
                        ),
                    }],
                )
                .expect("Failed to set subnet public key");
            local_store
                .store(
                    RegistryVersion::from(3),
                    vec![KeyMutation {
                        key: make_node_record_key(NODE_1),
                        value: Some(
                            NodeRecord {
                                http: Some(http_endpoint.clone()),
                                ..Default::default()
                            }
                            .encode_to_vec(),
                        ),
                    }],
                )
                .expect("Failed to set node record");
            local_store
                .store(
                    RegistryVersion::from(4),
                    vec![KeyMutation {
                        key: make_subnet_record_key(SUBNET_1),
                        value: Some(
                            SubnetRecord {
                                membership: vec![NODE_1.get().to_vec()],
                                ..Default::default()
                            }
                            .encode_to_vec(),
                        ),
                    }],
                )
                .expect("Failed to set subnet record");
            registry_client.reload();

            let mut internal_state = InternalState::new(
                logger,
                None,
                Arc::clone(&registry_client) as Arc<dyn RegistryClient>,
                Arc::clone(&local_store) as Arc<dyn LocalStore>,
                config_nns_urls.clone(),
                Some(config_nns_pub_key),
                TEST_POLL_DELAY,
            );

            // Will first try to fetch from data found inside the registry
            let node_api_url = internal_state.http_endpoint_to_url(&http_endpoint).unwrap();
            let fallback_url = &config_nns_urls[0];
            for _ in 0..MAX_CONSECUTIVE_FAILURES {
                let result = internal_state.poll().await;
                assert!(result.is_err_and(|err| {
                    // Full error message looks like:
                    //
                    // "Error when trying to fetch updates from NNS: UnknownError(\"Failed to query
                    // get_certified_changes_since on canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Request
                    // failed for
                    // http://[2001:db8::1]:8080/api/v2/canister/rwlget-iiaaa-aaaaa-aaaaa-cai/query:
                    // hyper_util::client::legacy::Error(Connect, ConnectError(\\\"tcp connect
                    // error\\\", Os { code: 101, kind: NetworkUnreachable, message: \\\"Network is
                    // unreachable\\\" }))\")"
                    err.contains("Error when trying to fetch updates from NNS:")
                        && err.contains(node_api_url.as_str())
                        && !err.contains(fallback_url.as_str())
                }));
            }

            // Will then try to fetch from the fallback URLs
            let result = internal_state.poll().await;
            assert!(result.is_err_and(|err| {
                // Full error message looks like:
                //
                // "Error when trying to fetch updates from NNS: UnknownError(\"Failed to query
                // get_certified_changes_since on canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Request
                // failed for
                // http://fallback:1234/api/v2/canister/rwlget-iiaaa-aaaaa-aaaaa-cai/query:
                // hyper_util::client::legacy::Error(Connect, ConnectError(\\\"tcp connect
                // error\\\", Os { code: 101, kind: NetworkUnreachable, message: \\\"Network is
                // unreachable\\\" }))\")"
                err.contains("Error when trying to fetch updates from NNS:")
                    && err.contains(fallback_url.as_str())
                    && !err.contains(node_api_url.as_str())
            }));
        })
        .await
    }

    #[test]
    fn test_apply_switch_over_modifies_last_changelog_entry_and_updates_keys_as_expected() {
        let old_nns_subnet_id = SUBNET_1;
        let new_nns_subnet_id = SUBNET_2;
        let other_subnet_id = SUBNET_3;
        let new_nns_subnet_record = create_test_subnet_record(true, SubnetType::Application);

        // Create routing table with old NNS subnet and another subnet
        let mut shards = BTreeMap::new();
        let mut routing_table = BTreeMap::new();
        routing_table.insert(
            CanisterIdRange {
                start: CanisterId::from_u64(0),
                end: CanisterId::from_u64(50),
            },
            old_nns_subnet_id,
        );
        shards.insert(
            make_canister_ranges_key(CanisterId::from_u64(0)),
            routing_table,
        );
        let mut routing_table = BTreeMap::new();
        routing_table.insert(
            CanisterIdRange {
                start: CanisterId::from_u64(51),
                end: CanisterId::from_u64(100),
            },
            other_subnet_id,
        );
        shards.insert(
            make_canister_ranges_key(CanisterId::from_u64(51)),
            routing_table,
        );

        let fake_client = setup_fake_registry_client(old_nns_subnet_id, shards);

        // Create changelog with multiple entries
        let mut changelog = vec![
            vec![
                KeyMutation {
                    key: "some_key_1".to_string(),
                    value: Some(b"value1".to_vec()),
                },
                KeyMutation {
                    key: "some_key_2".to_string(),
                    value: Some(b"value2".to_vec()),
                },
            ],
            vec![KeyMutation {
                key: "some_key_3".to_string(),
                value: Some(b"value3".to_vec()),
            }],
            vec![
                KeyMutation {
                    key: "some_key_4".to_string(),
                    value: Some(b"value4".to_vec()),
                },
                KeyMutation {
                    key: ROOT_SUBNET_ID_KEY.to_string(),
                    value: Some(vec![1]),
                },
                KeyMutation {
                    key: make_subnet_list_record_key(),
                    value: Some(vec![2]),
                },
                KeyMutation {
                    key: make_subnet_record_key(new_nns_subnet_id),
                    value: Some(vec![4]),
                },
                KeyMutation {
                    key: make_canister_ranges_key(CanisterId::from_u64(0)),
                    value: Some(vec![5]),
                },
                KeyMutation {
                    key: make_canister_ranges_key(CanisterId::from_u64(51)),
                    value: Some(vec![6]),
                },
                KeyMutation {
                    key: make_canister_ranges_key(CanisterId::from_u64(10000)),
                    value: None,
                },
            ],
        ];

        let original_first_entry = changelog[0].clone();
        let original_second_entry = changelog[1].clone();

        // Verify start_as_nns is initially true
        assert!(new_nns_subnet_record.start_as_nns);

        apply_switch_over_to_last_changelog_entry_impl(
            &fake_client,
            &mut changelog,
            new_nns_subnet_id,
            new_nns_subnet_record,
        );

        // Verify first two entries are unchanged
        assert_eq!(changelog[0], original_first_entry);
        assert_eq!(changelog[1], original_second_entry);

        // Verify last entry has the expected structure
        let last_entry = &changelog[2];
        let keys: Vec<&String> = last_entry.iter().map(|km| &km.key).collect();

        // Verify all required keys are present
        assert!(keys.contains(&&ROOT_SUBNET_ID_KEY.to_string()));
        assert!(keys.contains(&&make_subnet_list_record_key()));
        assert!(keys.contains(&&make_subnet_record_key(new_nns_subnet_id)));
        assert!(keys.contains(&&make_canister_ranges_key(CanisterId::from_u64(0))));

        // Verify that old ROOT_SUBNET_ID_KEY entry was removed and new one added
        let root_subnet_mutations: Vec<_> = last_entry
            .iter()
            .filter(|km| km.key == ROOT_SUBNET_ID_KEY)
            .collect();
        assert_eq!(root_subnet_mutations.len(), 1);
        assert!(root_subnet_mutations[0].value.is_some());
        assert_eq!(
            root_subnet_mutations[0].value.as_ref().unwrap(),
            &SubnetIdProto {
                principal_id: Some(PrincipalIdProto {
                    raw: new_nns_subnet_id.get().into_vec()
                })
            }
            .encode_to_vec()
        );

        // Find the subnet record mutation and verify start_as_nns is false
        let subnet_record_key = make_subnet_record_key(new_nns_subnet_id);
        let subnet_record_mutation = last_entry
            .iter()
            .find(|km| km.key == subnet_record_key)
            .expect("Subnet record mutation should exist");

        let decoded_record =
            SubnetRecord::decode(subnet_record_mutation.value.as_ref().unwrap().as_slice())
                .expect("Should decode successfully");

        assert!(!decoded_record.start_as_nns);
        assert_eq!(decoded_record.subnet_type, SubnetType::System as i32);

        // Verify canister range key handling
        let canister_0_key = make_canister_ranges_key(CanisterId::from_u64(0));
        let canister_0_mutation = last_entry
            .iter()
            .find(|km| km.key == canister_0_key)
            .expect("Expected mutation for CanisterId = 0");
        assert!(canister_0_mutation.value.is_some());

        let canister_51_key = make_canister_ranges_key(CanisterId::from_u64(51));
        let canister_51_mutation = last_entry
            .iter()
            .find(|km| km.key == canister_51_key)
            .expect("Expected deletion mutation for CanisterId = 51");
        assert!(canister_51_mutation.value.is_none());
    }
}
