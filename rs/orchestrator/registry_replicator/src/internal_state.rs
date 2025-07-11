use ic_interfaces_registry::{RegistryClient, ZERO_REGISTRY_VERSION};
use ic_logger::{info, warn, ReplicaLogger};
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
    make_canister_ranges_key, make_routing_table_record_key, make_subnet_list_record_key,
    make_subnet_record_key, CANISTER_RANGES_PREFIX, ROOT_SUBNET_ID_KEY,
};
use ic_registry_local_store::{Changelog, ChangelogEntry, KeyMutation, LocalStore};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_types::{
    crypto::threshold_sig::ThresholdSigPublicKey, CanisterId, NodeId, RegistryVersion, SubnetId,
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
    nns_pub_key: Option<ThresholdSigPublicKey>,
    nns_urls: Vec<Url>,
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
        config_urls: Vec<Url>,
        poll_delay: Duration,
    ) -> Self {
        let registry_canister_fallback = if !config_urls.is_empty() {
            Some(Arc::new(RegistryCanister::new_with_query_timeout(
                config_urls,
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
            nns_pub_key: None,
            nns_urls: vec![],
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

        let registry_canister = if self.failed_poll_count >= MAX_CONSECUTIVE_FAILURES
            && self.registry_canister_fallback.is_some()
        {
            info!(
                self.logger,
                "Polling NNS failed {} times consecutively, trying config urls once...",
                self.failed_poll_count
            );
            self.failed_poll_count = -1;
            self.registry_canister_fallback.as_ref()
        } else {
            self.registry_canister.as_ref()
        };

        // Poll registry canister and apply changes to local changelog
        if let Some(registry_canister_ref) = registry_canister {
            let registry_canister = Arc::clone(registry_canister_ref);
            let nns_pub_key = self
                .nns_pub_key
                .expect("registry canister is set => pub key is set");
            // Note, code duplicate in registry_replicator.rs initialize_local_store()
            let mut resp = match registry_canister
                .get_certified_changes_since(latest_version.get(), &nns_pub_key)
                .await
            {
                Ok((records, _, _)) => {
                    self.failed_poll_count = 0;
                    records
                }
                Err(e) => {
                    self.failed_poll_count += 1;
                    return Err(format!(
                        "Error when trying to fetch updates from NNS: {:?}",
                        e
                    ));
                }
            };

            resp.sort_by_key(|tr| tr.version);
            let changelog = resp.iter().fold(Changelog::default(), |mut cl, r| {
                let rel_version = (r.version - latest_version).get();
                if cl.len() < rel_version as usize {
                    cl.push(ChangelogEntry::default());
                }
                cl.last_mut().unwrap().push(KeyMutation {
                    key: r.key.clone(),
                    value: r.value.clone(),
                });
                cl
            });

            let entries = changelog.len();

            changelog
                .into_iter()
                .enumerate()
                .try_for_each(|(i, cle)| {
                    let v = latest_version + RegistryVersion::from(i as u64 + 1);
                    self.local_store.store(v, cle)
                })
                .expect("Writing to the FS failed: Stop.");

            if entries > 0 {
                info!(
                    self.logger,
                    "Stored registry versions up to: {}",
                    latest_version + RegistryVersion::from(entries as u64)
                );
            }
        }

        Ok(())
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
            format!("{} at version {}: {:?}", msg, v, e)
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
                ))
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
            Ok(_) => Err(format!(
                "No NNS subnet id configured at version {}",
                version
            )),
            Err(e) => Err(format!(
                "Could not fetch nns subnet id at version {}: {:?}",
                version, e
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
                "Public key for subnet {} not set at version {}",
                subnet_id, version
            )),
            Err(e) => Err(format!(
                "Error when retrieving public key for subnet {} at version {}: {:?}",
                subnet_id, version, e
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
                    "Missing or incomplete transport infos for subnet {} at version {}.",
                    subnet_id, version
                ))
            }
            Err(e) => {
                return Err(format!(
                    "Error retrieving transport infos for subnet {} at version {}: {:?}.",
                    subnet_id, version, e
                ))
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
                    format!("[{}]", v)
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

    assert!(!changelog.is_empty());

    let last = changelog.last_mut().expect("can't fail");

    // remove all entries that will be adjusted
    let subnet_record_key = make_subnet_record_key(new_nns_subnet_id);
    last.retain(|k| {
        k.key != ROOT_SUBNET_ID_KEY
            && k.key != make_subnet_list_record_key()
            && k.key != make_routing_table_record_key()
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

    last.push(KeyMutation {
        key: make_routing_table_record_key(),
        value: Some(new_routing_table.encode_to_vec()),
    });

    last.append(&mut routing_table_updates);
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_protobuf::registry::routing_table;
    use ic_protobuf::registry::routing_table::v1::routing_table::Entry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::{
        make_canister_ranges_key, make_routing_table_record_key, make_subnet_list_record_key,
        make_subnet_record_key, ROOT_SUBNET_ID_KEY,
    };
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_types::{CanisterId, PrincipalId, SubnetId};
    use std::collections::BTreeMap;
    use std::convert::TryFrom;
    use std::sync::Arc;

    fn create_test_subnet_id(id: u64) -> SubnetId {
        SubnetId::from(PrincipalId::new_subnet_test_id(id))
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

        // Set routing table
        let pb_routing_table = PbRoutingTable::from(
            RoutingTable::try_from(
                shards
                    .values()
                    .map(|map| {
                        PbRoutingTable::from(
                            RoutingTable::try_from(map.clone())
                                .expect("Invalid routing table shard"),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("Invalid routing table"),
        );
        data_provider
            .add(
                &make_routing_table_record_key(),
                RegistryVersion::from(2),
                Some(pb_routing_table.clone()),
            )
            .expect("Failed to set routing table");

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

    #[test]
    fn test_apply_switch_over_modifies_last_changelog_entry_and_updates_keys_as_expected() {
        let old_nns_subnet_id = create_test_subnet_id(1);
        let new_nns_subnet_id = create_test_subnet_id(2);
        let other_subnet_id = create_test_subnet_id(3);
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
                    key: make_routing_table_record_key(),
                    value: Some(vec![3]),
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
        assert!(keys.contains(&&make_routing_table_record_key()));
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

        // Verify routing table was updated correctly
        let routing_table_mutation = last_entry
            .iter()
            .find(|km| km.key == make_routing_table_record_key())
            .expect("Routing table mutation should exist");

        assert!(routing_table_mutation.value.is_some());

        let decoded_routing_table =
            PbRoutingTable::decode(routing_table_mutation.value.as_ref().unwrap().as_slice())
                .expect("Should decode successfully");

        // The routing table should only contain ranges that were previously assigned to old NNS
        assert!(!decoded_routing_table.entries.is_empty());
        let expected_routing_table = PbRoutingTable {
            entries: vec![Entry {
                range: Some(routing_table::v1::CanisterIdRange {
                    start_canister_id: Some(CanisterId::from_u64(0).into()),
                    end_canister_id: Some(CanisterId::from_u64(50).into()),
                }),
                subnet_id: Some(ic_types::subnet_id_into_protobuf(new_nns_subnet_id)),
            }],
        };
        assert_eq!(decoded_routing_table, expected_routing_table);

        // Verify canister range key handling
        let canister_0_key = make_canister_ranges_key(CanisterId::from_u64(0));
        let canister_0_mutation = last_entry
            .iter()
            .find(|km| km.key == canister_0_key)
            .expect("Expected mutation for CanisterId = 0");
        assert!(canister_0_mutation.value.is_some());
        assert_eq!(canister_0_mutation.value, routing_table_mutation.value);

        let canister_51_key = make_canister_ranges_key(CanisterId::from_u64(51));
        let canister_51_mutation = last_entry
            .iter()
            .find(|km| km.key == canister_51_key)
            .expect("Expected deletion mutation for CanisterId = 51");
        assert!(canister_51_mutation.value.is_none());
    }
}
