use ic_interfaces::registry::{RegistryClient, ZERO_REGISTRY_VERSION};
use ic_logger::{warn, ReplicaLogger};
use ic_protobuf::{
    registry::{
        node::v1::ConnectionEndpoint,
        routing_table::v1::RoutingTable as PbRoutingTable,
        subnet::v1::{SubnetListRecord, SubnetRecord, SubnetType},
    },
    types::v1::{PrincipalId as PrincipalIdProto, SubnetId as SubnetIdProto},
};
use ic_registry_client::helper::{
    crypto::CryptoRegistry,
    routing_table::RoutingTableRegistry,
    subnet::{SubnetRegistry, SubnetTransportRegistry},
};
use ic_registry_common::local_store::{Changelog, ChangelogEntry, KeyMutation, LocalStore};
use ic_registry_common::registry::RegistryCanister;
use ic_registry_keys::{
    make_routing_table_record_key, make_subnet_list_record_key, make_subnet_record_key,
    ROOT_SUBNET_ID_KEY,
};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::{NodeId, RegistryVersion, SubnetId};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

pub(crate) struct InternalState {
    logger: ReplicaLogger,
    node_id: Option<NodeId>,
    registry_client: Arc<dyn RegistryClient>,
    local_store: Arc<dyn LocalStore>,
    latest_version: RegistryVersion,
    nns_pub_key: Option<ThresholdSigPublicKey>,
    nns_urls: Vec<Url>,
    registry_canister: Option<Arc<RegistryCanister>>,
    poll_delay: Duration,
}

impl InternalState {
    pub(crate) fn new(
        logger: ReplicaLogger,
        node_id: Option<NodeId>,
        registry_client: Arc<dyn RegistryClient>,
        local_store: Arc<dyn LocalStore>,
        poll_delay: Duration,
    ) -> Self {
        Self {
            logger,
            node_id,
            registry_client,
            local_store,
            latest_version: ZERO_REGISTRY_VERSION,
            nns_pub_key: None,
            nns_urls: vec![],
            registry_canister: None,
            poll_delay,
        }
    }

    pub(crate) fn poll(&mut self) -> Result<(), String> {
        let latest_version = self.registry_client.get_latest_version();
        if latest_version != self.latest_version {
            // latest version has changed
            self.latest_version = latest_version;
            self.start_new_nns_subnet(latest_version)
                .expect("Start new NNS failed.");
            if let Err(e) = self.update_registry_canister(latest_version) {
                warn!(
                    self.logger,
                    "Could not update registry canister with new topology data: {:?}", e
                );
            }
        }

        if let Some(registry_canister_ref) = self.registry_canister.as_ref() {
            let registry_canister = Arc::clone(registry_canister_ref);
            let nns_pub_key = self
                .nns_pub_key
                .expect("registry canister is set => pub key is set");
            let (mut resp, t) = match tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    registry_canister
                        .get_certified_changes_since(latest_version.get(), &nns_pub_key),
                )
            }) {
                Ok((records, _, t)) => (records, t),
                Err(e) => {
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

            changelog
                .into_iter()
                .enumerate()
                .try_for_each(|(i, cle)| {
                    let v = latest_version + RegistryVersion::from(i as u64 + 1);
                    self.local_store.store(v, cle)
                })
                .expect("Writing to the FS failed: Stop.");

            self.local_store
                .update_certified_time(t.as_nanos_since_unix_epoch())
                .expect("Could not store certified time");
        }

        Ok(())
    }

    /// Iff at version `latest_version` the node id of this node appears on a
    /// subnet record that has the `start_as_nns`-flag set, this function will
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

        self.apply_switch_over_to_last_changelog_entry(
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

    /// Given a `changelog`, this function applies the changes (as described
    /// above) to the last changelog entry.
    fn apply_switch_over_to_last_changelog_entry(
        &self,
        changelog: &mut [ChangelogEntry],
        new_nns_subnet_id: SubnetId,
        mut new_nns_subnet_record: SubnetRecord,
    ) {
        use prost::Message;
        let registry_version = RegistryVersion::from(changelog.len() as u64);

        let routing_table = self
            .registry_client
            .get_routing_table(registry_version)
            .expect("Could not query registry for routing table.")
            .expect("No routing table configured in registry");

        let old_nns_subnet_id = self
            .registry_client
            .get_root_subnet_id(registry_version)
            .expect("Could not query registry for nns subnet id")
            .expect("No NNS subnet id configured in the registry");

        assert!(!changelog.is_empty());

        let last = changelog.last_mut().expect("can't fail");
        // remove all entries that will be adjusted
        let subnet_record_key = make_subnet_record_key(new_nns_subnet_id);
        last.retain(|k| {
            k.key != ROOT_SUBNET_ID_KEY
                && k.key != make_subnet_list_record_key()
                && k.key != make_routing_table_record_key()
                && k.key != subnet_record_key
        });

        // remove the start_nns flag on the subnet record
        new_nns_subnet_record.start_as_nns = false;
        // force subnet type to be a system subnet
        new_nns_subnet_record.subnet_type = SubnetType::System as i32;
        // adjust subnet record
        let mut subnet_record_bytes = vec![];
        new_nns_subnet_record
            .encode(&mut subnet_record_bytes)
            .expect("encode can't fail");
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
        let mut new_nns_subnet_id_bytes = vec![];
        new_nns_subnet_id_proto
            .encode(&mut new_nns_subnet_id_bytes)
            .expect("encoding can't fail");
        last.push(KeyMutation {
            key: ROOT_SUBNET_ID_KEY.to_string(),
            value: Some(new_nns_subnet_id_bytes),
        });

        // adjust subnet list
        let subnet_list_record = SubnetListRecord {
            subnets: vec![new_nns_subnet_id.get().into_vec()],
        };
        let mut subnet_list_record_bytes = vec![];
        subnet_list_record
            .encode(&mut subnet_list_record_bytes)
            .expect("encoding can't fail");
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

        // It's safe to unwrap here because we started from a valid table and
        // removed entries from it.  Removing entries cannot invalidate the
        // table.
        let new_routing_table =
            RoutingTable::try_from(new_routing_table).expect("bug: invalid routing table");
        let pb_routing_table = PbRoutingTable::from(new_routing_table);
        let mut pb_routing_table_bytes = vec![];
        pb_routing_table
            .encode(&mut pb_routing_table_bytes)
            .expect("encode can't fail");
        last.push(KeyMutation {
            key: make_routing_table_record_key(),
            value: Some(pb_routing_table_bytes),
        });
    }

    /// Update the RegistryCanister with the newest API Urls of the NNS nodes
    /// found in the registry.
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
            self.nns_urls = urls.clone();

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
            .get_subnet_transport_infos(subnet_id, version)
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
