//! # NNS Registry Replicator
//!
//! (1) It polls one of the NNS Nodes for registry updates on a regular basis,
//! verifies the response using the public key configured in the registry and
//! applies the received changelog to the Registry Local Store.
//!
//! (2) In case of a "switch-over" or starting a new independent NNS subnet, the
//! NNS Registry Replicator modifies the Registry Local Store before rebooting:
//!
//! Consider the registry of the «parent» IC instance as the source registry.
//! Let subnet_record be a subnet record (in the source registry) with
//! subnet_record.start_as_nns set to true. Let v be the registry version at
//! which subnet_record was added to the registry (i.e. the smallest v for which
//! subnet_record exists). Create a fresh (target) registry state that contains
//! all versions up to and including v-1. Add version v, but with the following
//! changes:
//! * subnet_record.start_as_nns is unset on all subnet records
//! * nns_subnet_id set to the new nns subnet id
//! * subnet_list: contains only the nns_subnet_id
//! * routing table: consists of a single entry that maps the same range of
//!   canister ids that was mapped to the NNS in the source registry to the
//!   subnet id obtained from subnet record
//!
//! # Concurrency
//!
//! This is the only component that writes to the Registry Local Store. While
//! individual changelog entries are stored atomically when replicating the
//! registry, the switch-over is *not* atomic. This is the reason why the
//! switch-over is handled in this component.

use ic_base_thread::async_safe_block_on_await;
use ic_interfaces::registry::{RegistryClient, ZERO_REGISTRY_VERSION};
use ic_logger::{debug, warn, ReplicaLogger};
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_protobuf::{
    registry::{
        node::v1::ConnectionEndpoint,
        routing_table::v1::RoutingTable as PbRoutingTable,
        subnet::v1::{SubnetListRecord, SubnetRecord},
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
use std::fmt::Debug;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

pub(crate) struct NnsRegistryReplicator {
    log: ReplicaLogger,
    node_id: NodeId,
    registry: Arc<dyn RegistryClient>,
    local_store: Arc<dyn LocalStore>,
    started: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    poll_delay: Duration,
}

impl NnsRegistryReplicator {
    pub(crate) fn new(
        log: ReplicaLogger,
        node_id: NodeId,
        registry: Arc<dyn RegistryClient>,
        local_store: Arc<dyn LocalStore>,
        poll_delay: Duration,
    ) -> Self {
        Self {
            log,
            node_id,
            registry,
            local_store,
            started: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            poll_delay,
        }
    }

    /// Calls `poll()` synchronously and spawns a background task that
    /// continuously polls for updates. Returns the result of the first poll.
    /// The background task is stopped when the object is dropped.
    pub fn fetch_and_start_polling(&self) -> Result<(), Error> {
        if self.started.swap(true, Ordering::Relaxed) {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "'start_polling' was already called",
            ));
        }

        let mut internal_state = InternalState::new(
            self.log.clone(),
            self.node_id,
            self.registry.clone(),
            self.local_store.clone(),
            self.poll_delay,
        );
        let res = internal_state
            .poll()
            .map_err(|err| Error::new(ErrorKind::Other, err));

        let log = self.log.clone();
        let cancelled = Arc::clone(&self.cancelled);
        let poll_delay = self.poll_delay;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(poll_delay);
            while !cancelled.load(Ordering::Relaxed) {
                let tick_time = interval.tick().await;
                // The relevant I/O-operation of the poll() function is querying
                // a node on the NNS for updates. As we set the query timeout to
                // `poll_delay` when constructing the underlying
                // `RegistryCanister` abstraction, we are guaranteed that
                // `poll()` returns after a maximal duration of `poll_delay`.
                if let Err(msg) = internal_state.poll() {
                    warn!(log, "Polling the NNS registry failed: {}", msg);
                } else {
                    debug!(log, "Polling the NNS succeeded.");
                }

                // Ticks happen at _absolute_ points in time. Thus, if the
                // delay between ticks (because, for example, under load the
                // scheduler cannot schedule this thread) is _longer_ than the
                // interval length, the intervals "pile up" and tick() will
                // immediately return a number of times.
                //
                // To prevent a situation where nodes start flooding the NNS
                // with requests, we simply reset the interval if the "skew"
                // becomes larger than poll_delay (or 2*poll_delay, accounting
                // for the maximum delay of poll() after the tick_time).
                if tokio::time::Instant::now().duration_since(tick_time) > 2 * poll_delay {
                    interval = tokio::time::interval(poll_delay);
                }
            }
        });
        res
    }

    /// Set the local registry data to what is contained in the provided local
    /// store.
    fn set_local_registry_data(&self, source_registry: &dyn LocalStore) {
        // Read the registry data.
        let changelog = source_registry
            .get_changelog_since_version(RegistryVersion::from(0))
            .expect("Could not read changelog from source registry.");

        // Reset the local store and fill it with the read registry data.
        self.local_store
            .clear()
            .expect("Could not clear registry local store");
        for (v, cle) in changelog.into_iter().enumerate() {
            self.local_store
                .store(RegistryVersion::from((v + 1) as u64), cle)
                .expect("Could not store change log entry");
        }
    }

    pub(crate) fn stop_polling_and_set_local_registry_data(
        &self,
        source_registry: &dyn LocalStore,
    ) {
        self.stop_polling();
        self.set_local_registry_data(source_registry);
    }

    pub fn stop_polling(&self) {
        self.cancelled.fetch_or(true, Ordering::Relaxed);
    }
}

impl Drop for NnsRegistryReplicator {
    fn drop(&mut self) {
        self.stop_polling();
    }
}

struct InternalState {
    log: ReplicaLogger,
    node_id: NodeId,
    registry: Arc<dyn RegistryClient>,
    local_store: Arc<dyn LocalStore>,
    latest_version: RegistryVersion,
    nns_pub_key: Option<ThresholdSigPublicKey>,
    nns_urls: Vec<Url>,
    registry_canister: Option<Arc<RegistryCanister>>,
    poll_delay: Duration,
}

impl InternalState {
    fn new(
        log: ReplicaLogger,
        node_id: NodeId,
        registry: Arc<dyn RegistryClient>,
        local_store: Arc<dyn LocalStore>,
        poll_delay: Duration,
    ) -> Self {
        Self {
            log,
            node_id,
            registry,
            local_store,
            latest_version: ZERO_REGISTRY_VERSION,
            nns_pub_key: None,
            nns_urls: vec![],
            registry_canister: None,
            poll_delay,
        }
    }

    fn poll(&mut self) -> Result<(), String> {
        let latest_version = self.registry.get_latest_version();
        if latest_version != self.latest_version {
            // latest version has changed
            self.latest_version = latest_version;
            self.start_new_nns_subnet(latest_version)
                .expect("Start new NNS failed.");
            if let Err(e) = self.update_registry_canister(latest_version) {
                warn!(
                    self.log,
                    "Could not update registry canister with new topology data: {:?}", e
                );
            }
        }

        if let Some(registry_canister_ref) = self.registry_canister.as_ref() {
            let registry_canister = Arc::clone(registry_canister_ref);
            let nns_pub_key = self
                .nns_pub_key
                .expect("registry canister is set => pub key is set");
            let (mut resp, t) = match async_safe_block_on_await(async move {
                registry_canister
                    .get_certified_changes_since(latest_version.get(), &nns_pub_key)
                    .await
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
        fn map_to_str<E: Debug>(msg: &str, v: RegistryVersion, e: E) -> String {
            format!("{} at version {}: {:?}", msg, v, e)
        }

        let (subnet_id, subnet_record) = match self
            .registry
            .get_listed_subnet_for_node_id(self.node_id, latest_version)
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
                .registry
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
            self.log,
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
            .registry
            .get_routing_table(registry_version)
            .expect("Could not query registry for routing table.")
            .expect("No routing table configured in registry");

        let old_nns_subnet_id = self
            .registry
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
            .0
            .into_iter()
            .filter_map(|(r, s_id)| {
                if s_id == old_nns_subnet_id {
                    Some((r, new_nns_subnet_id))
                } else {
                    None
                }
            })
            .collect();
        let new_routing_table = RoutingTable::new(new_routing_table);
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
        match self.registry.get_root_subnet_id(version) {
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
            .registry
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
        let t_infos = match self.registry.get_subnet_transport_infos(subnet_id, version) {
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
                warn!(self.log, "Invalid url: {}: {:?}", url, e);
                None
            }
        }
    }
}
