//! Resolution of the SOCKS proxies that HTTPS outcalls may be routed through.
//!
//! An outcall that cannot reach its target directly is retried through a SOCKS5
//! proxy on an API boundary node. Which nodes are eligible is registry policy
//! shared by every outcall path, so it lives here rather than in one of them.

use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, warn};
use ic_registry_client_helpers::{api_boundary_node::ApiBoundaryNodeRegistry, node::NodeRegistry};
use ic_registry_subnet_type::SubnetType;
use ic_types::{NodeId, RegistryVersion};
use std::sync::{Arc, RwLock};

/// The port on which every API boundary node exposes its SOCKS5 proxy.
const SOCKS_PROXY_PORT: u16 = 1080;

/// Labels for resolution failures, reported by the caller under its own metric.
pub mod errors {
    pub const BOUNDARY_NODE_IDS_LOOKUP_FAILED: &str = "boundary_node_ids_lookup_failed";
    pub const SOCKS_PROXY_ADDRS_UNRESOLVED: &str = "socks_proxy_addrs_unresolved";
}

/// Records a resolution failure, by the label the caller reports it under.
pub type ErrorObserver = Arc<dyn Fn(&str) + Send + Sync>;

pub struct ResolvedSocksProxies {
    pub addrs: Vec<String>,
    pub errors: Vec<&'static str>,
}

/// `System` subnets are proxied through the *system* API boundary nodes, every
/// other subnet type through the *app* ones. Nodes that do not resolve are
/// skipped rather than failing the lot.
pub fn socks_proxy_addrs_at(
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
    subnet_type: SubnetType,
    log: &ReplicaLogger,
) -> ResolvedSocksProxies {
    let allowed_boundary_nodes = match subnet_type {
        SubnetType::System => registry_client.get_system_api_boundary_node_ids(registry_version),
        SubnetType::Application | SubnetType::VerifiedApplication | SubnetType::CloudEngine => {
            registry_client.get_app_api_boundary_node_ids(registry_version)
        }
    };

    let mut errors = Vec::new();
    let allowed_boundary_nodes = allowed_boundary_nodes.unwrap_or_else(|e| {
        warn!(log, "Failed to get API boundary node IDs: {:?}", e);
        errors.push(errors::BOUNDARY_NODE_IDS_LOOKUP_FAILED);
        Vec::new()
    });
    let eligible = allowed_boundary_nodes.len();

    let addrs: Vec<String> = allowed_boundary_nodes
        .into_iter()
        .filter_map(|node_id| socks_proxy_addr_of(registry_client, registry_version, node_id, log))
        .collect();
    if addrs.len() != eligible {
        errors.push(errors::SOCKS_PROXY_ADDRS_UNRESOLVED);
    }

    ResolvedSocksProxies { addrs, errors }
}

fn socks_proxy_addr_of(
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
    node_id: NodeId,
    log: &ReplicaLogger,
) -> Option<String> {
    registry_client
        .get_node_record(node_id, registry_version)
        .map_err(|e| {
            warn!(
                log,
                "Failed to get node record for node ID {:?}: {:?}", node_id, e
            );
        })
        .ok()
        .and_then(|opt_record| {
            opt_record.or_else(|| {
                warn!(log, "No node record found for node ID {:?}", node_id);
                None
            })
        })
        .and_then(|record| {
            record.http.or_else(|| {
                warn!(log, "HTTP information missing for node ID {:?}", node_id);
                None
            })
        })
        .map(|http_info| format!("socks5h://[{0}]:{SOCKS_PROXY_PORT}", http_info.ip_addr))
}

/// The resolved addresses, memoized per registry version: they are a pure
/// function of it, so there is no staleness to invalidate, and resolving costs
/// a lookup per boundary node. Failures are reported on every call, memoized or
/// not, so a persistent one keeps being visible.
pub struct SocksProxyCache {
    registry_client: Arc<dyn RegistryClient>,
    subnet_type: SubnetType,
    log: ReplicaLogger,
    memo: RwLock<Option<(RegistryVersion, Arc<ResolvedSocksProxies>)>>,
    observe_error: Option<ErrorObserver>,
}

impl SocksProxyCache {
    pub fn new(
        registry_client: Arc<dyn RegistryClient>,
        subnet_type: SubnetType,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            registry_client,
            subnet_type,
            log,
            memo: RwLock::new(None),
            observe_error: None,
        }
    }

    pub fn with_error_observer(mut self, observe_error: ErrorObserver) -> Self {
        self.observe_error = Some(observe_error);
        self
    }

    /// Never fails: an unreadable registry yields no proxies, degrading an
    /// outcall to a direct attempt rather than failing it.
    pub fn addrs(&self) -> Vec<String> {
        let registry_version = self.registry_client.get_latest_version();

        let resolved = {
            let memo = self.memo.read().unwrap();
            match memo.as_ref() {
                Some((memoized_version, resolved)) if *memoized_version == registry_version => {
                    Arc::clone(resolved)
                }
                _ => {
                    drop(memo);
                    let resolved = Arc::new(socks_proxy_addrs_at(
                        &*self.registry_client,
                        registry_version,
                        self.subnet_type,
                        &self.log,
                    ));
                    // Losing a race only costs a recomputation: an entry is
                    // served only while its version is still the latest.
                    *self.memo.write().unwrap() = Some((registry_version, Arc::clone(&resolved)));
                    resolved
                }
            }
        };

        if let Some(observe_error) = &self.observe_error {
            for error in &resolved.errors {
                observe_error(error);
            }
        }
        resolved.addrs.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::replica_logger::no_op_logger;
    use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
    use ic_protobuf::registry::node::v1::{ConnectionEndpoint, NodeRecord};
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::{make_api_boundary_node_record_key, make_node_record_key};
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::Time;
    use ic_types::registry::RegistryClientError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use strum::IntoEnumIterator;

    const VERSION: RegistryVersion = RegistryVersion::new(2);

    /// Registers `count` API boundary nodes, each with a distinct IPv6 endpoint,
    /// and returns their ids paired with the address they should resolve to.
    fn registry_with_boundary_nodes(
        count: u64,
        with_http: impl Fn(u64) -> bool,
    ) -> (Arc<FakeRegistryClient>, Vec<(NodeId, String)>) {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let nodes: Vec<(NodeId, String)> = (1..=count)
            .map(|i| (node_test_id(i), format!("2001:db8::{i}")))
            .collect();

        for (i, (node_id, ip_addr)) in (1..=count).zip(&nodes) {
            data_provider
                .add(
                    &make_api_boundary_node_record_key(*node_id),
                    VERSION,
                    Some(ApiBoundaryNodeRecord::default()),
                )
                .unwrap();
            data_provider
                .add(
                    &make_node_record_key(*node_id),
                    VERSION,
                    Some(NodeRecord {
                        http: with_http(i).then(|| ConnectionEndpoint {
                            ip_addr: ip_addr.clone(),
                            port: 8080,
                        }),
                        ..Default::default()
                    }),
                )
                .unwrap();
        }

        let registry = Arc::new(FakeRegistryClient::new(data_provider));
        registry.update_to_latest_version();
        (registry, nodes)
    }

    fn expected_addr(ip_addr: &str) -> String {
        format!("socks5h://[{ip_addr}]:1080")
    }

    #[test]
    fn resolves_to_socks5h_address_on_port_1080() {
        let (registry, nodes) = registry_with_boundary_nodes(4, |_| true);
        let all_addrs: Vec<String> = nodes
            .iter()
            .map(|(_, ip_addr)| expected_addr(ip_addr))
            .collect();

        let addrs = socks_proxy_addrs_at(
            &*registry,
            VERSION,
            SubnetType::Application,
            &no_op_logger(),
        )
        .addrs;

        let expected_len = registry
            .get_app_api_boundary_node_ids(VERSION)
            .unwrap()
            .len();
        assert_eq!(addrs.len(), expected_len);
        for addr in &addrs {
            assert!(
                all_addrs.contains(addr),
                "unexpected address {addr}, expected one of {all_addrs:?}"
            );
        }
    }

    /// System subnets are proxied through the system API boundary nodes, every
    /// other subnet type through the app ones. The two sets are disjoint, which
    /// is what makes this test able to tell them apart.
    #[test]
    fn selects_boundary_nodes_by_subnet_type() {
        let (registry, nodes) = registry_with_boundary_nodes(4, |_| true);
        let addr_of = |node_id: &NodeId| {
            let ip_addr = &nodes
                .iter()
                .find(|(id, _)| id == node_id)
                .expect("unknown boundary node id")
                .1;
            expected_addr(ip_addr)
        };

        let mut expected_system: Vec<String> = registry
            .get_system_api_boundary_node_ids(VERSION)
            .unwrap()
            .iter()
            .map(addr_of)
            .collect();
        let mut expected_app: Vec<String> = registry
            .get_app_api_boundary_node_ids(VERSION)
            .unwrap()
            .iter()
            .map(addr_of)
            .collect();
        expected_system.sort();
        expected_app.sort();

        assert!(!expected_system.is_empty());
        assert!(!expected_app.is_empty());
        assert!(expected_system.iter().all(|a| !expected_app.contains(a)));

        for subnet_type in SubnetType::iter() {
            let expected = match subnet_type {
                SubnetType::System => &expected_system,
                SubnetType::Application
                | SubnetType::VerifiedApplication
                | SubnetType::CloudEngine => &expected_app,
            };

            let mut actual =
                socks_proxy_addrs_at(&*registry, VERSION, subnet_type, &no_op_logger()).addrs;
            actual.sort();

            assert_eq!(
                &actual, expected,
                "subnet type {subnet_type:?} selected the wrong API boundary nodes"
            );
        }
    }

    /// A boundary node without an HTTP endpoint is skipped rather than
    /// poisoning the whole list.
    #[test]
    fn skips_boundary_nodes_without_http_endpoint() {
        let (probe, nodes) = registry_with_boundary_nodes(4, |_| true);
        let app_ids = probe.get_app_api_boundary_node_ids(VERSION).unwrap();
        assert!(
            app_ids.len() > 1,
            "the fixture must leave a node to be returned"
        );
        let skipped = app_ids[0];

        let (registry, _) = registry_with_boundary_nodes(4, |i| node_test_id(i) != skipped);
        let mut expected: Vec<String> = app_ids
            .iter()
            .filter(|node_id| **node_id != skipped)
            .map(|node_id| {
                let (_, ip_addr) = nodes
                    .iter()
                    .find(|(id, _)| id == node_id)
                    .expect("unknown boundary node id");
                expected_addr(ip_addr)
            })
            .collect();
        expected.sort();

        let mut addrs = socks_proxy_addrs_at(
            &*registry,
            VERSION,
            SubnetType::Application,
            &no_op_logger(),
        )
        .addrs;
        addrs.sort();

        assert_eq!(addrs, expected);
    }

    #[test]
    fn returns_no_proxies_when_the_registry_is_unreadable() {
        let registry = FailingRegistryClient::new(VERSION);

        let addrs =
            socks_proxy_addrs_at(&registry, VERSION, SubnetType::Application, &no_op_logger())
                .addrs;

        assert_eq!(addrs, Vec::<String>::new());
    }

    /// The memo must serve repeated calls at the same registry version without
    /// touching the registry again.
    #[test]
    fn memoizes_within_a_registry_version() {
        let (registry, _) = registry_with_boundary_nodes(4, |_| true);
        let counting = Arc::new(CountingRegistryClient::new(registry));
        let cache = SocksProxyCache::new(
            Arc::clone(&counting) as Arc<_>,
            SubnetType::Application,
            no_op_logger(),
        );

        let first = cache.addrs();
        let lookups_after_first = counting.lookups();
        assert!(
            lookups_after_first > 0,
            "the first resolution must read the registry"
        );

        let second = cache.addrs();

        assert_eq!(first, second);
        assert_eq!(
            counting.lookups(),
            lookups_after_first,
            "a repeated resolution at the same version must not read the registry"
        );
    }

    /// A failure that persists has to keep being reported, or a metric built on
    /// it would show one failure and then silence.
    #[test]
    fn reports_failures_on_every_call_even_when_memoized() {
        let (registry, _) = registry_with_boundary_nodes(4, |_| false);
        let counting = Arc::new(CountingRegistryClient::new(registry));
        let observed = Arc::new(AtomicUsize::new(0));
        let cache = SocksProxyCache::new(
            Arc::clone(&counting) as Arc<_>,
            SubnetType::Application,
            no_op_logger(),
        )
        .with_error_observer({
            let observed = Arc::clone(&observed);
            Arc::new(move |label: &str| {
                assert_eq!(label, errors::SOCKS_PROXY_ADDRS_UNRESOLVED);
                observed.fetch_add(1, Ordering::Relaxed);
            })
        });

        assert!(cache.addrs().is_empty());
        let lookups_after_first = counting.lookups();
        assert!(cache.addrs().is_empty());

        assert_eq!(
            counting.lookups(),
            lookups_after_first,
            "the resolution must be memoized"
        );
        assert_eq!(
            observed.load(Ordering::Relaxed),
            2,
            "the reporting must not be"
        );
    }

    /// The memo is keyed on the registry version, so a new version is picked up
    /// rather than served stale.
    #[test]
    fn recomputes_when_the_registry_version_advances() {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let add_boundary_node = |i: u64, version: RegistryVersion| {
            let node_id = node_test_id(i);
            data_provider
                .add(
                    &make_api_boundary_node_record_key(node_id),
                    version,
                    Some(ApiBoundaryNodeRecord::default()),
                )
                .unwrap();
            data_provider
                .add(
                    &make_node_record_key(node_id),
                    version,
                    Some(NodeRecord {
                        http: Some(ConnectionEndpoint {
                            ip_addr: format!("2001:db8::{i}"),
                            port: 8080,
                        }),
                        ..Default::default()
                    }),
                )
                .unwrap();
        };

        for i in 1..=4 {
            add_boundary_node(i, RegistryVersion::from(2));
        }
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));
        registry.update_to_latest_version();

        let cache = SocksProxyCache::new(
            Arc::clone(&registry) as Arc<_>,
            SubnetType::Application,
            no_op_logger(),
        );
        let before = cache.addrs();

        // Add more boundary nodes at a later version. `get_app_api_boundary_node_ids`
        // splits the sorted ids in half, so a larger set yields a different app half.
        for i in 5..=8 {
            add_boundary_node(i, RegistryVersion::from(3));
        }
        registry.update_to_latest_version();
        let after = cache.addrs();

        assert_ne!(
            before, after,
            "the memo must not serve addresses from a superseded registry version"
        );
    }

    /// Counts how many registry reads the cache performs, so that the memo
    /// can be observed rather than inferred.
    struct CountingRegistryClient {
        inner: Arc<FakeRegistryClient>,
        lookups: AtomicUsize,
    }

    impl CountingRegistryClient {
        fn new(inner: Arc<FakeRegistryClient>) -> Self {
            Self {
                inner,
                lookups: AtomicUsize::new(0),
            }
        }

        fn lookups(&self) -> usize {
            self.lookups.load(Ordering::Relaxed)
        }
    }

    impl RegistryClient for CountingRegistryClient {
        fn get_versioned_value(
            &self,
            key: &str,
            version: RegistryVersion,
        ) -> ic_interfaces_registry::RegistryClientVersionedResult<Vec<u8>> {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            self.inner.get_versioned_value(key, version)
        }

        fn get_key_family(
            &self,
            key_prefix: &str,
            version: RegistryVersion,
        ) -> Result<Vec<String>, RegistryClientError> {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            self.inner.get_key_family(key_prefix, version)
        }

        fn get_latest_version(&self) -> RegistryVersion {
            self.inner.get_latest_version()
        }

        fn get_version_timestamp(&self, registry_version: RegistryVersion) -> Option<Time> {
            self.inner.get_version_timestamp(registry_version)
        }
    }

    /// A registry client whose every read fails.
    struct FailingRegistryClient {
        version: RegistryVersion,
    }

    impl FailingRegistryClient {
        fn new(version: RegistryVersion) -> Self {
            Self { version }
        }
    }

    impl RegistryClient for FailingRegistryClient {
        fn get_versioned_value(
            &self,
            _key: &str,
            version: RegistryVersion,
        ) -> ic_interfaces_registry::RegistryClientVersionedResult<Vec<u8>> {
            Err(RegistryClientError::VersionNotAvailable { version })
        }

        fn get_key_family(
            &self,
            _key_prefix: &str,
            version: RegistryVersion,
        ) -> Result<Vec<String>, RegistryClientError> {
            Err(RegistryClientError::VersionNotAvailable { version })
        }

        fn get_latest_version(&self) -> RegistryVersion {
            self.version
        }

        fn get_version_timestamp(&self, _registry_version: RegistryVersion) -> Option<Time> {
            None
        }
    }
}
