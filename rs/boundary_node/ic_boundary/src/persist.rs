use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use ethnum::u256;
use rand::seq::SliceRandom;
use tracing::{debug, error};

use crate::{
    errors::ErrorCause,
    metrics::{MetricParamsPersist, WithMetricsPersist},
    snapshot::{Node, Subnet},
};

#[derive(Copy, Clone)]
pub struct PersistResults {
    pub ranges_old: u32,
    pub ranges_new: u32,
    pub nodes_old: u32,
    pub nodes_new: u32,
}

#[derive(Copy, Clone)]
pub enum PersistStatus {
    Completed(PersistResults),
    SkippedEmpty,
}

// Converts byte slice principal to a u256
fn principal_bytes_to_u256(p: &[u8]) -> u256 {
    if p.len() > 29 {
        panic!("Principal length should be <30 bytes");
    }

    // Since Principal length can be anything in 0..29 range - prepend it with zeros to 32
    let pad = 32 - p.len();
    let mut padded: [u8; 32] = [0; 32];
    padded[pad..32].copy_from_slice(p);

    u256::from_be_bytes(padded)
}

// Principals are 2^232 max so we can use the u256 type to efficiently store them
// Under the hood u256 is using two u128
// This is more efficient than lexographically sorted hexadecimal strings as done in JS router
// Currently the largest canister_id range is somewhere around 2^40 - so probably using one u128 would work for a long time
// But going u256 makes it future proof and according to spec
#[derive(Eq, PartialEq, Debug)]
pub struct RouteSubnet {
    pub id: Principal,
    pub range_start: u256,
    pub range_end: u256,
    pub nodes: Vec<Arc<Node>>,
}

impl RouteSubnet {
    pub fn pick_random_nodes(&self, n: usize) -> Result<Vec<Arc<Node>>, ErrorCause> {
        let nodes = self
            .nodes
            .choose_multiple(&mut rand::thread_rng(), n)
            .cloned()
            .collect::<Vec<_>>();

        if nodes.is_empty() {
            return Err(ErrorCause::NoHealthyNodes);
        }

        Ok(nodes)
    }

    // max acceptable number of malicious nodes in a subnet
    pub fn fault_tolerance_factor(&self) -> usize {
        (self.nodes.len() - 1) / 3
    }

    pub fn pick_n_out_of_m_closest(
        &self,
        n: usize,
        m: usize,
    ) -> Result<Vec<Arc<Node>>, ErrorCause> {
        // nodes should already be sorted by latency after persist() invocation
        let m = std::cmp::min(m, self.nodes.len());
        let nodes = &self.nodes[0..m];

        let picked_nodes = nodes
            .choose_multiple(&mut rand::thread_rng(), n)
            .map(Arc::clone)
            .collect::<Vec<_>>();

        if picked_nodes.is_empty() {
            return Err(ErrorCause::NoHealthyNodes);
        }

        Ok(picked_nodes)
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct Routes {
    pub node_count: u32,
    // subnets should be sorted by `range_start` field for the binary search to work
    pub subnets: Vec<Arc<RouteSubnet>>,
    pub subnet_map: HashMap<Principal, Arc<RouteSubnet>>,
}

impl Routes {
    // Look up the subnet by canister_id
    pub fn lookup_by_canister_id(&self, canister_id: Principal) -> Option<Arc<RouteSubnet>> {
        let canister_id_u256 = principal_bytes_to_u256(canister_id.as_slice());

        let idx = match self
            .subnets
            .binary_search_by_key(&canister_id_u256, |x| x.range_start)
        {
            // Ok should happen rarely when canister_id equals lower bound of some subnet
            Ok(i) => i,

            // In the Err case the returned value might be:
            // - index of next subnet to the one we look for (can be equal to vec len)
            // - 0 in case if canister_id is < than first subnet's range_start
            //
            // For case 1 we subtract the index to get subnet to check
            // Case 2 always leads to a lookup error, but this is handled in the next step
            Err(i) => {
                if i > 0 {
                    i - 1
                } else {
                    i
                }
            }
        };

        let subnet = self.subnets[idx].clone();
        if canister_id_u256 < subnet.range_start || canister_id_u256 > subnet.range_end {
            return None;
        }

        Some(subnet)
    }

    // Look up the subnet by subnet_id
    pub fn lookup_by_id(&self, subnet_id: Principal) -> Option<Arc<RouteSubnet>> {
        self.subnet_map.get(&subnet_id).cloned()
    }
}

pub trait Persist: Send + Sync {
    fn persist(&self, subnets: Vec<Subnet>) -> PersistStatus;
}

pub struct Persister {
    published_routes: Arc<ArcSwapOption<Routes>>,
}

impl Persister {
    pub fn new(published_routes: Arc<ArcSwapOption<Routes>>) -> Self {
        Self { published_routes }
    }
}

#[async_trait]
impl Persist for Persister {
    // Construct a lookup table based on the provided subnet list
    fn persist(&self, subnets: Vec<Subnet>) -> PersistStatus {
        if subnets.is_empty() {
            return PersistStatus::SkippedEmpty;
        }

        let node_count = subnets.iter().map(|x| x.nodes.len()).sum::<usize>() as u32;

        // Generate a list of subnets with a single canister range
        // Can contain several entries with the same subnet ID
        let mut rt_subnets = subnets
            .into_iter()
            .flat_map(|subnet| {
                let mut nodes = subnet.nodes;
                // Sort nodes by latency before publishing to avoid sorting on each retry_request() call.
                nodes.sort_by(|a, b| a.avg_latency_secs.partial_cmp(&b.avg_latency_secs).unwrap());

                subnet.ranges.into_iter().map(move |range| {
                    Arc::new(RouteSubnet {
                        id: subnet.id,
                        range_start: principal_bytes_to_u256(range.start.as_slice()),
                        range_end: principal_bytes_to_u256(range.end.as_slice()),
                        nodes: nodes.clone(),
                    })
                })
            })
            .collect::<Vec<_>>();

        let subnet_map = rt_subnets
            .iter()
            .map(|subnet| (subnet.id, subnet.clone()))
            .collect::<HashMap<_, _>>();

        // Sort subnets by range_start for the binary search to work in lookup()
        rt_subnets.sort_by_key(|x| x.range_start);

        let rt = Arc::new(Routes {
            node_count,
            subnets: rt_subnets,
            subnet_map,
        });

        // Load old subnet to get previous numbers
        let rt_old = self.published_routes.load_full();
        let (ranges_old, nodes_old) =
            rt_old.map_or((0, 0), |x| (x.subnets.len() as u32, x.node_count));

        let results = PersistResults {
            ranges_old,
            ranges_new: rt.subnets.len() as u32,
            nodes_old,
            nodes_new: rt.node_count,
        };

        // Publish new routing table
        self.published_routes.store(Some(rt));

        PersistStatus::Completed(results)
    }
}

#[async_trait]
impl<T: Persist> Persist for WithMetricsPersist<T> {
    fn persist(&self, subnets: Vec<Subnet>) -> PersistStatus {
        let out = self.0.persist(subnets);
        let MetricParamsPersist { nodes, ranges } = &self.1;

        match out {
            PersistStatus::SkippedEmpty => {
                error!("Lookup table is empty");
            }

            PersistStatus::Completed(s) => {
                nodes.set(s.nodes_new as i64);
                ranges.set(s.ranges_new as i64);

                debug!(
                    action = "persist",
                    "Lookup table published: subnet ranges: {:?} -> {:?}, nodes: {:?} -> {:?}",
                    s.ranges_old,
                    s.ranges_new,
                    s.nodes_old,
                    s.nodes_new,
                );
            }
        }

        out
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::{principal_bytes_to_u256, Persist, PersistStatus, Persister, RouteSubnet, Routes};

    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    use anyhow::Error;
    use arc_swap::ArcSwapOption;
    use candid::Principal;
    use ethnum::u256;
    use ic_bn_lib::principal;
    use ic_registry_subnet_type::SubnetType;

    use crate::{
        snapshot::{node_test_id, CanisterRange, Node, Subnet},
        test_utils::valid_tls_certificate_and_validation_time,
    };

    // Converts string principal to a u256
    fn principal_to_u256(p: &str) -> Result<u256, Error> {
        // Parse textual representation into a byte slice
        let p = Principal::from_text(p)?;
        let p = p.as_slice();

        Ok(principal_bytes_to_u256(p))
    }

    #[test]
    fn test_principal_to_u256() -> Result<(), Error> {
        assert!(principal_to_u256("foo-bar-baz").is_err());

        assert_eq!(
            principal_to_u256("tg57h-slwo4-l4fga-d4zo2-4pc5z-lujes-uxqp3-pzchi-krm7r-sgvix-pae")?,
            u256::from_be_bytes([
                0x00, 0x00, 0x00, 0x76, 0x77, 0x17, 0xc2, 0x98, 0x03, 0xe6, 0x5d, 0xae, 0x3c, 0x5d,
                0xca, 0xe8, 0x92, 0x4a, 0x97, 0x83, 0xf6, 0xfc, 0x88, 0xe8, 0x54, 0x59, 0xf8, 0xc8,
                0xd5, 0x45, 0xde, 0x02
            ])
        );

        assert_eq!(
            principal_to_u256("iineg-fibai-bqibi-ga4ea-searc-ijrif-iwc4m-bsibb-eirsi-jjge4-ucs")?,
            u256::from_be_bytes([
                0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                0x26, 0x27, 0x28, 0x29
            ])
        );

        assert_eq!(
            principal_to_u256("xtqug-aqaae-bagba-faydq-q")?,
            u256::from_be_bytes([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
                0x05, 0x06, 0x07, 0x08
            ])
        );

        Ok(())
    }

    pub fn node(i: u64, subnet_id: Principal) -> Arc<Node> {
        Arc::new(Node {
            id: node_test_id(1001 + i).get().0,
            subnet_id,
            subnet_type: SubnetType::Application,
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, i as u8)),
            port: 8080,
            tls_certificate: valid_tls_certificate_and_validation_time()
                .0
                .certificate_der,
            avg_latency_secs: f64::MAX,
        })
    }

    pub fn generate_test_subnets(offset: u64) -> Vec<Subnet> {
        let subnet_id_1 =
            principal!("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe");
        let subnet_id_2 =
            principal!("uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe");
        let subnet_id_3 =
            principal!("snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae");

        let node1 = node(1 + offset, subnet_id_1);
        let node2 = node(2 + offset, subnet_id_2);
        let node3 = node(3 + offset, subnet_id_3);

        let subnet1 = Subnet {
            id: subnet_id_1,
            subnet_type: SubnetType::Application,
            ranges: vec![
                CanisterRange {
                    start: principal!("f7crg-kabae"),
                    end: principal!("sxiki-5ygae-aq"),
                },
                CanisterRange {
                    start: principal!("t5his-7iiae-aq"),
                    end: principal!("jlzvg-byp77-7qcai"),
                },
            ],
            nodes: vec![node1.clone()],
            replica_version: "7742d96ddd30aa6b607c9d2d4093a7b714f5b25b".to_string(),
        };

        let subnet2 = Subnet {
            id: subnet_id_2,
            subnet_type: SubnetType::Application,
            ranges: vec![
                CanisterRange {
                    start: principal!("sqjm4-qahae-aq"),
                    end: principal!("sqjm4-qahae-aq"),
                },
                CanisterRange {
                    start: principal!("6l3jn-7icca-aaaai-b"),
                    end: principal!("ca5tg-macd7-776ai-b"),
                },
            ],
            nodes: vec![node2.clone()],
            replica_version: "7742d96ddd30aa6b607c9d2d4093a7b714f5b25b".to_string(),
        };

        let subnet3 = Subnet {
            id: subnet_id_3,
            subnet_type: SubnetType::Application,
            ranges: vec![CanisterRange {
                start: principal!("zdpgc-saqaa-aacai"),
                end: principal!("fij4j-bi777-7qcai"),
            }],
            nodes: vec![node3.clone()],
            replica_version: "7742d96ddd30aa6b607c9d2d4093a7b714f5b25b".to_string(),
        };

        vec![subnet1, subnet2, subnet3]
    }

    pub fn generate_test_routes(offset: u64) -> Routes {
        let subnet_id_1 =
            principal!("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe");
        let subnet_id_2 =
            principal!("uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe");
        let subnet_id_3 =
            principal!("snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae");

        let subnet1 = RouteSubnet {
            id: subnet_id_1,
            range_start: principal_to_u256("f7crg-kabae").unwrap(),
            range_end: principal_to_u256("sxiki-5ygae-aq").unwrap(),
            nodes: vec![node(1 + offset, subnet_id_1)],
        };

        let subnet2 = RouteSubnet {
            id: subnet_id_2,
            range_start: principal_to_u256("sqjm4-qahae-aq").unwrap(),
            range_end: principal_to_u256("sqjm4-qahae-aq").unwrap(),
            nodes: vec![node(2 + offset, subnet_id_2)],
        };

        let subnet3 = RouteSubnet {
            id: subnet_id_1,
            range_start: principal_to_u256("t5his-7iiae-aq").unwrap(),
            range_end: principal_to_u256("jlzvg-byp77-7qcai").unwrap(),
            nodes: vec![node(1 + offset, subnet_id_1)],
        };

        let subnet4 = RouteSubnet {
            id: subnet_id_3,
            range_start: principal_to_u256("zdpgc-saqaa-aacai").unwrap(),
            range_end: principal_to_u256("fij4j-bi777-7qcai").unwrap(),
            nodes: vec![node(3 + offset, subnet_id_3)],
        };

        let subnet5 = RouteSubnet {
            id: subnet_id_2,
            range_start: principal_to_u256("6l3jn-7icca-aaaai-b").unwrap(),
            range_end: principal_to_u256("ca5tg-macd7-776ai-b").unwrap(),
            nodes: vec![node(2 + offset, subnet_id_2)],
        };

        let subnets = vec![
            Arc::new(subnet1),
            Arc::new(subnet2),
            Arc::new(subnet3),
            Arc::new(subnet4),
            Arc::new(subnet5),
        ];

        let subnet_map = subnets
            .iter()
            .map(|subnet| (subnet.id, subnet.clone()))
            .collect::<HashMap<_, _>>();

        Routes {
            node_count: 3,
            subnets,
            subnet_map,
        }
    }

    #[test]
    fn test_persist() -> Result<(), Error> {
        let routes = generate_test_routes(0);
        let subnets = generate_test_subnets(0);

        let rt_init = Arc::new(ArcSwapOption::empty());
        let persister = Persister::new(Arc::clone(&rt_init));

        // Persist the routing table
        let result = persister.persist(subnets.clone());
        // Check the result
        assert!(matches!(result, PersistStatus::Completed(_)));
        // Compare the persisted table state with expected
        assert_eq!(&routes, rt_init.load_full().unwrap().as_ref());

        // Check empty table
        let result = persister.persist(vec![]);
        assert!(matches!(result, PersistStatus::SkippedEmpty));
        // Check if the table hasn't changed
        assert_eq!(&routes, rt_init.load_full().unwrap().as_ref());

        // Generate different table
        let subnets = generate_test_subnets(1);
        let result = persister.persist(subnets);
        // Check if it was updated
        assert!(matches!(result, PersistStatus::Completed(_)));
        // Check if the routing table matches expected one
        let routes_new = generate_test_routes(1);
        assert_eq!(&routes_new, rt_init.load_full().unwrap().as_ref());

        Ok(())
    }

    #[test]
    fn test_lookup() -> Result<(), Error> {
        let r = generate_test_routes(0);

        assert_eq!(
            r.lookup_by_canister_id(principal!("ryjl3-tyaaa-aaaaa-aaaba-cai"))
                .unwrap()
                .id
                .to_string(),
            "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
        );

        assert_eq!(
            r.lookup_by_canister_id(principal!("qjdve-lqaaa-aaaaa-aaaeq-cai"))
                .unwrap()
                .id
                .to_string(),
            "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
        );

        assert_eq!(
            r.lookup_by_canister_id(principal!("2b2k4-rqaaa-aaaaa-qaatq-cai"))
                .unwrap()
                .id
                .to_string(),
            "snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae"
        );

        assert_eq!(
            r.lookup_by_canister_id(principal!("rdmx6-jaaaa-aaaaa-aaadq-cai"))
                .unwrap()
                .id
                .to_string(),
            "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
        );

        assert_eq!(
            r.lookup_by_canister_id(principal!("sqjm4-qahae-aq"))
                .unwrap()
                .id
                .to_string(),
            "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
        );

        assert_eq!(
            r.lookup_by_canister_id(principal!("rdmx6-jaaaa-aaaaa-aaadq-cai"))
                .unwrap()
                .id
                .to_string(),
            "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
        );

        assert_eq!(
            r.lookup_by_canister_id(principal!("uc7f6-kaaaa-aaaaq-qaaaa-cai"))
                .unwrap()
                .id
                .to_string(),
            "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
        );

        // Test failure
        assert!(r
            .lookup_by_canister_id(principal!("32fn4-qqaaa-aaaak-ad65a-cai"))
            .is_none());
        assert!(r
            .lookup_by_canister_id(principal!("3we4s-lyaaa-aaaak-aegrq-cai"))
            .is_none());

        Ok(())
    }
}
