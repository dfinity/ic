use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use ethnum::u256;
use tracing::{debug, error};

use crate::{
    metrics::{MetricParamsPersist, WithMetricsPersist},
    snapshot::Subnet,
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

/// Converts Principal to a u256
pub fn principal_to_u256(p: &Principal) -> u256 {
    let b = p.as_slice();

    // Since Principal length can be anything in 0..29 range - prepend it with zeros to 32
    let pad = 32 - b.len();
    let mut padded: [u8; 32] = [0; 32];
    padded[pad..32].copy_from_slice(b);

    u256::from_be_bytes(padded)
}

/// Route from a canister id range to a subnet.
///
/// Principals can be up to 2^232 long, so we can use the u256 type to efficiently store them.
/// Under the hood u256 is using two u128, this is more efficient than lexographically sorted hexadecimal strings as was done in JS router.
///
/// Currently the largest canister id is somewhere around 2^40 - so probably using one u128 would work for a long time,
/// but going u256 makes it future proof and according to spec.
#[derive(Eq, PartialEq, Debug)]
pub struct Route {
    pub subnet: Arc<Subnet>,
    pub range_start: u256,
    pub range_end: u256,
}

#[derive(Eq, PartialEq, Debug)]
pub struct Routes {
    pub node_count: u32,
    pub range_count: u32,

    // Routes should be sorted by `range_start` field for the binary search to work
    pub routes: Vec<Route>,
    // Direct mapping from the Canister ID to the subnet for faster lookups
    pub direct: HashMap<u256, Arc<Subnet>>,
    // Mapping from Subnet ID to subnet
    pub subnet_map: HashMap<Principal, Arc<Subnet>>,
}

impl Routes {
    // Look up the subnet by canister_id
    pub fn lookup_by_canister_id(&self, canister_id: Principal) -> Option<Arc<Subnet>> {
        let canister_id_u256 = principal_to_u256(&canister_id);

        // First take a look in the direct table
        if let Some(v) = self.direct.get(&canister_id_u256) {
            return Some(v.clone());
        }

        let idx = match self
            .routes
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

        let route = &self.routes[idx];
        if canister_id_u256 < route.range_start || canister_id_u256 > route.range_end {
            return None;
        }

        Some(route.subnet.clone())
    }

    // Look up the subnet by subnet_id
    pub fn lookup_by_id(&self, subnet_id: Principal) -> Option<Arc<Subnet>> {
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
        let range_count = subnets.iter().map(|x| x.ranges.len()).sum::<usize>() as u32;

        let mut direct = HashMap::new();
        let mut routes = Vec::new();
        let mut subnet_map = HashMap::with_capacity(subnets.len());

        for mut subnet in subnets {
            // Sort nodes by an average latency before publishing
            subnet.nodes.sort_by(|a, b| {
                a.avg_latency_us
                    .load(Ordering::SeqCst)
                    .cmp(&b.avg_latency_us.load(Ordering::SeqCst))
            });

            let subnet = Arc::new(subnet);
            subnet_map.insert(subnet.id, subnet.clone());

            for range in &subnet.ranges {
                // For smaller ranges create a direct mapping from the canister id to a subnet
                if range.len() <= 5 {
                    for canister_id in range.canisters() {
                        direct.insert(canister_id, subnet.clone());
                    }
                } else {
                    // The rest goes into normal binary search array
                    let route = Route {
                        subnet: subnet.clone(),
                        range_start: principal_to_u256(&range.start),
                        range_end: principal_to_u256(&range.end),
                    };

                    routes.push(route);
                }
            }
        }

        // Sort subnets by range_start for the binary search to work in lookup()
        routes.sort_by_key(|x| x.range_start);

        let rt = Arc::new(Routes {
            node_count,
            range_count,
            routes,
            direct,
            subnet_map,
        });

        // Load old subnet to get previous numbers
        let rt_old = self.published_routes.load_full();
        let (ranges_old, nodes_old) = rt_old.map_or((0, 0), |x| (x.range_count, x.node_count));

        let results = PersistResults {
            ranges_old,
            ranges_new: rt.range_count,
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
    use super::*;

    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    use anyhow::Error;
    use arc_swap::ArcSwapOption;
    use candid::Principal;
    use ethnum::u256;
    use ic_bn_lib_common::principal;
    use ic_registry_subnet_type::SubnetType;

    use crate::{
        snapshot::{CanisterRange, Node, Subnet, node_test_id},
        test_utils::valid_tls_certificate_and_validation_time,
    };

    #[test]
    fn test_principal_to_u256() {
        assert_eq!(
            principal_to_u256(&principal!(
                "tg57h-slwo4-l4fga-d4zo2-4pc5z-lujes-uxqp3-pzchi-krm7r-sgvix-pae"
            )),
            u256::from_be_bytes([
                0x00, 0x00, 0x00, 0x76, 0x77, 0x17, 0xc2, 0x98, 0x03, 0xe6, 0x5d, 0xae, 0x3c, 0x5d,
                0xca, 0xe8, 0x92, 0x4a, 0x97, 0x83, 0xf6, 0xfc, 0x88, 0xe8, 0x54, 0x59, 0xf8, 0xc8,
                0xd5, 0x45, 0xde, 0x02
            ])
        );

        assert_eq!(
            principal_to_u256(&principal!(
                "iineg-fibai-bqibi-ga4ea-searc-ijrif-iwc4m-bsibb-eirsi-jjge4-ucs"
            )),
            u256::from_be_bytes([
                0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                0x26, 0x27, 0x28, 0x29
            ])
        );

        assert_eq!(
            principal_to_u256(&principal!("xtqug-aqaae-bagba-faydq-q")),
            u256::from_be_bytes([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
                0x05, 0x06, 0x07, 0x08
            ])
        );
    }

    pub fn node(i: u64, subnet_id: Principal) -> Arc<Node> {
        Arc::new(
            Node::new(
                node_test_id(1001 + i).get().0,
                subnet_id,
                SubnetType::Application,
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, i as u8)),
                8080,
                valid_tls_certificate_and_validation_time()
                    .0
                    .certificate_der,
            )
            .unwrap(),
        )
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
            ranges: vec![
                CanisterRange {
                    start: principal!("zdpgc-saqaa-aacai"),
                    end: principal!("fij4j-bi777-7qcai"),
                },
                // Range with 5 canisters that should go into direct table
                CanisterRange {
                    start: Principal::from_slice(&[0x01]),
                    end: Principal::from_slice(&[0x05]),
                },
            ],
            nodes: vec![node3.clone()],
            replica_version: "7742d96ddd30aa6b607c9d2d4093a7b714f5b25b".to_string(),
        };

        vec![subnet1, subnet2, subnet3]
    }

    pub fn generate_test_routes(offset: u64) -> Routes {
        let subnets = generate_test_subnets(offset)
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<_>>();

        let subnet_map = subnets
            .iter()
            .map(|x| (x.id, x.clone()))
            .collect::<HashMap<_, _>>();

        let route1 = Route {
            subnet: subnets[0].clone(),
            range_start: principal_to_u256(&principal!("f7crg-kabae")),
            range_end: principal_to_u256(&principal!("sxiki-5ygae-aq")),
        };

        let route2 = Route {
            subnet: subnets[0].clone(),
            range_start: principal_to_u256(&principal!("t5his-7iiae-aq")),
            range_end: principal_to_u256(&principal!("jlzvg-byp77-7qcai")),
        };

        let route3 = Route {
            subnet: subnets[2].clone(),
            range_start: principal_to_u256(&principal!("zdpgc-saqaa-aacai")),
            range_end: principal_to_u256(&principal!("fij4j-bi777-7qcai")),
        };

        let route4 = Route {
            subnet: subnets[1].clone(),
            range_start: principal_to_u256(&principal!("6l3jn-7icca-aaaai-b")),
            range_end: principal_to_u256(&principal!("ca5tg-macd7-776ai-b")),
        };

        let routes = vec![route1, route2, route3, route4];
        let mut direct = HashMap::new();
        direct.insert(
            principal_to_u256(&principal!("sqjm4-qahae-aq")),
            subnets[1].clone(),
        );
        for i in 1..=5 {
            direct.insert(
                principal_to_u256(&Principal::from_slice(&[i])),
                subnets[2].clone(),
            );
        }

        Routes {
            node_count: 3,
            range_count: 6,
            routes,
            direct,
            subnet_map,
        }
    }

    #[test]
    fn test_persist() -> Result<(), Error> {
        let routes = generate_test_routes(0);
        let subnets = generate_test_subnets(0);

        let rt_init = Arc::new(ArcSwapOption::empty());
        let persister = Persister::new(rt_init.clone());

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

        // Test direct lookups
        assert_eq!(
            r.lookup_by_canister_id(principal!("sqjm4-qahae-aq"))
                .unwrap()
                .id
                .to_string(),
            "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
        );

        for i in 1..=5 {
            assert_eq!(
                r.lookup_by_canister_id(Principal::from_slice(&[i]))
                    .unwrap()
                    .id
                    .to_string(),
                "snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae"
            );
        }

        // Test failure
        assert!(
            r.lookup_by_canister_id(principal!("32fn4-qqaaa-aaaak-ad65a-cai"))
                .is_none()
        );
        assert!(
            r.lookup_by_canister_id(principal!("3we4s-lyaaa-aaaak-aegrq-cai"))
                .is_none()
        );

        Ok(())
    }
}
