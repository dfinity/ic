use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use ethnum::u256;
use rand::seq::SliceRandom;
use tracing::{debug, error};

use crate::{
    metrics::{MetricParamsPersist, WithMetricsPersist},
    routes::ErrorCause,
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
#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
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
pub mod test;
