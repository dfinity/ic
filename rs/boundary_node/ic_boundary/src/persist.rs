use std::sync::Arc;

use anyhow::{anyhow, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use ethnum::u256;

use crate::{
    snapshot::{Node, RoutingTable},
    Run,
};

pub enum PersistStatus {
    Completed,
    SkippedUnchanged,
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

// Converts string principal to a u256
fn principal_to_u256(p: &str) -> Result<u256, Error> {
    // Parse textual representation into a byte slice
    let p = Principal::from_text(p)?;
    let p = p.as_slice();

    Ok(principal_bytes_to_u256(p))
}

// Principals are 2^232 max so we can use the u256 type to efficiently store them
// Under the hood u256 is using two u128
// This is more efficient than lexographically sorted hexadecimal strings as done in JS router
// Currently the largest canister_id range is somewhere around 2^40 - so probably using one u128 would work for a long time
// But going u256 makes it future proof and according to spec
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSubnet {
    id: String,
    range_start: u256,
    range_end: u256,
    nodes: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routes {
    // subnets should be sorted by `range_start` field for the binary search to work
    subnets: Vec<Arc<RouteSubnet>>,
}

impl Routes {
    // Look up the subnet by canister_id
    pub fn lookup(&self, canister_id: &str) -> Result<Arc<RouteSubnet>, Error> {
        let canister_id_u256 = principal_to_u256(canister_id)?;

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
            return Err(anyhow!("Route for canister '{canister_id}' not found"));
        }

        Ok(subnet)
    }
}

#[async_trait]
pub trait Persist: Send + Sync {
    async fn persist(&self, rt: RoutingTable) -> Result<PersistStatus, Error>;
}

pub struct Persister<'a> {
    published_routes: &'a ArcSwapOption<Routes>,
}

impl<'a> Persister<'a> {
    pub fn new(published_routes: &'a ArcSwapOption<Routes>) -> Self {
        Self { published_routes }
    }
}

#[async_trait]
impl<'a> Persist for Persister<'a> {
    async fn persist(&self, rt: RoutingTable) -> Result<PersistStatus, Error> {
        if rt.subnets.is_empty() {
            return Ok(PersistStatus::SkippedEmpty);
        }

        let mut subnets = vec![];

        for subnet in rt.subnets.into_iter() {
            for range in subnet.ranges.into_iter() {
                subnets.push(Arc::new(RouteSubnet {
                    id: subnet.id.to_string(),
                    range_start: principal_bytes_to_u256(range.start.as_slice()),
                    range_end: principal_bytes_to_u256(range.end.as_slice()),
                    nodes: subnet.nodes.clone(),
                }))
            }
        }

        subnets.sort_by_key(|x| x.range_start);

        let rt = Arc::new(Routes { subnets });
        match self.published_routes.load_full() {
            None => {
                self.published_routes.store(Some(rt));
                return Ok(PersistStatus::Completed);
            }

            Some(rt_old) => {
                if rt == rt_old {
                    return Ok(PersistStatus::SkippedUnchanged);
                }

                self.published_routes.store(Some(rt));
                return Ok(PersistStatus::Completed);
            }
        }
    }
}

#[cfg(test)]
mod test;
