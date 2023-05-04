use anyhow::Error;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;

use crate::Run;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingTable {
    // TODO(BOUN-722): Implement Routing table
    // similar to rs/boundary_node/control_plane/src/registry.rs, but without encoding things as `String`s
}

pub struct Runner<'a> {
    published_routing_table: &'a ArcSwapOption<RoutingTable>,
    registry_client: (),
}

impl<'a> Runner<'a> {
    pub fn new(
        published_routing_table: &'a ArcSwapOption<RoutingTable>,
        registry_client: (),
    ) -> Self {
        Self {
            published_routing_table,
            registry_client,
        }
    }
}

#[async_trait]
impl<'a> Run for Runner<'a> {
    async fn run(&mut self) -> Result<(), Error> {
        // similar to rs/boundary_node/control_plane/src/registry.rs, but without encoding things as `String`s
        todo!("TODO(BOUN-722): Implement Routing reading routing table")
    }
}
