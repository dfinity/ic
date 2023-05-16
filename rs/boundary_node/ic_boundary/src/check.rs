use anyhow::Error;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;

use crate::{persist::Persist, snapshot::RoutingTable, Run};

pub struct Runner<'a, P: Persist> {
    published_routing_table: &'a ArcSwapOption<RoutingTable>,
    persist: P,
}

impl<'a, P: Persist> Runner<'a, P> {
    pub fn new(published_routing_table: &'a ArcSwapOption<RoutingTable>, persist: P) -> Self {
        Self {
            published_routing_table,
            persist,
        }
    }
}

#[async_trait]
impl<'a, P: Persist> Run for Runner<'a, P> {
    async fn run(&mut self) -> Result<(), Error> {
        // TODO(BOUN-725): Implement health check, similar to rs/boundary_node/control_plane/src/check.rs
        Ok(())
    }
}
