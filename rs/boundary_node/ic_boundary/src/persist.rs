use anyhow::Error;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;

use crate::{snapshot::RoutingTable, Run};

pub struct Routes {
    // TODO(BOUN-723): Implement Routes table mapping canister ranges to subnets and subnets to nodes
}

pub enum PersistStatus {
    Completed,
    SkippedUnchanged,
    SkippedEmpty,
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
        todo!("TODO(BOUN-724): Implement mapping of RoutingTable into Routes")
    }
}
