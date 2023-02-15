use std::{
    fs::{self, File},
    io::BufWriter,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Error};
use async_trait::async_trait;
use futures::{stream, StreamExt};

use crate::{encode::Encode, registry::RoutingTable, reload::Reload, WithReload};

pub enum PersistStatus {
    Completed,
    SkippedUnchanged,
    SkippedEmpty,
}

#[async_trait]
pub trait Persist: Send + Sync {
    async fn persist(&self, rt: &RoutingTable) -> Result<PersistStatus, Error>;
}

pub struct LegacyPersister {
    routes_dir: PathBuf,
}

impl LegacyPersister {
    pub fn new(routes_dir: PathBuf) -> Self {
        Self { routes_dir }
    }
}

#[async_trait]
impl Persist for LegacyPersister {
    async fn persist(&self, rt: &RoutingTable) -> Result<PersistStatus, Error> {
        let p = format!("{:020}.routes", rt.registry_version);
        let p = self.routes_dir.join(p);

        let w = File::create(p).context("failed to create routes file")?;
        let w = BufWriter::new(w);
        serde_json::to_writer(w, &rt).context("failed to write json routes file")?;

        Ok(PersistStatus::Completed)
    }
}

pub struct Persister {
    path: PathBuf,
    encoder: Arc<dyn Encode>,
}

impl Persister {
    pub fn new(path: PathBuf, encoder: Arc<dyn Encode>) -> Self {
        Self { path, encoder }
    }
}

#[async_trait]
impl Persist for Persister {
    async fn persist(&self, rt: &RoutingTable) -> Result<PersistStatus, Error> {
        let bs = self
            .encoder
            .encode(rt)
            .await
            .context("failed to encode routing table")?;

        fs::write(&self.path, bs).context("failed to write routes")?;

        Ok(PersistStatus::Completed)
    }
}

#[async_trait]
impl<T: Persist, R: Reload> Persist for WithReload<T, R> {
    async fn persist(&self, rt: &RoutingTable) -> Result<PersistStatus, Error> {
        let out = self.0.persist(rt).await?;
        self.1.reload().await?;
        Ok(out)
    }
}

pub struct WithDedup<T, U>(pub T, pub Arc<RwLock<Option<U>>>);

#[async_trait]
impl<T: Persist> Persist for WithDedup<T, RoutingTable> {
    async fn persist(&self, rt: &RoutingTable) -> Result<PersistStatus, Error> {
        if self
            .1
            .read()
            .map(|v| match &*v {
                None => false,
                Some(v) => *v == *rt,
            })
            .unwrap()
        {
            return Ok(PersistStatus::SkippedUnchanged);
        } else {
            self.1.write().map(|mut v| *v = Some(rt.clone())).unwrap();
        }

        self.0.persist(rt).await
    }
}

pub struct WithEmpty<T>(pub T);

#[async_trait]
impl<T: Persist> Persist for WithEmpty<T> {
    async fn persist(&self, rt: &RoutingTable) -> Result<PersistStatus, Error> {
        if rt.subnets.iter().filter(|&s| !s.nodes.is_empty()).count() == 0 {
            return Ok(PersistStatus::SkippedEmpty);
        }

        self.0.persist(rt).await
    }
}

pub struct WithMultiple(pub Vec<Arc<dyn Persist>>);

#[async_trait]
impl Persist for WithMultiple {
    async fn persist(&self, rt: &RoutingTable) -> Result<PersistStatus, Error> {
        let rs: Vec<Result<PersistStatus, Error>> = stream::iter(self.0.iter())
            .then(|p| p.persist(rt))
            .collect()
            .await;

        if let Some(err) = rs.into_iter().find(|r| r.is_err()) {
            return err;
        }

        // Assume Completed since this is meant to run after any other check
        // E.g Deduplication runs prior to this, so this can never return SkippedUnchanged
        Ok(PersistStatus::Completed)
    }
}
