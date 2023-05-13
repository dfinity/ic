use std::sync::Arc;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use certificate_orchestrator_interface::{self as ifc, EncryptedPair, Id};
use futures::{stream, StreamExt, TryStreamExt};
use ic_agent::Agent;
use mockall::automock;
use serde::Serialize;

use crate::encode::{Decode, Encode};

#[derive(Debug, PartialEq, Serialize)]
pub struct Pair(
    pub Vec<u8>, // Private Key
    pub Vec<u8>, // Certificate Chain
);

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("Not found")]
    NotFound,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[automock]
#[async_trait]
pub trait Upload: Sync + Send {
    async fn upload(&self, id: &Id, pair: Pair) -> Result<(), UploadError>;
}

#[derive(Serialize)]
pub struct Package {
    id: String,
    name: String,
    canister: Principal,
    pair: Pair,
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Export: Sync + Send {
    async fn export(&self, key: Option<String>, limit: u64) -> Result<Vec<Package>, ExportError>;
}

pub struct CanisterUploader {
    agent: Arc<Agent>,
    canister_id: Principal,
    encoder: Arc<dyn Encode>,
}

impl CanisterUploader {
    pub fn new(agent: Arc<Agent>, canister_id: Principal, encoder: Arc<dyn Encode>) -> Self {
        Self {
            agent,
            canister_id,
            encoder,
        }
    }
}

#[async_trait]
impl Upload for CanisterUploader {
    async fn upload(&self, id: &Id, pair: Pair) -> Result<(), UploadError> {
        use ifc::{UploadCertificateError as Error, UploadCertificateResponse as Response};

        let pair = EncryptedPair(
            self.encoder.encode(&pair.0).await?,
            self.encoder.encode(&pair.1).await?,
        );

        let args = Encode!(&id, &pair).context("failed to encode arg")?;

        let resp = self
            .agent
            .update(&self.canister_id, "uploadCertificate")
            .with_arg(args)
            .call_and_wait()
            .await
            .context("failed to query canister")?;

        let resp = Decode!(&resp, Response).context("failed to decode canister response")?;

        match resp {
            Response::Ok(()) => Ok(()),
            Response::Err(err) => Err(match err {
                Error::NotFound => UploadError::NotFound,
                Error::Unauthorized => UploadError::UnexpectedError(anyhow!("unauthorized")),
                Error::UnexpectedError(err) => UploadError::UnexpectedError(anyhow!(err)),
            }),
        }
    }
}

pub struct CanisterExporter {
    agent: Arc<Agent>,
    canister_id: Principal,
    decoder: Arc<dyn Decode>,
}

impl CanisterExporter {
    pub fn new(agent: Arc<Agent>, canister_id: Principal, decoder: Arc<dyn Decode>) -> Self {
        Self {
            agent,
            canister_id,
            decoder,
        }
    }
}

#[async_trait]
impl Export for CanisterExporter {
    async fn export(&self, key: Option<String>, limit: u64) -> Result<Vec<Package>, ExportError> {
        use ifc::{ExportCertificatesError as Error, ExportCertificatesResponse as Response};

        let args = Encode!(&key, &limit).context("failed to encode arg")?;

        let resp = self
            .agent
            .query(&self.canister_id, "exportCertificatesPaginated")
            .with_arg(args)
            .call()
            .await
            .context("failed to query canister")?;

        let resp = Decode!(&resp, Response).context("failed to decode canister response")?;

        let pkgs = match resp {
            Response::Ok(pkgs) => pkgs,
            Response::Err(err) => {
                return Err(match err {
                    Error::Unauthorized => ExportError::UnexpectedError(anyhow!("unauthorized")),
                    Error::UnexpectedError(err) => ExportError::UnexpectedError(anyhow!(err)),
                })
            }
        };

        // Decode certificate
        stream::iter(pkgs.into_iter())
            .then(|pkg| async move {
                Ok(Package {
                    id: pkg.id,
                    name: pkg.name.into(),
                    canister: pkg.canister,
                    pair: Pair(
                        self.decoder.decode(&pkg.pair.0).await?,
                        self.decoder.decode(&pkg.pair.1).await?,
                    ),
                })
            })
            .try_collect()
            .await
    }
}

pub struct WithPagination<T>(pub T, pub u64);

#[async_trait]
impl<T: Export> Export for WithPagination<T> {
    async fn export(&self, _: Option<String>, _: u64) -> Result<Vec<Package>, ExportError> {
        let mut out = Vec::new();

        // Disregard given `key` and `limit`, pagination will just process the entire dataset
        let mut key: Option<String> = None;

        loop {
            let mut pkgs = self
                .0
                .export(
                    key,    // key
                    self.1, // limit
                )
                .await?;

            if pkgs.len() < self.1 as usize {
                out.append(&mut pkgs);
                break;
            }

            key = Some(
                pkgs.last()
                    .expect("missing last element from packages list")
                    .id
                    .to_owned(),
            );

            out.append(&mut pkgs);
        }

        Ok(out)
    }
}
