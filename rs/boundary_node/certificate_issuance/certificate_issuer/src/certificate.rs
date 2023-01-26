use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use certificate_orchestrator_interface as ifc;
use futures::{stream, StreamExt, TryStreamExt};
use garcon::Delay;
use ic_agent::Agent;
use ifc::EncryptedPair;
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
    async fn upload(&self, id: &str, pair: Pair) -> Result<(), UploadError>;
}

#[derive(Serialize)]
pub struct Package {
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
    async fn export(&self) -> Result<Vec<Package>, ExportError>;
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
    async fn upload(&self, id: &str, pair: Pair) -> Result<(), UploadError> {
        use ifc::{UploadCertificateError as Error, UploadCertificateResponse as Response};

        let waiter = Delay::builder()
            .throttle(Duration::from_millis(500))
            .timeout(Duration::from_millis(10000))
            .build();

        let pair = EncryptedPair(
            self.encoder.encode(&pair.0).await?,
            self.encoder.encode(&pair.1).await?,
        );

        let args = Encode!(&id, &pair).context("failed to encode arg")?;

        let resp = self
            .agent
            .update(&self.canister_id, "uploadCertificate")
            .with_arg(args)
            .call_and_wait(waiter)
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
    async fn export(&self) -> Result<Vec<Package>, ExportError> {
        use ifc::{ExportCertificatesError as Error, ExportCertificatesResponse as Response};

        let args = Encode!().context("failed to encode arg")?;

        let resp = self
            .agent
            .query(&self.canister_id, "exportCertificates")
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
