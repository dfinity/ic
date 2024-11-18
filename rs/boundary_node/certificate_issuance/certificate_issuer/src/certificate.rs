use std::sync::Arc;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use certificate_orchestrator_interface::{self as ifc, EncryptedPair, IcCertificate, Id};
use futures::{stream, StreamExt, TryStreamExt};
use ic_agent::{hash_tree::HashTree, Agent, Certificate};
use mockall::automock;
use serde::Serialize;

use crate::{
    decoder_config,
    encode::{Decode, Encode},
    verification::Verify,
};

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct Pair(
    pub Vec<u8>, // Private Key
    pub Vec<u8>, // Certificate Chain
);

#[derive(Debug, thiserror::Error)]
pub enum GetCertError {
    #[error("Not found")]
    NotFound,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[automock]
#[async_trait]
pub trait GetCert: Send + Sync {
    async fn get_cert(&self, id: &Id) -> Result<Pair, GetCertError>;
}

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

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct Package {
    pub id: String,
    pub name: String,
    pub canister: Principal,
    pub pair: Pair,
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Export: Sync + Send {
    async fn export(
        &self,
        key: Option<String>,
        limit: u64,
    ) -> Result<(Vec<Package>, IcCertificate), ExportError>;
}

pub struct CanisterCertGetter {
    agent: Arc<Agent>,
    canister_id: Principal,
    decoder: Arc<dyn Decode>,
}

impl CanisterCertGetter {
    pub fn new(agent: Arc<Agent>, canister_id: Principal, decoder: Arc<dyn Decode>) -> Self {
        Self {
            agent,
            canister_id,
            decoder,
        }
    }
}

#[async_trait]
impl GetCert for CanisterCertGetter {
    async fn get_cert(&self, id: &Id) -> Result<Pair, GetCertError> {
        use ifc::{GetCertificateError as Error, GetCertificateResponse as Response};

        let args = Encode!(&id).context("failed to encode arg")?;

        let resp = self
            .agent
            .query(&self.canister_id, "getCertificate")
            .with_arg(args)
            .call()
            .await
            .context("failed to query canister")?;

        let resp = Decode!([decoder_config()]; &resp, Response)
            .context("failed to decode canister response")?;

        match resp {
            Response::Ok(enc_pair) => Ok(Pair(
                self.decoder.decode(&enc_pair.0).await?,
                self.decoder.decode(&enc_pair.1).await?,
            )),
            Response::Err(err) => Err(match err {
                Error::NotFound => GetCertError::NotFound,
                Error::Unauthorized => GetCertError::UnexpectedError(anyhow!("unauthorized")),
                Error::UnexpectedError(err) => GetCertError::UnexpectedError(anyhow!(err)),
            }),
        }
    }
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

        let resp = Decode!([decoder_config()]; &resp, Response)
            .context("failed to decode canister response")?;

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
}

impl CanisterExporter {
    pub fn new(agent: Arc<Agent>, canister_id: Principal) -> Self {
        Self { agent, canister_id }
    }
}

#[async_trait]
impl Export for CanisterExporter {
    async fn export(
        &self,
        key: Option<String>,
        limit: u64,
    ) -> Result<(Vec<Package>, IcCertificate), ExportError> {
        use ifc::{
            ExportCertificatesCertifiedResponse as Response, ExportCertificatesError as Error,
        };

        let args = Encode!(&key, &limit).context("failed to encode arg")?;

        let resp = self
            .agent
            .query(&self.canister_id, "exportCertificatesCertified")
            .with_arg(args)
            .call()
            .await
            .context("failed to query canister")?;

        let resp = Decode!([decoder_config()]; &resp, Response)
            .context("failed to decode canister response")?;

        match resp {
            Response::Ok((pkgs, iccert)) => Ok((
                pkgs.iter()
                    .map(|p| Package {
                        id: p.id.clone(),
                        name: p.name.clone().into(),
                        canister: p.canister,
                        pair: Pair(p.pair.0.clone(), p.pair.1.clone()),
                    })
                    .collect(),
                iccert,
            )),
            Response::Err(err) => {
                return Err(match err {
                    Error::Unauthorized => ExportError::UnexpectedError(anyhow!("unauthorized")),
                    Error::UnexpectedError(err) => ExportError::UnexpectedError(anyhow!(err)),
                })
            }
        }
    }
}

pub struct WithDecode<T>(pub T, pub Arc<dyn Decode>);

#[async_trait]
impl<T: Export> Export for WithDecode<T> {
    async fn export(
        &self,
        key: Option<String>,
        limit: u64,
    ) -> Result<(Vec<Package>, IcCertificate), ExportError> {
        let (pkgs, iccert) = self.0.export(key, limit).await?;

        // Decode certificate
        let pkgs: Vec<Package> = stream::iter(pkgs.into_iter())
            .then(|pkg| async move {
                Ok::<_, ExportError>(Package {
                    id: pkg.id,
                    name: pkg.name,
                    canister: pkg.canister,
                    pair: Pair(
                        self.1.decode(&pkg.pair.0).await?,
                        self.1.decode(&pkg.pair.1).await?,
                    ),
                })
            })
            .try_collect()
            .await
            .context("failed to decode certificates")?;

        Ok((pkgs, iccert))
    }
}

pub struct WithVerify<T>(pub T, pub Arc<dyn Verify>);

#[async_trait]
impl<T: Export> Export for WithVerify<T> {
    async fn export(
        &self,
        key: Option<String>,
        limit: u64,
    ) -> Result<(Vec<Package>, IcCertificate), ExportError> {
        let (pkgs, iccert) = self.0.export(key.clone(), limit).await?;

        let (cert, tree): (Certificate, HashTree<Vec<u8>>) = (
            serde_cbor::from_slice(&iccert.cert).context("failed to cbor-decode ic certificate")?,
            serde_cbor::from_slice(&iccert.tree).context("failed to cbor-decode tree")?,
        );

        self.1
            .verify(key, limit, &pkgs, &cert, &tree)
            .await
            .context("failed to verify certificate")?;

        Ok((pkgs, iccert))
    }
}

pub struct WithRetries<T>(pub T, pub u64);

#[async_trait]
impl<T: Export> Export for WithRetries<T> {
    async fn export(
        &self,
        key: Option<String>,
        limit: u64,
    ) -> Result<(Vec<Package>, IcCertificate), ExportError> {
        let mut counter = 0;
        while counter < self.1 {
            if let Ok(pkgs) = self.0.export(key.clone(), limit).await {
                return Ok(pkgs);
            }
            counter += 1;
        }
        self.0.export(key.clone(), limit).await
    }
}

pub struct WithPagination<T>(pub T, pub u64);

#[async_trait]
impl<T: Export> Export for WithPagination<T> {
    async fn export(
        &self,
        _: Option<String>,
        _: u64,
    ) -> Result<(Vec<Package>, IcCertificate), ExportError> {
        let mut out = Vec::new();

        // Disregard given `key` and `limit`, pagination will just process the entire dataset
        let mut key: Option<String> = None;

        loop {
            let (mut pkgs, _) = self
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

            // For every page but the last, remove the last entry
            // This is because the next page will include that entry as well (for certification purposes)
            pkgs.truncate(self.1 as usize - 1);

            out.append(&mut pkgs);
        }

        Ok((
            out,
            IcCertificate {
                cert: Vec::new(),
                tree: Vec::new(),
            },
        ))
    }
}
