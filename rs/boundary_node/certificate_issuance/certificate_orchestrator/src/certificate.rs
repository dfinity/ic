use anyhow::anyhow;
use certificate_orchestrator_interface::{EncryptedPair, ExportPackage, Id, Registration};
use ic_cdk::caller;
use ic_stable_structures::StableBTreeMap;
use prometheus::labels;

use crate::{
    acl::{Authorize, AuthorizeError, WithAuthorize},
    LocalRef, Memory, WithMetrics,
};

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Upload {
    fn upload(&self, id: &Id, pair: EncryptedPair) -> Result<(), UploadError>;
}

pub struct Uploader {
    pairs: LocalRef<StableBTreeMap<Memory, Id, EncryptedPair>>,
    registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
}

impl Uploader {
    pub fn new(
        pairs: LocalRef<StableBTreeMap<Memory, Id, EncryptedPair>>,
        registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
    ) -> Self {
        Self {
            pairs,
            registrations,
        }
    }
}

impl Upload for Uploader {
    fn upload(&self, id: &Id, pair: EncryptedPair) -> Result<(), UploadError> {
        self.registrations.with(|regs| {
            let regs = regs.borrow();
            regs.get(id).ok_or(UploadError::NotFound)
        })?;

        self.pairs.with(|pairs| {
            pairs
                .borrow_mut()
                .insert(id.to_owned(), pair)
                .map_err(|err| anyhow!(format!("failed to insert: {err}")))
        })?;

        Ok(())
    }
}

impl<T: Upload, A: Authorize> Upload for WithAuthorize<T, A> {
    fn upload(&self, id: &Id, pair: EncryptedPair) -> Result<(), UploadError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => UploadError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => UploadError::UnexpectedError(err),
            });
        };

        self.0.upload(id, pair)
    }
}

impl<T: Upload> Upload for WithMetrics<T> {
    fn upload(&self, id: &Id, pair: EncryptedPair) -> Result<(), UploadError> {
        let out = self.0.upload(id, pair);

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            UploadError::NotFound => "not-found",
                            UploadError::Unauthorized => "unauthorized",
                            UploadError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Export {
    fn export(&self) -> Result<Vec<ExportPackage>, ExportError>;
}

pub struct Exporter {
    pairs: LocalRef<StableBTreeMap<Memory, Id, EncryptedPair>>,
    registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
}

impl Exporter {
    pub fn new(
        pairs: LocalRef<StableBTreeMap<Memory, Id, EncryptedPair>>,
        registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
    ) -> Self {
        Self {
            pairs,
            registrations,
        }
    }
}

impl Export for Exporter {
    fn export(&self) -> Result<Vec<ExportPackage>, ExportError> {
        self.pairs.with(|pairs| {
            self.registrations.with(|regs| {
                pairs
                    .borrow()
                    .iter()
                    .map(|(id, pair)| match regs.borrow().get(&id) {
                        None => Err(ExportError::UnexpectedError(anyhow!(
                            "registration {id} is missing"
                        ))),
                        Some(Registration { name, canister, .. }) => Ok(ExportPackage {
                            name,
                            canister,
                            pair,
                        }),
                    })
                    .collect()
            })
        })
    }
}

impl<T: Export, A: Authorize> Export for WithAuthorize<T, A> {
    fn export(&self) -> Result<Vec<ExportPackage>, ExportError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => ExportError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => ExportError::UnexpectedError(err),
            });
        };

        self.0.export()
    }
}
