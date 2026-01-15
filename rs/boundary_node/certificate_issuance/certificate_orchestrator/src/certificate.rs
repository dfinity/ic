use std::ops::Bound;

use anyhow::anyhow;
use certificate_orchestrator_interface::{
    EncryptedPair, ExportPackage, IcCertificate, Id, LEFT_GUARD, RIGHT_GUARD, Registration,
};
use ic_cdk::api::msg_caller;
use prometheus::labels;

use crate::{
    LocalRef, StableMap, StorableId, WithMetrics,
    acl::{Authorize, AuthorizeError, WithAuthorize},
    ic_certification::{add_cert, get_cert_for_range, set_root_hash},
};

#[derive(Debug, thiserror::Error)]
pub enum GetCertError {
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait GetCert {
    fn get_cert(&self, id: &Id) -> Result<EncryptedPair, GetCertError>;
}

pub struct CertGetter {
    pairs: LocalRef<StableMap<StorableId, EncryptedPair>>,
}

impl CertGetter {
    pub fn new(pairs: LocalRef<StableMap<StorableId, EncryptedPair>>) -> Self {
        Self { pairs }
    }
}

impl GetCert for CertGetter {
    fn get_cert(&self, id: &Id) -> Result<EncryptedPair, GetCertError> {
        self.pairs
            .with(|pairs| pairs.borrow().get(&id.into()).ok_or(GetCertError::NotFound))
    }
}

impl<T: GetCert, A: Authorize> GetCert for WithAuthorize<T, A> {
    fn get_cert(&self, id: &Id) -> Result<EncryptedPair, GetCertError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => GetCertError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => GetCertError::UnexpectedError(err),
            });
        };

        self.0.get_cert(id)
    }
}

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
    pairs: LocalRef<StableMap<StorableId, EncryptedPair>>,
    registrations: LocalRef<StableMap<StorableId, Registration>>,
}

impl Uploader {
    pub fn new(
        pairs: LocalRef<StableMap<StorableId, EncryptedPair>>,
        registrations: LocalRef<StableMap<StorableId, Registration>>,
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
            regs.get(&id.into()).ok_or(UploadError::NotFound)
        })?;
        self.pairs
            .with(|pairs| pairs.borrow_mut().insert(id.into(), pair));
        Ok(())
    }
}

pub struct UploadWithIcCertification<T> {
    uploader: T,
    registrations: LocalRef<StableMap<StorableId, Registration>>,
}

impl<T: Upload> UploadWithIcCertification<T> {
    pub fn new(uploader: T, registrations: LocalRef<StableMap<StorableId, Registration>>) -> Self {
        Self {
            uploader,
            registrations,
        }
    }
}

impl<T: Upload> Upload for UploadWithIcCertification<T> {
    fn upload(&self, id: &Id, pair: EncryptedPair) -> Result<(), UploadError> {
        self.uploader.upload(id, pair.clone())?;
        let package_to_certify = self.registrations.with(|regs| {
            let reg = regs.borrow().get(&id.into()).unwrap();
            ExportPackage {
                id: id.into(),
                name: reg.name,
                canister: reg.canister,
                pair,
            }
        });
        add_cert(id.into(), &package_to_certify);
        set_root_hash();
        Ok(())
    }
}

impl<T: Upload, A: Authorize> Upload for WithAuthorize<T, A> {
    fn upload(&self, id: &Id, pair: EncryptedPair) -> Result<(), UploadError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
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
    fn export(&self, key: Option<String>, limit: u64) -> Result<Vec<ExportPackage>, ExportError>;
    fn export_certified(
        &self,
        key: Option<String>,
        limit: u64,
    ) -> Result<(Vec<ExportPackage>, IcCertificate), ExportError>;
}

pub struct Exporter {
    pairs: LocalRef<StableMap<StorableId, EncryptedPair>>,
    registrations: LocalRef<StableMap<StorableId, Registration>>,
}

impl Exporter {
    pub fn new(
        pairs: LocalRef<StableMap<StorableId, EncryptedPair>>,
        registrations: LocalRef<StableMap<StorableId, Registration>>,
    ) -> Self {
        Self {
            pairs,
            registrations,
        }
    }
}

impl Export for Exporter {
    fn export(&self, key: Option<String>, limit: u64) -> Result<Vec<ExportPackage>, ExportError> {
        self.pairs.with(|pairs| {
            self.registrations.with(|regs| {
                pairs
                    .borrow()
                    .range((
                        match key {
                            Some(key) => Bound::Excluded(StorableId::from(key)),
                            None => Bound::Unbounded,
                        },
                        Bound::Unbounded,
                    ))
                    .take(limit as usize)
                    .map(|(id, pair)| match regs.borrow().get(&id) {
                        None => Err(ExportError::UnexpectedError(anyhow!(
                            "registration {id} is missing",
                        ))),
                        Some(Registration { name, canister, .. }) => Ok(ExportPackage {
                            id: id.into(),
                            name,
                            canister,
                            pair,
                        }),
                    })
                    .collect()
            })
        })
    }

    fn export_certified(
        &self,
        key: Option<String>,
        limit: u64,
    ) -> Result<(Vec<ExportPackage>, IcCertificate), ExportError> {
        let result: Result<Vec<ExportPackage>, ExportError> = self.pairs.with(|pairs| {
            self.registrations.with(|regs| {
                let pairs = pairs.borrow();
                let iter = match key.clone() {
                    None => pairs.iter(),
                    Some(s) => {
                        let k = StorableId::from(s);
                        if pairs.contains_key(&k) {
                            let mut i = pairs.iter_upper_bound(&k);
                            if i.next().is_none() { pairs.iter() } else { i }
                        } else {
                            pairs.iter_upper_bound(&k)
                        }
                    }
                };
                iter.take(limit as usize)
                    .map(|(id, pair)| match regs.borrow().get(&id) {
                        None => Err(ExportError::UnexpectedError(anyhow!(
                            "registration {id} is missing",
                        ))),
                        Some(Registration { name, canister, .. }) => Ok(ExportPackage {
                            id: id.into(),
                            name,
                            canister,
                            pair,
                        }),
                    })
                    .collect()
            })
        });
        match result {
            Err(e) => Err(e),
            Ok(pkgs) => {
                let first = match (key, pkgs.first()) {
                    (None, _) => LEFT_GUARD.to_string(),
                    (_, None) => LEFT_GUARD.to_string(),
                    (Some(k), Some(p)) => {
                        if p.id > k {
                            LEFT_GUARD.to_string()
                        } else {
                            p.id.clone()
                        }
                    }
                };
                let last = if (pkgs.len() as u64) < limit {
                    RIGHT_GUARD.to_string()
                } else {
                    pkgs.last().unwrap().id.clone()
                };
                let cert = get_cert_for_range(&first, &last);
                Ok((pkgs, cert))
            }
        }
    }
}

impl<T: Export, A: Authorize> Export for WithAuthorize<T, A> {
    fn export(&self, key: Option<String>, limit: u64) -> Result<Vec<ExportPackage>, ExportError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => ExportError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => ExportError::UnexpectedError(err),
            });
        };

        self.0.export(key, limit)
    }

    fn export_certified(
        &self,
        key: Option<String>,
        limit: u64,
    ) -> Result<(Vec<ExportPackage>, IcCertificate), ExportError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => ExportError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => ExportError::UnexpectedError(err),
            });
        };

        self.0.export_certified(key, limit)
    }
}
