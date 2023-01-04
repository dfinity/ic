use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use certificate_orchestrator_interface as ifc;
use garcon::Delay;
use ic_agent::Agent;
use serde::Serialize;
use trust_dns_resolver::{error::ResolveErrorKind, proto::rr::RecordType};

use crate::{
    acme,
    certificate::{self, Pair},
    dns::{self, Resolve},
    registration::{Id, Registration, State},
};

#[derive(Debug, Clone, Serialize)]
pub enum Action {
    Order,
    Ready,
    Certificate,
}

impl ToString for Action {
    fn to_string(&self) -> String {
        serde_json::ser::to_string(self).unwrap_or_else(|_| "N/A".into())
    }
}

impl From<State> for Action {
    fn from(s: State) -> Self {
        match s {
            State::Failed(_) | State::PendingOrder => Action::Order,
            State::PendingChallengeResponse => Action::Ready,
            State::PendingAcmeApproval => Action::Certificate,
            State::Available => Action::Order,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Task {
    pub name: String,
    pub action: Action,
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("Not found")]
    NotFound,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Queue: Sync + Send {
    async fn queue(&self, id: &Id, t: u64) -> Result<(), QueueError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DispenseError {
    #[error("No tasks available")]
    NoTasksAvailable,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Dispense: Sync + Send {
    async fn dispense(&self) -> Result<(Id, Task), DispenseError>;
    async fn peek(&self) -> Result<Id, DispenseError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("awaiting propogation of challenge response dns txt record")]
    AwaitingDnsPropogation,

    #[error("awaiting acme approval for certificate order")]
    AwaitingAcmeOrderReady,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl From<&ProcessError> for Duration {
    fn from(_: &ProcessError) -> Self {
        Duration::from_secs(60)
    }
}

#[async_trait]
pub trait Process: Sync + Send {
    async fn process(&self, id: &Id, task: &Task) -> Result<(), ProcessError>;
}

pub struct CanisterQueuer(pub Arc<Agent>, pub Principal);

#[async_trait]
impl Queue for CanisterQueuer {
    async fn queue(&self, id: &Id, t: u64) -> Result<(), QueueError> {
        use ifc::{QueueTaskError as Error, QueueTaskResponse as Response};

        let waiter = Delay::builder()
            .throttle(Duration::from_millis(500))
            .timeout(Duration::from_millis(10000))
            .build();

        let args = Encode!(id, &t).context("failed to encode arg")?;

        let resp = self
            .0
            .update(&self.1, "queueTask")
            .with_arg(args)
            .call_and_wait(waiter)
            .await
            .context("failed to query canister")?;

        let resp = Decode!(&resp, Response).context("failed to decode canister response")?;

        match resp {
            Response::Ok(()) => Ok(()),
            Response::Err(err) => Err(match err {
                Error::NotFound => QueueError::NotFound,
                Error::Unauthorized => QueueError::UnexpectedError(anyhow!("unauthorized")),
                Error::UnexpectedError(err) => QueueError::UnexpectedError(anyhow!(err)),
            }),
        }
    }
}

pub struct CanisterDispenser(pub Arc<Agent>, pub Principal);

#[async_trait]
impl Dispense for CanisterDispenser {
    async fn dispense(&self) -> Result<(Id, Task), DispenseError> {
        let id = {
            use ifc::{DispenseTaskError as Error, DispenseTaskResponse as Response};

            let waiter = Delay::builder()
                .throttle(Duration::from_millis(500))
                .timeout(Duration::from_millis(10000))
                .build();

            let args = Encode!().context("failed to encode arg")?;

            let resp = self
                .0
                .update(&self.1, "dispenseTask")
                .with_arg(args)
                .call_and_wait(waiter)
                .await
                .context("failed to query canister")?;

            let resp = Decode!(&resp, Response).context("failed to decode canister response")?;

            match resp {
                Response::Ok(id) => Ok(id),
                Response::Err(err) => Err(match err {
                    Error::NoTasksAvailable => DispenseError::NoTasksAvailable,
                    Error::Unauthorized => DispenseError::UnexpectedError(anyhow!("unauthorized")),
                    Error::UnexpectedError(err) => DispenseError::UnexpectedError(anyhow!(err)),
                }),
            }?
        };

        let reg: Registration = {
            use ifc::{GetRegistrationError as Error, GetRegistrationResponse as Response};

            let args = Encode!(&id).context("failed to encode arg")?;

            let resp = self
                .0
                .query(&self.1, "getRegistration")
                .with_arg(args)
                .call()
                .await
                .context("failed to query canister")?;

            let resp = Decode!(&resp, Response).context("failed to decode canister response")?;

            match resp {
                Response::Ok(reg) => Ok(reg.into()),
                Response::Err(err) => Err(match err {
                    Error::NotFound => DispenseError::UnexpectedError(anyhow!("not found")),
                    Error::Unauthorized => DispenseError::UnexpectedError(anyhow!("unauthorized")),
                    Error::UnexpectedError(err) => DispenseError::UnexpectedError(anyhow!(err)),
                }),
            }?
        };

        Ok((
            id,
            Task {
                name: reg.name,
                action: reg.state.into(),
            },
        ))
    }

    async fn peek(&self) -> Result<Id, DispenseError> {
        use ifc::{DispenseTaskError as Error, DispenseTaskResponse as Response};

        let args = Encode!().context("failed to encode arg")?;

        let resp = self
            .0
            .query(&self.1, "peekTask")
            .with_arg(args)
            .call()
            .await
            .context("failed to query canister")?;

        let resp = Decode!(&resp, Response).context("failed to decode canister response")?;

        match resp {
            Response::Ok(id) => Ok(id),
            Response::Err(err) => Err(match err {
                Error::NoTasksAvailable => DispenseError::NoTasksAvailable,
                Error::Unauthorized => DispenseError::UnexpectedError(anyhow!("unauthorized")),
                Error::UnexpectedError(err) => DispenseError::UnexpectedError(anyhow!(err)),
            }),
        }
    }
}

pub struct Processor {
    // configuration
    delegation_domain: String,

    // dependencies
    resolver: Box<dyn Resolve>,
    acme_order: Box<dyn acme::Order>,
    acme_ready: Box<dyn acme::Ready>,
    acme_finalize: Box<dyn acme::Finalize>,
    dns_creator: Box<dyn dns::Create>,
    dns_deleter: Box<dyn dns::Delete>,
    certificate_uploader: Box<dyn certificate::Upload>,
}

impl Processor {
    pub fn new(
        delegation_domain: String,
        resolver: Box<dyn Resolve>,
        acme_order: Box<dyn acme::Order>,
        acme_ready: Box<dyn acme::Ready>,
        acme_finalize: Box<dyn acme::Finalize>,
        dns_creator: Box<dyn dns::Create>,
        dns_deleter: Box<dyn dns::Delete>,
        certificate_uploader: Box<dyn certificate::Upload>,
    ) -> Self {
        Self {
            delegation_domain,
            resolver,
            acme_order,
            acme_ready,
            acme_finalize,
            dns_creator,
            dns_deleter,
            certificate_uploader,
        }
    }
}

#[async_trait]
impl Process for Processor {
    async fn process(&self, id: &Id, task: &Task) -> Result<(), ProcessError> {
        match task.action {
            Action::Order => {
                // Phase 5 - Initiate certificate generation via ACME provider
                let challenge_key = self
                    .acme_order
                    .order(&task.name)
                    .await
                    .context("failed to create acme order")?;

                // Phase 6 - Create DNS record with challenge response
                self.dns_creator
                    .create(
                        &self.delegation_domain,
                        &format!("_acme-challenge.{}", task.name),
                        dns::Record::Txt(challenge_key),
                    )
                    .await
                    .context("failed to create dns record")?;

                Err(ProcessError::AwaitingDnsPropogation)
            }

            Action::Ready => {
                // Phase 7 - Ensure DNS TXT record has propogated
                self.resolver
                    .lookup(
                        &format!("_acme-challenge.{}.{}", task.name, self.delegation_domain),
                        RecordType::TXT,
                    )
                    .await
                    .map_err(|err| match err.kind() {
                        ResolveErrorKind::NoRecordsFound { .. } => {
                            ProcessError::AwaitingDnsPropogation
                        }
                        _ => ProcessError::UnexpectedError(anyhow!(
                            "failed to resolve TXT record: {err}"
                        )),
                    })?;

                // Phase 8 - Mark ACME order as ready
                self.acme_ready
                    .ready(&task.name)
                    .await
                    .context("failed to mark acme order as ready")?;

                Err(ProcessError::AwaitingAcmeOrderReady)
            }

            Action::Certificate => {
                // Phase 9 - Upload resulting certificate to repository
                let (certificate_chain_pem, private_key_pem) = self
                    .acme_finalize
                    .finalize(&task.name)
                    .await
                    .context("failed to finalize acme order")?;

                // Phase 10 - Remove DNS record with challenge response
                self.dns_deleter
                    .delete(
                        &self.delegation_domain,
                        &format!("_acme-challenge.{}", task.name),
                    )
                    .await
                    .context("failed to delete dns record")?;

                // Phase 11 - Upload certificates
                self.certificate_uploader
                    .upload(
                        id,
                        Pair(
                            private_key_pem.into_bytes(),
                            certificate_chain_pem.into_bytes(),
                        ),
                    )
                    .await
                    .context("failed to upload certificates")?;

                Ok(())
            }
        }
    }
}
