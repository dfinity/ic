use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use redis::AsyncCommands;
use serde::Serialize;
use tokio::sync::Mutex;
use trust_dns_resolver::{error::ResolveErrorKind, proto::rr::RecordType};
use uuid::Uuid;

use crate::{
    acme,
    certificate::{self, Pair},
    dns::{self, Resolve},
    registration::{Registration, State},
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
            State::Available => panic!(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Task {
    pub domain: String,
    pub action: Action,
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Queue: Sync + Send {
    async fn queue(&self, id: &Uuid, t: u64) -> Result<(), QueueError>;
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
    async fn dispense(&self) -> Result<(Uuid, Task), DispenseError>;
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
    async fn process(&self, task: &Task) -> Result<(), ProcessError>;
}

pub struct RedisQueuer<T>(pub Arc<Mutex<T>>);

#[async_trait]
impl<T> Queue for RedisQueuer<T>
where
    T: AsyncCommands + Clone + Send + Sync,
{
    async fn queue(&self, id: &Uuid, t: u64) -> Result<(), QueueError> {
        self.0
            .lock()
            .await
            .clone()
            .zadd("tasks", id.to_string(), t)
            .await
            .context("failed to queue task")?;

        Ok(())
    }
}

pub struct RedisDispenser<T>(pub Arc<Mutex<T>>);

#[async_trait]
impl<T> Dispense for RedisDispenser<T>
where
    T: AsyncCommands + Clone + Send + Sync,
{
    async fn dispense(&self) -> Result<(Uuid, Task), DispenseError> {
        // Retrieve next available task
        let script = redis::Script::new(
            r"
            -- RETRIEVE ITEM
            local ids = redis.call('ZRANGE', KEYS[1], '-inf', ARGV[1], 'BYSCORE', 'LIMIT', 0, 1)
            if (#ids == 0) then
                return nil
            end

            -- POP ITEM
            local id = ids[1];
            redis.call('ZREM', KEYS[1], id)

            return id
        ",
        );

        // Get current timestamp
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("failed to get current time")?
            .as_millis() as u64;

        let id: Option<String> = script
            .key("tasks")
            .arg(t)
            .invoke_async(&mut self.0.lock().await.clone())
            .await
            .context("failed to fetch task")?;

        // Extract registration ID
        let id = id.ok_or(DispenseError::NoTasksAvailable)?;
        let id = Uuid::from_str(&id).context("failed to parse uuid")?;

        // Retrieve registration
        let reg: Option<Registration> = self
            .0
            .lock()
            .await
            .clone()
            .get(format!("registration:{id}"))
            .await
            .context("failed to get registration")?;

        // Check record exists
        let reg = reg.ok_or_else(|| anyhow!("registration not found"))?;

        Ok((
            id,
            Task {
                domain: reg.domain,
                action: reg.state.into(),
            },
        ))
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
    async fn process(&self, task: &Task) -> Result<(), ProcessError> {
        match task.action {
            Action::Order => {
                // Phase 5 - Initiate certificate generation via ACME provider
                let challenge_key = self
                    .acme_order
                    .order(&task.domain)
                    .await
                    .context("failed to create acme order")?;

                // Phase 6 - Create DNS record with challenge response
                self.dns_creator
                    .create(
                        &self.delegation_domain,
                        &format!("_acme-challenge.{}", task.domain),
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
                        &format!("_acme-challenge.{}.{}", task.domain, self.delegation_domain),
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
                    .ready(&task.domain)
                    .await
                    .context("failed to mark acme order as ready")?;

                Err(ProcessError::AwaitingAcmeOrderReady)
            }

            Action::Certificate => {
                // Phase 9 - Upload resulting certificate to repository
                let (certificate_chain_pem, private_key_pem) = self
                    .acme_finalize
                    .finalize(&task.domain)
                    .await
                    .context("failed to finalize acme order")?;

                // Phase 10 - Remove DNS record with challenge response
                self.dns_deleter
                    .delete(
                        &self.delegation_domain,
                        &format!("_acme-challenge.{}", task.domain),
                    )
                    .await
                    .context("failed to delete dns record")?;

                // Phase 11 - Upload certificates
                self.certificate_uploader
                    .upload(&task.domain, &Pair(certificate_chain_pem, private_key_pem))
                    .await
                    .context("failed to upload certificates")?;

                Ok(())
            }
        }
    }
}
