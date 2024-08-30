use std::{
    collections::HashSet, fmt, iter::once, sync::atomic::Ordering, sync::Arc, time::Duration,
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use certificate_orchestrator_interface as ifc;
use ic_agent::Agent;
use opentelemetry::{baggage::BaggageExt, trace::FutureExt, KeyValue};
use serde::Serialize;
use trust_dns_resolver::{error::ResolveErrorKind, proto::rr::RecordType};

use crate::{
    acme::{self, FinalizeError},
    certificate::{self, GetCert, GetCertError, Pair},
    check::Check,
    decoder_config,
    dns::{self, Resolve},
    registration::{Id, Registration, State},
    TASK_DELAY_SEC, TASK_ERROR_DELAY_SEC,
};

#[derive(Debug, Clone, Serialize)]
pub enum Action {
    Order,
    Ready,
    Certificate,
    Renewal,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<State> for Action {
    fn from(s: State) -> Self {
        match s {
            State::Failed(_) | State::PendingOrder => Action::Order,
            State::PendingChallengeResponse => Action::Ready,
            State::PendingAcmeApproval => Action::Certificate,
            State::Available => Action::Renewal,
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
pub enum PeekError {
    #[error("No tasks available")]
    NoTasksAvailable,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Peek: Sync + Send {
    async fn peek(&self) -> Result<Id, PeekError>;
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
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("awaiting creation of an acme order")]
    AwaitingAcmeOrderCreation,

    #[error("awaiting propagation of challenge response dns txt record")]
    AwaitingDnsPropagation,

    #[error("awaiting acme approval for certificate order")]
    AwaitingAcmeOrderReady,

    #[error("user configured configuration")]
    FailedUserConfigurationCheck,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl From<&ProcessError> for Duration {
    fn from(error: &ProcessError) -> Self {
        match error {
            ProcessError::AwaitingAcmeOrderCreation => {
                Duration::from_secs(TASK_DELAY_SEC.load(Ordering::SeqCst))
            }
            ProcessError::AwaitingDnsPropagation => {
                Duration::from_secs(TASK_DELAY_SEC.load(Ordering::SeqCst))
            }
            ProcessError::AwaitingAcmeOrderReady => {
                Duration::from_secs(TASK_DELAY_SEC.load(Ordering::SeqCst))
            }
            ProcessError::FailedUserConfigurationCheck => {
                Duration::from_secs(TASK_ERROR_DELAY_SEC.load(Ordering::SeqCst))
            }
            ProcessError::UnexpectedError(_) => {
                Duration::from_secs(TASK_ERROR_DELAY_SEC.load(Ordering::SeqCst))
            }
        }
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

        let args = Encode!(id, &t).context("failed to encode arg")?;

        let resp = self
            .0
            .update(&self.1, "queueTask")
            .with_arg(args)
            .call_and_wait()
            .await
            .context("failed to query canister")?;

        let resp = Decode!([decoder_config()]; &resp, Response)
            .context("failed to decode canister response")?;

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

pub struct CanisterPeeker(pub Arc<Agent>, pub Principal);

#[async_trait]
impl Peek for CanisterPeeker {
    async fn peek(&self) -> Result<Id, PeekError> {
        use ifc::{PeekTaskError as Error, PeekTaskResponse as Response};

        let args = Encode!().context("failed to encode arg")?;

        let resp = self
            .0
            .query(&self.1, "peekTask")
            .with_arg(args)
            .call()
            .await
            .context("failed to query canister")?;

        let resp = Decode!([decoder_config()]; &resp, Response)
            .context("failed to decode canister response")?;

        match resp {
            Response::Ok(id) => Ok(id),
            Response::Err(err) => Err(match err {
                Error::NoTasksAvailable => PeekError::NoTasksAvailable,
                Error::Unauthorized => PeekError::UnexpectedError(anyhow!("unauthorized")),
                Error::UnexpectedError(err) => PeekError::UnexpectedError(anyhow!(err)),
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

            let args = Encode!().context("failed to encode arg")?;

            let resp = self
                .0
                .update(&self.1, "dispenseTask")
                .with_arg(args)
                .call_and_wait()
                .await
                .context("failed to query canister")?;

            let resp = Decode!([decoder_config()]; &resp, Response)
                .context("failed to decode canister response")?;

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

            let resp = Decode!([decoder_config()]; &resp, Response)
                .context("failed to decode canister response")?;

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
}

pub struct Processor {
    // configuration
    delegation_domain: String,

    // dependencies
    checker: Arc<dyn Check>,
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
        checker: Arc<dyn Check>,
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
            checker,
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

                Err(ProcessError::AwaitingDnsPropagation)
            }

            Action::Ready => {
                // Phase 7 - Ensure DNS TXT record has propagated
                self.resolver
                    .lookup(&format!("_acme-challenge.{}", task.name), RecordType::TXT)
                    .await
                    .map_err(|err| match err.kind() {
                        ResolveErrorKind::NoRecordsFound { .. } => {
                            ProcessError::AwaitingDnsPropagation
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
                // Phase 9 - Obtain the certificate once the order is finalized
                let (certificate_chain_pem, private_key_pem) = self
                    .acme_finalize
                    .finalize(&task.name)
                    .await
                    .map_err(|err| match err {
                        FinalizeError::OrderNotReady(_) => ProcessError::AwaitingAcmeOrderReady,
                        FinalizeError::UnexpectedError(err) => err.into(),
                    })?;

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

            Action::Renewal => match self.checker.check(&task.name).await {
                // Renewal - Before trying to renew the certificate of a domain,
                // the issuer needs to check whether the domain and canister
                // is still correctly configured (e.g., the DNS records are in place
                // to delegate the ACME challenge to the delegation domain).
                Ok(_) => Err(ProcessError::AwaitingAcmeOrderCreation),
                Err(_err) => Err(ProcessError::FailedUserConfigurationCheck),
            },
        }
    }
}

pub struct WithDetectRenewal<T: Process> {
    pub processor: T,
    pub renewal_detector: Arc<dyn GetCert>,
}

impl<T: Process> WithDetectRenewal<T> {
    pub fn new(processor: T, renewal_detector: Arc<dyn GetCert>) -> Self {
        Self {
            processor,
            renewal_detector,
        }
    }
}

#[async_trait]
impl<T: Process> Process for WithDetectRenewal<T> {
    async fn process(&self, id: &Id, task: &Task) -> Result<(), ProcessError> {
        let is_renewal = match self.renewal_detector.get_cert(id).await {
            Ok(_) => String::from("1"),
            Err(GetCertError::NotFound) => String::from("0"),
            Err(err) => return Err(ProcessError::UnexpectedError(anyhow!(err))),
        };
        let ctx = opentelemetry::Context::current_with_baggage(once(KeyValue::new(
            "is_renewal",
            is_renewal,
        )));
        self.processor.process(id, task).with_context(ctx).await
    }
}

pub struct WithDetectImportance<T: Process> {
    pub processor: T,
    pub domains: HashSet<String>,
}

impl<T: Process> WithDetectImportance<T> {
    pub fn new(processor: T, domains: Vec<String>) -> Self {
        Self {
            processor,
            domains: domains.into_iter().collect(),
        }
    }
}

pub fn extract_domain(name: &str) -> &str {
    match name.rmatch_indices('.').nth(1) {
        Some((idx, _)) => name.split_at(idx + 1).1,
        None => name,
    }
}

#[async_trait]
impl<T: Process> Process for WithDetectImportance<T> {
    async fn process(&self, id: &Id, task: &Task) -> Result<(), ProcessError> {
        let domain = extract_domain(&task.name);

        let is_important = match self.domains.contains(domain) {
            false => "0",
            true => "1",
        };

        let ctx = opentelemetry::Context::current_with_baggage(once(KeyValue::new(
            "is_important",
            is_important,
        )));

        self.processor.process(id, task).with_context(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Error;
    use mockall::predicate;
    use trust_dns_resolver::{
        lookup::Lookup,
        proto::{op::Query, rr::Record as TrustRecord},
        Name,
    };

    use crate::{
        acme::{MockFinalize, MockOrder, MockReady},
        certificate::MockUpload,
        check::{CheckError, MockCheck},
        dns::{MockCreate, MockDelete, MockResolve, Record},
    };

    #[tokio::test]
    async fn test_process_order() -> Result<(), Error> {
        let id: String = "id".into();

        let task = Task {
            name: "name".into(),
            action: Action::Order,
        };

        let mut resolver = MockResolve::new();
        resolver.expect_lookup().never();

        let mut checker = MockCheck::new();
        checker.expect_check().never();

        let mut acme_order = MockOrder::new();
        acme_order
            .expect_order()
            .times(1)
            .with(predicate::eq("name"))
            .returning(|_| Ok("token".into()));

        let mut acme_ready = MockReady::new();
        acme_ready.expect_ready().never();

        let mut acme_finalize = MockFinalize::new();
        acme_finalize.expect_finalize().never();

        let mut dns_creator = MockCreate::new();
        dns_creator
            .expect_create()
            .times(1)
            .with(
                predicate::eq("delegation"),
                predicate::eq("_acme-challenge.name"),
                predicate::eq(Record::Txt("token".into())),
            )
            .returning(|_, _, _| Ok(()));

        let mut dns_deleter = MockDelete::new();
        dns_deleter.expect_delete().never();

        let mut certificate_uploader = MockUpload::new();
        certificate_uploader.expect_upload().never();

        let processor = Processor::new(
            "delegation".into(),            // delegation_domain
            Arc::new(checker),              // checker
            Box::new(resolver),             // resolver
            Box::new(acme_order),           // acme_order
            Box::new(acme_ready),           // acme_ready
            Box::new(acme_finalize),        // acme_finalize
            Box::new(dns_creator),          // dns_creator
            Box::new(dns_deleter),          // dns_deleter
            Box::new(certificate_uploader), // certificate_uploader
        );

        match processor.process(&id, &task).await {
            Err(ProcessError::AwaitingDnsPropagation) => Ok(()),
            other => Err(anyhow!(
                "expected AwaitingDnsPropagation but got {:?}",
                other
            )),
        }
    }

    #[tokio::test]
    async fn test_process_ready() -> Result<(), Error> {
        let id: String = "id".into();

        let task = Task {
            name: "name".into(),
            action: Action::Ready,
        };

        let mut resolver = MockResolve::new();
        resolver
            .expect_lookup()
            .times(1)
            .with(
                predicate::eq("_acme-challenge.name"),
                predicate::eq(RecordType::TXT),
            )
            .returning(|_, _| {
                Ok({
                    let q = Query::new();

                    let mut r = TrustRecord::new();
                    r.set_name(Name::from_utf8("token")?);
                    r.set_record_type(RecordType::TXT);

                    Lookup::new_with_max_ttl(q, Arc::new([r]))
                })
            });

        let mut checker = MockCheck::new();
        checker.expect_check().never();

        let mut acme_order = MockOrder::new();
        acme_order.expect_order().never();

        let mut acme_ready = MockReady::new();
        acme_ready
            .expect_ready()
            .times(1)
            .with(predicate::eq("name"))
            .returning(|_| Ok(()));

        let mut acme_finalize = MockFinalize::new();
        acme_finalize.expect_finalize().never();

        let mut dns_creator = MockCreate::new();
        dns_creator.expect_create().never();

        let mut dns_deleter = MockDelete::new();
        dns_deleter.expect_delete().never();

        let mut certificate_uploader = MockUpload::new();
        certificate_uploader.expect_upload().never();

        let processor = Processor::new(
            "delegation".into(),            // delegation_domain
            Arc::new(checker),              // checker
            Box::new(resolver),             // resolver
            Box::new(acme_order),           // acme_order
            Box::new(acme_ready),           // acme_ready
            Box::new(acme_finalize),        // acme_finalize
            Box::new(dns_creator),          // dns_creator
            Box::new(dns_deleter),          // dns_deleter
            Box::new(certificate_uploader), // certificate_uploader
        );

        match processor.process(&id, &task).await {
            Err(ProcessError::AwaitingAcmeOrderReady) => Ok(()),
            other => Err(anyhow!(
                "expected AwaitingAcmeOrderReady but got {:?}",
                other
            )),
        }
    }

    #[tokio::test]
    async fn test_process_certificate() -> Result<(), Error> {
        let id: String = "id".into();

        let task = Task {
            name: "name".into(),
            action: Action::Certificate,
        };

        let mut resolver = MockResolve::new();
        resolver.expect_lookup().never();

        let mut checker = MockCheck::new();
        checker.expect_check().never();

        let mut acme_order = MockOrder::new();
        acme_order.expect_order().never();

        let mut acme_ready = MockReady::new();
        acme_ready.expect_ready().never();

        let mut acme_finalize = MockFinalize::new();
        acme_finalize
            .expect_finalize()
            .times(1)
            .with(predicate::eq("name"))
            .returning(|_| Ok(("cert".into(), "key".into())));

        let mut dns_creator = MockCreate::new();
        dns_creator.expect_create().never();

        let mut dns_deleter = MockDelete::new();
        dns_deleter
            .expect_delete()
            .times(1)
            .with(
                predicate::eq("delegation"),
                predicate::eq("_acme-challenge.name"),
            )
            .returning(|_, _| Ok(()));

        let mut certificate_uploader = MockUpload::new();
        certificate_uploader
            .expect_upload()
            .times(1)
            .with(
                predicate::eq(Id::from("id")),
                predicate::eq(Pair("key".into(), "cert".into())),
            )
            .returning(|_, _| Ok(()));

        let processor = Processor::new(
            "delegation".into(),            // delegation_domain
            Arc::new(checker),              // checker
            Box::new(resolver),             // resolver
            Box::new(acme_order),           // acme_order
            Box::new(acme_ready),           // acme_ready
            Box::new(acme_finalize),        // acme_finalize
            Box::new(dns_creator),          // dns_creator
            Box::new(dns_deleter),          // dns_deleter
            Box::new(certificate_uploader), // certificate_uploader
        );

        match processor.process(&id, &task).await {
            Ok(()) => Ok(()),
            other => Err(anyhow!("expected Ok(()) but got {:?}", other)),
        }
    }

    #[tokio::test]
    async fn test_failed_renewal_check() -> Result<(), Error> {
        let id: String = "id".into();

        let task = Task {
            name: "name".into(),
            action: Action::Renewal,
        };

        let mut resolver = MockResolve::new();
        resolver.expect_lookup().never();

        let mut checker = MockCheck::new();
        checker
            .expect_check()
            .times(1)
            .with(predicate::eq("name"))
            .returning(|_| {
                Err(CheckError::KnownDomainsUnavailable {
                    id: "oa7fk-maaaa-aaaam-abgka-cai".into(),
                })
            });

        let mut acme_order = MockOrder::new();
        acme_order.expect_order().never();

        let mut acme_ready = MockReady::new();
        acme_ready.expect_ready().never();

        let mut acme_finalize = MockFinalize::new();
        acme_finalize.expect_finalize().never();

        let mut dns_creator = MockCreate::new();
        dns_creator.expect_create().never();

        let mut dns_deleter = MockDelete::new();
        dns_deleter.expect_delete().never();

        let mut certificate_uploader = MockUpload::new();
        certificate_uploader.expect_upload().never();

        let processor = Processor::new(
            "delegation".into(),            // delegation_domain
            Arc::new(checker),              // checker
            Box::new(resolver),             // resolver
            Box::new(acme_order),           // acme_order
            Box::new(acme_ready),           // acme_ready
            Box::new(acme_finalize),        // acme_finalize
            Box::new(dns_creator),          // dns_creator
            Box::new(dns_deleter),          // dns_deleter
            Box::new(certificate_uploader), // certificate_uploader
        );

        match processor.process(&id, &task).await {
            Err(ProcessError::FailedUserConfigurationCheck) => Ok(()),
            other => Err(anyhow!(
                "expected FailedUserConfigurationCheck but got {:?}",
                other
            )),
        }
    }

    #[tokio::test]
    async fn test_passed_renewal_check() -> Result<(), Error> {
        let id: String = "id".into();

        let task = Task {
            name: "name".into(),
            action: Action::Renewal,
        };

        let mut resolver = MockResolve::new();
        resolver.expect_lookup().never();

        let mut checker = MockCheck::new();
        checker
            .expect_check()
            .times(1)
            .with(predicate::eq("name"))
            .returning(|_| Ok(Principal::from_text("oa7fk-maaaa-aaaam-abgka-cai").unwrap()));

        let mut acme_order = MockOrder::new();
        acme_order.expect_order().never();

        let mut acme_ready = MockReady::new();
        acme_ready.expect_ready().never();

        let mut acme_finalize = MockFinalize::new();
        acme_finalize.expect_finalize().never();

        let mut dns_creator = MockCreate::new();
        dns_creator.expect_create().never();

        let mut dns_deleter = MockDelete::new();
        dns_deleter.expect_delete().never();

        let mut certificate_uploader = MockUpload::new();
        certificate_uploader.expect_upload().never();

        let processor = Processor::new(
            "delegation".into(),            // delegation_domain
            Arc::new(checker),              // checker
            Box::new(resolver),             // resolver
            Box::new(acme_order),           // acme_order
            Box::new(acme_ready),           // acme_ready
            Box::new(acme_finalize),        // acme_finalize
            Box::new(dns_creator),          // dns_creator
            Box::new(dns_deleter),          // dns_deleter
            Box::new(certificate_uploader), // certificate_uploader
        );

        match processor.process(&id, &task).await {
            Err(ProcessError::AwaitingAcmeOrderCreation) => Ok(()),
            other => Err(anyhow!(
                "expected AwaitingAcmeOrderCreation but got {:?}",
                other
            )),
        }
    }

    #[tokio::test]
    async fn test_extract_domain() -> Result<(), Error> {
        for tc in [
            ("example.com", "example.com"),
            ("a.example.com", "example.com"),
            ("a.b.example.com", "example.com"),
            ("a.b.c.example.com", "example.com"),
        ] {
            assert_eq!(extract_domain(tc.0), tc.1);
        }

        Ok(())
    }
}
