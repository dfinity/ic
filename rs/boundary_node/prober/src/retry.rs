use ic_agent::{
    agent::{RejectCode, RejectResponse},
    export::Principal,
    Agent, AgentError,
    AgentError::*,
};

use anyhow::Error;
use async_trait::async_trait;
use std::future::Future;

use crate::{Create, Delete, Install, Stop};

pub struct WithRetry<T> {
    inner: T,
    num_retries: i32,
}

impl<T> WithRetry<T> {
    pub fn new(inner: T, num_retries: i32) -> Self {
        Self { inner, num_retries }
    }

    async fn exec_with_retry<F, G, Fut, R>(&self, mut f: F, mut result_is_retry: G) -> R
    where
        F: FnMut() -> Fut,
        G: FnMut(&R) -> bool,
        Fut: Future<Output = R>,
    {
        let mut i = 0;
        loop {
            let res = f().await;
            i += 1;
            if !result_is_retry(&res) || i > self.num_retries {
                break res;
            }
        }
    }
}

#[async_trait]
impl<C: Create> Create for WithRetry<C> {
    async fn create(&self, agent: &Agent, wallet_id: &str) -> Result<Principal, Error> {
        let f = || async { self.inner.create(agent, wallet_id).await };
        self.exec_with_retry(f, |r| {
            let err = if let Err(err) = r {
                err.downcast_ref::<AgentError>()
            } else {
                return true;
            };
            match err {
                Some(InvalidCborData(..) | CandidError(..) | RequestStatusDoneNoReply(..)) => false,
                Some(UncertifiedReject(RejectResponse { reject_code, .. })) => {
                    *reject_code != RejectCode::CanisterError
                }
                Some(CertifiedReject(RejectResponse { reject_code, .. })) => {
                    *reject_code != RejectCode::CanisterError
                }
                _ => true,
            }
        })
        .await
    }
}

#[async_trait]
impl<T: Install> Install for WithRetry<T> {
    async fn install(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error> {
        let f = || async { self.inner.install(agent, wallet_id, canister_id).await };
        self.exec_with_retry(f, |r| {
            let err = if let Err(err) = r {
                err.downcast_ref::<AgentError>()
            } else {
                return true;
            };
            match err {
                Some(RequestStatusDoneNoReply(..)) => false,
                Some(UncertifiedReject(RejectResponse { reject_code, .. })) => {
                    *reject_code != RejectCode::CanisterError
                }
                Some(CertifiedReject(RejectResponse { reject_code, .. })) => {
                    *reject_code != RejectCode::CanisterError
                }
                _ => true,
            }
        })
        .await
    }
}

#[async_trait]
impl<T: Stop> Stop for WithRetry<T> {
    async fn stop(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error> {
        let f = || async { self.inner.stop(agent, wallet_id, canister_id).await };
        self.exec_with_retry(f, |r| {
            let err = if let Err(err) = r {
                err.downcast_ref::<AgentError>()
            } else {
                return true;
            };
            match err {
                Some(RequestStatusDoneNoReply(..)) => false,
                Some(UncertifiedReject(RejectResponse { reject_code, .. })) => {
                    *reject_code != RejectCode::CanisterError
                }
                Some(CertifiedReject(RejectResponse { reject_code, .. })) => {
                    *reject_code != RejectCode::CanisterError
                }
                _ => true,
            }
        })
        .await
    }
}

#[async_trait]
impl<T: Delete> Delete for WithRetry<T> {
    async fn delete(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error> {
        let f = || async { self.inner.delete(agent, wallet_id, canister_id).await };
        self.exec_with_retry(f, |r| {
            let err = if let Err(err) = r {
                err.downcast_ref::<AgentError>()
            } else {
                return true;
            };
            match err {
                Some(RequestStatusDoneNoReply(..)) => false,
                Some(UncertifiedReject(RejectResponse { reject_code, .. })) => {
                    *reject_code != RejectCode::CanisterError
                }
                Some(CertifiedReject(RejectResponse { reject_code, .. })) => {
                    *reject_code != RejectCode::CanisterError
                }
                _ => true,
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[tokio::test]
    async fn test_exec_with_rety_all_true() -> Result<(), Error> {
        let test_cases = [0, 1, 10];
        for ts in test_cases {
            let res = Rc::new(RefCell::new(0));
            let rt = WithRetry::new((), ts);

            rt.exec_with_retry(
                || async {
                    *(res.borrow_mut()) += 1;
                },
                |_| true,
            )
            .await;

            assert_eq!(*(res.borrow()), ts + 1);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_exec_with_rety_all_false() -> Result<(), Error> {
        let test_cases = [0, 1, 10];
        for ts in test_cases {
            let res = Rc::new(RefCell::new(0));
            let rt = WithRetry::new((), ts);

            rt.exec_with_retry(
                || async {
                    *(res.borrow_mut()) += 1;
                },
                |_| false,
            )
            .await;

            assert_eq!(*(res.borrow()), 1);
        }
        Ok(())
    }
}
