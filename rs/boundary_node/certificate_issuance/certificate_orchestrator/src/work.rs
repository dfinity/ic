use std::{cmp::Reverse, time::Duration};

use anyhow::anyhow;
use certificate_orchestrator_interface::{Id, Registration};
use ic_cdk::api::msg_caller;
use priority_queue::PriorityQueue;
use prometheus::labels;

cfg_if::cfg_if! {
    if #[cfg(test)] {
        use tests::time as time;
    } else {
        use ic_cdk::api::time;
    }
}

use crate::{
    IN_PROGRESS_TTL, LocalRef, StableMap, StorableId, WithMetrics,
    acl::{Authorize, AuthorizeError, WithAuthorize},
};

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Queue {
    fn queue(&self, id: Id, timestamp: u64) -> Result<(), QueueError>;
}

pub struct Queuer {
    tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    registrations: LocalRef<StableMap<StorableId, Registration>>,
}

impl Queuer {
    pub fn new(
        tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
        registrations: LocalRef<StableMap<StorableId, Registration>>,
    ) -> Self {
        Self {
            tasks,
            registrations,
        }
    }
}

impl Queue for Queuer {
    fn queue(&self, id: Id, timestamp: u64) -> Result<(), QueueError> {
        self.registrations.with(|regs| {
            let regs = regs.borrow();
            regs.get(&id.to_owned().into()).ok_or(QueueError::NotFound)
        })?;

        self.tasks.with(|tasks| {
            let mut tasks = tasks.borrow_mut();
            tasks.push(id, Reverse(timestamp));
        });

        Ok(())
    }
}

impl<T: Queue, A: Authorize> Queue for WithAuthorize<T, A> {
    fn queue(&self, id: Id, timestamp: u64) -> Result<(), QueueError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => QueueError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => QueueError::UnexpectedError(err),
            });
        };

        self.0.queue(id, timestamp)
    }
}

impl<T: Queue> Queue for WithMetrics<T> {
    fn queue(&self, id: Id, timestamp: u64) -> Result<(), QueueError> {
        let out = self.0.queue(id, timestamp);

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            QueueError::NotFound => "not-found",
                            QueueError::Unauthorized => "unauthorized",
                            QueueError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PeekError {
    #[error("No tasks available")]
    NoTasksAvailable,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Peek {
    fn peek(&self) -> Result<Id, PeekError>;
}

pub struct Peeker {
    tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Peeker {
    pub fn new(tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>) -> Self {
        Self { tasks }
    }
}

impl Peek for Peeker {
    fn peek(&self) -> Result<Id, PeekError> {
        self.tasks.with(|tasks| {
            // Check for available task
            match tasks.borrow().peek() {
                None => Err(PeekError::NoTasksAvailable),
                Some((id, Reverse(timestamp))) => {
                    if time().lt(timestamp) {
                        return Err(PeekError::NoTasksAvailable);
                    }
                    Ok(id.clone())
                }
            }
        })
    }
}

impl<T: Peek, A: Authorize> Peek for WithAuthorize<T, A> {
    fn peek(&self) -> Result<Id, PeekError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => PeekError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => PeekError::UnexpectedError(err),
            });
        };

        self.0.peek()
    }
}

impl<T: Peek> Peek for WithMetrics<T> {
    fn peek(&self) -> Result<Id, PeekError> {
        let out = self.0.peek();

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            PeekError::NoTasksAvailable => "no-tasks-available",
                            PeekError::Unauthorized => "unauthorized",
                            PeekError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error("Unauthorized")]
    Unauthorized,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait List {
    fn list(&self) -> Result<Vec<(String, u64, Registration)>, ListError>;
}

pub struct Lister {
    tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    registrations: LocalRef<StableMap<StorableId, Registration>>,
}

impl Lister {
    pub fn new(
        tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
        registrations: LocalRef<StableMap<StorableId, Registration>>,
    ) -> Self {
        Self {
            tasks,
            registrations,
        }
    }
}

impl List for Lister {
    fn list(&self) -> Result<Vec<(String, u64, Registration)>, ListError> {
        self.tasks.with(|tasks| {
            tasks
                .borrow()
                .iter()
                .map(|(id, Reverse(timestamp))| {
                    match self
                        .registrations
                        .with(|rs| rs.borrow().get(&id.to_owned().into()))
                    {
                        Some(r) => Ok((id.to_owned(), timestamp.to_owned(), r)),
                        None => Err(anyhow!(
                            "invalid state: task id {id} not found in registrations"
                        )
                        .into()),
                    }
                })
                .collect()
        })
    }
}

impl<T: List, A: Authorize> List for WithAuthorize<T, A> {
    fn list(&self) -> Result<Vec<(String, u64, Registration)>, ListError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => ListError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => ListError::UnexpectedError(err),
            });
        };

        self.0.list()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DispenseError {
    #[error("No tasks available")]
    NoTasksAvailable,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Dispense {
    fn dispense(&self) -> Result<Id, DispenseError>;
}

pub struct Dispenser {
    tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Dispenser {
    pub fn new(
        tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
        retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    ) -> Self {
        Self { tasks, retries }
    }
}

impl Dispense for Dispenser {
    fn dispense(&self) -> Result<Id, DispenseError> {
        self.tasks.with(|tasks| {
            // Check for available task
            match tasks.borrow().peek() {
                None => return Err(DispenseError::NoTasksAvailable),
                Some((_, Reverse(timestamp))) => {
                    if time().lt(timestamp) {
                        return Err(DispenseError::NoTasksAvailable);
                    }
                }
            };

            // Pop task
            let id = match tasks.borrow_mut().pop() {
                None => return Err(DispenseError::NoTasksAvailable),
                Some((id, _)) => id,
            };

            // Schedule a retry in case the task failed and was not re-queued
            let retry_delay =
                Duration::from_secs(IN_PROGRESS_TTL.with(|s| s.borrow().get(&()).unwrap()));

            self.retries.with(|retries| {
                retries.borrow_mut().push(
                    id.to_owned(),
                    Reverse(time() + retry_delay.as_nanos() as u64),
                )
            });

            Ok(id)
        })
    }
}

impl<T: Dispense, A: Authorize> Dispense for WithAuthorize<T, A> {
    fn dispense(&self) -> Result<Id, DispenseError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => DispenseError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => DispenseError::UnexpectedError(err),
            });
        };

        self.0.dispense()
    }
}

impl<T: Dispense> Dispense for WithMetrics<T> {
    fn dispense(&self) -> Result<Id, DispenseError> {
        let out = self.0.dispense();

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            DispenseError::NoTasksAvailable => "no-tasks-available",
                            DispenseError::Unauthorized => "unauthorized",
                            DispenseError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RemoveError {
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Remove {
    fn remove(&self, id: &str) -> Result<(), RemoveError>;
}

pub struct TaskRemover {
    tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl TaskRemover {
    pub fn new(tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>) -> Self {
        Self { tasks }
    }
}

impl Remove for TaskRemover {
    fn remove(&self, id: &str) -> Result<(), RemoveError> {
        self.tasks.with(|ts| match ts.borrow_mut().remove(id) {
            Some(_) => Ok(()),
            None => Err(RemoveError::NotFound),
        })
    }
}

impl<T: Remove, A: Authorize> Remove for WithAuthorize<T, A> {
    fn remove(&self, id: &str) -> Result<(), RemoveError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => RemoveError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => RemoveError::UnexpectedError(err),
            });
        };

        self.0.remove(id)
    }
}

impl<T: Remove> Remove for WithMetrics<T> {
    fn remove(&self, id: &str) -> Result<(), RemoveError> {
        let out = self.0.remove(id);

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            RemoveError::NotFound => "not-found",
                            RemoveError::Unauthorized => "unauthorized",
                            RemoveError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RetryError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Retry {
    fn retry(&self, t: u64) -> Result<(), RetryError>;
}

pub struct Retrier {
    tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Retrier {
    pub fn new(
        tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
        retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    ) -> Self {
        Self { tasks, retries }
    }
}

impl Retry for Retrier {
    fn retry(&self, t: u64) -> Result<(), RetryError> {
        self.retries.with(|retries| {
            let mut retries = retries.borrow_mut();

            #[allow(clippy::while_let_loop)]
            loop {
                // Check for next retry
                let p = match retries.peek() {
                    Some((_, p)) => p.0,
                    None => break,
                };

                if p > t {
                    break;
                }

                let id = match retries.pop() {
                    Some((id, _)) => id,
                    None => break,
                };

                // Schedule a task for the ID
                self.tasks.with(|tasks| {
                    let mut tasks = tasks.borrow_mut();
                    tasks.push(id, Reverse(t));
                });
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{RETRIES, TASKS};

    pub fn time() -> u64 {
        0
    }

    #[test]
    fn dispense_empty() {
        match Dispenser::new(&TASKS, &RETRIES).dispense() {
            Err(DispenseError::NoTasksAvailable) => {}
            _ => panic!("Not the error that was expected."),
        };
    }

    #[test]
    fn dispense_ok() {
        IN_PROGRESS_TTL.with(|s| {
            let mut s = s.borrow_mut();
            s.insert((), 10 * 60);
        });

        TASKS.with(|t| {
            t.borrow_mut().push(
                "id".into(), // item
                Reverse(0),  // priority
            )
        });

        let id = match Dispenser::new(&TASKS, &RETRIES).dispense() {
            Ok(id) => id,
            other => panic!("expected id but got {other:?}"),
        };

        assert_eq!(id, "id");
    }

    #[test]
    fn dispense_unavailable() {
        TASKS.with(|t| {
            t.borrow_mut().push(
                "id".into(), // item
                Reverse(1),  // priority
            )
        });

        match Dispenser::new(&TASKS, &RETRIES).dispense() {
            Err(DispenseError::NoTasksAvailable) => {}
            other => panic!("expected NoTasksAvailable but got {other:?}"),
        };
    }
}
